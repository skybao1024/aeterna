use std::ptr;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use core_foundation::string::CFStringRef;
use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    string::CFString,
};
use objc2::rc::Retained;
use objc2::{AnyThread, DefinedClass, define_class, msg_send, sel};
use objc2_app_kit::{
    NSWorkspace, NSWorkspaceDidWakeNotification, NSWorkspaceSessionDidBecomeActiveNotification,
    NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillSleepNotification,
};
use objc2_core_graphics::{CGEventSource, CGEventSourceStateID, CGEventType};
use objc2_foundation::{NSNotification, NSNotificationCenter, NSObject, NSObjectProtocol};
use security_framework_sys::{
    access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    base::{
        errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecDuplicateItem as ERR_SEC_DUPLICATE_ITEM,
        errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND, errSecSuccess as ERR_SEC_SUCCESS,
    },
    item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnData, kSecUseAuthenticationUI,
        kSecUseAuthenticationUISkip, kSecUseDataProtectionKeychain, kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching},
};

use super::observer::{
    ActivitySampler, ObserverStartError, ObserverStopError, PollingObserver, monotonic_time,
};
use super::policy::{
    ActivityObservation, ActivitySampleValue, EligibleInputClass, InputSampleValue,
    ObservationKind, SessionState, UnlockGateFailure, UnlockGateState,
};

const ANY_INPUT_EVENT_TYPE: CGEventType = CGEventType(u32::MAX);
const UNLOCK_GATE_SERVICE: &str = "dev.aeterna.desktop.i01.activity-gate";
const UNLOCK_GATE_ACCOUNT: &str = "v1:unlock-gate";
const UNLOCK_GATE_VALUE: &[u8] = b"aeterna-i01-nonsecret-gate-v1";
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;

// SAFETY CONTRACT: this declaration matches the public Security.framework
// `CFStringRef` symbol from SecItem.h on every supported macOS target.
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
}

macro_rules! security_constant {
    ($constant:ident) => {{
        // SAFETY: Security.framework exports these process-lifetime CFString
        // constants on the supported macOS target. The wrapper below retains
        // each value before it enters an owned Core Foundation dictionary.
        unsafe { $constant }
    }};
}

struct WorkspaceObserverIvars {
    observations: Sender<ActivityObservation>,
    epoch: Instant,
}

define_class!(
    // SAFETY:
    // - NSObject has no subclassing requirements relevant to this observer.
    // - The class does not implement Drop; Rust ivars are released by objc2.
    // - Every registered selector below is implemented with the exact one-argument
    //   NSNotification signature expected by NSNotificationCenter.
    #[unsafe(super(NSObject))]
    #[name = "AeternaI01WorkspaceObserver"]
    #[ivars = WorkspaceObserverIvars]
    struct WorkspaceObserver;

    impl WorkspaceObserver {
        #[unsafe(method(aeternaI01WillSleep:))]
        fn will_sleep(&self, _notification: &NSNotification) {
            self.send(ObservationKind::WillSleep);
        }

        #[unsafe(method(aeternaI01DidWake:))]
        fn did_wake(&self, _notification: &NSNotification) {
            self.send(ObservationKind::DidWake);
        }

        #[unsafe(method(aeternaI01SessionDidResignActive:))]
        fn session_did_resign_active(&self, _notification: &NSNotification) {
            self.send(ObservationKind::SessionChanged(SessionState::Inactive));
        }

        #[unsafe(method(aeternaI01SessionDidBecomeActive:))]
        fn session_did_become_active(&self, _notification: &NSNotification) {
            // A documented switch-in notification does not prove screen unlock.
            self.send(ObservationKind::SessionChanged(SessionState::Unknown));
        }
    }

    unsafe impl NSObjectProtocol for WorkspaceObserver {}
);

impl WorkspaceObserver {
    fn new(observations: Sender<ActivityObservation>, epoch: Instant) -> Retained<Self> {
        let observer = Self::alloc().set_ivars(WorkspaceObserverIvars {
            observations,
            epoch,
        });
        // SAFETY: `observer` is an allocated NSObject subclass with all Rust ivars
        // initialized. NSObject's designated `init` has no additional arguments.
        unsafe { msg_send![super(observer), init] }
    }

    fn send(&self, kind: ObservationKind) {
        let observed_at = monotonic_time(self.ivars().epoch);
        let _ = self
            .ivars()
            .observations
            .send(ActivityObservation { observed_at, kind });
    }
}

struct QuartzActivitySampler {
    unlock_gate: KeychainUnlockGate,
}

impl ActivitySampler for QuartzActivitySampler {
    fn sample_activity(&mut self) -> ActivitySampleValue {
        // Preserve this order. A successful gate read follows the input reads,
        // so a later distinct HID epoch proves that a successful unlock check
        // occurred between the two HID-class input epochs.
        let hid = CGEventSource::seconds_since_last_event_type(
            CGEventSourceStateID::HIDSystemState,
            ANY_INPUT_EVENT_TYPE,
        );
        let combined = CGEventSource::seconds_since_last_event_type(
            CGEventSourceStateID::CombinedSessionState,
            ANY_INPUT_EVENT_TYPE,
        );
        ActivitySampleValue {
            eligible: InputSampleValue::AgeSeconds(hid),
            broader: Some(InputSampleValue::AgeSeconds(combined)),
            eligible_class: EligibleInputClass::HidClass,
            unlock_gate: self.unlock_gate.sample(),
        }
    }
}

struct KeychainUnlockGate {
    initialized: bool,
}

impl KeychainUnlockGate {
    const fn new() -> Self {
        Self { initialized: false }
    }

    fn sample(&mut self) -> UnlockGateState {
        match read_unlock_gate() {
            Ok(()) => {
                self.initialized = true;
                UnlockGateState::Accessible
            }
            Err(GateReadError::Status(ERR_SEC_ITEM_NOT_FOUND)) if !self.initialized => {
                match create_unlock_gate() {
                    ERR_SEC_SUCCESS | ERR_SEC_DUPLICATE_ITEM => match read_unlock_gate() {
                        Ok(()) => {
                            self.initialized = true;
                            UnlockGateState::Accessible
                        }
                        Err(error) => map_gate_error(error),
                    },
                    status => map_gate_status(status),
                }
            }
            Err(error) => map_gate_error(error),
        }
    }
}

enum GateReadError {
    Status(i32),
    InvalidItem,
}

fn read_unlock_gate() -> Result<(), GateReadError> {
    let query = unlock_gate_identity_dictionary(true, None);
    let mut result = ptr::null();
    // SAFETY: `query` owns every value for the synchronous call. The output is
    // initialized to null and a successful Copy-rule result is wrapped once.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status != ERR_SEC_SUCCESS {
        return Err(GateReadError::Status(status));
    }
    if result.is_null() {
        return Err(GateReadError::InvalidItem);
    }
    // SAFETY: a successful non-null Copy-rule result transfers one ownership
    // reference to this wrapper.
    let value = unsafe { CFType::wrap_under_create_rule(result) };
    let data = value
        .downcast::<CFData>()
        .ok_or(GateReadError::InvalidItem)?;
    if data.bytes() == UNLOCK_GATE_VALUE {
        Ok(())
    } else {
        Err(GateReadError::InvalidItem)
    }
}

fn create_unlock_gate() -> i32 {
    let query = unlock_gate_identity_dictionary(false, Some(UNLOCK_GATE_VALUE));
    // SAFETY: `query` owns every key/value for the synchronous call. No result
    // is requested, so a null output pointer is permitted.
    unsafe { SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut()) }
}

fn unlock_gate_identity_dictionary(
    return_data: bool,
    value: Option<&[u8]>,
) -> CFDictionary<CFType, CFType> {
    let mut pairs = vec![
        static_pair(
            security_constant!(kSecClass),
            security_constant!(kSecClassGenericPassword),
        ),
        (
            static_string(security_constant!(kSecUseDataProtectionKeychain)),
            CFBoolean::true_value().into_CFType(),
        ),
        (
            static_string(security_constant!(kSecAttrService)),
            CFString::new(UNLOCK_GATE_SERVICE).into_CFType(),
        ),
        (
            static_string(security_constant!(kSecAttrAccount)),
            CFString::new(UNLOCK_GATE_ACCOUNT).into_CFType(),
        ),
    ];
    if return_data {
        pairs.push((
            static_string(security_constant!(kSecReturnData)),
            CFBoolean::true_value().into_CFType(),
        ));
        pairs.push(static_pair(
            security_constant!(kSecUseAuthenticationUI),
            security_constant!(kSecUseAuthenticationUISkip),
        ));
    } else {
        pairs.push(static_pair(
            security_constant!(kSecAttrAccessible),
            security_constant!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
        ));
        pairs.push((
            static_string(security_constant!(kSecAttrSynchronizable)),
            CFBoolean::false_value().into_CFType(),
        ));
    }
    if let Some(value) = value {
        pairs.push((
            static_string(security_constant!(kSecValueData)),
            CFData::from_buffer(value).into_CFType(),
        ));
    }
    CFDictionary::from_CFType_pairs(&pairs)
}

fn static_pair(key: CFStringRef, value: CFStringRef) -> (CFType, CFType) {
    (static_string(key), static_string(value))
}

fn static_string(reference: CFStringRef) -> CFType {
    // SAFETY: Security.framework exports immortal CFString constants. The get
    // rule wrapper retains one reference which CFType later releases once.
    unsafe { CFString::wrap_under_get_rule(reference) }.into_CFType()
}

fn map_gate_error(error: GateReadError) -> UnlockGateState {
    match error {
        GateReadError::Status(status) => map_gate_status(status),
        GateReadError::InvalidItem => UnlockGateState::Failed(UnlockGateFailure::InvalidItem),
    }
}

fn map_gate_status(status: i32) -> UnlockGateState {
    match status {
        ERR_SEC_INTERACTION_NOT_ALLOWED => UnlockGateState::Locked,
        ERR_SEC_ITEM_NOT_FOUND => UnlockGateState::Failed(UnlockGateFailure::ItemMissing),
        ERR_SEC_AUTH_FAILED => UnlockGateState::Failed(UnlockGateFailure::AccessDenied),
        ERR_SEC_MISSING_ENTITLEMENT => {
            UnlockGateState::Failed(UnlockGateFailure::MissingEntitlement)
        }
        ERR_SEC_NOT_AVAILABLE => UnlockGateState::Failed(UnlockGateFailure::KeychainUnavailable),
        _ => UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed),
    }
}

pub struct MacOsActivityObserver {
    notification_center: Retained<NSNotificationCenter>,
    notification_target: Retained<WorkspaceObserver>,
    poller: PollingObserver,
    stopped: bool,
}

impl MacOsActivityObserver {
    pub fn start(
        observations: Sender<ActivityObservation>,
        epoch: Instant,
        poll_interval: Duration,
    ) -> Result<Self, ObserverStartError> {
        let notification_center = NSWorkspace::sharedWorkspace().notificationCenter();
        let notification_target = WorkspaceObserver::new(observations.clone(), epoch);

        // SAFETY: Each selector is implemented by `WorkspaceObserver` with the
        // required NSNotification argument. The target is retained in this struct
        // until all registrations are removed during `stop`/Drop. The static
        // notification names and a null sender object are valid for this center.
        unsafe {
            notification_center.addObserver_selector_name_object(
                &notification_target,
                sel!(aeternaI01WillSleep:),
                Some(NSWorkspaceWillSleepNotification),
                None,
            );
            notification_center.addObserver_selector_name_object(
                &notification_target,
                sel!(aeternaI01DidWake:),
                Some(NSWorkspaceDidWakeNotification),
                None,
            );
            notification_center.addObserver_selector_name_object(
                &notification_target,
                sel!(aeternaI01SessionDidResignActive:),
                Some(NSWorkspaceSessionDidResignActiveNotification),
                None,
            );
            notification_center.addObserver_selector_name_object(
                &notification_target,
                sel!(aeternaI01SessionDidBecomeActive:),
                Some(NSWorkspaceSessionDidBecomeActiveNotification),
                None,
            );
        }

        let poller = match PollingObserver::start(
            QuartzActivitySampler {
                unlock_gate: KeychainUnlockGate::new(),
            },
            poll_interval,
            epoch,
            observations,
        ) {
            Ok(poller) => poller,
            Err(error) => {
                // SAFETY: The same live target was registered immediately above,
                // and removal occurs on the same main-thread startup path.
                unsafe { notification_center.removeObserver(&notification_target) };
                return Err(error);
            }
        };

        Ok(Self {
            notification_center,
            notification_target,
            poller,
            stopped: false,
        })
    }

    pub fn stop(&mut self) -> Result<(), ObserverStopError> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        // SAFETY: The target is still retained and is removed before it can be
        // dropped. Removing an observer that has these registrations is supported.
        unsafe {
            self.notification_center
                .removeObserver(&self.notification_target)
        };
        self.poller.stop()
    }
}

impl Drop for MacOsActivityObserver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_statuses_map_to_fixed_fail_closed_gate_states() {
        assert_eq!(
            map_gate_status(ERR_SEC_INTERACTION_NOT_ALLOWED),
            UnlockGateState::Locked
        );
        assert_eq!(
            map_gate_status(ERR_SEC_MISSING_ENTITLEMENT),
            UnlockGateState::Failed(UnlockGateFailure::MissingEntitlement)
        );
        assert_eq!(
            map_gate_status(ERR_SEC_ITEM_NOT_FOUND),
            UnlockGateState::Failed(UnlockGateFailure::ItemMissing)
        );
        assert_eq!(
            map_gate_status(i32::MIN),
            UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed)
        );
    }

    #[test]
    fn activity_gate_namespace_and_value_are_explicitly_nonsecret() {
        assert_eq!(UNLOCK_GATE_SERVICE, "dev.aeterna.desktop.i01.activity-gate");
        assert_eq!(UNLOCK_GATE_ACCOUNT, "v1:unlock-gate");
        assert_eq!(UNLOCK_GATE_VALUE, b"aeterna-i01-nonsecret-gate-v1");
        assert_ne!(UNLOCK_GATE_SERVICE, crate::secure_storage::KEYCHAIN_SERVICE);
    }
}
