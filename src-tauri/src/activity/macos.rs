use std::ptr;
#[cfg(feature = "activity-prototype")]
use std::sync::mpsc::Sender;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{SyncSender, TrySendError},
};
#[cfg(feature = "activity-prototype")]
use std::time::Duration;
use std::time::Instant;

use core_foundation::string::CFStringRef;
use core_foundation::{
    base::{CFEqual, CFType, CFTypeRef, TCFType, kCFAllocatorDefault},
    boolean::CFBoolean,
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryGetValueIfPresent},
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
#[cfg(feature = "i08-native-probe")]
use security_framework_sys::keychain_item::{SecItemDelete, SecItemUpdate};
use security_framework_sys::{
    access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    base::{
        errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecDuplicateItem as ERR_SEC_DUPLICATE_ITEM,
        errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND, errSecSuccess as ERR_SEC_SUCCESS,
    },
    item::{
        kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecMatchLimit, kSecReturnAttributes, kSecReturnData,
        kSecUseAuthenticationUI, kSecUseAuthenticationUISkip, kSecUseDataProtectionKeychain,
        kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching},
};

use super::observer::{ActivitySampler, monotonic_time};
#[cfg(feature = "activity-prototype")]
use super::observer::{ObserverStartError, ObserverStopError, PollingObserver};
use super::policy::{
    ActivityObservation, ActivitySampleValue, EligibleInputClass, InputSampleValue,
    ObservationKind, SessionState, UnlockGateFailure, UnlockGateState,
};

const ANY_INPUT_EVENT_TYPE: CGEventType = CGEventType(u32::MAX);
const UNLOCK_GATE_SERVICE: &str = "aeterna.desktop.activity-gate.v1";
const UNLOCK_GATE_ACCOUNT: &str = "unlock-availability";
const UNLOCK_GATE_VALUE: &[u8] = b"AETERNA-ACTIVITY-GATE-V1";
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;

// SAFETY CONTRACT: this declaration matches the public Security.framework
// `CFStringRef` symbol from SecItem.h on every supported macOS target.
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
    fn SecTaskCreateFromSelf(allocator: *const core::ffi::c_void) -> CFTypeRef;
    fn SecTaskCopyValueForEntitlement(
        task: CFTypeRef,
        entitlement: CFStringRef,
        error: *mut *mut core::ffi::c_void,
    ) -> CFTypeRef;
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
    observations: ObservationSender,
    epoch: Instant,
}

#[derive(Clone)]
enum ObservationSender {
    #[cfg(feature = "activity-prototype")]
    Unbounded(Sender<ActivityObservation>),
    #[cfg_attr(feature = "activity-prototype", allow(dead_code))]
    Bounded {
        sender: SyncSender<ActivityObservation>,
        overflowed: Arc<AtomicBool>,
    },
}

impl ObservationSender {
    fn send(&self, observation: ActivityObservation) {
        match self {
            #[cfg(feature = "activity-prototype")]
            Self::Unbounded(sender) => {
                let _ = sender.send(observation);
            }
            Self::Bounded { sender, overflowed } => match sender.try_send(observation) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => overflowed.store(true, Ordering::Release),
                Err(TrySendError::Disconnected(_)) => overflowed.store(true, Ordering::Release),
            },
        }
    }
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
    fn new(observations: ObservationSender, epoch: Instant) -> Retained<Self> {
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
        let observation = ActivityObservation { observed_at, kind };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.ivars().observations.send(observation);
        }));
    }
}

pub(crate) struct QuartzActivitySampler {
    unlock_gate: KeychainUnlockGate,
}

impl QuartzActivitySampler {
    pub(crate) const fn new() -> Self {
        Self {
            unlock_gate: KeychainUnlockGate::new(),
        }
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateMetadataMismatch {
    MissingResult,
    ResultType,
    Service,
    Account,
    AccessGroup,
    Accessible,
    Value,
}

enum GateReadError {
    Status(i32),
    InvalidItem(GateMetadataMismatch),
}

fn read_unlock_gate() -> Result<(), GateReadError> {
    let query = unlock_gate_read_dictionary()?;
    let mut result = ptr::null();
    // SAFETY: `query` owns every value for the synchronous call. The output is
    // initialized to null and a successful Copy-rule result is wrapped once.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status != ERR_SEC_SUCCESS {
        return Err(GateReadError::Status(status));
    }
    if result.is_null() {
        return Err(GateReadError::InvalidItem(
            GateMetadataMismatch::MissingResult,
        ));
    }
    // SAFETY: a successful non-null Copy-rule result transfers one ownership
    // reference to this wrapper.
    let value = unsafe { CFType::wrap_under_create_rule(result) };
    let attributes = value
        .downcast::<CFDictionary>()
        .ok_or(GateReadError::InvalidItem(GateMetadataMismatch::ResultType))?;
    let access_group = application_access_group()?;
    match unlock_gate_metadata_mismatch(&attributes, &access_group) {
        Some(mismatch) => Err(GateReadError::InvalidItem(mismatch)),
        None => Ok(()),
    }
}

fn unlock_gate_metadata_mismatch(
    attributes: &CFDictionary,
    access_group: &CFString,
) -> Option<GateMetadataMismatch> {
    if !dictionary_value_matches(
        attributes,
        static_string(security_constant!(kSecAttrService)),
        CFString::new(UNLOCK_GATE_SERVICE).into_CFType(),
    ) {
        return Some(GateMetadataMismatch::Service);
    }
    if !dictionary_value_matches(
        attributes,
        static_string(security_constant!(kSecAttrAccount)),
        CFString::new(UNLOCK_GATE_ACCOUNT).into_CFType(),
    ) {
        return Some(GateMetadataMismatch::Account);
    }
    if !dictionary_value_matches(
        attributes,
        static_string(security_constant!(kSecAttrAccessGroup)),
        access_group.clone().into_CFType(),
    ) {
        return Some(GateMetadataMismatch::AccessGroup);
    }
    if !dictionary_value_matches(
        attributes,
        static_string(security_constant!(kSecAttrAccessible)),
        static_string(security_constant!(
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )),
    ) {
        return Some(GateMetadataMismatch::Accessible);
    }
    if !dictionary_data_matches_constant_time(
        attributes,
        static_string(security_constant!(kSecValueData)),
        UNLOCK_GATE_VALUE,
    ) {
        return Some(GateMetadataMismatch::Value);
    }
    None
}

fn create_unlock_gate() -> i32 {
    let Ok(query) = unlock_gate_creation_dictionary() else {
        return ERR_SEC_MISSING_ENTITLEMENT;
    };
    // SAFETY: `query` owns every key/value for the synchronous call. No result
    // is requested, so a null output pointer is permitted.
    unsafe { SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut()) }
}

fn unlock_gate_identity_pairs_for(access_group: CFString) -> Vec<(CFType, CFType)> {
    vec![
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
        (
            static_string(security_constant!(kSecAttrAccessGroup)),
            access_group.into_CFType(),
        ),
    ]
}

fn unlock_gate_read_dictionary() -> Result<CFDictionary<CFType, CFType>, GateReadError> {
    let access_group = application_access_group()?;
    Ok(unlock_gate_read_dictionary_for(access_group))
}

fn unlock_gate_read_dictionary_for(access_group: CFString) -> CFDictionary<CFType, CFType> {
    let mut pairs = unlock_gate_identity_pairs_for(access_group);
    pairs.extend([
        (
            static_string(security_constant!(kSecAttrSynchronizable)),
            CFBoolean::false_value().into_CFType(),
        ),
        (
            static_string(security_constant!(kSecReturnData)),
            CFBoolean::true_value().into_CFType(),
        ),
        static_pair(
            security_constant!(kSecUseAuthenticationUI),
            security_constant!(kSecUseAuthenticationUISkip),
        ),
        static_pair(
            security_constant!(kSecMatchLimit),
            security_constant!(kSecMatchLimitOne),
        ),
        (
            static_string(security_constant!(kSecReturnAttributes)),
            CFBoolean::true_value().into_CFType(),
        ),
    ]);
    CFDictionary::from_CFType_pairs(&pairs)
}

fn unlock_gate_creation_dictionary() -> Result<CFDictionary<CFType, CFType>, GateReadError> {
    let access_group = application_access_group()?;
    Ok(unlock_gate_creation_dictionary_for(access_group))
}

fn unlock_gate_creation_dictionary_for(access_group: CFString) -> CFDictionary<CFType, CFType> {
    let mut pairs = unlock_gate_identity_pairs_for(access_group);
    pairs.extend([
        (
            static_string(security_constant!(kSecAttrSynchronizable)),
            CFBoolean::false_value().into_CFType(),
        ),
        static_pair(
            security_constant!(kSecAttrAccessible),
            security_constant!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
        ),
        (
            static_string(security_constant!(kSecValueData)),
            CFData::from_buffer(UNLOCK_GATE_VALUE).into_CFType(),
        ),
    ]);
    CFDictionary::from_CFType_pairs(&pairs)
}

#[cfg(feature = "i08-native-probe")]
fn unlock_gate_maintenance_dictionary() -> Result<CFDictionary<CFType, CFType>, GateReadError> {
    let access_group = application_access_group()?;
    Ok(unlock_gate_maintenance_dictionary_for(access_group))
}

#[cfg(feature = "i08-native-probe")]
fn unlock_gate_maintenance_dictionary_for(access_group: CFString) -> CFDictionary<CFType, CFType> {
    let mut pairs = unlock_gate_identity_pairs_for(access_group);
    // kSecUseAuthenticationUISkip is valid only for SecItemCopyMatching.
    // Including it here makes SecItemUpdate and SecItemDelete reject the query.
    pairs.extend([
        (
            static_string(security_constant!(kSecAttrSynchronizable)),
            CFBoolean::false_value().into_CFType(),
        ),
        static_pair(
            security_constant!(kSecAttrAccessible),
            security_constant!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
        ),
    ]);
    CFDictionary::from_CFType_pairs(&pairs)
}

fn dictionary_value_matches(dictionary: &CFDictionary, key: CFType, expected: CFType) -> bool {
    let mut value = ptr::null();
    // SAFETY: The dictionary and key remain owned for the lookup. The returned
    // value is borrowed and both operands are valid CF objects for CFEqual.
    let found = unsafe {
        CFDictionaryGetValueIfPresent(
            dictionary.as_concrete_TypeRef(),
            key.as_concrete_TypeRef().cast(),
            &mut value,
        )
    };
    found != 0
        && !value.is_null()
        && unsafe { CFEqual(value.cast(), expected.as_concrete_TypeRef()) != 0 }
}

fn dictionary_data_matches_constant_time(
    dictionary: &CFDictionary,
    key: CFType,
    expected: &[u8],
) -> bool {
    let mut value = ptr::null();
    // SAFETY: The dictionary and key remain owned for the lookup. A present
    // borrowed value is retained by the get-rule wrapper before downcasting.
    let found = unsafe {
        CFDictionaryGetValueIfPresent(
            dictionary.as_concrete_TypeRef(),
            key.as_concrete_TypeRef().cast(),
            &mut value,
        )
    };
    if found == 0 || value.is_null() {
        return false;
    }
    // SAFETY: `value` is a live CF object borrowed from `dictionary`; the
    // get-rule wrapper retains its own reference for the downcast lifetime.
    let value = unsafe { CFType::wrap_under_get_rule(value.cast()) };
    let Some(data) = value.downcast::<CFData>() else {
        return false;
    };
    constant_time_bytes_equal(data.bytes(), expected)
}

fn constant_time_bytes_equal(actual: &[u8], expected: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn application_access_group() -> Result<CFString, GateReadError> {
    let entitlement = CFString::new("com.apple.application-identifier");
    let mut error = ptr::null_mut();
    // SAFETY: Both Security.framework functions follow Copy/Create ownership
    // rules. The task and entitlement result are wrapped exactly once.
    let task = unsafe { SecTaskCreateFromSelf(kCFAllocatorDefault) };
    if task.is_null() {
        return Err(GateReadError::Status(ERR_SEC_MISSING_ENTITLEMENT));
    }
    let _task = unsafe { CFType::wrap_under_create_rule(task) };
    let result = unsafe {
        SecTaskCopyValueForEntitlement(task, entitlement.as_concrete_TypeRef(), &mut error)
    };
    if !error.is_null() {
        // SAFETY: A non-null Copy API error is a retained CF object.
        drop(unsafe { CFType::wrap_under_create_rule(error.cast_const()) });
    }
    if result.is_null() {
        return Err(GateReadError::Status(ERR_SEC_MISSING_ENTITLEMENT));
    }
    let value = unsafe { CFType::wrap_under_create_rule(result) };
    let value = value
        .downcast::<CFString>()
        .ok_or(GateReadError::Status(ERR_SEC_MISSING_ENTITLEMENT))?;
    if value.to_string().is_empty() {
        return Err(GateReadError::Status(ERR_SEC_MISSING_ENTITLEMENT));
    }
    Ok(value)
}

#[cfg(feature = "i08-native-probe")]
pub(super) fn native_probe_verify_metadata() -> Result<(), &'static str> {
    read_unlock_gate().map_err(native_probe_error_code)
}

#[cfg(feature = "i08-native-probe")]
pub(super) fn native_probe_update_same_value() -> Result<(), &'static str> {
    read_unlock_gate().map_err(native_probe_error_code)?;
    let query = unlock_gate_maintenance_dictionary().map_err(native_probe_error_code)?;
    let updates = CFDictionary::from_CFType_pairs(&[(
        static_string(security_constant!(kSecValueData)),
        CFData::from_buffer(UNLOCK_GATE_VALUE).into_CFType(),
    )]);
    // SAFETY: Both dictionaries own their objects for the synchronous update.
    // The update dictionary can change only the canonical public value.
    let status =
        unsafe { SecItemUpdate(query.as_concrete_TypeRef(), updates.as_concrete_TypeRef()) };
    if status != ERR_SEC_SUCCESS {
        return Err(native_probe_error_code(GateReadError::Status(status)));
    }
    read_unlock_gate().map_err(native_probe_error_code)
}

#[cfg(feature = "i08-native-probe")]
pub(super) fn native_probe_delete_exact() -> Result<bool, String> {
    match read_unlock_gate() {
        Ok(()) => {}
        Err(GateReadError::Status(ERR_SEC_ITEM_NOT_FOUND)) => return Ok(false),
        Err(error) => return Err(native_probe_error_code(error).to_owned()),
    }
    let query = unlock_gate_maintenance_dictionary()
        .map_err(|error| native_probe_error_code(error).to_owned())?;
    // SAFETY: The exact identity dictionary remains alive for the synchronous
    // delete and cannot match any other service, account, or access group.
    let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
    let deleted = match status {
        ERR_SEC_SUCCESS => true,
        ERR_SEC_ITEM_NOT_FOUND => false,
        // OSStatus is a bounded public error code, not item data. Retaining it
        // in this feature-gated probe distinguishes invalid-query and access
        // failures without exposing the gate value or access group.
        other => return Err(format!("gate_delete_osstatus_{other}")),
    };
    match read_unlock_gate() {
        Err(GateReadError::Status(ERR_SEC_ITEM_NOT_FOUND)) => Ok(deleted),
        Ok(()) => Err("gate_delete_incomplete".to_owned()),
        Err(error) => Err(native_probe_error_code(error).to_owned()),
    }
}

#[cfg(feature = "i08-native-probe")]
fn native_probe_error_code(error: GateReadError) -> &'static str {
    match error {
        GateReadError::InvalidItem(GateMetadataMismatch::MissingResult) => {
            "gate_invalid_result_missing"
        }
        GateReadError::InvalidItem(GateMetadataMismatch::ResultType) => "gate_invalid_result_type",
        GateReadError::InvalidItem(GateMetadataMismatch::Service) => "gate_invalid_service",
        GateReadError::InvalidItem(GateMetadataMismatch::Account) => "gate_invalid_account",
        GateReadError::InvalidItem(GateMetadataMismatch::AccessGroup) => {
            "gate_invalid_access_group"
        }
        GateReadError::InvalidItem(GateMetadataMismatch::Accessible) => "gate_invalid_accessible",
        GateReadError::InvalidItem(GateMetadataMismatch::Value) => "gate_invalid_value",
        GateReadError::Status(ERR_SEC_ITEM_NOT_FOUND) => "gate_not_found",
        GateReadError::Status(ERR_SEC_INTERACTION_NOT_ALLOWED) => "gate_locked",
        GateReadError::Status(ERR_SEC_AUTH_FAILED) => "gate_access_denied",
        GateReadError::Status(ERR_SEC_MISSING_ENTITLEMENT) => "gate_missing_entitlement",
        GateReadError::Status(ERR_SEC_NOT_AVAILABLE) => "gate_keychain_unavailable",
        GateReadError::Status(_) => "gate_native_failure",
    }
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
        GateReadError::InvalidItem(mismatch) => {
            let _ = mismatch;
            UnlockGateState::Failed(UnlockGateFailure::InvalidItem)
        }
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

#[cfg(feature = "activity-prototype")]
pub struct MacOsActivityObserver {
    notification_center: Retained<NSNotificationCenter>,
    notification_target: Retained<WorkspaceObserver>,
    poller: PollingObserver,
    stopped: bool,
}

#[cfg(feature = "activity-prototype")]
impl MacOsActivityObserver {
    pub fn start(
        observations: Sender<ActivityObservation>,
        epoch: Instant,
        poll_interval: Duration,
    ) -> Result<Self, ObserverStartError> {
        let notification_center = NSWorkspace::sharedWorkspace().notificationCenter();
        let notification_target =
            WorkspaceObserver::new(ObservationSender::Unbounded(observations.clone()), epoch);

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
            QuartzActivitySampler::new(),
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

#[cfg_attr(feature = "activity-prototype", allow(dead_code))]
pub(crate) struct MacOsNativeObservers {
    notification_center: Retained<NSNotificationCenter>,
    notification_target: Retained<WorkspaceObserver>,
    stopped: bool,
}

#[cfg_attr(feature = "activity-prototype", allow(dead_code))]
impl MacOsNativeObservers {
    pub(crate) fn start(
        observations: SyncSender<ActivityObservation>,
        overflowed: Arc<AtomicBool>,
        epoch: Instant,
    ) -> Self {
        let notification_center = NSWorkspace::sharedWorkspace().notificationCenter();
        let notification_target = WorkspaceObserver::new(
            ObservationSender::Bounded {
                sender: observations,
                overflowed,
            },
            epoch,
        );
        // SAFETY: Selectors and target lifetime follow the same contract as the
        // prototype observer. Registration and removal stay on the app thread.
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
        Self {
            notification_center,
            notification_target,
            stopped: false,
        }
    }

    pub(crate) fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        // SAFETY: The target remains retained until after removal.
        unsafe {
            self.notification_center
                .removeObserver(&self.notification_target)
        };
    }
}

impl Drop for MacOsNativeObservers {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(feature = "activity-prototype")]
impl Drop for MacOsActivityObserver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_native_sender_marks_full_and_disconnected_queues() {
        let observation = || ActivityObservation {
            observed_at: monotonic_time(Instant::now()),
            kind: ObservationKind::DidWake,
        };

        let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
        sender
            .try_send(observation())
            .unwrap_or_else(|error| panic!("prefill bounded queue: {error}"));
        let overflowed = Arc::new(AtomicBool::new(false));
        ObservationSender::Bounded {
            sender,
            overflowed: Arc::clone(&overflowed),
        }
        .send(observation());
        assert!(overflowed.load(Ordering::Acquire));

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        let disconnected = Arc::new(AtomicBool::new(false));
        ObservationSender::Bounded {
            sender,
            overflowed: Arc::clone(&disconnected),
        }
        .send(observation());
        assert!(disconnected.load(Ordering::Acquire));
    }

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
        assert_eq!(UNLOCK_GATE_SERVICE, "aeterna.desktop.activity-gate.v1");
        assert_eq!(UNLOCK_GATE_ACCOUNT, "unlock-availability");
        assert_eq!(UNLOCK_GATE_VALUE, b"AETERNA-ACTIVITY-GATE-V1");
        assert_ne!(UNLOCK_GATE_SERVICE, crate::secure_storage::KEYCHAIN_SERVICE);
    }

    #[test]
    fn gate_value_comparison_requires_exact_length_and_bytes() {
        assert!(constant_time_bytes_equal(
            UNLOCK_GATE_VALUE,
            UNLOCK_GATE_VALUE
        ));
        assert!(!constant_time_bytes_equal(
            UNLOCK_GATE_VALUE,
            b"AETERNA-ACTIVITY-GATE-V2"
        ));
        assert!(!constant_time_bytes_equal(
            UNLOCK_GATE_VALUE,
            b"AETERNA-ACTIVITY-GATE-V1-EXTRA"
        ));
    }

    #[test]
    fn gate_creation_and_read_validation_require_the_complete_contract() {
        let access_group = CFString::new("TESTTEAM.dev.aeterna.desktop.foundation");
        let typed_item = unlock_gate_creation_dictionary_for(access_group.clone());
        // SAFETY: The typed dictionary remains live while this retained,
        // type-erased view is used for the same validation path as Keychain.
        let item: CFDictionary =
            unsafe { CFDictionary::wrap_under_get_rule(typed_item.as_concrete_TypeRef()) };
        assert!(dictionary_value_matches(
            &item,
            static_string(security_constant!(kSecClass)),
            static_string(security_constant!(kSecClassGenericPassword)),
        ));
        assert_eq!(unlock_gate_metadata_mismatch(&item, &access_group), None);

        let typed_missing_synchronizable = CFDictionary::from_CFType_pairs(&[
            (
                static_string(security_constant!(kSecAttrService)),
                CFString::new(UNLOCK_GATE_SERVICE).into_CFType(),
            ),
            (
                static_string(security_constant!(kSecAttrAccount)),
                CFString::new(UNLOCK_GATE_ACCOUNT).into_CFType(),
            ),
            (
                static_string(security_constant!(kSecAttrAccessGroup)),
                access_group.clone().into_CFType(),
            ),
            static_pair(
                security_constant!(kSecAttrAccessible),
                security_constant!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            ),
            (
                static_string(security_constant!(kSecValueData)),
                CFData::from_buffer(UNLOCK_GATE_VALUE).into_CFType(),
            ),
        ]);
        // SAFETY: The source dictionary remains live for this retained view.
        let missing_synchronizable: CFDictionary = unsafe {
            CFDictionary::wrap_under_get_rule(typed_missing_synchronizable.as_concrete_TypeRef())
        };
        assert_eq!(
            unlock_gate_metadata_mismatch(&missing_synchronizable, &access_group),
            None
        );
    }

    #[cfg(feature = "i08-native-probe")]
    #[test]
    fn native_probe_reports_only_fixed_metadata_mismatch_codes() {
        let cases = [
            (GateMetadataMismatch::Service, "gate_invalid_service"),
            (GateMetadataMismatch::Account, "gate_invalid_account"),
            (
                GateMetadataMismatch::AccessGroup,
                "gate_invalid_access_group",
            ),
            (GateMetadataMismatch::Accessible, "gate_invalid_accessible"),
            (GateMetadataMismatch::Value, "gate_invalid_value"),
        ];
        for (mismatch, expected) in cases {
            assert_eq!(
                native_probe_error_code(GateReadError::InvalidItem(mismatch)),
                expected
            );
        }
    }

    #[test]
    fn gate_creation_and_read_queries_explicitly_require_non_synchronizable_items() {
        fn erase(dictionary: &CFDictionary<CFType, CFType>) -> CFDictionary {
            // SAFETY: Each typed dictionary remains live while its retained,
            // type-erased view is used by the production comparison helper.
            unsafe { CFDictionary::wrap_under_get_rule(dictionary.as_concrete_TypeRef()) }
        }

        let access_group = CFString::new("TESTTEAM.dev.aeterna.desktop.foundation");
        let creation = unlock_gate_creation_dictionary_for(access_group.clone());
        let read = unlock_gate_read_dictionary_for(access_group);
        let creation = erase(&creation);
        let read = erase(&read);
        let synchronizable = || static_string(security_constant!(kSecAttrSynchronizable));
        let explicit_false = || CFBoolean::false_value().into_CFType();

        assert!(dictionary_value_matches(
            &creation,
            synchronizable(),
            explicit_false()
        ));
        assert!(dictionary_value_matches(
            &read,
            synchronizable(),
            explicit_false()
        ));
    }

    #[cfg(feature = "i08-native-probe")]
    #[test]
    fn gate_mutation_query_excludes_copy_only_authentication_option() {
        let query = unlock_gate_maintenance_dictionary_for(CFString::new(
            "TESTTEAM.dev.aeterna.desktop.foundation",
        ));
        let authentication_ui = static_string(security_constant!(kSecUseAuthenticationUI));
        let mut value = ptr::null();
        // SAFETY: The query and key own their CF values for this lookup.
        let found = unsafe {
            CFDictionaryGetValueIfPresent(
                query.as_concrete_TypeRef(),
                authentication_ui.as_concrete_TypeRef().cast(),
                &mut value,
            )
        };
        assert_eq!(found, 0);
        assert!(value.is_null());
    }
}
