use std::{ptr::NonNull, sync::mpsc, time::Duration};

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::NSError;
use objc2_service_management::{SMAppService, SMAppServiceStatus};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNAuthorizationStatus, UNUserNotificationCenter,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AutostartStatus {
    Enabled,
    Disabled,
    RequiresApproval,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NotificationStatus {
    NotRequested,
    Authorized,
    Denied,
    Unavailable,
}

pub(crate) fn autostart_status() -> AutostartStatus {
    // SAFETY: SMAppService's process-wide main-app service is available on the
    // repository's macOS 15 deployment floor; this call does not mutate state.
    let status = unsafe { SMAppService::mainAppService().status() };
    map_autostart_status(status)
}

fn map_autostart_status(status: SMAppServiceStatus) -> AutostartStatus {
    match status {
        SMAppServiceStatus::Enabled => AutostartStatus::Enabled,
        SMAppServiceStatus::NotRegistered | SMAppServiceStatus::NotFound => {
            // A first-time main-app service may be unknown until its first registration.
            AutostartStatus::Disabled
        }
        SMAppServiceStatus::RequiresApproval => AutostartStatus::RequiresApproval,
        _ => AutostartStatus::Unavailable,
    }
}

pub(crate) fn set_autostart(enabled: bool) -> Result<AutostartStatus, ()> {
    // SAFETY: The operation is initiated only by a focused, visible window
    // after an explicit user command. The retained service spans both calls.
    let service = unsafe { SMAppService::mainAppService() };
    let current = unsafe { service.status() };
    let result = if enabled {
        if current == SMAppServiceStatus::Enabled {
            Ok(())
        } else if current == SMAppServiceStatus::RequiresApproval {
            return Ok(AutostartStatus::RequiresApproval);
        } else {
            // SAFETY: See service lifetime and user-gesture precondition above.
            unsafe { service.registerAndReturnError() }.map_err(|_| ())
        }
    } else if matches!(
        current,
        SMAppServiceStatus::NotRegistered | SMAppServiceStatus::NotFound
    ) {
        Ok(())
    } else {
        // SAFETY: See service lifetime and user-gesture precondition above.
        unsafe { service.unregisterAndReturnError() }.map_err(|_| ())
    };
    let observed = autostart_status();
    if result.is_ok() || enabled && observed == AutostartStatus::RequiresApproval {
        Ok(observed)
    } else {
        Err(())
    }
}

pub(crate) fn open_login_items_settings() {
    // SAFETY: The caller enforces a distinct focused, visible-window action.
    unsafe { SMAppService::openSystemSettingsLoginItems() };
}

pub(crate) fn notification_status() -> NotificationStatus {
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let (sender, receiver) = mpsc::sync_channel(1);
    let completion = RcBlock::new(
        move |settings: NonNull<objc2_user_notifications::UNNotificationSettings>| {
            // SAFETY: UserNotifications guarantees a non-null settings object for
            // the duration of this completion callback.
            let status = unsafe { settings.as_ref() }.authorizationStatus();
            let _ = sender.try_send(map_notification_status(status));
        },
    );
    center.getNotificationSettingsWithCompletionHandler(&completion);
    receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or(NotificationStatus::Unavailable)
}

pub(crate) fn request_notification_permission() -> NotificationStatus {
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let (sender, receiver) = mpsc::sync_channel(1);
    let completion = RcBlock::new(move |granted: Bool, error: *mut NSError| {
        let status = if !error.is_null() {
            NotificationStatus::Unavailable
        } else if granted.as_bool() {
            NotificationStatus::Authorized
        } else {
            NotificationStatus::Denied
        };
        let _ = sender.try_send(status);
    });
    center.requestAuthorizationWithOptions_completionHandler(
        UNAuthorizationOptions::Alert,
        &completion,
    );
    receiver
        .recv_timeout(Duration::from_secs(30))
        .unwrap_or(NotificationStatus::Unavailable)
}

fn map_notification_status(status: UNAuthorizationStatus) -> NotificationStatus {
    match status {
        UNAuthorizationStatus::NotDetermined => NotificationStatus::NotRequested,
        UNAuthorizationStatus::Denied => NotificationStatus::Denied,
        UNAuthorizationStatus::Authorized => NotificationStatus::Authorized,
        UNAuthorizationStatus::Provisional | UNAuthorizationStatus::Ephemeral => {
            NotificationStatus::Unavailable
        }
        _ => NotificationStatus::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_time_main_app_service_is_disabled_until_registration() {
        assert_eq!(
            map_autostart_status(SMAppServiceStatus::NotFound),
            AutostartStatus::Disabled
        );
        assert_eq!(
            map_autostart_status(SMAppServiceStatus::NotRegistered),
            AutostartStatus::Disabled
        );
    }

    #[test]
    fn notification_status_mapping_is_fail_closed() {
        assert_eq!(
            map_notification_status(UNAuthorizationStatus::NotDetermined),
            NotificationStatus::NotRequested
        );
        assert_eq!(
            map_notification_status(UNAuthorizationStatus::Authorized),
            NotificationStatus::Authorized
        );
        assert_eq!(
            map_notification_status(UNAuthorizationStatus::Denied),
            NotificationStatus::Denied
        );
        assert_eq!(
            map_notification_status(UNAuthorizationStatus::Provisional),
            NotificationStatus::Unavailable
        );
        assert_eq!(
            map_notification_status(UNAuthorizationStatus::Ephemeral),
            NotificationStatus::Unavailable
        );
    }
}
