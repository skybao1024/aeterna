#![cfg_attr(feature = "activity-prototype", allow(dead_code))]

use objc2::msg_send;
use objc2_foundation::{NSAppleEventDescriptor, NSAppleEventManager};
use tauri::{
    AppHandle, Emitter, Manager, RunEvent, WindowEvent,
    menu::{Menu, MenuItem},
    tray::{TrayIcon, TrayIconBuilder},
};

use crate::ipc::VaultAppState;

use super::{
    AgentFacet, LifecycleAppState,
    agent::{ActivityAgent, secure_lock_and_hide},
    strings::{Locale, native_strings},
};

const OPEN_ITEM_ID: &str = "lifecycle-open";
const LOCK_ITEM_ID: &str = "lifecycle-lock";
const QUIT_ITEM_ID: &str = "lifecycle-quit";
const EVENT_OPEN_APPLICATION: u32 = u32::from_be_bytes(*b"oapp");
const KEY_EVENT_PROPERTY_DATA: u32 = u32::from_be_bytes(*b"prdt");
const KEY_LAUNCHED_AS_LOGIN_ITEM: u32 = u32::from_be_bytes(*b"lgit");

pub(crate) struct MacAppRuntime {
    agent: ActivityAgent,
    _tray: TrayIcon,
    status_item: MenuItem<tauri::Wry>,
    open_item: MenuItem<tauri::Wry>,
    lock_item: MenuItem<tauri::Wry>,
    quit_item: MenuItem<tauri::Wry>,
    rendered_locale: Locale,
    rendered_agent: AgentFacet,
    stopped: bool,
}

impl MacAppRuntime {
    pub(crate) fn start(app: &AppHandle<tauri::Wry>) -> Result<Self, tauri::Error> {
        let lifecycle_state = app
            .try_state::<LifecycleAppState>()
            .ok_or(tauri::Error::FailedToReceiveMessage)?;
        if app.try_state::<VaultAppState>().is_none() {
            return Err(tauri::Error::FailedToReceiveMessage);
        }
        let locale = lifecycle_state.locale();
        let labels = native_strings(locale);
        let initial_agent = lifecycle_state.agent_facet();
        let initial_status = match initial_agent {
            AgentFacet::Ready => labels.status_ready,
            AgentFacet::GateUnavailable => labels.status_gate_unavailable,
            AgentFacet::Error => labels.status_agent_error,
        };
        debug_assert!(
            !labels.notification_title.is_empty() && !labels.notification_body.is_empty()
        );
        let status_item =
            MenuItem::with_id(app, "lifecycle-status", initial_status, false, None::<&str>)?;
        let open_item = MenuItem::with_id(app, OPEN_ITEM_ID, labels.open, true, None::<&str>)?;
        let lock_item = MenuItem::with_id(app, LOCK_ITEM_ID, labels.lock, true, None::<&str>)?;
        let quit_item = MenuItem::with_id(app, QUIT_ITEM_ID, labels.quit, true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&status_item, &open_item, &lock_item, &quit_item])?;
        let mut builder = TrayIconBuilder::with_id("aeterna-lifecycle")
            .menu(&menu)
            .tooltip("Aeterna")
            .icon_as_template(true)
            .on_menu_event(|app, event| match event.id().as_ref() {
                OPEN_ITEM_ID => show_main_window(app),
                LOCK_ITEM_ID => secure_lock_and_hide(app),
                QUIT_ITEM_ID => app.exit(0),
                _ => {}
            });
        if let Some(icon) = app.default_window_icon() {
            builder = builder.icon(icon.clone());
        }
        let tray = builder.build(app)?;
        let agent =
            ActivityAgent::start(app.clone()).map_err(|()| tauri::Error::FailedToReceiveMessage)?;
        Ok(Self {
            agent,
            _tray: tray,
            status_item,
            open_item,
            lock_item,
            quit_item,
            rendered_locale: locale,
            rendered_agent: initial_agent,
            stopped: false,
        })
    }

    pub(crate) fn handle(&mut self, app: &AppHandle, event: RunEvent) {
        match event {
            RunEvent::Ready => {
                if !launched_as_login_item() {
                    show_main_window(app);
                }
            }
            RunEvent::Reopen { .. } => show_main_window(app),
            RunEvent::WindowEvent {
                label,
                event: WindowEvent::CloseRequested { api, .. },
                ..
            } if label == "main" => {
                api.prevent_close();
                if app.state::<VaultAppState>().is_unlocked_for_lifecycle() {
                    let _ = app.emit_to("main", "lifecycle://close-requested", ());
                } else {
                    secure_lock_and_hide(app);
                }
            }
            RunEvent::MainEventsCleared => self.refresh_labels(app),
            RunEvent::ExitRequested { .. } | RunEvent::Exit => self.stop(app),
            _ => {}
        }
    }

    fn refresh_labels(&mut self, app: &AppHandle) {
        let state = app.state::<LifecycleAppState>();
        let locale = state.locale();
        let agent = state.agent_facet();
        if locale == self.rendered_locale && agent == self.rendered_agent {
            return;
        }
        let labels = native_strings(locale);
        let status = match agent {
            AgentFacet::Ready => labels.status_ready,
            AgentFacet::GateUnavailable => labels.status_gate_unavailable,
            AgentFacet::Error => labels.status_agent_error,
        };
        let _ = self.status_item.set_text(status);
        let _ = self.open_item.set_text(labels.open);
        let _ = self.lock_item.set_text(labels.lock);
        let _ = self.quit_item.set_text(labels.quit);
        self.rendered_locale = locale;
        self.rendered_agent = agent;
    }

    fn stop(&mut self, app: &AppHandle) {
        if self.stopped || !app.state::<LifecycleAppState>().begin_stopping() {
            return;
        }
        self.stopped = true;
        let lock_failed = app
            .state::<VaultAppState>()
            .secure_lock_for_lifecycle()
            .is_err();
        if lock_failed {
            app.state::<LifecycleAppState>()
                .set_agent_facet(AgentFacet::Error);
        }
        self.agent.stop();
        let flush_failed = app.state::<LifecycleAppState>().flush().is_err();
        if lock_failed || flush_failed {
            app.state::<LifecycleAppState>()
                .set_agent_facet(AgentFacet::Error);
            app.exit(1);
        }
    }
}

pub(crate) fn hide_main_window_after_lock(app: &AppHandle) {
    super::agent::hide_main_window(app);
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn launched_as_login_item() -> bool {
    let Some(event) = NSAppleEventManager::sharedAppleEventManager().currentAppleEvent() else {
        return false;
    };
    // SAFETY: Both selectors are public NSAppleEventDescriptor API. FourCharCode
    // values use the same u32 ABI as OSType/AEKeyword on Apple platforms.
    let event_id: u32 = unsafe { msg_send![&*event, eventID] };
    if event_id != EVENT_OPEN_APPLICATION {
        return false;
    }
    let property: Option<objc2::rc::Retained<NSAppleEventDescriptor>> =
        unsafe { msg_send![&*event, paramDescriptorForKeyword: KEY_EVENT_PROPERTY_DATA] };
    property.is_some_and(|property| property.enumCodeValue() == KEY_LAUNCHED_AS_LOGIN_ITEM)
}
