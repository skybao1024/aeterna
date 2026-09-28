mod health;
mod strings;

#[cfg(target_os = "macos")]
pub(crate) mod agent;
#[cfg(target_os = "macos")]
pub(crate) mod runtime;

#[cfg(target_os = "macos")]
mod macos;

use std::{
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tauri::{State, WebviewWindow, ipc::InvokeBody};

use health::{HealthRecord, HealthStore};
use strings::Locale;

const CLOCK_ROLLBACK_TOLERANCE: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "activity-prototype", allow(dead_code))]
pub(crate) enum AgentFacet {
    Ready,
    GateUnavailable,
    Error,
}

pub(crate) struct LifecycleAppState {
    inner: Mutex<LifecycleInner>,
    mutation: Mutex<()>,
}

struct LifecycleInner {
    store: HealthStore,
    record: HealthRecord,
    health_reset_required: bool,
    agent: AgentFacet,
    wall_clock_anchor_ms: u64,
    wall_clock_anchor: Instant,
    #[cfg(target_os = "macos")]
    stopping: bool,
}

#[cfg(target_os = "macos")]
impl LifecycleAppState {
    pub(crate) fn agent_facet(&self) -> AgentFacet {
        self.inner
            .lock()
            .map_or(AgentFacet::Error, |inner| inner.agent)
    }

    pub(crate) fn agent_health_valid(&self) -> bool {
        self.inner.lock().is_ok_and(|inner| {
            !inner.health_reset_required
                && !inner.stopping
                && wall_clock_is_consistent(
                    inner.wall_clock_anchor_ms,
                    inner.wall_clock_anchor.elapsed(),
                    health::unix_time_ms(),
                )
        })
    }
}

impl core::fmt::Debug for LifecycleAppState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("LifecycleAppState([REDACTED])")
    }
}

impl LifecycleAppState {
    pub(crate) fn load(app_local_data: &Path) -> Self {
        let mut store = HealthStore::new(app_local_data);
        let (record, health_reset_required) = match store.load() {
            Ok(Some(record)) => (record, false),
            Ok(None) => {
                let mut record = HealthRecord::default();
                let invalid = store.save(&mut record).is_err();
                (record, invalid)
            }
            Err(_) => (HealthRecord::default(), true),
        };
        Self {
            inner: Mutex::new(LifecycleInner {
                store,
                record,
                health_reset_required,
                agent: AgentFacet::GateUnavailable,
                wall_clock_anchor_ms: health::unix_time_ms(),
                wall_clock_anchor: Instant::now(),
                #[cfg(target_os = "macos")]
                stopping: false,
            }),
            mutation: Mutex::new(()),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn set_agent_facet(&self, agent: AgentFacet) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.agent = agent;
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn locale(&self) -> Locale {
        self.inner
            .lock()
            .map_or(Locale::En, |inner| inner.record.locale)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn begin_stopping(&self) -> bool {
        self.inner.lock().is_ok_and(|mut inner| {
            if inner.stopping {
                false
            } else {
                inner.stopping = true;
                true
            }
        })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn flush(&self) -> Result<(), ()> {
        let mut inner = self.inner.lock().map_err(|_| ())?;
        if inner.health_reset_required {
            return Err(());
        }
        let failed = {
            let LifecycleInner { store, record, .. } = &mut *inner;
            store.save(record).is_err()
        };
        if failed {
            inner.health_reset_required = true;
            inner.agent = AgentFacet::Error;
            Err(())
        } else {
            Ok(())
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LifecycleStatusResponse {
    service: &'static str,
    activity: &'static str,
    autostart: &'static str,
    autostart_desired: bool,
    notifications: &'static str,
    locale: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_server_accepted_at_ms: Option<String>,
    health_reset_required: bool,
    can_request_notifications: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LifecycleError {
    code: &'static str,
}

impl LifecycleError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AutostartRequest {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocaleRequest {
    locale: String,
}

#[tauri::command]
pub(crate) async fn lifecycle_status(
    request: tauri::ipc::Request<'_>,
    state: State<'_, LifecycleAppState>,
) -> Result<LifecycleStatusResponse, LifecycleError> {
    parse_json::<EmptyRequest>(request.body())?;
    status_response(state.inner())
}

#[tauri::command]
pub(crate) async fn lifecycle_set_autostart(
    request: tauri::ipc::Request<'_>,
    window: WebviewWindow,
    state: State<'_, LifecycleAppState>,
) -> Result<LifecycleStatusResponse, LifecycleError> {
    require_user_gesture(&window)?;
    let request = parse_json::<AutostartRequest>(request.body())?;
    let _mutation = state
        .mutation
        .lock()
        .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
    let mut inner = state
        .inner
        .lock()
        .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
    check_mutation(&inner, true)?;
    #[cfg(target_os = "macos")]
    {
        let observed = macos::autostart_status();
        if should_open_login_items_settings(
            request.enabled,
            inner.record.desired_autostart,
            observed,
        ) {
            macos::open_login_items_settings();
            drop(inner);
            return status_response(state.inner());
        }

        let old_record = inner.record;
        let result = macos::set_autostart(request.enabled)
            .map_err(|()| LifecycleError::new("lifecycle_autostart_failed"))?;
        let accepted = matches!(
            (request.enabled, result),
            (
                true,
                macos::AutostartStatus::Enabled | macos::AutostartStatus::RequiresApproval
            ) | (false, macos::AutostartStatus::Disabled)
        );
        if !accepted {
            return Err(LifecycleError::new("lifecycle_autostart_failed"));
        }
        inner.record.desired_autostart = request.enabled;
        if let Err(error) = persist(&mut inner) {
            inner.record = old_record;
            if old_record.desired_autostart != request.enabled {
                let _ = macos::set_autostart(old_record.desired_autostart);
            }
            return Err(error);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        inner.record.desired_autostart = request.enabled;
        persist(&mut inner)?;
    }
    drop(inner);
    status_response(state.inner())
}

#[cfg(target_os = "macos")]
const fn should_open_login_items_settings(
    requested_enabled: bool,
    desired_enabled: bool,
    observed: macos::AutostartStatus,
) -> bool {
    requested_enabled
        && desired_enabled
        && matches!(observed, macos::AutostartStatus::RequiresApproval)
}

#[tauri::command]
pub(crate) async fn lifecycle_request_notification_permission(
    request: tauri::ipc::Request<'_>,
    window: WebviewWindow,
    state: State<'_, LifecycleAppState>,
) -> Result<LifecycleStatusResponse, LifecycleError> {
    parse_json::<EmptyRequest>(request.body())?;
    require_user_gesture(&window)?;
    let _mutation = state
        .mutation
        .lock()
        .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
    {
        let inner = state
            .inner
            .lock()
            .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
        check_mutation(&inner, false)?;
    }
    #[cfg(target_os = "macos")]
    {
        let _ = macos::request_notification_permission();
    }
    status_response(state.inner())
}

#[tauri::command]
pub(crate) async fn lifecycle_set_locale(
    request: tauri::ipc::Request<'_>,
    window: WebviewWindow,
    state: State<'_, LifecycleAppState>,
) -> Result<LifecycleStatusResponse, LifecycleError> {
    require_user_gesture(&window)?;
    let request = parse_json::<LocaleRequest>(request.body())?;
    let locale = Locale::parse(&request.locale)
        .ok_or_else(|| LifecycleError::new("lifecycle_invalid_locale"))?;
    let _mutation = state
        .mutation
        .lock()
        .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
    let mut inner = state
        .inner
        .lock()
        .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
    check_mutation(&inner, true)?;
    inner.record.locale = locale;
    persist(&mut inner)?;
    drop(inner);
    status_response(state.inner())
}

#[tauri::command]
pub(crate) async fn lifecycle_reset_health_state(
    request: tauri::ipc::Request<'_>,
    window: WebviewWindow,
    state: State<'_, LifecycleAppState>,
) -> Result<LifecycleStatusResponse, LifecycleError> {
    parse_json::<EmptyRequest>(request.body())?;
    require_user_gesture(&window)?;
    let _mutation = state
        .mutation
        .lock()
        .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
    let mut inner = state
        .inner
        .lock()
        .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
    check_mutation(&inner, false)?;
    let LifecycleInner { store, record, .. } = &mut *inner;
    store
        .reset(record)
        .map_err(|_| LifecycleError::new("lifecycle_health_reset_failed"))?;
    inner.health_reset_required = false;
    drop(inner);
    status_response(state.inner())
}

fn status_response(state: &LifecycleAppState) -> Result<LifecycleStatusResponse, LifecycleError> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| LifecycleError::new("lifecycle_internal"))?;
    #[cfg(target_os = "macos")]
    let (autostart, notifications) = (
        autostart_code(macos::autostart_status(), inner.record.desired_autostart),
        notification_code(macos::notification_status()),
    );
    #[cfg(not(target_os = "macos"))]
    let (autostart, notifications) = ("unavailable", "unavailable");
    let agent = if !inner.health_reset_required
        && !inner.stopping
        && wall_clock_is_consistent(
            inner.wall_clock_anchor_ms,
            inner.wall_clock_anchor.elapsed(),
            health::unix_time_ms(),
        ) {
        inner.agent
    } else {
        AgentFacet::Error
    };
    Ok(LifecycleStatusResponse {
        service: "unbound",
        activity: match agent {
            AgentFacet::Ready => "ready",
            AgentFacet::GateUnavailable => "gate_unavailable",
            AgentFacet::Error => "agent_error",
        },
        autostart,
        autostart_desired: inner.record.desired_autostart,
        notifications,
        locale: inner.record.locale.code(),
        last_server_accepted_at_ms: inner
            .record
            .last_server_accepted_at_ms
            .map(|value| value.to_string()),
        health_reset_required: inner.health_reset_required,
        can_request_notifications: notifications == "not_requested",
    })
}

fn wall_clock_is_consistent(anchor_ms: u64, elapsed: Duration, current_ms: u64) -> bool {
    if current_ms == 0 {
        return false;
    }
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let tolerance_ms = u64::try_from(CLOCK_ROLLBACK_TOLERANCE.as_millis()).unwrap_or(u64::MAX);
    let minimum_expected = anchor_ms
        .saturating_add(elapsed_ms)
        .saturating_sub(tolerance_ms);
    current_ms >= minimum_expected
}

#[cfg(target_os = "macos")]
fn autostart_code(status: macos::AutostartStatus, desired: bool) -> &'static str {
    use macos::AutostartStatus;
    match (status, desired) {
        (AutostartStatus::Enabled, true) => "enabled",
        (AutostartStatus::Disabled, false) => "disabled",
        (AutostartStatus::Unavailable, _) => "unavailable",
        _ => "drifted",
    }
}

#[cfg(target_os = "macos")]
const fn notification_code(status: macos::NotificationStatus) -> &'static str {
    use macos::NotificationStatus;
    match status {
        NotificationStatus::NotRequested => "not_requested",
        NotificationStatus::Authorized => "authorized",
        NotificationStatus::Denied => "denied",
        NotificationStatus::Unavailable => "unavailable",
    }
}

fn persist(inner: &mut LifecycleInner) -> Result<(), LifecycleError> {
    if inner.health_reset_required {
        return Err(LifecycleError::new("lifecycle_health_reset_required"));
    }
    let LifecycleInner { store, record, .. } = inner;
    store.save(record).map_err(|_| {
        inner.health_reset_required = true;
        LifecycleError::new("lifecycle_health_write_failed")
    })
}

fn check_mutation(
    inner: &LifecycleInner,
    requires_writable_health: bool,
) -> Result<(), LifecycleError> {
    #[cfg(target_os = "macos")]
    if inner.stopping {
        return Err(LifecycleError::new("lifecycle_stopping"));
    }
    if requires_writable_health && inner.health_reset_required {
        return Err(LifecycleError::new("lifecycle_health_reset_required"));
    }
    Ok(())
}

fn require_user_gesture(window: &WebviewWindow) -> Result<(), LifecycleError> {
    if window.label() != "main"
        || !window.is_visible().unwrap_or(false)
        || !window.is_focused().unwrap_or(false)
    {
        return Err(LifecycleError::new("lifecycle_user_gesture_required"));
    }
    Ok(())
}

fn parse_json<T: DeserializeOwned>(body: &InvokeBody) -> Result<T, LifecycleError> {
    match body {
        InvokeBody::Json(value) => {
            T::deserialize(value).map_err(|_| LifecycleError::new("lifecycle_invalid_request"))
        }
        InvokeBody::Raw(_) => Err(LifecycleError::new("lifecycle_invalid_request")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shapes_are_strict() {
        let valid = InvokeBody::Json(serde_json::json!({ "enabled": true }));
        assert!(parse_json::<AutostartRequest>(&valid).is_ok());
        let extra = InvokeBody::Json(serde_json::json!({ "enabled": true, "x": 1 }));
        assert!(parse_json::<AutostartRequest>(&extra).is_err());
        assert!(parse_json::<EmptyRequest>(&InvokeBody::Raw(vec![])).is_err());
    }

    #[test]
    fn wall_clock_rollback_is_bounded_and_forward_steps_are_allowed() {
        let anchor = 1_000_000;
        let elapsed = Duration::from_secs(300);
        assert!(wall_clock_is_consistent(anchor, elapsed, 1_180_000));
        assert!(!wall_clock_is_consistent(anchor, elapsed, 1_179_999));
        assert!(wall_clock_is_consistent(anchor, elapsed, 9_000_000));
        assert!(!wall_clock_is_consistent(anchor, elapsed, 0));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn autostart_status_reports_drift_against_durable_intent() {
        use macos::AutostartStatus;
        assert_eq!(autostart_code(AutostartStatus::Enabled, true), "enabled");
        assert_eq!(autostart_code(AutostartStatus::Disabled, false), "disabled");
        assert_eq!(autostart_code(AutostartStatus::Enabled, false), "drifted");
        assert_eq!(
            autostart_code(AutostartStatus::RequiresApproval, true),
            "drifted"
        );
        assert_eq!(
            autostart_code(AutostartStatus::Unavailable, true),
            "unavailable"
        );
        assert!(!should_open_login_items_settings(
            true,
            false,
            AutostartStatus::RequiresApproval
        ));
        assert!(should_open_login_items_settings(
            true,
            true,
            AutostartStatus::RequiresApproval
        ));
        assert!(!should_open_login_items_settings(
            false,
            true,
            AutostartStatus::RequiresApproval
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn invalid_health_is_not_repaired_by_shutdown_flush() {
        let root = std::env::temp_dir().join(format!(
            "aeterna-lifecycle-invalid-{}-{}",
            std::process::id(),
            health::unix_time_ms()
        ));
        std::fs::create_dir(&root)
            .unwrap_or_else(|error| panic!("create lifecycle test root: {error}"));
        let initial = LifecycleAppState::load(&root);
        assert_eq!(initial.agent_facet(), AgentFacet::GateUnavailable);
        assert!(initial.flush().is_ok());
        let path = root.join("health").join("activity-health-v1.bin");
        let mut corrupt =
            std::fs::read(&path).unwrap_or_else(|error| panic!("read lifecycle record: {error}"));
        corrupt[20] ^= 1;
        std::fs::write(&path, &corrupt)
            .unwrap_or_else(|error| panic!("corrupt lifecycle record: {error}"));
        let restarted = LifecycleAppState::load(&root);
        assert!(!restarted.agent_health_valid());
        assert!(
            restarted
                .inner
                .lock()
                .unwrap_or_else(|error| panic!("lock lifecycle state: {error}"))
                .health_reset_required
        );
        assert!(restarted.flush().is_err());
        assert_eq!(
            std::fs::read(&path)
                .unwrap_or_else(|error| panic!("re-read lifecycle record: {error}")),
            corrupt
        );
        std::fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("remove lifecycle test root: {error}"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn shutdown_flush_reports_an_unwritable_health_directory() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "aeterna-lifecycle-flush-{}-{}",
            std::process::id(),
            health::unix_time_ms()
        ));
        std::fs::create_dir(&root)
            .unwrap_or_else(|error| panic!("create lifecycle test root: {error}"));
        let state = LifecycleAppState::load(&root);
        let health_directory = root.join("health");
        std::fs::set_permissions(&health_directory, std::fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("make health directory read-only: {error}"));

        assert!(state.flush().is_err());
        assert_eq!(state.agent_facet(), AgentFacet::Error);
        assert!(!state.agent_health_valid());

        std::fs::set_permissions(&health_directory, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("restore health directory permissions: {error}"));
        std::fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("remove lifecycle test root: {error}"));
    }
}
