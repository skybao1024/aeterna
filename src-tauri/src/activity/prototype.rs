#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::io::BufWriter;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::path::PathBuf;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::sync::mpsc;
use std::sync::mpsc::Sender;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::thread;
use std::thread::JoinHandle;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::time::Duration;
use std::time::Instant;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use super::diagnostics::{DiagnosticConfig, DiagnosticHarness};
use super::policy::{ActivityObservation, ObservationKind};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use super::policy::{ActivityPolicyConfig, MonotonicTime};

#[cfg(any(target_os = "macos", target_os = "windows"))]
const POLL_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(target_os = "macos")]
const COMPRESSED_CONFIG_ENV: &str = "AETERNA_I01_TEST_ONLY_COMPRESSED";
#[cfg(target_os = "windows")]
const COMPRESSED_CONFIG_ENV: &str = "AETERNA_I04_TEST_ONLY_COMPRESSED";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrototypeStartError {
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    UnsupportedPlatform,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    Artifact,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    DiagnosticThread,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    NativeObserver,
}

#[cfg(target_os = "macos")]
type PlatformObserver = super::macos::MacOsActivityObserver;
#[cfg(target_os = "windows")]
type PlatformObserver = super::windows::WindowsActivityObserver;

struct ActivityPrototype {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    observer: Option<PlatformObserver>,
    observations: Sender<ActivityObservation>,
    diagnostics: Option<JoinHandle<io::Result<()>>>,
    epoch: Instant,
    stopped: bool,
}

impl ActivityPrototype {
    fn start() -> Result<Self, PrototypeStartError> {
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Err(PrototypeStartError::UnsupportedPlatform)
        }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            let trace_file = open_trace_file()?;
            let epoch = Instant::now();
            let (observations, receiver) = mpsc::channel::<ActivityObservation>();
            let (policy_config, diagnostic_config) = prototype_config();
            let diagnostics = thread::Builder::new()
                .name("aeterna-activity-diagnostics".to_owned())
                .spawn(move || {
                    let mut harness = DiagnosticHarness::new(
                        BufWriter::new(trace_file),
                        policy_config,
                        diagnostic_config,
                    );
                    harness.record(ActivityObservation {
                        observed_at: MonotonicTime::ZERO,
                        kind: ObservationKind::ProcessStarted,
                    })?;
                    for observation in receiver {
                        let should_stop =
                            matches!(observation.kind, ObservationKind::ObserverStopped);
                        harness.record(observation)?;
                        if should_stop {
                            break;
                        }
                    }
                    Ok(())
                })
                .map_err(|_| PrototypeStartError::DiagnosticThread)?;

            let observer = match PlatformObserver::start(observations.clone(), epoch, POLL_INTERVAL)
            {
                Ok(observer) => observer,
                Err(_) => {
                    send_observation(
                        &observations,
                        epoch,
                        ObservationKind::ObserverInitializationFailed,
                    );
                    send_observation(&observations, epoch, ObservationKind::ObserverStopped);
                    let _ = diagnostics.join();
                    return Err(PrototypeStartError::NativeObserver);
                }
            };

            Ok(Self {
                observer: Some(observer),
                observations,
                diagnostics: Some(diagnostics),
                epoch,
                stopped: false,
            })
        }
    }

    fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        if let Some(mut observer) = self.observer.take() {
            let _ = observer.stop();
        }

        send_observation(
            &self.observations,
            self.epoch,
            ObservationKind::ObserverStopped,
        );
        if let Some(diagnostics) = self.diagnostics.take() {
            let _ = diagnostics.join();
        }
    }
}

impl Drop for ActivityPrototype {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn run(app: tauri::App) {
    let mut prototype = match ActivityPrototype::start() {
        Ok(prototype) => {
            eprintln!("Aeterna activity prototype started with redacted local diagnostics.");
            Some(prototype)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Err(PrototypeStartError::UnsupportedPlatform) => {
            eprintln!("Aeterna activity prototype is unsupported on this platform.");
            None
        }
        Err(_) => {
            eprintln!("Aeterna activity prototype failed to initialize and is inactive.");
            None
        }
    };

    app.run(move |app_handle, event| {
        let should_exit = matches!(
            event,
            tauri::RunEvent::WindowEvent {
                event: tauri::WindowEvent::CloseRequested { .. },
                ..
            }
        );
        if (should_exit
            || matches!(
                event,
                tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
            ))
            && let Some(prototype) = prototype.as_mut()
        {
            prototype.stop();
        }
        if should_exit {
            // The prototype has no tray or background-only mode. Closing its only
            // window is therefore a complete run and must exercise orderly cleanup.
            app_handle.exit(0);
        }
    });
}

fn send_observation(
    observations: &Sender<ActivityObservation>,
    epoch: Instant,
    kind: ObservationKind,
) {
    let observed_at = super::observer::monotonic_time(epoch);
    let _ = observations.send(ActivityObservation { observed_at, kind });
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn open_trace_file() -> Result<File, PrototypeStartError> {
    let trace_path = trace_path();
    let Some(parent) = trace_path.parent() else {
        return Err(PrototypeStartError::Artifact);
    };
    fs::create_dir_all(parent).map_err(|_| PrototypeStartError::Artifact)?;
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(trace_path)
        .map_err(|_| PrototypeStartError::Artifact)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn trace_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    let directory = "i01-diagnostics";
    #[cfg(target_os = "windows")]
    let directory = "i04-diagnostics";
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(directory)
        .join("activity.jsonl")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn prototype_config() -> (ActivityPolicyConfig, DiagnosticConfig) {
    if std::env::var(COMPRESSED_CONFIG_ENV).as_deref() == Ok("1") {
        (
            ActivityPolicyConfig {
                post_unlock_window: Duration::from_secs(15),
                idle_recovery_threshold: Duration::from_secs(20),
                continuous_use_refresh: Duration::from_secs(20),
                candidate_cooldown: Duration::from_secs(30),
                input_confirmation_window: Duration::from_secs(15),
                maximum_sample_staleness: Duration::from_secs(2),
                input_time_tolerance: Duration::from_millis(100),
            },
            DiagnosticConfig::TEST_ONLY_COMPRESSED,
        )
    } else {
        (ActivityPolicyConfig::default(), DiagnosticConfig::DEFAULT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn prototype_is_explicitly_unsupported_off_supported_desktop_platforms() {
        assert_eq!(
            ActivityPrototype::start().map(|_| ()),
            Err(PrototypeStartError::UnsupportedPlatform)
        );
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn trace_stays_under_the_ignored_cargo_target_directory() {
        let path = trace_path();
        assert!(path.starts_with(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target")));
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("activity.jsonl")
        );
    }
}
