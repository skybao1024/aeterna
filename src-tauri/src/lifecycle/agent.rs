#![cfg_attr(feature = "activity-prototype", allow(dead_code))]

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use tauri::{AppHandle, Manager};

use crate::{
    activity::{
        macos::{MacOsNativeObservers, QuartzActivitySampler},
        observer::{ActivitySampler, monotonic_time},
        policy::{
            ActivityCandidate, ActivityDecision, ActivityObservation, ActivityPolicy,
            ActivityPolicyConfig, ActivitySample, ObservationKind, SessionState, SuppressionReason,
        },
    },
    ipc::VaultAppState,
};

use super::{AgentFacet, LifecycleAppState};

const EVENT_CAPACITY: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const STARTUP_COOLDOWN: Duration = Duration::from_secs(30 * 60);
const CANDIDATE_EXPIRY: Duration = Duration::from_secs(15 * 60);

pub(crate) struct ActivityAgent {
    observers: MacOsNativeObservers,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    sender: SyncSender<ActivityObservation>,
    epoch: Instant,
}

impl ActivityAgent {
    pub(crate) fn start(app: AppHandle) -> Result<Self, ()> {
        let epoch = Instant::now();
        let (sender, receiver) = mpsc::sync_channel(EVENT_CAPACITY);
        let overflowed = Arc::new(AtomicBool::new(false));
        let observers = MacOsNativeObservers::start(sender.clone(), Arc::clone(&overflowed), epoch);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("aeterna-activity-agent".to_owned())
            .spawn(move || {
                let completed = catch_unwind(AssertUnwindSafe(|| {
                    run_worker(app.clone(), receiver, worker_stop, overflowed, epoch)
                }));
                if completed.is_err() {
                    app.state::<LifecycleAppState>()
                        .set_agent_facet(AgentFacet::Error);
                    secure_lock_and_hide(&app);
                }
            })
            .map_err(|_| ())?;
        Ok(Self {
            observers,
            stop,
            worker: Some(worker),
            sender,
            epoch,
        })
    }

    pub(crate) fn stop(&mut self) {
        self.observers.stop();
        self.stop.store(true, Ordering::Release);
        let _ = self.sender.try_send(ActivityObservation {
            observed_at: monotonic_time(self.epoch),
            kind: ObservationKind::ObserverStopped,
        });
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for ActivityAgent {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_worker(
    app: AppHandle,
    receiver: Receiver<ActivityObservation>,
    stop: Arc<AtomicBool>,
    overflowed: Arc<AtomicBool>,
    epoch: Instant,
) {
    let mut policy = ActivityPolicy::new(ActivityPolicyConfig::default());
    let started_at = Instant::now();
    let mut startup_guard_complete = false;
    let mut next_sample = Instant::now();
    let mut sampler = QuartzActivitySampler::new();
    let mut candidate: Option<(ActivityCandidate, Instant)> = None;
    observe(
        &app,
        &mut policy,
        ActivityObservation {
            observed_at: monotonic_time(epoch),
            kind: ObservationKind::ProcessStarted,
        },
        startup_guard_complete,
        &mut candidate,
    );

    loop {
        if stop.load(Ordering::Acquire) {
            let _ = policy.observe(ActivityObservation {
                observed_at: monotonic_time(epoch),
                kind: ObservationKind::ObserverStopped,
            });
            let _ = candidate.take();
            break;
        }
        if overflowed.swap(false, Ordering::AcqRel) {
            app.state::<LifecycleAppState>()
                .set_agent_facet(AgentFacet::Error);
            secure_lock_and_hide(&app);
            return;
        }
        for _ in 0..EVENT_CAPACITY {
            match receiver.try_recv() {
                Ok(observation) => observe(
                    &app,
                    &mut policy,
                    observation,
                    startup_guard_complete,
                    &mut candidate,
                ),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    app.state::<LifecycleAppState>()
                        .set_agent_facet(AgentFacet::Error);
                    secure_lock_and_hide(&app);
                    return;
                }
            }
        }
        if Instant::now() >= next_sample {
            if !app.state::<LifecycleAppState>().agent_health_valid() {
                let _ = candidate.take();
                app.state::<LifecycleAppState>()
                    .set_agent_facet(AgentFacet::Error);
                secure_lock_and_hide(&app);
                return;
            }
            if !startup_guard_complete && started_at.elapsed() >= STARTUP_COOLDOWN {
                policy = ActivityPolicy::new(ActivityPolicyConfig::default());
                candidate = None;
                let _ = policy.observe(ActivityObservation {
                    observed_at: monotonic_time(epoch),
                    kind: ObservationKind::ProcessStarted,
                });
                startup_guard_complete = true;
            }
            let captured_at = monotonic_time(epoch);
            let observation = ActivityObservation {
                observed_at: captured_at,
                kind: ObservationKind::ActivitySample(ActivitySample {
                    captured_at,
                    value: sampler.sample_activity(),
                }),
            };
            observe(
                &app,
                &mut policy,
                observation,
                startup_guard_complete,
                &mut candidate,
            );
            next_sample = Instant::now() + POLL_INTERVAL;
        }
        if candidate.is_some_and(|(_, created)| created.elapsed() > CANDIDATE_EXPIRY) {
            candidate = None;
        }
        // The next sample or a native lifecycle signal wakes the worker.
        // A fixed short sleep would wake an otherwise idle agent hundreds of
        // times per minute and defeat the background energy budget.
        match receiver.recv_timeout(next_sample.saturating_duration_since(Instant::now())) {
            Ok(observation) => observe(
                &app,
                &mut policy,
                observation,
                startup_guard_complete,
                &mut candidate,
            ),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                app.state::<LifecycleAppState>()
                    .set_agent_facet(AgentFacet::Error);
                secure_lock_and_hide(&app);
                return;
            }
        }
    }
}

fn observe(
    app: &AppHandle,
    policy: &mut ActivityPolicy,
    observation: ActivityObservation,
    startup_guard_complete: bool,
    candidate: &mut Option<(ActivityCandidate, Instant)>,
) {
    let force_lock = matches!(
        observation.kind,
        ObservationKind::WillSleep | ObservationKind::SessionChanged(SessionState::Inactive)
    );
    let accessible_sample = matches!(
        observation.kind,
        ObservationKind::ActivitySample(ActivitySample {
            value: crate::activity::policy::ActivitySampleValue {
                unlock_gate: crate::activity::policy::UnlockGateState::Accessible,
                ..
            },
            ..
        })
    );
    let decision = policy.observe(observation);
    match decision {
        ActivityDecision::Candidate(next) if startup_guard_complete => {
            *candidate = Some((next, Instant::now()));
            app.state::<LifecycleAppState>()
                .set_agent_facet(AgentFacet::Ready);
        }
        ActivityDecision::Candidate(_) => {}
        ActivityDecision::Suppressed(SuppressionReason::UnlockGateUnavailable) => {
            *candidate = None;
            app.state::<LifecycleAppState>()
                .set_agent_facet(AgentFacet::GateUnavailable);
            secure_lock_and_hide(app);
        }
        ActivityDecision::Suppressed(SuppressionReason::ObserverInitializationFailed) => {
            *candidate = None;
            app.state::<LifecycleAppState>()
                .set_agent_facet(AgentFacet::Error);
            secure_lock_and_hide(app);
        }
        ActivityDecision::Suppressed(SuppressionReason::ContradictoryObservation) => {
            *candidate = None;
            app.state::<LifecycleAppState>()
                .set_agent_facet(AgentFacet::Error);
            secure_lock_and_hide(app);
        }
        ActivityDecision::Suppressed(SuppressionReason::UnlockGateLocked) => {
            *candidate = None;
            secure_lock_and_hide(app);
        }
        _ if force_lock => {
            *candidate = None;
            secure_lock_and_hide(app);
        }
        _ if accessible_sample => {
            app.state::<LifecycleAppState>()
                .set_agent_facet(AgentFacet::Ready);
        }
        _ => {}
    }
}

pub(crate) fn secure_lock_and_hide(app: &AppHandle) {
    if app
        .state::<VaultAppState>()
        .secure_lock_for_lifecycle()
        .is_err()
    {
        app.exit(1);
        return;
    }
    hide_main_window(app);
}

pub(crate) fn hide_main_window(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(window) = handle.get_webview_window("main")
            && window.is_visible().unwrap_or(false)
        {
            let _ = window.reload();
            let _ = window.hide();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_agent_bounds_are_fixed() {
        assert_eq!(EVENT_CAPACITY, 32);
        assert_eq!(POLL_INTERVAL, Duration::from_secs(5));
        assert_eq!(STARTUP_COOLDOWN, Duration::from_secs(30 * 60));
        assert_eq!(CANDIDATE_EXPIRY, Duration::from_secs(15 * 60));
        assert!(CANDIDATE_EXPIRY < STARTUP_COOLDOWN);
        assert!(
            ActivityPolicyConfig::default().continuous_use_refresh
                <= Duration::from_secs(12 * 60 * 60)
        );
    }
}
