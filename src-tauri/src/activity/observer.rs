use std::io;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc::Sender,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::policy::{
    ActivityObservation, ActivitySample, ActivitySampleValue, EligibleInputClass,
    InputSampleFailure, InputSampleValue, MonotonicTime, ObservationKind, UnlockGateFailure,
    UnlockGateState,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverStartError {
    UnsupportedPlatform,
    ThreadInitializationFailed,
    NativeInitializationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverStopError {
    WorkerPanicked,
    NativeShutdownFailed,
}

pub trait ActivitySampler: Send + 'static {
    fn sample_activity(&mut self) -> ActivitySampleValue;
}

pub struct PollingObserver {
    stop_requested: Arc<AtomicBool>,
    wake_worker: Arc<(Mutex<()>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}

impl PollingObserver {
    pub fn start<S: ActivitySampler>(
        mut sampler: S,
        interval: Duration,
        epoch: Instant,
        observations: Sender<ActivityObservation>,
    ) -> Result<Self, ObserverStartError> {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let wake_worker = Arc::new((Mutex::new(()), Condvar::new()));
        let worker_stop = Arc::clone(&stop_requested);
        let worker_wake = Arc::clone(&wake_worker);
        let worker = thread::Builder::new()
            .name("aeterna-i01-input-poll".to_owned())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    let value = sampler.sample_activity();
                    let captured_at = monotonic_time(epoch);
                    let observation = ActivityObservation {
                        observed_at: captured_at,
                        kind: ObservationKind::ActivitySample(ActivitySample {
                            captured_at,
                            value,
                        }),
                    };
                    if observations.send(observation).is_err() {
                        break;
                    }

                    let (lock, condition) = &*worker_wake;
                    let Ok(guard) = lock.lock() else {
                        break;
                    };
                    if condition.wait_timeout(guard, interval).is_err() {
                        break;
                    }
                }
            })
            .map_err(map_thread_start_error)?;

        Ok(Self {
            stop_requested,
            wake_worker,
            worker: Some(worker),
        })
    }

    pub fn stop(&mut self) -> Result<(), ObserverStopError> {
        self.stop_requested.store(true, Ordering::Release);
        self.wake_worker.1.notify_all();
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| ObserverStopError::WorkerPanicked)?;
        }
        Ok(())
    }
}

impl Drop for PollingObserver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub fn monotonic_time(epoch: Instant) -> MonotonicTime {
    let milliseconds = u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
    MonotonicTime::from_millis(milliseconds)
}

pub fn failed_sample() -> InputSampleValue {
    InputSampleValue::Failed(InputSampleFailure::NativeReadFailed)
}

pub fn failed_activity_sample() -> ActivitySampleValue {
    ActivitySampleValue {
        eligible: failed_sample(),
        broader: None,
        eligible_class: EligibleInputClass::CurrentSession,
        unlock_gate: UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn start_platform_observer() -> Result<(), ObserverStartError> {
    Err(ObserverStartError::UnsupportedPlatform)
}

fn map_thread_start_error(_error: io::Error) -> ObserverStartError {
    ObserverStartError::ThreadInitializationFailed
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    use super::*;

    struct CountingSampler {
        calls: Arc<AtomicUsize>,
    }

    impl ActivitySampler for CountingSampler {
        fn sample_activity(&mut self) -> ActivitySampleValue {
            self.calls.fetch_add(1, Ordering::Relaxed);
            ActivitySampleValue {
                eligible: InputSampleValue::AgeSeconds(10.0),
                broader: None,
                eligible_class: EligibleInputClass::CurrentSession,
                unlock_gate: UnlockGateState::Accessible,
            }
        }
    }

    #[test]
    fn polling_observer_stops_cleanly_and_is_idempotent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = mpsc::channel();
        let mut observer = PollingObserver::start(
            CountingSampler {
                calls: Arc::clone(&calls),
            },
            Duration::from_secs(60),
            Instant::now(),
            sender,
        )
        .unwrap_or_else(|error| panic!("observer should start: {error:?}"));

        let first = receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("observer should emit a sample: {error}"));
        assert!(matches!(first.kind, ObservationKind::ActivitySample(_)));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(observer.stop(), Ok(()));
        assert_eq!(observer.stop(), Ok(()));
    }

    #[test]
    fn failed_native_samples_are_typed_and_fail_closed() {
        assert_eq!(
            failed_sample(),
            InputSampleValue::Failed(InputSampleFailure::NativeReadFailed)
        );
        assert_eq!(
            failed_activity_sample().unlock_gate,
            UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed)
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn unsupported_platform_is_explicit() {
        assert_eq!(
            start_platform_observer(),
            Err(ObserverStartError::UnsupportedPlatform)
        );
    }
}
