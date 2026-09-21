use std::time::Duration;

const MILLIS_PER_SECOND: f64 = 1_000.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    pub const ZERO: Self = Self(0);

    pub const fn from_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    pub const fn as_millis(self) -> u64 {
        self.0
    }

    fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_millis)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Inactive,
    Locked,
    Unlocked,
    Unknown,
}

impl SessionState {
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSampleFailure {
    NativeUnavailable,
    NativeReadFailed,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InputSampleValue {
    AgeSeconds(f64),
    Missing,
    Failed(InputSampleFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockGateFailure {
    ItemMissing,
    AccessDenied,
    MissingEntitlement,
    KeychainUnavailable,
    InvalidItem,
    NativeReadFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockGateState {
    Accessible,
    Locked,
    Failed(UnlockGateFailure),
}

impl UnlockGateState {
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::Accessible => "accessible",
            Self::Locked => "locked",
            Self::Failed(_) => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ActivitySampleValue {
    pub eligible: InputSampleValue,
    pub broader: Option<InputSampleValue>,
    pub eligible_class: EligibleInputClass,
    pub unlock_gate: UnlockGateState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EligibleInputClass {
    HidClass,
    CurrentSession,
}

impl EligibleInputClass {
    const fn source_class(self) -> InputSourceClass {
        match self {
            Self::HidClass => InputSourceClass::HidClass,
            Self::CurrentSession => InputSourceClass::CurrentSession,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ActivitySample {
    pub captured_at: MonotonicTime,
    pub value: ActivitySampleValue,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ObservationKind {
    ProcessStarted,
    SessionChanged(SessionState),
    WillSleep,
    DidWake,
    ActivitySample(ActivitySample),
    ObserverInitializationFailed,
    ObserverStopped,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ActivityObservation {
    pub observed_at: MonotonicTime,
    pub kind: ObservationKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSourceClass {
    NotApplicable,
    None,
    HidClass,
    CurrentSession,
    BroaderOnly,
    Invalid,
}

impl InputSourceClass {
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::None => "none",
            Self::HidClass => "hid_class",
            Self::CurrentSession => "current_session",
            Self::BroaderOnly => "broader_only",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateReason {
    PostUnlockInput,
    IdleRecovery,
    ContinuousUseRefresh,
}

impl CandidateReason {
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::PostUnlockInput => "post_unlock_input",
            Self::IdleRecovery => "idle_recovery",
            Self::ContinuousUseRefresh => "continuous_use_refresh",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivityCandidate {
    pub observed_at: MonotonicTime,
    pub reason: CandidateReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuppressionReason {
    ProcessStarted,
    ProcessNotStarted,
    DuplicateProcessStart,
    SessionActive,
    SessionInactive,
    SessionLocked,
    SessionUnlocked,
    SessionUnknown,
    Sleeping,
    WokeWithoutInput,
    ObserverInitializationFailed,
    ObserverStopped,
    ContradictoryObservation,
    NonMonotonicObservation,
    FutureSample,
    StaleSample,
    DecreasingSampleTime,
    MissingInputAge,
    InputSampleFailed,
    NonFiniteInputAge,
    NegativeInputAge,
    InputAgeOutOfRange,
    InputBaselineEstablished,
    UnlockBaselineRequired,
    UnlockGateLocked,
    UnlockGateUnavailable,
    NoNewInput,
    BroaderOnlyInput,
    InputWhileInactive,
    InputWhileSleeping,
    InputConfirmationPending,
    InputConfirmationExpired,
    PostUnlockWindowExpired,
    IdleThresholdNotReached,
    ContinuousUseRefreshPending,
    CandidateCooldown,
}

impl SuppressionReason {
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::ProcessStarted => "process_started",
            Self::ProcessNotStarted => "process_not_started",
            Self::DuplicateProcessStart => "duplicate_process_start",
            Self::SessionActive => "session_active",
            Self::SessionInactive => "session_inactive",
            Self::SessionLocked => "session_locked",
            Self::SessionUnlocked => "session_unlocked",
            Self::SessionUnknown => "session_unknown",
            Self::Sleeping => "sleeping",
            Self::WokeWithoutInput => "woke_without_input",
            Self::ObserverInitializationFailed => "observer_initialization_failed",
            Self::ObserverStopped => "observer_stopped",
            Self::ContradictoryObservation => "contradictory_observation",
            Self::NonMonotonicObservation => "non_monotonic_observation",
            Self::FutureSample => "future_sample",
            Self::StaleSample => "stale_sample",
            Self::DecreasingSampleTime => "decreasing_sample_time",
            Self::MissingInputAge => "missing_input_age",
            Self::InputSampleFailed => "input_sample_failed",
            Self::NonFiniteInputAge => "non_finite_input_age",
            Self::NegativeInputAge => "negative_input_age",
            Self::InputAgeOutOfRange => "input_age_out_of_range",
            Self::InputBaselineEstablished => "input_baseline_established",
            Self::UnlockBaselineRequired => "unlock_baseline_required",
            Self::UnlockGateLocked => "unlock_gate_locked",
            Self::UnlockGateUnavailable => "unlock_gate_unavailable",
            Self::NoNewInput => "no_new_input",
            Self::BroaderOnlyInput => "broader_only_input",
            Self::InputWhileInactive => "input_while_inactive",
            Self::InputWhileSleeping => "input_while_sleeping",
            Self::InputConfirmationPending => "input_confirmation_pending",
            Self::InputConfirmationExpired => "input_confirmation_expired",
            Self::PostUnlockWindowExpired => "post_unlock_window_expired",
            Self::IdleThresholdNotReached => "idle_threshold_not_reached",
            Self::ContinuousUseRefreshPending => "continuous_use_refresh_pending",
            Self::CandidateCooldown => "candidate_cooldown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityDecision {
    Candidate(ActivityCandidate),
    Suppressed(SuppressionReason),
}

impl ActivityDecision {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Candidate(candidate) => candidate.reason.as_code(),
            Self::Suppressed(reason) => reason.as_code(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivityPolicyConfig {
    pub post_unlock_window: Duration,
    pub idle_recovery_threshold: Duration,
    pub continuous_use_refresh: Duration,
    pub candidate_cooldown: Duration,
    pub input_confirmation_window: Duration,
    pub maximum_sample_staleness: Duration,
    pub input_time_tolerance: Duration,
}

impl Default for ActivityPolicyConfig {
    fn default() -> Self {
        Self {
            post_unlock_window: Duration::from_secs(2 * 60),
            idle_recovery_threshold: Duration::from_secs(30 * 60),
            continuous_use_refresh: Duration::from_secs(4 * 60 * 60),
            candidate_cooldown: Duration::from_secs(30 * 60),
            input_confirmation_window: Duration::from_secs(2 * 60),
            maximum_sample_staleness: Duration::from_secs(2),
            input_time_tolerance: Duration::from_millis(100),
        }
    }
}

#[derive(Clone, Copy)]
struct PendingCandidate {
    armed_at: MonotonicTime,
    first_eligible_time_seconds: f64,
    reason: CandidateReason,
}

pub struct ActivityPolicy {
    config: ActivityPolicyConfig,
    started: bool,
    stopped: bool,
    sleeping: bool,
    session: SessionState,
    last_observation_at: Option<MonotonicTime>,
    last_sample_at: Option<MonotonicTime>,
    last_eligible_time_seconds: Option<f64>,
    last_broader_time_seconds: Option<f64>,
    last_eligible_age: Option<Duration>,
    gate_accessible: bool,
    unlock_transition_pending: bool,
    unlock_at: Option<MonotonicTime>,
    continuous_use_since: Option<MonotonicTime>,
    pending_candidate: Option<PendingCandidate>,
    last_candidate_at: Option<MonotonicTime>,
    input_source_class: InputSourceClass,
}

impl ActivityPolicy {
    pub fn new(config: ActivityPolicyConfig) -> Self {
        Self {
            config,
            started: false,
            stopped: false,
            sleeping: false,
            session: SessionState::Unknown,
            last_observation_at: None,
            last_sample_at: None,
            last_eligible_time_seconds: None,
            last_broader_time_seconds: None,
            last_eligible_age: None,
            gate_accessible: false,
            unlock_transition_pending: false,
            unlock_at: None,
            continuous_use_since: None,
            pending_candidate: None,
            last_candidate_at: None,
            input_source_class: InputSourceClass::NotApplicable,
        }
    }

    pub const fn session_state(&self) -> SessionState {
        self.session
    }

    pub const fn input_source_class(&self) -> InputSourceClass {
        self.input_source_class
    }

    pub fn observe(&mut self, observation: ActivityObservation) -> ActivityDecision {
        self.input_source_class = if matches!(observation.kind, ObservationKind::ActivitySample(_))
        {
            InputSourceClass::Invalid
        } else {
            InputSourceClass::NotApplicable
        };

        if let Some(previous) = self.last_observation_at
            && observation.observed_at < previous
        {
            return ActivityDecision::Suppressed(SuppressionReason::NonMonotonicObservation);
        }
        self.last_observation_at = Some(observation.observed_at);

        if !self.started && !matches!(observation.kind, ObservationKind::ProcessStarted) {
            return ActivityDecision::Suppressed(SuppressionReason::ProcessNotStarted);
        }

        match observation.kind {
            ObservationKind::ProcessStarted => self.process_started(),
            ObservationKind::SessionChanged(state) => self.session_changed(state),
            ObservationKind::WillSleep => {
                self.sleeping = true;
                self.session = SessionState::Unknown;
                self.reset_eligibility(true);
                ActivityDecision::Suppressed(SuppressionReason::Sleeping)
            }
            ObservationKind::DidWake => {
                self.sleeping = false;
                self.session = SessionState::Unknown;
                self.reset_eligibility(true);
                ActivityDecision::Suppressed(SuppressionReason::WokeWithoutInput)
            }
            ObservationKind::ActivitySample(sample) => {
                self.observe_sample(observation.observed_at, sample)
            }
            ObservationKind::ObserverInitializationFailed => {
                self.session = SessionState::Unknown;
                self.reset_eligibility(true);
                ActivityDecision::Suppressed(SuppressionReason::ObserverInitializationFailed)
            }
            ObservationKind::ObserverStopped => {
                self.stopped = true;
                self.session = SessionState::Unknown;
                self.reset_eligibility(true);
                ActivityDecision::Suppressed(SuppressionReason::ObserverStopped)
            }
        }
    }

    fn process_started(&mut self) -> ActivityDecision {
        if self.started {
            return ActivityDecision::Suppressed(SuppressionReason::DuplicateProcessStart);
        }
        self.started = true;
        self.stopped = false;
        self.sleeping = false;
        self.session = SessionState::Unknown;
        self.reset_eligibility(false);
        ActivityDecision::Suppressed(SuppressionReason::ProcessStarted)
    }

    fn session_changed(&mut self, state: SessionState) -> ActivityDecision {
        if self.sleeping && matches!(state, SessionState::Active | SessionState::Unlocked) {
            self.session = SessionState::Unknown;
            self.reset_eligibility(true);
            return ActivityDecision::Suppressed(SuppressionReason::ContradictoryObservation);
        }

        let reason = match state {
            SessionState::Active => SuppressionReason::SessionActive,
            SessionState::Inactive => SuppressionReason::SessionInactive,
            SessionState::Locked => SuppressionReason::SessionLocked,
            SessionState::Unlocked => SuppressionReason::SessionUnlocked,
            SessionState::Unknown => SuppressionReason::SessionUnknown,
        };
        self.session = if state == SessionState::Inactive {
            SessionState::Inactive
        } else {
            SessionState::Unknown
        };
        self.reset_eligibility(true);
        ActivityDecision::Suppressed(reason)
    }

    fn observe_sample(
        &mut self,
        observed_at: MonotonicTime,
        sample: ActivitySample,
    ) -> ActivityDecision {
        if self.stopped {
            return ActivityDecision::Suppressed(SuppressionReason::ObserverStopped);
        }
        let Some(sample_delay) = observed_at.checked_duration_since(sample.captured_at) else {
            return ActivityDecision::Suppressed(SuppressionReason::FutureSample);
        };
        if sample_delay > self.config.maximum_sample_staleness {
            return ActivityDecision::Suppressed(SuppressionReason::StaleSample);
        }
        if self
            .last_sample_at
            .is_some_and(|previous| sample.captured_at < previous)
        {
            return ActivityDecision::Suppressed(SuppressionReason::DecreasingSampleTime);
        }
        self.last_sample_at = Some(sample.captured_at);

        match sample.value.unlock_gate {
            UnlockGateState::Locked => {
                self.session = SessionState::Locked;
                self.reset_eligibility(true);
                return ActivityDecision::Suppressed(SuppressionReason::UnlockGateLocked);
            }
            UnlockGateState::Failed(_) => {
                self.session = SessionState::Unknown;
                self.reset_eligibility(true);
                return ActivityDecision::Suppressed(SuppressionReason::UnlockGateUnavailable);
            }
            UnlockGateState::Accessible => {}
        }

        if self.sleeping {
            self.reset_eligibility(true);
            return ActivityDecision::Suppressed(SuppressionReason::InputWhileSleeping);
        }
        if self.session == SessionState::Inactive {
            self.reset_eligibility(true);
            return ActivityDecision::Suppressed(SuppressionReason::InputWhileInactive);
        }

        let (eligible_age, eligible_time_seconds) =
            match parse_input_sample(sample.captured_at, sample.value.eligible) {
                Ok(parsed) => parsed,
                Err(reason) => {
                    self.session = SessionState::Unknown;
                    self.reset_eligibility(true);
                    return ActivityDecision::Suppressed(reason);
                }
            };
        let broader_time_seconds = match sample.value.broader {
            Some(value) => match parse_input_sample(sample.captured_at, value) {
                Ok((_, time_seconds)) => Some(time_seconds),
                Err(reason) => {
                    self.session = SessionState::Unknown;
                    self.reset_eligibility(true);
                    return ActivityDecision::Suppressed(reason);
                }
            },
            None => None,
        };

        if !self.gate_accessible {
            let opens_unlock_window = self.unlock_transition_pending;
            self.session = SessionState::Unlocked;
            self.gate_accessible = true;
            self.unlock_transition_pending = false;
            self.last_eligible_time_seconds = Some(eligible_time_seconds);
            self.last_broader_time_seconds = broader_time_seconds;
            self.last_eligible_age = Some(eligible_age);
            self.pending_candidate = None;
            self.continuous_use_since = None;
            self.unlock_at = opens_unlock_window.then_some(sample.captured_at);
            self.input_source_class = InputSourceClass::None;
            return ActivityDecision::Suppressed(if opens_unlock_window {
                SuppressionReason::UnlockBaselineRequired
            } else {
                SuppressionReason::InputBaselineEstablished
            });
        }

        self.session = SessionState::Unlocked;
        let previous_eligible_time = self.last_eligible_time_seconds;
        let previous_broader_time = self.last_broader_time_seconds;
        let previous_eligible_age = self.last_eligible_age;
        let tolerance = self.config.input_time_tolerance.as_secs_f64();
        let eligible_is_new = previous_eligible_time
            .is_some_and(|previous| eligible_time_seconds > previous + tolerance);
        let broader_is_new = previous_broader_time
            .zip(broader_time_seconds)
            .is_some_and(|(previous, current)| current > previous + tolerance);
        self.last_eligible_time_seconds = Some(
            previous_eligible_time.map_or(eligible_time_seconds, |previous| {
                previous.max(eligible_time_seconds)
            }),
        );
        if let Some(current) = broader_time_seconds {
            self.last_broader_time_seconds =
                Some(previous_broader_time.map_or(current, |previous| previous.max(current)));
        }
        self.last_eligible_age = Some(eligible_age);

        if broader_is_new && !eligible_is_new {
            self.input_source_class = InputSourceClass::BroaderOnly;
            self.pending_candidate = None;
            return ActivityDecision::Suppressed(SuppressionReason::BroaderOnlyInput);
        }
        if !eligible_is_new {
            self.input_source_class = InputSourceClass::None;
            if self.pending_candidate.is_some_and(|pending| {
                sample
                    .captured_at
                    .checked_duration_since(pending.armed_at)
                    .is_some_and(|elapsed| elapsed > self.config.input_confirmation_window)
            }) {
                self.pending_candidate = None;
                return ActivityDecision::Suppressed(SuppressionReason::InputConfirmationExpired);
            }
            return ActivityDecision::Suppressed(SuppressionReason::NoNewInput);
        }

        self.input_source_class = sample.value.eligible_class.source_class();
        if let Some(pending) = self.pending_candidate.take() {
            let expired = sample
                .captured_at
                .checked_duration_since(pending.armed_at)
                .is_none_or(|elapsed| elapsed > self.config.input_confirmation_window);
            if expired || eligible_time_seconds <= pending.first_eligible_time_seconds + tolerance {
                return ActivityDecision::Suppressed(SuppressionReason::InputConfirmationExpired);
            }
            if pending.reason == CandidateReason::PostUnlockInput
                && !self.inside_post_unlock_window(observed_at)
            {
                self.unlock_at = None;
                return ActivityDecision::Suppressed(SuppressionReason::PostUnlockWindowExpired);
            }
            self.unlock_at = None;
            return self.emit_candidate(observed_at, pending.reason);
        }

        let reason = if let Some(unlock_at) = self.unlock_at {
            if !self.inside_post_unlock_window(observed_at) {
                self.unlock_at = None;
                return ActivityDecision::Suppressed(SuppressionReason::PostUnlockWindowExpired);
            }
            let after_unlock = eligible_time_seconds
                > unlock_at.as_millis() as f64 / MILLIS_PER_SECOND + tolerance;
            if !after_unlock {
                return ActivityDecision::Suppressed(SuppressionReason::UnlockBaselineRequired);
            }
            CandidateReason::PostUnlockInput
        } else if previous_eligible_age
            .is_some_and(|age| age >= self.config.idle_recovery_threshold)
        {
            CandidateReason::IdleRecovery
        } else {
            let continuous_start = *self.continuous_use_since.get_or_insert(observed_at);
            if observed_at
                .checked_duration_since(continuous_start)
                .is_some_and(|elapsed| elapsed >= self.config.continuous_use_refresh)
            {
                CandidateReason::ContinuousUseRefresh
            } else if previous_eligible_age.is_some() {
                return ActivityDecision::Suppressed(SuppressionReason::IdleThresholdNotReached);
            } else {
                return ActivityDecision::Suppressed(
                    SuppressionReason::ContinuousUseRefreshPending,
                );
            }
        };

        self.pending_candidate = Some(PendingCandidate {
            armed_at: sample.captured_at,
            first_eligible_time_seconds: eligible_time_seconds,
            reason,
        });
        ActivityDecision::Suppressed(SuppressionReason::InputConfirmationPending)
    }

    fn inside_post_unlock_window(&self, observed_at: MonotonicTime) -> bool {
        self.unlock_at.is_some_and(|unlock_at| {
            observed_at
                .checked_duration_since(unlock_at)
                .is_some_and(|elapsed| elapsed <= self.config.post_unlock_window)
        })
    }

    fn emit_candidate(
        &mut self,
        observed_at: MonotonicTime,
        reason: CandidateReason,
    ) -> ActivityDecision {
        if self.last_candidate_at.is_some_and(|last_candidate| {
            observed_at
                .checked_duration_since(last_candidate)
                .is_some_and(|elapsed| elapsed < self.config.candidate_cooldown)
        }) {
            return ActivityDecision::Suppressed(SuppressionReason::CandidateCooldown);
        }

        self.last_candidate_at = Some(observed_at);
        self.continuous_use_since = Some(observed_at);
        ActivityDecision::Candidate(ActivityCandidate {
            observed_at,
            reason,
        })
    }

    fn reset_eligibility(&mut self, expect_unlock_transition: bool) {
        self.gate_accessible = false;
        self.unlock_transition_pending = expect_unlock_transition;
        self.unlock_at = None;
        self.continuous_use_since = None;
        self.pending_candidate = None;
    }
}

fn parse_input_sample(
    captured_at: MonotonicTime,
    value: InputSampleValue,
) -> Result<(Duration, f64), SuppressionReason> {
    let age_seconds = match value {
        InputSampleValue::AgeSeconds(value) if !value.is_finite() => {
            return Err(SuppressionReason::NonFiniteInputAge);
        }
        InputSampleValue::AgeSeconds(value) if value < 0.0 => {
            return Err(SuppressionReason::NegativeInputAge);
        }
        InputSampleValue::AgeSeconds(value) if value > Duration::MAX.as_secs_f64() => {
            return Err(SuppressionReason::InputAgeOutOfRange);
        }
        InputSampleValue::AgeSeconds(value) => value,
        InputSampleValue::Missing => return Err(SuppressionReason::MissingInputAge),
        InputSampleValue::Failed(_) => return Err(SuppressionReason::InputSampleFailed),
    };
    Ok((
        Duration::from_secs_f64(age_seconds),
        captured_at.as_millis() as f64 / MILLIS_PER_SECOND - age_seconds,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_millis(seconds * 1_000)
    }

    fn observation(seconds: u64, kind: ObservationKind) -> ActivityObservation {
        ActivityObservation {
            observed_at: at(seconds),
            kind,
        }
    }

    fn sample(
        captured_at: u64,
        eligible_age_seconds: f64,
        broader_age_seconds: f64,
        unlock_gate: UnlockGateState,
    ) -> ObservationKind {
        ObservationKind::ActivitySample(ActivitySample {
            captured_at: at(captured_at),
            value: ActivitySampleValue {
                eligible: InputSampleValue::AgeSeconds(eligible_age_seconds),
                broader: Some(InputSampleValue::AgeSeconds(broader_age_seconds)),
                eligible_class: EligibleInputClass::HidClass,
                unlock_gate,
            },
        })
    }

    fn started_unlocked_policy() -> ActivityPolicy {
        let mut policy = ActivityPolicy::new(ActivityPolicyConfig::default());
        assert_eq!(
            policy.observe(observation(0, ObservationKind::ProcessStarted)),
            ActivityDecision::Suppressed(SuppressionReason::ProcessStarted)
        );
        assert_eq!(
            policy.observe(observation(
                1,
                sample(1, 10.0, 10.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::InputBaselineEstablished)
        );
        policy
    }

    #[test]
    fn startup_and_existing_input_only_establish_a_baseline() {
        let policy = started_unlocked_policy();
        assert_eq!(policy.session_state(), SessionState::Unlocked);
        assert_eq!(policy.input_source_class(), InputSourceClass::None);
    }

    #[test]
    fn locked_or_unavailable_gate_clears_eligibility() {
        for gate in [
            UnlockGateState::Locked,
            UnlockGateState::Failed(UnlockGateFailure::KeychainUnavailable),
        ] {
            let mut policy = started_unlocked_policy();
            assert_eq!(
                policy.observe(observation(2, sample(2, 1_800.0, 1_800.0, gate))),
                ActivityDecision::Suppressed(if gate == UnlockGateState::Locked {
                    SuppressionReason::UnlockGateLocked
                } else {
                    SuppressionReason::UnlockGateUnavailable
                })
            );
            assert_ne!(policy.session_state(), SessionState::Unlocked);
        }
    }

    #[test]
    fn unlock_credential_input_becomes_a_baseline() {
        let mut policy = started_unlocked_policy();
        policy.observe(observation(2, sample(2, 0.0, 0.0, UnlockGateState::Locked)));
        assert_eq!(
            policy.observe(observation(
                10,
                sample(10, 0.2, 0.2, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::UnlockBaselineRequired)
        );
    }

    #[test]
    fn post_unlock_candidate_requires_two_distinct_hid_inputs() {
        let mut policy = started_unlocked_policy();
        policy.observe(observation(2, sample(2, 0.0, 0.0, UnlockGateState::Locked)));
        policy.observe(observation(
            10,
            sample(10, 1.0, 1.0, UnlockGateState::Accessible),
        ));
        assert_eq!(
            policy.observe(observation(
                11,
                sample(11, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::InputConfirmationPending)
        );
        assert_eq!(
            policy.observe(observation(
                12,
                sample(12, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Candidate(ActivityCandidate {
                observed_at: at(12),
                reason: CandidateReason::PostUnlockInput,
            })
        );
    }

    #[test]
    fn broader_only_input_is_suppressed_and_disarms_confirmation() {
        let mut policy = started_unlocked_policy();
        policy.observe(observation(
            2,
            sample(2, 1_800.0, 1_800.0, UnlockGateState::Accessible),
        ));
        policy.observe(observation(
            3,
            sample(3, 0.0, 0.0, UnlockGateState::Accessible),
        ));
        assert_eq!(
            policy.observe(observation(
                4,
                sample(4, 1.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::BroaderOnlyInput)
        );
        assert_eq!(policy.input_source_class(), InputSourceClass::BroaderOnly);
        assert_eq!(
            policy.observe(observation(
                5,
                sample(5, 0.0, 1.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::IdleThresholdNotReached)
        );
    }

    #[test]
    fn idle_recovery_requires_two_hid_class_inputs() {
        let mut policy = started_unlocked_policy();
        policy.observe(observation(
            2,
            sample(2, 1_800.0, 1_800.0, UnlockGateState::Accessible),
        ));
        assert_eq!(
            policy.observe(observation(
                3,
                sample(3, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::InputConfirmationPending)
        );
        assert_eq!(
            policy.observe(observation(
                4,
                sample(4, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Candidate(ActivityCandidate {
                observed_at: at(4),
                reason: CandidateReason::IdleRecovery,
            })
        );
    }

    #[test]
    fn current_session_input_needs_no_fabricated_broader_sample() {
        let mut policy = ActivityPolicy::new(ActivityPolicyConfig::default());
        policy.observe(observation(0, ObservationKind::ProcessStarted));
        let windows_sample = |captured_at: u64, eligible_age_seconds: f64| {
            ObservationKind::ActivitySample(ActivitySample {
                captured_at: at(captured_at),
                value: ActivitySampleValue {
                    eligible: InputSampleValue::AgeSeconds(eligible_age_seconds),
                    broader: None,
                    eligible_class: EligibleInputClass::CurrentSession,
                    unlock_gate: UnlockGateState::Accessible,
                },
            })
        };
        assert_eq!(
            policy.observe(observation(1, windows_sample(1, 1_800.0))),
            ActivityDecision::Suppressed(SuppressionReason::InputBaselineEstablished)
        );
        assert_eq!(
            policy.observe(observation(2, windows_sample(2, 0.0))),
            ActivityDecision::Suppressed(SuppressionReason::InputConfirmationPending)
        );
        assert_eq!(
            policy.input_source_class(),
            InputSourceClass::CurrentSession
        );
        assert!(matches!(
            policy.observe(observation(3, windows_sample(3, 0.0))),
            ActivityDecision::Candidate(ActivityCandidate {
                reason: CandidateReason::IdleRecovery,
                ..
            })
        ));
    }

    #[test]
    fn confirmation_expires_without_second_hid_class_input() {
        let config = ActivityPolicyConfig {
            input_confirmation_window: Duration::from_secs(5),
            ..ActivityPolicyConfig::default()
        };
        let mut policy = ActivityPolicy::new(config);
        policy.observe(observation(0, ObservationKind::ProcessStarted));
        policy.observe(observation(
            1,
            sample(1, 1_800.0, 1_800.0, UnlockGateState::Accessible),
        ));
        policy.observe(observation(
            2,
            sample(2, 0.0, 0.0, UnlockGateState::Accessible),
        ));
        assert_eq!(
            policy.observe(observation(
                8,
                sample(8, 6.0, 6.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::InputConfirmationExpired)
        );
    }

    #[test]
    fn continuous_use_refresh_also_requires_two_hid_class_inputs() {
        let config = ActivityPolicyConfig {
            continuous_use_refresh: Duration::from_secs(5),
            ..ActivityPolicyConfig::default()
        };
        let mut policy = ActivityPolicy::new(config);
        policy.observe(observation(0, ObservationKind::ProcessStarted));
        policy.observe(observation(
            1,
            sample(1, 1.0, 1.0, UnlockGateState::Accessible),
        ));
        assert_eq!(
            policy.observe(observation(
                2,
                sample(2, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::IdleThresholdNotReached)
        );
        assert_eq!(
            policy.observe(observation(
                7,
                sample(7, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::InputConfirmationPending)
        );
        assert_eq!(
            policy.observe(observation(
                8,
                sample(8, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Candidate(ActivityCandidate {
                observed_at: at(8),
                reason: CandidateReason::ContinuousUseRefresh,
            })
        );
    }

    #[test]
    fn second_qualified_sequence_inside_cooldown_is_suppressed() {
        let config = ActivityPolicyConfig {
            idle_recovery_threshold: Duration::from_secs(10),
            candidate_cooldown: Duration::from_secs(100),
            ..ActivityPolicyConfig::default()
        };
        let mut policy = ActivityPolicy::new(config);
        policy.observe(observation(0, ObservationKind::ProcessStarted));
        policy.observe(observation(
            1,
            sample(1, 10.0, 10.0, UnlockGateState::Accessible),
        ));
        policy.observe(observation(
            2,
            sample(2, 0.0, 0.0, UnlockGateState::Accessible),
        ));
        assert!(matches!(
            policy.observe(observation(
                3,
                sample(3, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Candidate(_)
        ));
        policy.observe(observation(
            14,
            sample(14, 11.0, 11.0, UnlockGateState::Accessible),
        ));
        policy.observe(observation(
            15,
            sample(15, 0.0, 0.0, UnlockGateState::Accessible),
        ));
        assert_eq!(
            policy.observe(observation(
                16,
                sample(16, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::CandidateCooldown)
        );
    }

    #[test]
    fn sleep_and_inactive_session_fail_closed() {
        let mut sleeping = started_unlocked_policy();
        sleeping.observe(observation(2, ObservationKind::WillSleep));
        assert_eq!(
            sleeping.observe(observation(
                3,
                sample(3, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::InputWhileSleeping)
        );

        let mut inactive = started_unlocked_policy();
        inactive.observe(observation(
            2,
            ObservationKind::SessionChanged(SessionState::Inactive),
        ));
        assert_eq!(
            inactive.observe(observation(
                3,
                sample(3, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::InputWhileInactive)
        );
    }

    #[test]
    fn malformed_samples_fail_closed() {
        let cases = [
            (
                InputSampleValue::AgeSeconds(f64::NAN),
                SuppressionReason::NonFiniteInputAge,
            ),
            (
                InputSampleValue::AgeSeconds(-0.1),
                SuppressionReason::NegativeInputAge,
            ),
            (
                InputSampleValue::Missing,
                SuppressionReason::MissingInputAge,
            ),
            (
                InputSampleValue::Failed(InputSampleFailure::NativeReadFailed),
                SuppressionReason::InputSampleFailed,
            ),
        ];
        for (value, expected) in cases {
            let mut policy = started_unlocked_policy();
            assert_eq!(
                policy.observe(observation(
                    2,
                    ObservationKind::ActivitySample(ActivitySample {
                        captured_at: at(2),
                        value: ActivitySampleValue {
                            eligible: value,
                            broader: Some(InputSampleValue::AgeSeconds(0.0)),
                            eligible_class: EligibleInputClass::HidClass,
                            unlock_gate: UnlockGateState::Accessible,
                        },
                    })
                )),
                ActivityDecision::Suppressed(expected)
            );
            assert_eq!(policy.session_state(), SessionState::Unknown);
        }
    }

    #[test]
    fn stale_future_and_decreasing_samples_fail_closed() {
        let mut policy = started_unlocked_policy();
        assert_eq!(
            policy.observe(ActivityObservation {
                observed_at: at(5),
                kind: sample(2, 0.0, 0.0, UnlockGateState::Accessible),
            }),
            ActivityDecision::Suppressed(SuppressionReason::StaleSample)
        );
        assert_eq!(
            policy.observe(ActivityObservation {
                observed_at: at(6),
                kind: sample(7, 0.0, 0.0, UnlockGateState::Accessible),
            }),
            ActivityDecision::Suppressed(SuppressionReason::FutureSample)
        );
        policy.observe(observation(
            8,
            sample(8, 7.0, 7.0, UnlockGateState::Accessible),
        ));
        assert_eq!(
            policy.observe(ActivityObservation {
                observed_at: at(9),
                kind: sample(7, 0.0, 0.0, UnlockGateState::Accessible),
            }),
            ActivityDecision::Suppressed(SuppressionReason::DecreasingSampleTime)
        );
    }

    #[test]
    fn wall_clock_is_not_a_policy_input() {
        let mut first = started_unlocked_policy();
        let mut second = started_unlocked_policy();
        for policy in [&mut first, &mut second] {
            policy.observe(observation(
                2,
                sample(2, 1_800.0, 1_800.0, UnlockGateState::Accessible),
            ));
            policy.observe(observation(
                3,
                sample(3, 0.0, 0.0, UnlockGateState::Accessible),
            ));
        }
        let first_decision = first.observe(observation(
            4,
            sample(4, 0.0, 0.0, UnlockGateState::Accessible),
        ));
        let second_decision = second.observe(observation(
            4,
            sample(4, 0.0, 0.0, UnlockGateState::Accessible),
        ));
        assert_eq!(first_decision, second_decision);
        assert!(matches!(first_decision, ActivityDecision::Candidate(_)));
    }

    #[test]
    fn observer_shutdown_is_terminal() {
        let mut policy = started_unlocked_policy();
        assert_eq!(
            policy.observe(observation(2, ObservationKind::ObserverStopped)),
            ActivityDecision::Suppressed(SuppressionReason::ObserverStopped)
        );
        assert_eq!(
            policy.observe(observation(
                3,
                sample(3, 0.0, 0.0, UnlockGateState::Accessible)
            )),
            ActivityDecision::Suppressed(SuppressionReason::ObserverStopped)
        );
    }
}
