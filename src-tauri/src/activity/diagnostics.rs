use std::io::{self, Write};

use super::policy::{
    ActivityDecision, ActivityObservation, ActivityPolicy, ActivityPolicyConfig, InputSampleValue,
    InputSourceClass, ObservationKind, SessionState,
};

const MAX_RECORDED_INPUT_AGE_SECONDS: u64 = 30 * 60;
const INPUT_AGE_BUCKET_SECONDS: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticConfig {
    version: &'static str,
}

impl DiagnosticConfig {
    pub const DEFAULT: Self = Self {
        version: "i04-platform-activity-v1",
    };

    pub const TEST_ONLY_COMPRESSED: Self = Self {
        version: "i04-platform-activity-test-only-compressed-v1",
    };

    pub const fn version(self) -> &'static str {
        self.version
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticRecord {
    elapsed_milliseconds: u64,
    event_type: &'static str,
    session_state: SessionState,
    unlock_gate_state: &'static str,
    eligible_input_age_bucket_seconds: Option<u64>,
    broader_input_age_bucket_seconds: Option<u64>,
    input_source: InputSourceClass,
    decision_type: &'static str,
    reason_code: &'static str,
    config_version: &'static str,
}

impl DiagnosticRecord {
    pub fn from_observation(
        observation: ActivityObservation,
        session_state: SessionState,
        input_source: InputSourceClass,
        decision: ActivityDecision,
        config: DiagnosticConfig,
    ) -> Self {
        let decision_type = match decision {
            ActivityDecision::Candidate(_) => "candidate",
            ActivityDecision::Suppressed(_) => "suppressed",
        };
        let (unlock_gate_state, eligible_age, broader_age) = sample_diagnostics(observation.kind);
        Self {
            elapsed_milliseconds: observation.observed_at.as_millis(),
            event_type: event_code(observation.kind),
            session_state,
            unlock_gate_state,
            eligible_input_age_bucket_seconds: age_bucket(eligible_age),
            broader_input_age_bucket_seconds: age_bucket(broader_age),
            input_source,
            decision_type,
            reason_code: decision.reason_code(),
            config_version: config.version(),
        }
    }

    pub fn to_json_line(self) -> String {
        let eligible_age = optional_number(self.eligible_input_age_bucket_seconds);
        let broader_age = optional_number(self.broader_input_age_bucket_seconds);
        format!(
            concat!(
                r#"{{"elapsedMilliseconds":{},"#,
                r#""eventType":"{}","#,
                r#""sessionState":"{}","#,
                r#""unlockGateState":"{}","#,
                r#""eligibleInputAgeBucketSeconds":{},"#,
                r#""broaderInputAgeBucketSeconds":{},"#,
                r#""inputSource":"{}","#,
                r#""decision":"{}","#,
                r#""reasonCode":"{}","#,
                r#""configVersion":"{}"}}"#
            ),
            self.elapsed_milliseconds,
            self.event_type,
            self.session_state.as_code(),
            self.unlock_gate_state,
            eligible_age,
            broader_age,
            self.input_source.as_code(),
            self.decision_type,
            self.reason_code,
            self.config_version,
        )
    }
}

pub struct DiagnosticHarness<W: Write> {
    policy: ActivityPolicy,
    output: W,
    config: DiagnosticConfig,
}

impl<W: Write> DiagnosticHarness<W> {
    pub fn new(output: W, policy_config: ActivityPolicyConfig, config: DiagnosticConfig) -> Self {
        Self {
            policy: ActivityPolicy::new(policy_config),
            output,
            config,
        }
    }

    pub fn record(&mut self, observation: ActivityObservation) -> io::Result<ActivityDecision> {
        let decision = self.policy.observe(observation);
        let record = DiagnosticRecord::from_observation(
            observation,
            self.policy.session_state(),
            self.policy.input_source_class(),
            decision,
            self.config,
        );
        self.output.write_all(record.to_json_line().as_bytes())?;
        self.output.write_all(b"\n")?;
        self.output.flush()?;
        Ok(decision)
    }

    pub fn into_inner(self) -> W {
        self.output
    }
}

fn event_code(kind: ObservationKind) -> &'static str {
    match kind {
        ObservationKind::ProcessStarted => "process_started",
        ObservationKind::SessionChanged(_) => "session_changed",
        ObservationKind::WillSleep => "will_sleep",
        ObservationKind::DidWake => "did_wake",
        ObservationKind::ActivitySample(_) => "activity_sample",
        ObservationKind::ObserverInitializationFailed => "observer_initialization_failed",
        ObservationKind::ObserverStopped => "observer_stopped",
    }
}

fn sample_diagnostics(
    kind: ObservationKind,
) -> (
    &'static str,
    Option<InputSampleValue>,
    Option<InputSampleValue>,
) {
    let ObservationKind::ActivitySample(sample) = kind else {
        return ("not_sampled", None, None);
    };
    (
        sample.value.unlock_gate.as_code(),
        Some(sample.value.eligible),
        sample.value.broader,
    )
}

fn age_bucket(value: Option<InputSampleValue>) -> Option<u64> {
    let Some(InputSampleValue::AgeSeconds(age)) = value else {
        return None;
    };
    if !age.is_finite() || age < 0.0 {
        return None;
    }
    let bounded = age.min(MAX_RECORDED_INPUT_AGE_SECONDS as f64) as u64;
    Some((bounded / INPUT_AGE_BUCKET_SECONDS) * INPUT_AGE_BUCKET_SECONDS)
}

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |number| number.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::policy::{
        ActivityCandidate, ActivitySample, ActivitySampleValue, CandidateReason, MonotonicTime,
        SuppressionReason, UnlockGateState,
    };

    #[test]
    fn diagnostic_json_is_fixed_redacted_and_bounded() {
        let observation = ActivityObservation {
            observed_at: MonotonicTime::from_millis(12_345),
            kind: ObservationKind::ActivitySample(ActivitySample {
                captured_at: MonotonicTime::from_millis(12_345),
                value: ActivitySampleValue {
                    eligible: InputSampleValue::AgeSeconds(9_999.8),
                    broader: Some(InputSampleValue::AgeSeconds(8.2)),
                    eligible_class: crate::activity::policy::EligibleInputClass::HidClass,
                    unlock_gate: UnlockGateState::Accessible,
                },
            }),
        };
        let decision = ActivityDecision::Candidate(ActivityCandidate {
            observed_at: MonotonicTime::from_millis(12_345),
            reason: CandidateReason::IdleRecovery,
        });

        let line = DiagnosticRecord::from_observation(
            observation,
            SessionState::Unlocked,
            InputSourceClass::HidClass,
            decision,
            DiagnosticConfig::DEFAULT,
        )
        .to_json_line();

        assert_eq!(
            line,
            concat!(
                r#"{"elapsedMilliseconds":12345,"#,
                r#""eventType":"activity_sample","#,
                r#""sessionState":"unlocked","#,
                r#""unlockGateState":"accessible","#,
                r#""eligibleInputAgeBucketSeconds":1800,"#,
                r#""broaderInputAgeBucketSeconds":5,"#,
                r#""inputSource":"hid_class","#,
                r#""decision":"candidate","#,
                r#""reasonCode":"idle_recovery","#,
                r#""configVersion":"i04-platform-activity-v1"}"#
            )
        );

        for prohibited in [
            "username",
            "deviceIdentifier",
            "applicationName",
            "windowTitle",
            "url",
            "inputValue",
            "keyCode",
            "pointerPosition",
            "eventObject",
        ] {
            assert!(!line.contains(prohibited));
        }
    }

    #[test]
    fn invalid_or_failed_ages_are_never_serialized() {
        for value in [
            InputSampleValue::AgeSeconds(f64::NAN),
            InputSampleValue::AgeSeconds(-1.0),
            InputSampleValue::Missing,
        ] {
            let observation = ActivityObservation {
                observed_at: MonotonicTime::ZERO,
                kind: ObservationKind::ActivitySample(ActivitySample {
                    captured_at: MonotonicTime::ZERO,
                    value: ActivitySampleValue {
                        eligible: value,
                        broader: Some(value),
                        eligible_class: crate::activity::policy::EligibleInputClass::HidClass,
                        unlock_gate: UnlockGateState::Accessible,
                    },
                }),
            };
            let line = DiagnosticRecord::from_observation(
                observation,
                SessionState::Unknown,
                InputSourceClass::Invalid,
                ActivityDecision::Suppressed(SuppressionReason::MissingInputAge),
                DiagnosticConfig::DEFAULT,
            )
            .to_json_line();

            assert!(line.contains(r#""eligibleInputAgeBucketSeconds":null"#));
            assert!(line.contains(r#""broaderInputAgeBucketSeconds":null"#));
        }
    }

    #[test]
    fn current_session_schema_does_not_fabricate_a_broader_input_age() {
        let observation = ActivityObservation {
            observed_at: MonotonicTime::from_millis(5_000),
            kind: ObservationKind::ActivitySample(ActivitySample {
                captured_at: MonotonicTime::from_millis(5_000),
                value: ActivitySampleValue {
                    eligible: InputSampleValue::AgeSeconds(0.5),
                    broader: None,
                    eligible_class: crate::activity::policy::EligibleInputClass::CurrentSession,
                    unlock_gate: UnlockGateState::Accessible,
                },
            }),
        };
        let line = DiagnosticRecord::from_observation(
            observation,
            SessionState::Unlocked,
            InputSourceClass::CurrentSession,
            ActivityDecision::Suppressed(SuppressionReason::InputConfirmationPending),
            DiagnosticConfig::DEFAULT,
        )
        .to_json_line();

        assert!(line.contains(r#""eligibleInputAgeBucketSeconds":0"#));
        assert!(line.contains(r#""broaderInputAgeBucketSeconds":null"#));
        assert!(line.contains(r#""inputSource":"current_session""#));
    }

    #[test]
    fn harness_records_only_policy_decisions_without_a_webview_bridge() {
        let mut harness = DiagnosticHarness::new(
            Vec::new(),
            ActivityPolicyConfig::default(),
            DiagnosticConfig::DEFAULT,
        );
        let decision = harness
            .record(ActivityObservation {
                observed_at: MonotonicTime::ZERO,
                kind: ObservationKind::ProcessStarted,
            })
            .unwrap_or_else(|error| panic!("diagnostic write should succeed: {error}"));
        assert_eq!(
            decision,
            ActivityDecision::Suppressed(SuppressionReason::ProcessStarted)
        );

        let output = String::from_utf8(harness.into_inner())
            .unwrap_or_else(|error| panic!("diagnostic output should be UTF-8: {error}"));
        assert_eq!(
            output,
            concat!(
                r#"{"elapsedMilliseconds":0,"#,
                r#""eventType":"process_started","#,
                r#""sessionState":"unknown","#,
                r#""unlockGateState":"not_sampled","#,
                r#""eligibleInputAgeBucketSeconds":null,"#,
                r#""broaderInputAgeBucketSeconds":null,"#,
                r#""inputSource":"not_applicable","#,
                r#""decision":"suppressed","#,
                r#""reasonCode":"process_started","#,
                r#""configVersion":"i04-platform-activity-v1"}"#,
                "\n"
            )
        );
    }
}
