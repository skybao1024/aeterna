use super::policy::{SessionState, UnlockGateFailure, UnlockGateState};

const MAX_UNAMBIGUOUS_TICK_DISTANCE: u32 = u32::MAX / 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionTransition {
    ConsoleConnect,
    ConsoleDisconnect,
    RemoteConnect,
    RemoteDisconnect,
    Logon,
    Logoff,
    Lock,
    Unlock,
    RemoteControl,
    Create,
    Terminate,
}

pub(crate) const fn transition_state(transition: SessionTransition) -> SessionState {
    match transition {
        SessionTransition::Lock => SessionState::Locked,
        SessionTransition::Unlock => SessionState::Unlocked,
        SessionTransition::ConsoleDisconnect
        | SessionTransition::RemoteDisconnect
        | SessionTransition::Logoff
        | SessionTransition::Terminate => SessionState::Inactive,
        SessionTransition::ConsoleConnect
        | SessionTransition::RemoteConnect
        | SessionTransition::Logon
        | SessionTransition::RemoteControl
        | SessionTransition::Create => SessionState::Unknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectState {
    Active,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockState {
    Locked,
    Unlocked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionProtocol {
    Console,
    RemoteDesktop,
    Unknown,
}

pub(crate) const fn unlock_gate(
    connect: ConnectState,
    lock: LockState,
    protocol: SessionProtocol,
) -> UnlockGateState {
    if matches!(lock, LockState::Locked) {
        return UnlockGateState::Locked;
    }
    if matches!(connect, ConnectState::Active)
        && matches!(lock, LockState::Unlocked)
        && matches!(
            protocol,
            SessionProtocol::Console | SessionProtocol::RemoteDesktop
        )
    {
        UnlockGateState::Accessible
    } else {
        UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TickSampleError {
    AmbiguousAge,
    Regressed,
}

#[derive(Default)]
pub(crate) struct LastInputTracker {
    previous_tick: Option<u32>,
}

impl LastInputTracker {
    pub(crate) fn sample_age_seconds(
        &mut self,
        uptime_milliseconds: u64,
        last_input_tick: u32,
    ) -> Result<f64, TickSampleError> {
        if let Some(previous) = self.previous_tick
            && previous != last_input_tick
            && last_input_tick.wrapping_sub(previous) > MAX_UNAMBIGUOUS_TICK_DISTANCE
        {
            self.previous_tick = Some(last_input_tick);
            return Err(TickSampleError::Regressed);
        }
        self.previous_tick = Some(last_input_tick);

        let age_milliseconds = (uptime_milliseconds as u32).wrapping_sub(last_input_tick);
        if age_milliseconds > MAX_UNAMBIGUOUS_TICK_DISTANCE {
            return Err(TickSampleError::AmbiguousAge);
        }
        Ok(f64::from(age_milliseconds) / 1_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_transitions_never_claim_activity() {
        assert_eq!(
            transition_state(SessionTransition::Lock),
            SessionState::Locked
        );
        assert_eq!(
            transition_state(SessionTransition::Unlock),
            SessionState::Unlocked
        );
        for transition in [
            SessionTransition::ConsoleDisconnect,
            SessionTransition::RemoteDisconnect,
            SessionTransition::Logoff,
            SessionTransition::Terminate,
        ] {
            assert_eq!(transition_state(transition), SessionState::Inactive);
        }
        for transition in [
            SessionTransition::ConsoleConnect,
            SessionTransition::RemoteConnect,
            SessionTransition::Logon,
            SessionTransition::RemoteControl,
            SessionTransition::Create,
        ] {
            assert_eq!(transition_state(transition), SessionState::Unknown);
        }
    }

    #[test]
    fn unlock_gate_requires_active_unlocked_known_protocol_state() {
        for protocol in [SessionProtocol::Console, SessionProtocol::RemoteDesktop] {
            assert_eq!(
                unlock_gate(ConnectState::Active, LockState::Unlocked, protocol),
                UnlockGateState::Accessible
            );
        }
        assert_eq!(
            unlock_gate(
                ConnectState::Active,
                LockState::Locked,
                SessionProtocol::Console
            ),
            UnlockGateState::Locked
        );
        for state in [
            unlock_gate(
                ConnectState::Other,
                LockState::Unlocked,
                SessionProtocol::Console,
            ),
            unlock_gate(
                ConnectState::Active,
                LockState::Unknown,
                SessionProtocol::Console,
            ),
            unlock_gate(
                ConnectState::Active,
                LockState::Unlocked,
                SessionProtocol::Unknown,
            ),
        ] {
            assert_eq!(
                state,
                UnlockGateState::Failed(UnlockGateFailure::NativeReadFailed)
            );
        }
    }

    #[test]
    fn tick_tracker_accepts_normal_progress_and_u32_wrap() {
        let mut tracker = LastInputTracker::default();
        assert_eq!(tracker.sample_age_seconds(10_000, 9_500), Ok(0.5));
        assert_eq!(tracker.sample_age_seconds(11_000, 10_750), Ok(0.25));

        let mut wrapped = LastInputTracker::default();
        let before_wrap = u32::MAX - 500;
        assert_eq!(
            wrapped.sample_age_seconds(u64::from(u32::MAX) + 500, before_wrap),
            Ok(1.0)
        );
        assert_eq!(
            wrapped.sample_age_seconds(u64::from(u32::MAX) + 1_500, 999),
            Ok(0.5)
        );
    }

    #[test]
    fn tick_tracker_fails_closed_on_future_or_regressed_values() {
        let mut future = LastInputTracker::default();
        assert_eq!(
            future.sample_age_seconds(1_000, 1_001),
            Err(TickSampleError::AmbiguousAge)
        );

        let mut regressed = LastInputTracker::default();
        assert_eq!(regressed.sample_age_seconds(10_000, 9_000), Ok(1.0));
        assert_eq!(
            regressed.sample_age_seconds(11_000, 8_000),
            Err(TickSampleError::Regressed)
        );
        assert_eq!(regressed.sample_age_seconds(12_000, 8_000), Ok(4.0));
    }
}
