//! Deterministic I10 heartbeat preparation and retry boundary.
//!
//! Platform activity code must provide an explicit confirmed candidate. This
//! module does not observe process lifetime, online state, input, or wall time.

use core::fmt;
use std::time::Duration;

use crate::{
    crypto::SigningSecret,
    protocol::{
        CANONICALIZATION, HEARTBEAT_SUBMIT_DOMAIN, HeartbeatData, HeartbeatRequestDocument,
        MAX_HEARTBEAT_SEQUENCE, PROTOCOL_VERSION, ProtocolError, SIGNATURE_VERSION, SignedEnvelope,
        SuccessResponse, sign_document, validate_heartbeat,
    },
};

pub const HEARTBEAT_RETRY_FRESHNESS: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedActivityCandidate {
    confirmed_at: Duration,
}

impl ConfirmedActivityCandidate {
    pub const fn new(confirmed_at: Duration) -> Self {
        Self { confirmed_at }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingHeartbeat {
    pub request_id: String,
    pub account_id: String,
    pub device_id: String,
    pub sequence: u64,
    pub expires_at: Duration,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeartbeatTransportResult {
    Accepted(SuccessResponse<HeartbeatData>),
    Rejected { code: String },
    TimedOut,
}

pub trait MonotonicClock {
    fn now(&self) -> Duration;
}

pub trait RequestIdSource {
    fn next_request_id(&mut self) -> Result<String, HeartbeatClientError>;
}

pub trait HeartbeatSigner {
    fn sign(&self, document: &HeartbeatRequestDocument) -> Result<String, ProtocolError>;
}

impl HeartbeatSigner for SigningSecret {
    fn sign(&self, document: &HeartbeatRequestDocument) -> Result<String, ProtocolError> {
        sign_document(self, document)
    }
}

pub trait HeartbeatStateStore {
    /// Atomically persist and return the next never-before-allocated sequence.
    fn reserve_sequence(&mut self) -> Result<u64, HeartbeatClientError>;
    fn pending(&self) -> Result<Option<PendingHeartbeat>, HeartbeatClientError>;
    fn save_pending(&mut self, pending: PendingHeartbeat) -> Result<(), HeartbeatClientError>;
    fn clear_pending(&mut self) -> Result<(), HeartbeatClientError>;
    /// Atomically records success and clears the matching pending request.
    fn complete_success(
        &mut self,
        request_id: &str,
        accepted_at: &str,
    ) -> Result<(), HeartbeatClientError>;
}

pub trait HeartbeatTransport {
    fn send(&mut self, body: &[u8]) -> HeartbeatTransportResult;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeartbeatClientError {
    AlreadyPending,
    CandidateFromFuture,
    CandidateStale,
    InvalidResponse,
    NoPending,
    Protocol(ProtocolError),
    SequenceExhausted,
    SerializationFailed,
    StateUnavailable,
}

impl fmt::Display for HeartbeatClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::AlreadyPending => "heartbeat_already_pending",
            Self::CandidateFromFuture => "heartbeat_candidate_from_future",
            Self::CandidateStale => "heartbeat_candidate_stale",
            Self::InvalidResponse => "heartbeat_invalid_response",
            Self::NoPending => "heartbeat_no_pending_request",
            Self::Protocol(error) => return error.fmt(formatter),
            Self::SequenceExhausted => "heartbeat_sequence_exhausted",
            Self::SerializationFailed => "heartbeat_serialization_failed",
            Self::StateUnavailable => "heartbeat_state_unavailable",
        };
        formatter.write_str(code)
    }
}

impl std::error::Error for HeartbeatClientError {}

impl From<ProtocolError> for HeartbeatClientError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeartbeatSendOutcome {
    Accepted(HeartbeatData),
    Rejected { code: String },
    TimedOut,
}

pub struct HeartbeatCoordinator<S, C, R, K> {
    account_id: String,
    device_id: String,
    store: S,
    clock: C,
    request_ids: R,
    signer: K,
}

impl<S, C, R, K> HeartbeatCoordinator<S, C, R, K>
where
    S: HeartbeatStateStore,
    C: MonotonicClock,
    R: RequestIdSource,
    K: HeartbeatSigner,
{
    pub fn new(
        account_id: String,
        device_id: String,
        store: S,
        clock: C,
        request_ids: R,
        signer: K,
    ) -> Self {
        Self {
            account_id,
            device_id,
            store,
            clock,
            request_ids,
            signer,
        }
    }

    pub fn prepare(
        &mut self,
        candidate: ConfirmedActivityCandidate,
    ) -> Result<PendingHeartbeat, HeartbeatClientError> {
        let now = self.clock.now();
        if candidate.confirmed_at > now {
            return Err(HeartbeatClientError::CandidateFromFuture);
        }
        let expires_at = candidate
            .confirmed_at
            .checked_add(HEARTBEAT_RETRY_FRESHNESS)
            .ok_or(HeartbeatClientError::CandidateStale)?;
        if now >= expires_at {
            return Err(HeartbeatClientError::CandidateStale);
        }
        if let Some(pending) = self.store.pending()? {
            if now < pending.expires_at {
                return Err(HeartbeatClientError::AlreadyPending);
            }
            self.store.clear_pending()?;
        }

        let sequence = self.store.reserve_sequence()?;
        if sequence == 0 || sequence > MAX_HEARTBEAT_SEQUENCE {
            return Err(HeartbeatClientError::SequenceExhausted);
        }
        let request_id = self.request_ids.next_request_id()?;
        let document = HeartbeatRequestDocument {
            account_id: self.account_id.clone(),
            canonicalization: CANONICALIZATION.to_owned(),
            device_id: self.device_id.clone(),
            domain: HEARTBEAT_SUBMIT_DOMAIN.to_owned(),
            operation: "heartbeat.submit".to_owned(),
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.clone(),
            sequence,
            signature_version: SIGNATURE_VERSION,
        };
        validate_heartbeat(&document)?;
        let signature = self.signer.sign(&document)?;
        let envelope = SignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            signed: document,
            signature,
        };
        let body =
            serde_json::to_vec(&envelope).map_err(|_| HeartbeatClientError::SerializationFailed)?;
        let pending = PendingHeartbeat {
            request_id,
            account_id: self.account_id.clone(),
            device_id: self.device_id.clone(),
            sequence,
            expires_at,
            body,
        };
        self.store.save_pending(pending.clone())?;
        Ok(pending)
    }

    pub fn send_pending<T: HeartbeatTransport>(
        &mut self,
        transport: &mut T,
    ) -> Result<HeartbeatSendOutcome, HeartbeatClientError> {
        let pending = self
            .store
            .pending()?
            .ok_or(HeartbeatClientError::NoPending)?;
        if self.clock.now() >= pending.expires_at {
            self.store.clear_pending()?;
            return Err(HeartbeatClientError::CandidateStale);
        }
        match transport.send(&pending.body) {
            HeartbeatTransportResult::TimedOut => Ok(HeartbeatSendOutcome::TimedOut),
            HeartbeatTransportResult::Rejected { code } => {
                self.store.clear_pending()?;
                Ok(HeartbeatSendOutcome::Rejected { code })
            }
            HeartbeatTransportResult::Accepted(response) => {
                if !response_matches(&response, &pending) {
                    return Err(HeartbeatClientError::InvalidResponse);
                }
                self.store
                    .complete_success(&pending.request_id, &response.data.accepted_at)?;
                Ok(HeartbeatSendOutcome::Accepted(response.data))
            }
        }
    }

    pub fn discard_pending(&mut self) -> Result<(), HeartbeatClientError> {
        self.store.clear_pending()
    }

    pub fn into_store(self) -> S {
        self.store
    }
}

fn response_matches(response: &SuccessResponse<HeartbeatData>, pending: &PendingHeartbeat) -> bool {
    response.protocol_version == PROTOCOL_VERSION
        && response.request_id == pending.request_id
        && response.data.account_id == pending.account_id
        && response.data.device_id == pending.device_id
        && response.data.accepted_sequence == pending.sequence
        && response.data.accepted_at.ends_with('Z')
        && response.data.next_heartbeat_not_before.ends_with('Z')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        last_allocated: u64,
        pending: Option<PendingHeartbeat>,
        last_successful_at: Option<String>,
    }

    impl HeartbeatStateStore for MemoryStore {
        fn reserve_sequence(&mut self) -> Result<u64, HeartbeatClientError> {
            self.last_allocated = self
                .last_allocated
                .checked_add(1)
                .ok_or(HeartbeatClientError::SequenceExhausted)?;
            Ok(self.last_allocated)
        }

        fn pending(&self) -> Result<Option<PendingHeartbeat>, HeartbeatClientError> {
            Ok(self.pending.clone())
        }

        fn save_pending(&mut self, pending: PendingHeartbeat) -> Result<(), HeartbeatClientError> {
            self.pending = Some(pending);
            Ok(())
        }

        fn clear_pending(&mut self) -> Result<(), HeartbeatClientError> {
            self.pending = None;
            Ok(())
        }

        fn complete_success(
            &mut self,
            request_id: &str,
            accepted_at: &str,
        ) -> Result<(), HeartbeatClientError> {
            if self
                .pending
                .as_ref()
                .map(|pending| pending.request_id.as_str())
                != Some(request_id)
            {
                return Err(HeartbeatClientError::StateUnavailable);
            }
            self.last_successful_at = Some(accepted_at.to_owned());
            self.pending = None;
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock(Duration);

    impl MonotonicClock for FixedClock {
        fn now(&self) -> Duration {
            self.0
        }
    }

    struct FixedRequestIds(u64);

    impl RequestIdSource for FixedRequestIds {
        fn next_request_id(&mut self) -> Result<String, HeartbeatClientError> {
            self.0 += 1;
            Ok(format!("00000000-0000-4000-8000-{:012x}", self.0))
        }
    }

    struct SyntheticSigner(SigningSecret);

    impl HeartbeatSigner for SyntheticSigner {
        fn sign(&self, document: &HeartbeatRequestDocument) -> Result<String, ProtocolError> {
            sign_document(&self.0, document)
        }
    }

    #[derive(Default)]
    struct RecordingTransport {
        bodies: Vec<Vec<u8>>,
        results: Vec<HeartbeatTransportResult>,
    }

    impl HeartbeatTransport for RecordingTransport {
        fn send(&mut self, body: &[u8]) -> HeartbeatTransportResult {
            self.bodies.push(body.to_vec());
            if self.results.is_empty() {
                HeartbeatTransportResult::TimedOut
            } else {
                self.results.remove(0)
            }
        }
    }

    fn coordinator(
        clock: FixedClock,
    ) -> HeartbeatCoordinator<MemoryStore, FixedClock, FixedRequestIds, SyntheticSigner> {
        HeartbeatCoordinator::new(
            "00000000-0000-4000-8000-000000000020".to_owned(),
            "00000000-0000-4000-8000-000000000003".to_owned(),
            MemoryStore::default(),
            clock,
            FixedRequestIds(40),
            SyntheticSigner(SigningSecret::from_storage_bytes([0x11; 32])),
        )
    }

    #[test]
    fn timeout_retry_reuses_exact_bytes_and_one_sequence() {
        let now = Duration::from_secs(1_000);
        let mut coordinator = coordinator(FixedClock(now));
        let pending = coordinator
            .prepare(ConfirmedActivityCandidate::new(now))
            .expect("candidate should prepare");
        assert_eq!(pending.sequence, 1);
        assert_eq!(
            coordinator.prepare(ConfirmedActivityCandidate::new(now)),
            Err(HeartbeatClientError::AlreadyPending)
        );

        let mut transport = RecordingTransport::default();
        assert_eq!(
            coordinator.send_pending(&mut transport),
            Ok(HeartbeatSendOutcome::TimedOut)
        );
        assert_eq!(
            coordinator.send_pending(&mut transport),
            Ok(HeartbeatSendOutcome::TimedOut)
        );
        assert_eq!(transport.bodies.len(), 2);
        assert_eq!(transport.bodies[0], transport.bodies[1]);
        let store = coordinator.into_store();
        assert_eq!(store.last_allocated, 1);
        assert_eq!(store.pending.map(|value| value.body), Some(pending.body));
    }

    #[test]
    fn accepted_response_is_validated_and_completes_pending_state() {
        let now = Duration::from_secs(2_000);
        let mut coordinator = coordinator(FixedClock(now));
        let pending = coordinator
            .prepare(ConfirmedActivityCandidate::new(now))
            .expect("candidate should prepare");
        let response = SuccessResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id: pending.request_id.clone(),
            data: HeartbeatData {
                accepted_at: "2030-01-02T03:04:05Z".to_owned(),
                accepted_sequence: pending.sequence,
                account_id: pending.account_id.clone(),
                device_id: pending.device_id.clone(),
                next_heartbeat_not_before: "2030-01-02T03:34:05Z".to_owned(),
            },
        };
        let mut transport = RecordingTransport {
            bodies: Vec::new(),
            results: vec![HeartbeatTransportResult::Accepted(response)],
        };
        assert!(matches!(
            coordinator.send_pending(&mut transport),
            Ok(HeartbeatSendOutcome::Accepted(data)) if data.accepted_sequence == 1
        ));
        let store = coordinator.into_store();
        assert!(store.pending.is_none());
        assert_eq!(
            store.last_successful_at.as_deref(),
            Some("2030-01-02T03:04:05Z")
        );
    }

    #[test]
    fn stale_future_gate_loss_and_rejection_never_create_fresh_activity() {
        let now = Duration::from_secs(5_000);
        let stale = now - HEARTBEAT_RETRY_FRESHNESS;
        let mut coordinator = coordinator(FixedClock(now));
        assert_eq!(
            coordinator.prepare(ConfirmedActivityCandidate::new(stale)),
            Err(HeartbeatClientError::CandidateStale)
        );
        assert_eq!(
            coordinator.prepare(ConfirmedActivityCandidate::new(
                now + Duration::from_secs(1)
            )),
            Err(HeartbeatClientError::CandidateFromFuture)
        );
        assert_eq!(
            coordinator.send_pending(&mut RecordingTransport::default()),
            Err(HeartbeatClientError::NoPending)
        );

        coordinator
            .prepare(ConfirmedActivityCandidate::new(now))
            .expect("fresh candidate should prepare");
        coordinator
            .discard_pending()
            .expect("gate loss should discard pending request");
        assert_eq!(
            coordinator.send_pending(&mut RecordingTransport::default()),
            Err(HeartbeatClientError::NoPending)
        );

        coordinator
            .prepare(ConfirmedActivityCandidate::new(now))
            .expect("new candidate should use the next sequence");
        let mut transport = RecordingTransport {
            bodies: Vec::new(),
            results: vec![HeartbeatTransportResult::Rejected {
                code: "heartbeat.cooldown".to_owned(),
            }],
        };
        assert_eq!(
            coordinator.send_pending(&mut transport),
            Ok(HeartbeatSendOutcome::Rejected {
                code: "heartbeat.cooldown".to_owned()
            })
        );
        let store = coordinator.into_store();
        assert_eq!(store.last_allocated, 2);
        assert!(store.pending.is_none());
    }
}
