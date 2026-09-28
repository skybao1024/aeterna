//! Public Aeterna protocol v1 types and signature canonicalization.
//!
//! The machine-readable source of truth lives in `protocol/v1`. These Rust
//! types cover I09 account/device binding, the I10 signed heartbeat/device
//! status boundary, and I13 delayed-recovery record and claim operations.

use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    DevicePublicKey, DeviceSignature, SigningSecret, sign_message, verify_message,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const SIGNATURE_VERSION: u16 = 1;
pub const CANONICALIZATION: &str = "jcs-rfc8785";
pub const DEVICE_BINDING_REQUEST_DOMAIN: &str = "aeterna.device-binding.request.v1";
pub const DEVICE_BINDING_APPROVAL_DOMAIN: &str = "aeterna.device-binding.approval.v1";
pub const HEARTBEAT_SUBMIT_DOMAIN: &str = "aeterna.heartbeat.submit.v1";
pub const DEVICE_STATUS_CHANGE_DOMAIN: &str = "aeterna.device-status.change.v1";
pub const RECOVERY_PROVISION_DOMAIN: &str = "aeterna.recovery-record.provision.v1";
pub const RECOVERY_CONFIRM_DOMAIN: &str = "aeterna.recovery-record.confirm.v1";
pub const RECOVERY_ABANDON_DOMAIN: &str = "aeterna.recovery-record.abandon.v1";
pub const OWNER_RECOVERY_START_DOMAIN: &str = "aeterna.owner-recovery.start.v1";
pub const OWNER_RECOVERY_ACTION_DOMAIN: &str = "aeterna.owner-recovery.action.v1";
pub const RECOVERY_ROTATION_PROVISION_DOMAIN: &str = "aeterna.recovery-rotation.provision.v1";
pub const RECOVERY_ROTATION_CONFIRM_DOMAIN: &str = "aeterna.recovery-rotation.confirm.v1";
pub const MAX_PROTOCOL_BODY_BYTES: usize = 16_384;
pub const MAX_EMAIL_BYTES: usize = 254;
pub const MAX_DEVICE_LABEL_BYTES: usize = 64;
pub const MAX_HEARTBEAT_SEQUENCE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountChallengePurpose {
    AccountOnboarding,
    DeviceBinding,
    DeviceBindingCancellation,
    DeviceBindingDelayedConfirmation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountChallengeRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub email: String,
    pub purpose: AccountChallengePurpose,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountChallengeData {
    pub challenge_id: String,
    pub expires_in_seconds: u16,
    pub resend_after_seconds: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountChallengeVerificationRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub challenge_id: String,
    pub code: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingGrantData {
    pub account_id: String,
    pub binding_grant_id: String,
    pub binding_grant_token: String,
    pub expires_at: String,
    pub purpose: AccountChallengePurpose,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBindingRequestDocument {
    pub canonicalization: String,
    pub domain: String,
    pub operation: String,
    pub protocol_version: u16,
    pub signature_version: u16,
    pub request_id: String,
    pub binding_grant_id: String,
    pub device_id: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBindingApprovalDocument {
    pub canonicalization: String,
    pub domain: String,
    pub operation: String,
    pub protocol_version: u16,
    pub signature_version: u16,
    pub request_id: String,
    pub account_id: String,
    pub binding_id: String,
    pub approving_device_id: String,
    pub device_id: String,
    pub public_key: String,
    pub challenge: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBindingConfirmationDocument {
    pub canonicalization: String,
    pub domain: String,
    pub operation: String,
    pub protocol_version: u16,
    pub signature_version: u16,
    pub request_id: String,
    pub account_id: String,
    pub binding_grant_id: String,
    pub binding_id: String,
    pub device_id: String,
    pub public_key: String,
    pub challenge: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequestDocument {
    pub account_id: String,
    pub canonicalization: String,
    pub device_id: String,
    pub domain: String,
    pub operation: String,
    pub protocol_version: u16,
    pub request_id: String,
    pub sequence: u64,
    pub signature_version: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatusAction {
    MarkLost,
    Revoke,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStatusChangeDocument {
    pub account_id: String,
    pub action: DeviceStatusAction,
    pub authorizing_device_id: String,
    pub canonicalization: String,
    pub domain: String,
    pub operation: String,
    pub protocol_version: u16,
    pub request_id: String,
    pub signature_version: u16,
    pub target_device_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecordProvisionDocument {
    pub account_id: String,
    pub canonicalization: String,
    pub crypto_format_version: u16,
    pub device_id: String,
    pub domain: String,
    pub operation: String,
    pub protocol_version: u16,
    pub recovery_context_version: u16,
    pub recovery_id: String,
    pub request_id: String,
    pub signature_version: u16,
    pub vault_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecordActionDocument {
    pub account_id: String,
    pub canonicalization: String,
    pub device_id: String,
    pub domain: String,
    pub operation: String,
    pub protocol_version: u16,
    pub recovery_id: String,
    pub request_id: String,
    pub signature_version: u16,
    pub vault_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapper_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryClaimStartRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub claim_link_token: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryClaimStartData {
    pub challenge_id: String,
    pub expires_in_seconds: u16,
    pub resend_after_seconds: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryClaimVerifyRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub challenge_id: String,
    pub claim_link_token: String,
    pub code: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryClaimData {
    pub account_id: String,
    pub claim_token: String,
    pub device_id: String,
    pub expires_at: String,
    pub recovery_id: String,
    pub scope: String,
    pub vault_id: String,
    pub wrapper_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySecretRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub claim_token: String,
    pub device_id: String,
    pub recovery_id: String,
    pub vault_id: String,
    pub wrapper_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySecretData {
    pub account_id: String,
    pub device_id: String,
    pub policy_epoch: u64,
    pub recovery_generation: u64,
    pub recovery_id: String,
    pub rekey_required: bool,
    pub srs: String,
    pub vault_id: String,
    pub wrapper_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecoveryStartDocument {
    pub account_id: String,
    pub canonicalization: String,
    pub device_id: String,
    pub domain: String,
    pub operation: String,
    pub policy_epoch: u64,
    pub protocol_version: u16,
    pub recovery_generation: u64,
    pub recovery_id: String,
    pub request_id: String,
    pub signature_version: u16,
    pub vault_id: String,
    pub wrapper_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecoveryVerifyRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub owner_recovery_id: String,
    pub challenge_id: String,
    pub code: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRecoveryAction {
    Cancel,
    Release,
    Complete,
    Status,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecoveryActionDocument {
    pub account_id: String,
    pub action: OwnerRecoveryAction,
    pub canonicalization: String,
    pub device_id: String,
    pub domain: String,
    pub operation: String,
    pub owner_recovery_id: String,
    pub protocol_version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<String>,
    pub request_id: String,
    pub signature_version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapper_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRecoveryState {
    PendingEmail,
    CoolingDown,
    Ready,
    MaterialReleased,
    Completed,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecoveryData {
    pub account_id: String,
    pub challenge_id: String,
    pub cooldown_seconds: u32,
    pub device_id: String,
    pub expires_at: String,
    pub owner_recovery_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_at: Option<String>,
    pub rekey_required: bool,
    pub state: OwnerRecoveryState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecoverySecretData {
    pub account_id: String,
    pub device_id: String,
    pub owner_recovery_id: String,
    pub policy_epoch: u64,
    pub recovery_generation: u64,
    pub recovery_id: String,
    pub rekey_required: bool,
    pub srs: String,
    pub vault_id: String,
    pub wrapper_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRotationKind {
    ErcRotation,
    PostCompromise,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRotationProvisionDocument {
    pub account_id: String,
    pub canonicalization: String,
    pub device_id: String,
    pub domain: String,
    pub kind: RecoveryRotationKind,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_recovery_id: Option<String>,
    pub protocol_version: u16,
    pub recovery_id: String,
    pub request_id: String,
    pub rotation_id: String,
    pub signature_version: u16,
    pub source_generation: u64,
    pub source_policy_epoch: u64,
    pub target_generation: u64,
    pub target_policy_epoch: u64,
    pub vault_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRotationConfirmDocument {
    pub account_id: String,
    pub canonicalization: String,
    pub device_id: String,
    pub domain: String,
    pub operation: String,
    pub protocol_version: u16,
    pub recovery_id: String,
    pub request_id: String,
    pub rotation_id: String,
    pub signature_version: u16,
    pub target_generation: u64,
    pub target_policy_epoch: u64,
    pub vault_id: String,
    pub wrapper_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRotationProvisionData {
    pub account_id: String,
    pub device_id: String,
    pub expires_at: String,
    pub recovery_id: String,
    pub rotation_id: String,
    pub srs: String,
    pub target_generation: u64,
    pub target_policy_epoch: u64,
    pub vault_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationDeviceState {
    Pending,
    NotEnrolled,
    Complete,
    Excluded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotationDeviceData {
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    pub state: RotationDeviceState,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRotationState {
    Preparing,
    Active,
    Complete,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRotationData {
    pub account_id: String,
    pub complete: bool,
    pub devices: Vec<RotationDeviceData>,
    pub kind: RecoveryRotationKind,
    pub rotation_id: String,
    pub state: RecoveryRotationState,
    pub target_generation: u64,
    pub target_policy_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope<T> {
    pub protocol_version: u16,
    pub signed: T,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceBindingState {
    Active,
    Pending,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBindingData {
    pub account_id: String,
    pub binding_id: String,
    pub device_id: String,
    pub state: DeviceBindingState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatData {
    pub accepted_at: String,
    pub accepted_sequence: u64,
    pub account_id: String,
    pub device_id: String,
    pub next_heartbeat_not_before: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatusChangeStatus {
    Lost,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStatusChangeData {
    pub account_id: String,
    pub changed_at: String,
    pub device_id: String,
    pub status: DeviceStatusChangeStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessResponse<T> {
    pub protocol_version: u16,
    pub request_id: String,
    pub data: T,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_protocol_versions: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub protocol_version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub error: ErrorBody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    CanonicalizationFailed,
    InvalidBase64Url,
    InvalidChallenge,
    InvalidDeviceLabel,
    InvalidEmail,
    InvalidPublicKey,
    InvalidRequestId,
    InvalidSequence,
    InvalidSignature,
    InvalidUuid,
    UnsupportedCanonicalization,
    UnsupportedDomain,
    UnsupportedOperation,
    UnsupportedProtocolVersion,
    UnsupportedSignatureVersion,
}

impl ProtocolError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::CanonicalizationFailed => "protocol.canonicalization_failed",
            Self::InvalidBase64Url => "protocol.invalid_base64url",
            Self::InvalidChallenge => "protocol.invalid_challenge",
            Self::InvalidDeviceLabel => "protocol.invalid_device_label",
            Self::InvalidEmail => "protocol.invalid_email",
            Self::InvalidPublicKey => "protocol.invalid_public_key",
            Self::InvalidRequestId => "protocol.invalid_request_id",
            Self::InvalidSequence => "protocol.invalid_sequence",
            Self::InvalidSignature => "device.proof_invalid",
            Self::InvalidUuid => "protocol.invalid_uuid",
            Self::UnsupportedCanonicalization => "protocol.unsupported_version",
            Self::UnsupportedDomain => "protocol.unsupported_domain",
            Self::UnsupportedOperation => "protocol.unsupported_operation",
            Self::UnsupportedProtocolVersion => "protocol.unsupported_version",
            Self::UnsupportedSignatureVersion => "protocol.unsupported_version",
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProtocolError {}

pub fn canonical_bytes<T: Serialize>(document: &T) -> Result<Vec<u8>, ProtocolError> {
    serde_jcs::to_vec(document).map_err(|_| ProtocolError::CanonicalizationFailed)
}

pub fn sign_document<T: Serialize>(
    secret: &SigningSecret,
    document: &T,
) -> Result<String, ProtocolError> {
    let bytes = canonical_bytes(document)?;
    Ok(URL_SAFE_NO_PAD.encode(sign_message(secret, &bytes).as_bytes()))
}

pub fn verify_document<T: Serialize>(
    public_key: &DevicePublicKey,
    document: &T,
    encoded_signature: &str,
) -> Result<(), ProtocolError> {
    let bytes = canonical_bytes(document)?;
    let signature_bytes = decode_exact::<64>(encoded_signature)?;
    verify_message(
        public_key,
        &bytes,
        &DeviceSignature::from_bytes(signature_bytes),
    )
    .map_err(|_| ProtocolError::InvalidSignature)
}

pub fn decode_public_key(encoded: &str) -> Result<DevicePublicKey, ProtocolError> {
    decode_exact::<32>(encoded)
        .map(DevicePublicKey::from_bytes)
        .map_err(|_| ProtocolError::InvalidPublicKey)
}

pub fn validate_account_challenge(request: &AccountChallengeRequest) -> Result<(), ProtocolError> {
    validate_version_and_request_id(request.protocol_version, &request.request_id)?;
    if request.email.is_empty()
        || request.email.len() > MAX_EMAIL_BYTES
        || request.email.bytes().any(|byte| byte.is_ascii_control())
        || !request.email.contains('@')
    {
        return Err(ProtocolError::InvalidEmail);
    }
    let needs_binding = matches!(
        request.purpose,
        AccountChallengePurpose::DeviceBindingCancellation
            | AccountChallengePurpose::DeviceBindingDelayedConfirmation
    );
    match (&request.binding_id, needs_binding) {
        (Some(binding_id), true) => validate_uuid(binding_id),
        (None, false) => Ok(()),
        _ => Err(ProtocolError::InvalidUuid),
    }
}

pub fn validate_binding_request(
    document: &DeviceBindingRequestDocument,
) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_request(document),
        DEVICE_BINDING_REQUEST_DOMAIN,
        "device_binding.request",
    )?;
    validate_uuid(&document.binding_grant_id)?;
    validate_uuid(&document.device_id)?;
    decode_public_key(&document.public_key)?;
    if let Some(label) = &document.device_label
        && (label.is_empty()
            || label.len() > MAX_DEVICE_LABEL_BYTES
            || label.chars().any(char::is_control))
    {
        return Err(ProtocolError::InvalidDeviceLabel);
    }
    Ok(())
}

pub fn validate_binding_approval(
    document: &DeviceBindingApprovalDocument,
) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_approval(document),
        DEVICE_BINDING_APPROVAL_DOMAIN,
        "device_binding.approval",
    )?;
    for value in [
        &document.account_id,
        &document.binding_id,
        &document.approving_device_id,
        &document.device_id,
    ] {
        validate_uuid(value)?;
    }
    decode_public_key(&document.public_key)?;
    decode_exact::<32>(&document.challenge).map_err(|_| ProtocolError::InvalidChallenge)?;
    Ok(())
}

pub fn validate_binding_confirmation(
    document: &DeviceBindingConfirmationDocument,
) -> Result<(), ProtocolError> {
    let expected_operation = match document.operation.as_str() {
        "device_binding.delayed_confirmation" => "device_binding.delayed_confirmation",
        "device_binding.cancellation" => "device_binding.cancellation",
        _ => return Err(ProtocolError::UnsupportedOperation),
    };
    validate_signed_header(
        SignedHeaderRef::from_confirmation(document),
        DEVICE_BINDING_REQUEST_DOMAIN,
        expected_operation,
    )?;
    for value in [
        &document.account_id,
        &document.binding_grant_id,
        &document.binding_id,
        &document.device_id,
    ] {
        validate_uuid(value)?;
    }
    decode_public_key(&document.public_key)?;
    decode_exact::<32>(&document.challenge).map_err(|_| ProtocolError::InvalidChallenge)?;
    Ok(())
}

pub fn validate_heartbeat(document: &HeartbeatRequestDocument) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_heartbeat(document),
        HEARTBEAT_SUBMIT_DOMAIN,
        "heartbeat.submit",
    )?;
    validate_uuid(&document.account_id)?;
    validate_uuid(&document.device_id)?;
    if document.sequence == 0 || document.sequence > MAX_HEARTBEAT_SEQUENCE {
        return Err(ProtocolError::InvalidSequence);
    }
    Ok(())
}

pub fn validate_device_status_change(
    document: &DeviceStatusChangeDocument,
) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_device_status_change(document),
        DEVICE_STATUS_CHANGE_DOMAIN,
        "device_status.change",
    )?;
    for value in [
        &document.account_id,
        &document.authorizing_device_id,
        &document.target_device_id,
    ] {
        validate_uuid(value)?;
    }
    Ok(())
}

pub fn validate_recovery_provision(
    document: &RecoveryRecordProvisionDocument,
) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_recovery_provision(document),
        RECOVERY_PROVISION_DOMAIN,
        "recovery_record.provision",
    )?;
    for value in [
        &document.account_id,
        &document.device_id,
        &document.recovery_id,
        &document.vault_id,
    ] {
        validate_uuid(value)?;
    }
    if document.crypto_format_version != 1 || document.recovery_context_version != 1 {
        return Err(ProtocolError::UnsupportedProtocolVersion);
    }
    Ok(())
}

pub fn validate_recovery_action(
    document: &RecoveryRecordActionDocument,
) -> Result<(), ProtocolError> {
    let (domain, operation, needs_digest) = match document.operation.as_str() {
        "recovery_record.confirm" => (RECOVERY_CONFIRM_DOMAIN, "recovery_record.confirm", true),
        "recovery_record.abandon" => (RECOVERY_ABANDON_DOMAIN, "recovery_record.abandon", false),
        _ => return Err(ProtocolError::UnsupportedOperation),
    };
    validate_signed_header(
        SignedHeaderRef::from_recovery_action(document),
        domain,
        operation,
    )?;
    for value in [
        &document.account_id,
        &document.device_id,
        &document.recovery_id,
        &document.vault_id,
    ] {
        validate_uuid(value)?;
    }
    match (&document.wrapper_digest, needs_digest) {
        (Some(value), true) => {
            decode_exact::<32>(value)?;
            Ok(())
        }
        (None, false) => Ok(()),
        _ => Err(ProtocolError::InvalidBase64Url),
    }
}

pub fn validate_recovery_secret_data(data: &RecoverySecretData) -> Result<(), ProtocolError> {
    for value in [
        &data.account_id,
        &data.device_id,
        &data.recovery_id,
        &data.vault_id,
    ] {
        validate_uuid(value)?;
    }
    if data.policy_epoch == 0 || data.recovery_generation == 0 || !data.rekey_required {
        return Err(ProtocolError::UnsupportedProtocolVersion);
    }
    decode_exact::<32>(&data.wrapper_digest)?;
    decode_exact::<32>(&data.srs)?;
    Ok(())
}

pub fn validate_owner_recovery_start(
    document: &OwnerRecoveryStartDocument,
) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_owner_recovery_start(document),
        OWNER_RECOVERY_START_DOMAIN,
        "owner_recovery.start",
    )?;
    for value in [
        &document.account_id,
        &document.device_id,
        &document.recovery_id,
        &document.vault_id,
    ] {
        validate_uuid(value)?;
    }
    if document.policy_epoch == 0 || document.recovery_generation == 0 {
        return Err(ProtocolError::UnsupportedProtocolVersion);
    }
    decode_exact::<32>(&document.wrapper_digest)?;
    Ok(())
}

pub fn validate_owner_recovery_action(
    document: &OwnerRecoveryActionDocument,
) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_owner_recovery_action(document),
        OWNER_RECOVERY_ACTION_DOMAIN,
        "owner_recovery.action",
    )?;
    for value in [
        &document.account_id,
        &document.device_id,
        &document.owner_recovery_id,
    ] {
        validate_uuid(value)?;
    }
    let needs_binding = matches!(
        document.action,
        OwnerRecoveryAction::Release | OwnerRecoveryAction::Complete
    );
    match (
        &document.recovery_id,
        &document.vault_id,
        &document.wrapper_digest,
        needs_binding,
    ) {
        (Some(recovery_id), Some(vault_id), Some(wrapper_digest), true) => {
            validate_uuid(recovery_id)?;
            validate_uuid(vault_id)?;
            decode_exact::<32>(wrapper_digest)?;
            Ok(())
        }
        (None, None, None, false) => Ok(()),
        _ => Err(ProtocolError::InvalidBase64Url),
    }
}

pub fn validate_owner_recovery_secret_data(
    data: &OwnerRecoverySecretData,
) -> Result<(), ProtocolError> {
    for value in [
        &data.account_id,
        &data.device_id,
        &data.owner_recovery_id,
        &data.recovery_id,
        &data.vault_id,
    ] {
        validate_uuid(value)?;
    }
    if data.policy_epoch == 0 || data.recovery_generation == 0 {
        return Err(ProtocolError::UnsupportedProtocolVersion);
    }
    decode_exact::<32>(&data.wrapper_digest)?;
    decode_exact::<32>(&data.srs)?;
    Ok(())
}

pub fn validate_rotation_provision(
    document: &RecoveryRotationProvisionDocument,
) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_rotation_provision(document),
        RECOVERY_ROTATION_PROVISION_DOMAIN,
        "recovery_rotation.provision",
    )?;
    for value in [
        &document.account_id,
        &document.device_id,
        &document.recovery_id,
        &document.rotation_id,
        &document.vault_id,
    ] {
        validate_uuid(value)?;
    }
    if let Some(value) = &document.owner_recovery_id {
        validate_uuid(value)?;
    }
    if document.source_generation == 0
        || document.source_policy_epoch == 0
        || document.target_generation != document.source_generation.saturating_add(1)
        || document.target_policy_epoch < document.source_policy_epoch
        || (document.kind == RecoveryRotationKind::ErcRotation
            && (document.target_policy_epoch != document.source_policy_epoch
                || document.owner_recovery_id.is_some()))
        || (document.kind == RecoveryRotationKind::PostCompromise
            && (document.target_policy_epoch != document.source_policy_epoch.saturating_add(1)
                || document.owner_recovery_id.is_none()))
    {
        return Err(ProtocolError::UnsupportedProtocolVersion);
    }
    Ok(())
}

pub fn validate_rotation_confirm(
    document: &RecoveryRotationConfirmDocument,
) -> Result<(), ProtocolError> {
    validate_signed_header(
        SignedHeaderRef::from_rotation_confirm(document),
        RECOVERY_ROTATION_CONFIRM_DOMAIN,
        "recovery_rotation.confirm",
    )?;
    for value in [
        &document.account_id,
        &document.device_id,
        &document.recovery_id,
        &document.rotation_id,
        &document.vault_id,
    ] {
        validate_uuid(value)?;
    }
    if document.target_generation < 2 || document.target_policy_epoch == 0 {
        return Err(ProtocolError::UnsupportedProtocolVersion);
    }
    decode_exact::<32>(&document.wrapper_digest)?;
    Ok(())
}

pub fn decode_base64url_32(encoded: &str) -> Result<[u8; 32], ProtocolError> {
    decode_exact(encoded)
}

struct SignedHeaderRef<'a> {
    protocol_version: u16,
    signature_version: u16,
    canonicalization: &'a str,
    domain: &'a str,
    operation: &'a str,
    request_id: &'a str,
}

impl<'a> SignedHeaderRef<'a> {
    fn from_request(document: &'a DeviceBindingRequestDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_approval(document: &'a DeviceBindingApprovalDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_confirmation(document: &'a DeviceBindingConfirmationDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_heartbeat(document: &'a HeartbeatRequestDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_device_status_change(document: &'a DeviceStatusChangeDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_recovery_provision(document: &'a RecoveryRecordProvisionDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_recovery_action(document: &'a RecoveryRecordActionDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_owner_recovery_start(document: &'a OwnerRecoveryStartDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_owner_recovery_action(document: &'a OwnerRecoveryActionDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_rotation_provision(document: &'a RecoveryRotationProvisionDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }

    fn from_rotation_confirm(document: &'a RecoveryRotationConfirmDocument) -> Self {
        Self {
            protocol_version: document.protocol_version,
            signature_version: document.signature_version,
            canonicalization: &document.canonicalization,
            domain: &document.domain,
            operation: &document.operation,
            request_id: &document.request_id,
        }
    }
}

fn validate_signed_header(
    header: SignedHeaderRef<'_>,
    expected_domain: &str,
    expected_operation: &str,
) -> Result<(), ProtocolError> {
    validate_version_and_request_id(header.protocol_version, header.request_id)?;
    if header.signature_version != SIGNATURE_VERSION {
        return Err(ProtocolError::UnsupportedSignatureVersion);
    }
    if header.canonicalization != CANONICALIZATION {
        return Err(ProtocolError::UnsupportedCanonicalization);
    }
    if header.domain != expected_domain {
        return Err(ProtocolError::UnsupportedDomain);
    }
    if header.operation != expected_operation {
        return Err(ProtocolError::UnsupportedOperation);
    }
    Ok(())
}

fn validate_version_and_request_id(
    protocol_version: u16,
    request_id: &str,
) -> Result<(), ProtocolError> {
    if protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocolVersion);
    }
    validate_uuid(request_id).map_err(|_| ProtocolError::InvalidRequestId)
}

pub fn validate_uuid(value: &str) -> Result<(), ProtocolError> {
    if value.len() != 36 {
        return Err(ProtocolError::InvalidUuid);
    }
    for (index, byte) in value.bytes().enumerate() {
        let valid = if matches!(index, 8 | 13 | 18 | 23) {
            byte == b'-'
        } else {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        };
        if !valid {
            return Err(ProtocolError::InvalidUuid);
        }
    }
    Ok(())
}

fn decode_exact<const LENGTH: usize>(encoded: &str) -> Result<[u8; LENGTH], ProtocolError> {
    if encoded.contains('=') {
        return Err(ProtocolError::InvalidBase64Url);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidBase64Url)?;
    let bytes: [u8; LENGTH] = decoded
        .try_into()
        .map_err(|_| ProtocolError::InvalidBase64Url)?;
    if URL_SAFE_NO_PAD.encode(bytes) != encoded {
        return Err(ProtocolError::InvalidBase64Url);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: DeviceBindingRequestDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignatureFailureFixture {
        fixture_version: u16,
        expected: String,
        verification_public_key: String,
        envelope: SignedEnvelope<DeviceBindingRequestDocument>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ApprovalSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: DeviceBindingApprovalDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CanonicalizationFixture {
        fixture_version: u16,
        canonical_bytes: String,
        document: serde_json::Value,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HeartbeatSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: HeartbeatRequestDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HeartbeatFailureFixture {
        fixture_version: u16,
        expected: String,
        verification_public_key: String,
        envelope: SignedEnvelope<HeartbeatRequestDocument>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DeviceStatusSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: DeviceStatusChangeDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecoveryProvisionSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: RecoveryRecordProvisionDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecoveryActionSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: RecoveryRecordActionDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OwnerRecoveryStartSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: OwnerRecoveryStartDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OwnerRecoveryActionSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: OwnerRecoveryActionDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RotationProvisionSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: RecoveryRotationProvisionDocument,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RotationConfirmSignatureFixture {
        fixture_version: u16,
        seed: String,
        public_key: String,
        canonical_bytes: String,
        signature: String,
        document: RecoveryRotationConfirmDocument,
    }

    #[test]
    fn recovery_record_signature_fixtures_match_and_validate() {
        let provision: RecoveryProvisionSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/recovery-record-provision.json"
        ))
        .expect("recovery provision fixture should parse");
        assert_eq!(provision.fixture_version, 1);
        assert_eq!(decode_exact::<32>(&provision.seed), Ok([0x11; 32]));
        validate_recovery_provision(&provision.document).expect("provision should validate");
        let public = decode_public_key(&provision.public_key).expect("public key should decode");
        let canonical = canonical_bytes(&provision.document).expect("JCS should succeed");
        assert_eq!(URL_SAFE_NO_PAD.encode(canonical), provision.canonical_bytes);
        assert_eq!(
            verify_document(&public, &provision.document, &provision.signature),
            Ok(())
        );

        let confirm: RecoveryActionSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/recovery-record-confirm.json"
        ))
        .expect("recovery confirm fixture should parse");
        assert_eq!(confirm.fixture_version, 1);
        assert_eq!(decode_exact::<32>(&confirm.seed), Ok([0x11; 32]));
        validate_recovery_action(&confirm.document).expect("confirm should validate");
        assert_eq!(confirm.public_key, provision.public_key);
        let canonical = canonical_bytes(&confirm.document).expect("JCS should succeed");
        assert_eq!(URL_SAFE_NO_PAD.encode(canonical), confirm.canonical_bytes);
        assert_eq!(
            verify_document(&public, &confirm.document, &confirm.signature),
            Ok(())
        );
    }

    #[test]
    fn recovery_secret_fixture_is_closed_and_exactly_bound() {
        let response: SuccessResponse<RecoverySecretData> = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/valid/recovery-secret-response.json"
        ))
        .expect("recovery secret response should parse");
        assert_eq!(response.protocol_version, 1);
        assert_eq!(validate_recovery_secret_data(&response.data), Ok(()));

        let invalid = include_str!(
            "../../protocol/v1/fixtures/invalid/recovery-record-provision-forbidden-data.json"
        );
        assert!(
            serde_json::from_str::<SignedEnvelope<RecoveryRecordProvisionDocument>>(invalid)
                .is_err()
        );
    }

    #[test]
    fn owner_recovery_and_rotation_fixtures_use_distinct_signed_domains() {
        let owner_start: OwnerRecoveryStartSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/owner-recovery-start.json"
        ))
        .expect("Owner recovery start fixture should parse");
        let owner_action: OwnerRecoveryActionSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/owner-recovery-action.json"
        ))
        .expect("Owner recovery action fixture should parse");
        let rotation_provision: RotationProvisionSignatureFixture = serde_json::from_str(
            include_str!("../../protocol/v1/fixtures/signatures/recovery-rotation-provision.json"),
        )
        .expect("rotation provision fixture should parse");
        let rotation_confirm: RotationConfirmSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/recovery-rotation-confirm.json"
        ))
        .expect("rotation confirm fixture should parse");
        assert_eq!(owner_start.fixture_version, 1);
        assert_eq!(owner_action.fixture_version, 1);
        assert_eq!(rotation_provision.fixture_version, 1);
        assert_eq!(rotation_confirm.fixture_version, 1);
        assert_eq!(decode_exact::<32>(&owner_start.seed), Ok([0x11; 32]));
        assert_eq!(decode_exact::<32>(&owner_action.seed), Ok([0x11; 32]));
        assert_eq!(decode_exact::<32>(&rotation_provision.seed), Ok([0x11; 32]));
        assert_eq!(decode_exact::<32>(&rotation_confirm.seed), Ok([0x11; 32]));
        assert_eq!(validate_owner_recovery_start(&owner_start.document), Ok(()));
        assert_eq!(
            validate_owner_recovery_action(&owner_action.document),
            Ok(())
        );
        assert_eq!(
            validate_rotation_provision(&rotation_provision.document),
            Ok(())
        );
        assert_eq!(
            validate_rotation_confirm(&rotation_confirm.document),
            Ok(())
        );
        let mut mismatched_rotation = rotation_provision.document.clone();
        mismatched_rotation.kind = RecoveryRotationKind::ErcRotation;
        mismatched_rotation.target_policy_epoch = mismatched_rotation.source_policy_epoch;
        assert!(validate_rotation_provision(&mismatched_rotation).is_err());
        let public = decode_public_key(&owner_start.public_key).expect("public key should decode");
        for (document, canonical, signature) in [
            (
                serde_json::to_value(&owner_start.document).expect("document should serialize"),
                owner_start.canonical_bytes,
                owner_start.signature,
            ),
            (
                serde_json::to_value(&owner_action.document).expect("document should serialize"),
                owner_action.canonical_bytes,
                owner_action.signature,
            ),
            (
                serde_json::to_value(&rotation_provision.document)
                    .expect("document should serialize"),
                rotation_provision.canonical_bytes,
                rotation_provision.signature,
            ),
            (
                serde_json::to_value(&rotation_confirm.document)
                    .expect("document should serialize"),
                rotation_confirm.canonical_bytes,
                rotation_confirm.signature,
            ),
        ] {
            assert_eq!(
                URL_SAFE_NO_PAD.encode(canonical_bytes(&document).expect("JCS should succeed")),
                canonical
            );
            assert_eq!(verify_document(&public, &document, &signature), Ok(()));
        }
        assert_eq!(owner_action.public_key, owner_start.public_key);
        assert_eq!(rotation_provision.public_key, owner_start.public_key);
        assert_eq!(rotation_confirm.public_key, owner_start.public_key);

        let secret: SuccessResponse<OwnerRecoverySecretData> = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/valid/owner-recovery-secret-response.json"
        ))
        .expect("Owner secret fixture should parse");
        assert_eq!(validate_owner_recovery_secret_data(&secret.data), Ok(()));
        assert!(
            serde_json::from_str::<SignedEnvelope<OwnerRecoveryStartDocument>>(include_str!(
                "../../protocol/v1/fixtures/invalid/owner-recovery-start-forbidden-data.json"
            ))
            .is_err()
        );
    }

    #[test]
    fn public_binding_signature_fixture_matches_exact_bytes_and_signature() {
        let fixture: SignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/device-binding-request.json"
        ))
        .expect("public fixture should parse");
        assert_eq!(fixture.fixture_version, 1);
        validate_binding_request(&fixture.document).expect("document should validate");

        let seed = decode_exact::<32>(&fixture.seed).expect("synthetic seed should decode");
        let secret = SigningSecret::from_storage_bytes(seed);
        let public = decode_public_key(&fixture.public_key).expect("public key should decode");
        let canonical = canonical_bytes(&fixture.document).expect("JCS should succeed");
        assert_eq!(URL_SAFE_NO_PAD.encode(&canonical), fixture.canonical_bytes);
        assert_eq!(
            sign_document(&secret, &fixture.document),
            Ok(fixture.signature.clone())
        );
        assert_eq!(
            verify_document(&public, &fixture.document, &fixture.signature),
            Ok(())
        );
    }

    #[test]
    fn signed_documents_fail_closed_for_mutation_and_unknown_fields() {
        let envelope: SignedEnvelope<DeviceBindingRequestDocument> = serde_json::from_str(
            include_str!("../../protocol/v1/fixtures/valid/device-binding-request.json"),
        )
        .expect("valid public fixture should parse");
        validate_binding_request(&envelope.signed).expect("fixture should validate");
        let public =
            decode_public_key(&envelope.signed.public_key).expect("public key should parse");
        assert!(verify_document(&public, &envelope.signed, &envelope.signature).is_ok());

        let mut modified = envelope.signed.clone();
        modified.device_id = "00000000-0000-4000-8000-000000000099".to_owned();
        assert_eq!(
            verify_document(&public, &modified, &envelope.signature),
            Err(ProtocolError::InvalidSignature)
        );

        assert!(
            serde_json::from_str::<SignedEnvelope<DeviceBindingRequestDocument>>(include_str!(
                "../../protocol/v1/fixtures/invalid/device-binding-request-extra-field.json"
            ))
            .is_err()
        );
    }

    #[test]
    fn canonical_encodings_and_bounds_reject_ambiguous_values() {
        assert!(validate_uuid("00000000-0000-4000-8000-000000000001").is_ok());
        assert!(validate_uuid("00000000-0000-4000-8000-00000000000A").is_err());
        assert!(decode_exact::<32>("AA==").is_err());
        assert!(decode_exact::<32>("AA").is_err());

        let request: AccountChallengeRequest = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/valid/account-challenge-request.json"
        ))
        .expect("valid account fixture should parse");
        assert_eq!(validate_account_challenge(&request), Ok(()));
    }

    #[test]
    fn published_failure_fixtures_reject_key_signature_domain_and_padding() {
        for fixture_text in [
            include_str!(
                "../../protocol/v1/fixtures/signatures/device-binding-request-wrong-key.json"
            ),
            include_str!(
                "../../protocol/v1/fixtures/signatures/device-binding-request-modified-signature.json"
            ),
            include_str!(
                "../../protocol/v1/fixtures/signatures/device-binding-cross-domain-replay.json"
            ),
        ] {
            let fixture: SignatureFailureFixture =
                serde_json::from_str(fixture_text).expect("failure fixture should parse");
            assert_eq!(fixture.fixture_version, 1);
            assert_eq!(fixture.expected, "device.proof_invalid");
            let public = decode_public_key(&fixture.verification_public_key)
                .expect("fixture verification key should parse");
            assert_eq!(
                verify_document(
                    &public,
                    &fixture.envelope.signed,
                    &fixture.envelope.signature,
                ),
                Err(ProtocolError::InvalidSignature)
            );
        }

        let padded: SignedEnvelope<DeviceBindingRequestDocument> =
            serde_json::from_str(include_str!(
                "../../protocol/v1/fixtures/invalid/device-binding-request-signature-padding.json"
            ))
            .expect("padding fixture should remain valid JSON");
        let public = decode_public_key(&padded.signed.public_key).expect("public key should parse");
        assert_eq!(
            verify_document(&public, &padded.signed, &padded.signature),
            Err(ProtocolError::InvalidBase64Url)
        );
    }

    #[test]
    fn approval_signature_covers_every_security_field() {
        let fixture: ApprovalSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/device-binding-approval.json"
        ))
        .expect("approval fixture should parse");
        assert_eq!(fixture.fixture_version, 1);
        validate_binding_approval(&fixture.document).expect("approval should validate");
        let seed = decode_exact::<32>(&fixture.seed).expect("seed should parse");
        let public = decode_public_key(&fixture.public_key).expect("public key should parse");
        assert_eq!(
            URL_SAFE_NO_PAD
                .encode(canonical_bytes(&fixture.document).expect("approval JCS should succeed")),
            fixture.canonical_bytes
        );
        assert_eq!(
            sign_document(&SigningSecret::from_storage_bytes(seed), &fixture.document),
            Ok(fixture.signature.clone())
        );

        let mutations = [
            ("domain", "aeterna.device-binding.request.v1"),
            ("account_id", "00000000-0000-4000-8000-000000000099"),
            ("binding_id", "00000000-0000-4000-8000-000000000099"),
            (
                "approving_device_id",
                "00000000-0000-4000-8000-000000000099",
            ),
            ("device_id", "00000000-0000-4000-8000-000000000099"),
            ("public_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ];
        for (field, value) in mutations {
            let mut mutated = fixture.document.clone();
            match field {
                "domain" => mutated.domain = value.to_owned(),
                "account_id" => mutated.account_id = value.to_owned(),
                "binding_id" => mutated.binding_id = value.to_owned(),
                "approving_device_id" => mutated.approving_device_id = value.to_owned(),
                "device_id" => mutated.device_id = value.to_owned(),
                "public_key" => mutated.public_key = value.to_owned(),
                "challenge" => mutated.challenge = value.to_owned(),
                _ => unreachable!("fixture mutation field is exhaustive"),
            }
            assert_eq!(
                verify_document(&public, &mutated, &fixture.signature),
                Err(ProtocolError::InvalidSignature),
                "field {field} must be signed"
            );
        }

        let mut version_mutation = fixture.document.clone();
        version_mutation.protocol_version = 2;
        assert_eq!(
            validate_binding_approval(&version_mutation),
            Err(ProtocolError::UnsupportedProtocolVersion)
        );
        let mut signature_version_mutation = fixture.document.clone();
        signature_version_mutation.signature_version = 2;
        assert_eq!(
            validate_binding_approval(&signature_version_mutation),
            Err(ProtocolError::UnsupportedSignatureVersion)
        );
    }

    #[test]
    fn published_unicode_and_escaping_case_matches_rfc8785_bytes() {
        let fixture: CanonicalizationFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/jcs-unicode-and-escaping.json"
        ))
        .expect("canonicalization fixture should parse");
        assert_eq!(fixture.fixture_version, 1);
        let canonical = canonical_bytes(&fixture.document).expect("JCS should succeed");
        assert_eq!(URL_SAFE_NO_PAD.encode(canonical), fixture.canonical_bytes);
    }

    #[test]
    fn heartbeat_fixture_matches_and_forbidden_fields_fail_closed() {
        let fixture: HeartbeatSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/heartbeat-request.json"
        ))
        .expect("heartbeat signature fixture should parse");
        assert_eq!(fixture.fixture_version, 1);
        assert_eq!(validate_heartbeat(&fixture.document), Ok(()));
        let seed = decode_exact::<32>(&fixture.seed).expect("seed should parse");
        let public = decode_public_key(&fixture.public_key).expect("public key should parse");
        assert_eq!(
            URL_SAFE_NO_PAD
                .encode(canonical_bytes(&fixture.document).expect("heartbeat JCS should succeed")),
            fixture.canonical_bytes
        );
        assert_eq!(
            sign_document(&SigningSecret::from_storage_bytes(seed), &fixture.document),
            Ok(fixture.signature.clone())
        );
        assert_eq!(
            verify_document(&public, &fixture.document, &fixture.signature),
            Ok(())
        );

        assert!(
            serde_json::from_str::<SignedEnvelope<HeartbeatRequestDocument>>(include_str!(
                "../../protocol/v1/fixtures/invalid/heartbeat-request-forbidden-data.json"
            ))
            .is_err()
        );
        let mut invalid = fixture.document.clone();
        invalid.sequence = 0;
        assert_eq!(
            validate_heartbeat(&invalid),
            Err(ProtocolError::InvalidSequence)
        );
        invalid.sequence = MAX_HEARTBEAT_SEQUENCE + 1;
        assert_eq!(
            validate_heartbeat(&invalid),
            Err(ProtocolError::InvalidSequence)
        );
    }

    #[test]
    fn heartbeat_mutation_and_cross_domain_replay_fail_signature_verification() {
        for fixture_text in [
            include_str!("../../protocol/v1/fixtures/signatures/heartbeat-modified-payload.json"),
            include_str!(
                "../../protocol/v1/fixtures/signatures/heartbeat-cross-domain-replay.json"
            ),
        ] {
            let fixture: HeartbeatFailureFixture =
                serde_json::from_str(fixture_text).expect("failure fixture should parse");
            assert_eq!(fixture.fixture_version, 1);
            assert_eq!(fixture.expected, "device.proof_invalid");
            let public = decode_public_key(&fixture.verification_public_key)
                .expect("verification key should parse");
            assert_eq!(
                verify_document(
                    &public,
                    &fixture.envelope.signed,
                    &fixture.envelope.signature,
                ),
                Err(ProtocolError::InvalidSignature)
            );
        }
    }

    #[test]
    fn device_status_fixture_uses_its_own_domain() {
        let fixture: DeviceStatusSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/device-status-change.json"
        ))
        .expect("device status fixture should parse");
        assert_eq!(fixture.fixture_version, 1);
        assert_eq!(validate_device_status_change(&fixture.document), Ok(()));
        let seed = decode_exact::<32>(&fixture.seed).expect("seed should parse");
        let public = decode_public_key(&fixture.public_key).expect("public key should parse");
        assert_eq!(
            URL_SAFE_NO_PAD.encode(
                canonical_bytes(&fixture.document).expect("device status JCS should succeed")
            ),
            fixture.canonical_bytes
        );
        assert_eq!(
            sign_document(&SigningSecret::from_storage_bytes(seed), &fixture.document),
            Ok(fixture.signature.clone())
        );
        assert_eq!(
            verify_document(&public, &fixture.document, &fixture.signature),
            Ok(())
        );
        let heartbeat: HeartbeatSignatureFixture = serde_json::from_str(include_str!(
            "../../protocol/v1/fixtures/signatures/heartbeat-request.json"
        ))
        .expect("heartbeat fixture should parse");
        assert_eq!(
            verify_document(&public, &fixture.document, &heartbeat.signature),
            Err(ProtocolError::InvalidSignature)
        );
    }
}
