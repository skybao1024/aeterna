//! Delayed-recovery coordinator that keeps bearer and key material in Rust.

use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{Argon2Profile, ErcEntropy, MasterPassword, decode_erc, fill_random},
    protocol::{
        OwnerRecoveryAction, OwnerRecoveryActionDocument, OwnerRecoverySecretData,
        PROTOCOL_VERSION, RecoverySecretData, RecoverySecretRequest, SignedEnvelope,
        SuccessResponse, decode_base64url_32, validate_owner_recovery_action,
        validate_owner_recovery_secret_data, validate_recovery_secret_data, validate_uuid,
    },
    vault::{
        PostCompromiseRekey, RecoveryEnrollment, RecoveryMaterial, UnlockedVault, VaultError,
        VaultRepository,
    },
};

pub trait RecoveryTransport {
    fn release_secret(
        &mut self,
        request: &RecoverySecretRequest,
    ) -> Result<SuccessResponse<RecoverySecretData>, RecoveryError>;
}

pub trait OwnerRecoveryTransport {
    fn release_owner_secret(
        &mut self,
        request: &SignedEnvelope<OwnerRecoveryActionDocument>,
    ) -> Result<SuccessResponse<OwnerRecoverySecretData>, RecoveryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    BindingMismatch,
    InvalidErc,
    InvalidProtocol,
    LocalVaultUnavailable,
    MaterialUnavailable,
    RekeyRequired,
    TransportUnavailable,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::BindingMismatch => "recovery.binding_mismatch",
            Self::InvalidErc => "recovery.erc_invalid",
            Self::InvalidProtocol => "recovery.protocol_invalid",
            Self::LocalVaultUnavailable => "recovery.local_vault_unavailable",
            Self::MaterialUnavailable => "recovery.material_unavailable",
            Self::RekeyRequired => "recovery.rekey_required",
            Self::TransportUnavailable => "recovery.transport_unavailable",
        };
        formatter.write_str(code)
    }
}

impl std::error::Error for RecoveryError {}

impl From<VaultError> for RecoveryError {
    fn from(_: VaultError) -> Self {
        Self::LocalVaultUnavailable
    }
}

pub struct RecoveryCoordinator<T> {
    transport: T,
}

impl<T: RecoveryTransport> RecoveryCoordinator<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn recover_existing_vault(
        &mut self,
        repository: &VaultRepository,
        account_id: &str,
        request_id: &str,
        claim_token: String,
        encoded_erc: String,
    ) -> Result<UnlockedVault, RecoveryError> {
        let (material, rekey_required) =
            self.release_material(repository, account_id, request_id, claim_token, encoded_erc)?;
        if rekey_required {
            return Err(RecoveryError::RekeyRequired);
        }
        repository
            .unlock_recovery(&material)
            .map_err(|_| RecoveryError::MaterialUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recover_and_rekey_compromised_vault(
        &mut self,
        repository: &VaultRepository,
        account_id: &str,
        request_id: &str,
        claim_token: String,
        encoded_erc: String,
        new_password: &MasterPassword,
        new_profile: Argon2Profile,
        new_recovery_id: [u8; 16],
        mut new_srs: [u8; 32],
    ) -> Result<PostCompromiseRekey, RecoveryError> {
        let (material, rekey_required) =
            self.release_material(repository, account_id, request_id, claim_token, encoded_erc)?;
        if !rekey_required {
            new_srs.zeroize();
            return Err(RecoveryError::InvalidProtocol);
        }
        let unlocked = repository
            .unlock_recovery(&material)
            .map_err(|_| RecoveryError::MaterialUnavailable)?;
        let result = unlocked.rekey_after_release_or_claim(
            new_password,
            new_profile,
            new_recovery_id,
            new_srs,
        );
        new_srs.zeroize();
        result.map_err(Into::into)
    }

    fn release_material(
        &mut self,
        repository: &VaultRepository,
        account_id: &str,
        request_id: &str,
        claim_token: String,
        encoded_erc: String,
    ) -> Result<(RecoveryMaterial, bool), RecoveryError> {
        let claim_token = Zeroizing::new(claim_token);
        let encoded_erc = Zeroizing::new(encoded_erc);
        validate_uuid(account_id).map_err(|_| RecoveryError::InvalidProtocol)?;
        validate_uuid(request_id).map_err(|_| RecoveryError::InvalidProtocol)?;
        decode_base64url_32(&claim_token).map_err(|_| RecoveryError::InvalidProtocol)?;
        let binding = repository.recovery_binding()?;
        let mut request = RecoverySecretRequest {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.to_owned(),
            claim_token: claim_token.to_string(),
            device_id: uuid_text(binding.device_id),
            recovery_id: uuid_text(binding.recovery_id),
            vault_id: uuid_text(binding.vault_id),
            wrapper_digest: URL_SAFE_NO_PAD.encode(binding.wrapper_digest),
        };
        let mut response = match self.transport.release_secret(&request) {
            Ok(value) => value,
            Err(error) => {
                request.claim_token.zeroize();
                return Err(error);
            }
        };
        request.claim_token.zeroize();
        if response.protocol_version != PROTOCOL_VERSION
            || response.request_id != request.request_id
            || validate_recovery_secret_data(&response.data).is_err()
            || response.data.account_id != account_id
            || response.data.device_id != request.device_id
            || response.data.recovery_id != request.recovery_id
            || response.data.vault_id != request.vault_id
            || response.data.wrapper_digest != request.wrapper_digest
        {
            response.data.srs.zeroize();
            return Err(RecoveryError::BindingMismatch);
        }
        let rekey_required = response.data.rekey_required;
        let decoded_srs = decode_base64url_32(&response.data.srs);
        response.data.srs.zeroize();
        let mut srs = decoded_srs.map_err(|_| RecoveryError::MaterialUnavailable)?;
        let erc = decode_erc(&encoded_erc).map_err(|_| RecoveryError::InvalidErc)?;
        let material = RecoveryMaterial::from_parts(erc, srs);
        srs.zeroize();
        Ok((material, rekey_required))
    }
}

pub struct OwnerRecoveryCoordinator<T> {
    transport: T,
}

impl<T: OwnerRecoveryTransport> OwnerRecoveryCoordinator<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recover_and_replace_access_wrappers(
        &mut self,
        repository: &VaultRepository,
        request: &SignedEnvelope<OwnerRecoveryActionDocument>,
        encoded_erc: String,
        new_password: &MasterPassword,
        new_profile: Argon2Profile,
        new_recovery_id: [u8; 16],
        mut new_srs: [u8; 32],
    ) -> Result<RecoveryEnrollment, RecoveryError> {
        if request.protocol_version != PROTOCOL_VERSION
            || request.signed.action != OwnerRecoveryAction::Release
            || validate_owner_recovery_action(&request.signed).is_err()
        {
            new_srs.zeroize();
            return Err(RecoveryError::InvalidProtocol);
        }
        let encoded_erc = Zeroizing::new(encoded_erc);
        let binding = repository.recovery_binding()?;
        let mut response = match self.transport.release_owner_secret(request) {
            Ok(value) => value,
            Err(error) => {
                new_srs.zeroize();
                return Err(error);
            }
        };
        let matches_binding = response.protocol_version == PROTOCOL_VERSION
            && response.request_id == request.signed.request_id
            && validate_owner_recovery_secret_data(&response.data).is_ok()
            && response.data.account_id == request.signed.account_id
            && response.data.device_id == request.signed.device_id
            && response.data.owner_recovery_id == request.signed.owner_recovery_id
            && response.data.recovery_id == uuid_text(binding.recovery_id)
            && response.data.vault_id == uuid_text(binding.vault_id)
            && response.data.wrapper_digest == URL_SAFE_NO_PAD.encode(binding.wrapper_digest)
            && !response.data.rekey_required;
        if !matches_binding {
            response.data.srs.zeroize();
            new_srs.zeroize();
            return Err(RecoveryError::BindingMismatch);
        }
        let decoded_srs = decode_base64url_32(&response.data.srs);
        response.data.srs.zeroize();
        let mut old_srs = decoded_srs.map_err(|_| RecoveryError::MaterialUnavailable)?;
        let old_erc = decode_erc(&encoded_erc).map_err(|_| RecoveryError::InvalidErc)?;
        let old_material = RecoveryMaterial::from_parts(old_erc, old_srs);
        old_srs.zeroize();
        let unlocked = repository
            .unlock_recovery(&old_material)
            .map_err(|_| RecoveryError::MaterialUnavailable)?;
        let mut new_erc = [0_u8; 16];
        fill_random(&mut new_erc).map_err(|_| RecoveryError::MaterialUnavailable)?;
        let result = unlocked.replace_access_wrappers_after_owner_recovery(
            new_password,
            new_profile,
            new_recovery_id,
            ErcEntropy::from_bytes(new_erc),
            new_srs,
        );
        new_srs.zeroize();
        result.map_err(Into::into)
    }
}

fn uuid_text(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use crate::{
        crypto::{Argon2Profile, MasterPassword, encode_erc, fill_random},
        vault::RecoveryBinding,
    };

    use super::*;

    struct FakeTransport {
        response: Option<SuccessResponse<RecoverySecretData>>,
        observed: Option<RecoverySecretRequest>,
    }

    struct FakeOwnerTransport {
        response: Option<SuccessResponse<OwnerRecoverySecretData>>,
    }

    impl OwnerRecoveryTransport for FakeOwnerTransport {
        fn release_owner_secret(
            &mut self,
            _request: &SignedEnvelope<OwnerRecoveryActionDocument>,
        ) -> Result<SuccessResponse<OwnerRecoverySecretData>, RecoveryError> {
            self.response
                .take()
                .ok_or(RecoveryError::TransportUnavailable)
        }
    }

    impl RecoveryTransport for FakeTransport {
        fn release_secret(
            &mut self,
            request: &RecoverySecretRequest,
        ) -> Result<SuccessResponse<RecoverySecretData>, RecoveryError> {
            self.observed = Some(request.clone());
            self.response
                .take()
                .ok_or(RecoveryError::TransportUnavailable)
        }
    }

    fn temporary_path() -> PathBuf {
        let mut random = [0_u8; 8];
        fill_random(&mut random).expect("OS randomness should be available");
        fs::canonicalize(std::env::temp_dir())
            .expect("temporary directory should resolve")
            .join(format!(
                "aeterna-recovery-coordinator-{:016x}.sqlite",
                u64::from_be_bytes(random)
            ))
    }

    fn remove_vault(path: &Path) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    fn response(binding: RecoveryBinding, srs: &[u8; 32]) -> SuccessResponse<RecoverySecretData> {
        SuccessResponse {
            protocol_version: 1,
            request_id: "00000000-0000-4000-8000-000000000047".to_owned(),
            data: RecoverySecretData {
                account_id: "00000000-0000-4000-8000-000000000020".to_owned(),
                device_id: uuid_text(binding.device_id),
                policy_epoch: 1,
                recovery_generation: 1,
                recovery_id: uuid_text(binding.recovery_id),
                rekey_required: true,
                srs: URL_SAFE_NO_PAD.encode(srs),
                vault_id: uuid_text(binding.vault_id),
                wrapper_digest: URL_SAFE_NO_PAD.encode(binding.wrapper_digest),
            },
        }
    }

    fn owner_request(binding: RecoveryBinding) -> SignedEnvelope<OwnerRecoveryActionDocument> {
        SignedEnvelope {
            protocol_version: 1,
            signed: OwnerRecoveryActionDocument {
                account_id: "00000000-0000-4000-8000-000000000020".to_owned(),
                action: OwnerRecoveryAction::Release,
                canonicalization: "jcs-rfc8785".to_owned(),
                device_id: uuid_text(binding.device_id),
                domain: "aeterna.owner-recovery.action.v1".to_owned(),
                operation: "owner_recovery.action".to_owned(),
                owner_recovery_id: "00000000-0000-4000-8000-000000000050".to_owned(),
                protocol_version: 1,
                recovery_id: Some(uuid_text(binding.recovery_id)),
                request_id: "00000000-0000-4000-8000-000000000051".to_owned(),
                signature_version: 1,
                vault_id: Some(uuid_text(binding.vault_id)),
                wrapper_digest: Some(URL_SAFE_NO_PAD.encode(binding.wrapper_digest)),
            },
            signature: URL_SAFE_NO_PAD.encode([0x55; 64]),
        }
    }

    fn owner_response(
        binding: RecoveryBinding,
        srs: &[u8; 32],
    ) -> SuccessResponse<OwnerRecoverySecretData> {
        SuccessResponse {
            protocol_version: 1,
            request_id: "00000000-0000-4000-8000-000000000051".to_owned(),
            data: OwnerRecoverySecretData {
                account_id: "00000000-0000-4000-8000-000000000020".to_owned(),
                device_id: uuid_text(binding.device_id),
                owner_recovery_id: "00000000-0000-4000-8000-000000000050".to_owned(),
                policy_epoch: 1,
                recovery_generation: 1,
                recovery_id: uuid_text(binding.recovery_id),
                rekey_required: false,
                srs: URL_SAFE_NO_PAD.encode(srs),
                vault_id: uuid_text(binding.vault_id),
                wrapper_digest: URL_SAFE_NO_PAD.encode(binding.wrapper_digest),
            },
        }
    }

    #[test]
    fn released_srs_cannot_open_content_without_post_compromise_rekey() {
        let path = temporary_path();
        let password = MasterPassword::new(vec![0x41; 16]).expect("password is valid");
        let bootstrap =
            VaultRepository::initialize(&path, &password, Argon2Profile::new(65_536, 1, 1))
                .expect("vault should initialize");
        let (repository, material) = bootstrap.into_parts();
        let unlocked = repository.unlock(&password).expect("vault should unlock");
        let record = unlocked
            .create_record(b"existing encrypted item")
            .expect("record should be created");
        drop(unlocked);
        let binding = repository.recovery_binding().expect("binding should load");
        let erc = encode_erc(material.erc()).expect("ERC should encode");
        let transport = FakeTransport {
            response: Some(response(binding, material.recovery_salt().expose())),
            observed: None,
        };
        let mut coordinator = RecoveryCoordinator::new(transport);
        assert!(matches!(
            coordinator.recover_existing_vault(
                &repository,
                "00000000-0000-4000-8000-000000000020",
                "00000000-0000-4000-8000-000000000047",
                URL_SAFE_NO_PAD.encode([0x88; 32]),
                erc,
            ),
            Err(RecoveryError::RekeyRequired)
        ));
        assert!(
            repository
                .unlock(&password)
                .and_then(|vault| vault.read_record(record.id))
                .is_ok()
        );
        remove_vault(&path);
    }

    #[test]
    fn response_binding_substitution_fails_before_local_unwrap() {
        let path = temporary_path();
        let password = MasterPassword::new(vec![0x42; 16]).expect("password is valid");
        let bootstrap =
            VaultRepository::initialize(&path, &password, Argon2Profile::new(65_536, 1, 1))
                .expect("vault should initialize");
        let (repository, material) = bootstrap.into_parts();
        let binding = repository.recovery_binding().expect("binding should load");
        let erc = encode_erc(material.erc()).expect("ERC should encode");
        let mut substituted = response(binding, material.recovery_salt().expose());
        substituted.data.vault_id = "00000000-0000-4000-8000-000000000099".to_owned();
        let mut coordinator = RecoveryCoordinator::new(FakeTransport {
            response: Some(substituted),
            observed: None,
        });
        assert!(matches!(
            coordinator.recover_existing_vault(
                &repository,
                "00000000-0000-4000-8000-000000000020",
                "00000000-0000-4000-8000-000000000047",
                URL_SAFE_NO_PAD.encode([0x88; 32]),
                erc,
            ),
            Err(RecoveryError::BindingMismatch)
        ));
        remove_vault(&path);
    }

    #[test]
    fn claimed_material_requires_atomic_rekey_before_content_access() {
        let path = temporary_path();
        let old_password = MasterPassword::new(vec![0x61; 16]).expect("password is valid");
        let new_password = MasterPassword::new(vec![0x62; 16]).expect("password is valid");
        let bootstrap =
            VaultRepository::initialize(&path, &old_password, Argon2Profile::new(65_536, 1, 1))
                .expect("vault should initialize");
        let (repository, material) = bootstrap.into_parts();
        let unlocked = repository
            .unlock(&old_password)
            .expect("vault should unlock");
        let record = unlocked
            .create_record(b"claimed data must be rekeyed")
            .expect("record should be created");
        drop(unlocked);
        let binding = repository.recovery_binding().expect("binding should load");
        let erc = encode_erc(material.erc()).expect("ERC should encode");
        let claim_response = response(binding, material.recovery_salt().expose());
        let mut coordinator = RecoveryCoordinator::new(FakeTransport {
            response: Some(claim_response),
            observed: None,
        });
        let outcome = coordinator
            .recover_and_rekey_compromised_vault(
                &repository,
                "00000000-0000-4000-8000-000000000020",
                "00000000-0000-4000-8000-000000000047",
                URL_SAFE_NO_PAD.encode([0x88; 32]),
                erc,
                &new_password,
                Argon2Profile::new(65_536, 1, 1),
                [0x91; 16],
                [0x92; 32],
            )
            .expect("claim recovery should atomically rekey");
        assert_eq!(
            outcome
                .vault
                .read_record(record.id)
                .expect("rekeyed record should decrypt")
                .plaintext(),
            b"claimed data must be rekeyed"
        );
        assert!(repository.unlock(&old_password).is_err());
        assert!(repository.unlock_recovery(&material).is_err());
        assert!(repository.unlock(&new_password).is_ok());
        remove_vault(&path);
    }

    #[test]
    fn owner_recovery_replaces_both_access_wrappers_before_returning() {
        let path = temporary_path();
        let old_password = MasterPassword::new(vec![0x71; 16]).expect("password is valid");
        let new_password = MasterPassword::new(vec![0x72; 16]).expect("password is valid");
        let bootstrap =
            VaultRepository::initialize(&path, &old_password, Argon2Profile::new(65_536, 1, 1))
                .expect("vault should initialize");
        let (repository, old_material) = bootstrap.into_parts();
        let old_vault = repository
            .unlock(&old_password)
            .expect("vault should unlock");
        let record = old_vault
            .create_record(b"owner recovered data")
            .expect("record should be created");
        drop(old_vault);
        let binding = repository.recovery_binding().expect("binding should load");
        let request = owner_request(binding);
        let response = owner_response(binding, old_material.recovery_salt().expose());
        let mut coordinator = OwnerRecoveryCoordinator::new(FakeOwnerTransport {
            response: Some(response),
        });
        let enrollment = coordinator
            .recover_and_replace_access_wrappers(
                &repository,
                &request,
                encode_erc(old_material.erc()).expect("ERC should encode"),
                &new_password,
                Argon2Profile::new(65_536, 1, 1),
                [0x81; 16],
                [0x82; 32],
            )
            .expect("owner recovery should replace wrappers");
        assert!(repository.unlock(&old_password).is_err());
        assert!(repository.unlock_recovery(&old_material).is_err());
        assert_eq!(
            repository
                .unlock(&new_password)
                .and_then(|vault| vault.read_record(record.id))
                .expect("new password should read the existing record")
                .plaintext(),
            b"owner recovered data"
        );
        assert!(repository.unlock_recovery(&enrollment.material).is_ok());
        remove_vault(&path);
    }
}
