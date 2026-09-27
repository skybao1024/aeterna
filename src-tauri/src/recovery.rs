//! Delayed-recovery coordinator that keeps bearer and key material in Rust.

use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::decode_erc,
    protocol::{
        PROTOCOL_VERSION, RecoverySecretData, RecoverySecretRequest, SuccessResponse,
        decode_base64url_32, validate_recovery_secret_data, validate_uuid,
    },
    vault::{RecoveryMaterial, UnlockedVault, VaultError, VaultRepository},
};

pub trait RecoveryTransport {
    fn release_secret(
        &mut self,
        request: &RecoverySecretRequest,
    ) -> Result<SuccessResponse<RecoverySecretData>, RecoveryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    BindingMismatch,
    InvalidErc,
    InvalidProtocol,
    LocalVaultUnavailable,
    MaterialUnavailable,
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
        let decoded_srs = decode_base64url_32(&response.data.srs);
        response.data.srs.zeroize();
        let mut srs = decoded_srs.map_err(|_| RecoveryError::MaterialUnavailable)?;
        let erc = decode_erc(&encoded_erc).map_err(|_| RecoveryError::InvalidErc)?;
        let material = RecoveryMaterial::from_parts(erc, srs);
        srs.zeroize();
        repository
            .unlock_recovery(&material)
            .map_err(|_| RecoveryError::MaterialUnavailable)
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
                recovery_id: uuid_text(binding.recovery_id),
                srs: URL_SAFE_NO_PAD.encode(srs),
                vault_id: uuid_text(binding.vault_id),
                wrapper_digest: URL_SAFE_NO_PAD.encode(binding.wrapper_digest),
            },
        }
    }

    #[test]
    fn released_srs_opens_existing_local_vault_without_exposing_keys_to_ui() {
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
        let recovered = coordinator
            .recover_existing_vault(
                &repository,
                "00000000-0000-4000-8000-000000000020",
                "00000000-0000-4000-8000-000000000047",
                URL_SAFE_NO_PAD.encode([0x88; 32]),
                erc,
            )
            .expect("released factors should recover the vault");
        assert_eq!(
            recovered
                .read_record(record.id)
                .expect("existing record should decrypt")
                .plaintext(),
            b"existing encrypted item"
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
}
