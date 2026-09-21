use core::fmt;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::secret::Kek;

pub const AES_NONCE_LENGTH: usize = 12;
pub const AES_TAG_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    AuthenticationFailed,
    InvalidFormat,
    InvalidInput,
    RandomnessUnavailable,
    StorageUnavailable,
    StorageNotFound,
    StorageAlreadyExists,
    StorageAccessDenied,
    StorageInvalidConfiguration,
    StorageKeychainUnavailable,
    StorageLocked,
    StorageMissingEntitlement,
    StorageSessionUnavailable,
    StoragePolicyUnsupported,
    StorageUnsupported,
}

impl CryptoError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "crypto_authentication_failed",
            Self::InvalidFormat => "crypto_invalid_format",
            Self::InvalidInput => "crypto_invalid_input",
            Self::RandomnessUnavailable => "crypto_randomness_unavailable",
            Self::StorageUnavailable => "secure_storage_unavailable",
            Self::StorageNotFound => "secure_storage_not_found",
            Self::StorageAlreadyExists => "secure_storage_already_exists",
            Self::StorageAccessDenied => "secure_storage_access_denied",
            Self::StorageInvalidConfiguration => "secure_storage_invalid_configuration",
            Self::StorageKeychainUnavailable => "secure_storage_keychain_unavailable",
            Self::StorageLocked => "secure_storage_locked",
            Self::StorageMissingEntitlement => "secure_storage_missing_entitlement",
            Self::StorageSessionUnavailable => "secure_storage_session_unavailable",
            Self::StoragePolicyUnsupported => "secure_storage_policy_unsupported",
            Self::StorageUnsupported => "secure_storage_unsupported",
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CryptoError {}

pub type CryptoResult<T> = Result<T, CryptoError>;

pub(crate) fn fill_random(output: &mut [u8]) -> CryptoResult<()> {
    getrandom::fill(output).map_err(|_| CryptoError::RandomnessUnavailable)
}

pub(crate) fn derive_argon2id(
    password: &[u8],
    salt: &[u8; 16],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> CryptoResult<Kek> {
    let params = Params::new(memory_kib, time_cost, parallelism, Some(32))
        .map_err(|_| CryptoError::InvalidInput)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let block_count = usize::try_from(memory_kib).map_err(|_| CryptoError::InvalidInput)?;
    let mut memory = Zeroizing::new(vec![Block::default(); block_count]);
    let mut output = [0_u8; 32];
    argon
        .hash_password_into_with_memory(password, salt, &mut output, &mut memory[..])
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(Kek::from_bytes(output))
}

pub(crate) fn derive_recovery_kek(
    erc: &[u8; 16],
    salt: &[u8; 32],
    info: &[u8],
) -> CryptoResult<Kek> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), erc);
    let mut output = [0_u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(Kek::from_bytes(output))
}

pub(crate) fn encrypt_vdk(
    kek: &Kek,
    nonce: &[u8; AES_NONCE_LENGTH],
    plaintext: &[u8; 32],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kek.expose()).map_err(|_| CryptoError::InvalidInput)?;
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub(crate) fn decrypt_vdk(
    kek: &Kek,
    nonce: &[u8; AES_NONCE_LENGTH],
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<[u8; 32]> {
    if ciphertext.len() != 32 + AES_TAG_LENGTH {
        return Err(CryptoError::InvalidFormat);
    }
    let cipher = Aes256Gcm::new_from_slice(kek.expose()).map_err(|_| CryptoError::InvalidInput)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidFormat);
    }
    let mut output = [0_u8; 32];
    output.copy_from_slice(&plaintext);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, Payload},
    };
    use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
    use ed25519_dalek::{Signer, SigningKey};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    fn hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2));
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = core::str::from_utf8(pair);
                match text {
                    Ok(text) => u8::from_str_radix(text, 16).unwrap_or_default(),
                    Err(_) => 0,
                }
            })
            .collect()
    }

    #[test]
    fn rfc_9106_argon2id_version_19_vector() {
        let mut builder = ParamsBuilder::new();
        builder
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(AssociatedData::new(&[4_u8; 12]).unwrap_or_default());
        let params = match builder.build() {
            Ok(value) => value,
            Err(_) => panic!("invalid published Argon2 parameters"),
        };
        let argon = match Argon2::new_with_secret(
            &[3_u8; 8],
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        ) {
            Ok(value) => value,
            Err(_) => panic!("invalid published Argon2 secret"),
        };
        let mut memory = Zeroizing::new(vec![Block::default(); 32]);
        let mut actual = [0_u8; 32];
        let result = argon.hash_password_into_with_memory(
            &[1_u8; 32],
            &[2_u8; 16],
            &mut actual,
            &mut memory[..],
        );
        assert!(result.is_ok());
        assert!(
            actual.as_slice()
                == hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    #[test]
    fn rfc_5869_sha256_test_case_one() {
        let ikm = [0x0b_u8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut actual = [0_u8; 42];
        assert!(hkdf.expand(&info, &mut actual).is_ok());
        assert!(
            actual.as_slice()
                == hex(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
                )
        );
    }

    #[test]
    fn nist_aes_256_gcm_zero_key_vector_and_rejections() {
        let cipher = Aes256Gcm::new_from_slice(&[0_u8; 32]);
        let cipher = match cipher {
            Ok(value) => value,
            Err(_) => panic!("invalid AES-256 key length"),
        };
        let nonce = [0_u8; 12];
        let plaintext = [0_u8; 16];
        let actual = cipher.encrypt((&nonce).into(), plaintext.as_slice());
        let actual = match actual {
            Ok(value) => value,
            Err(_) => panic!("published AES-GCM encryption failed"),
        };
        assert!(actual == hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"));
        assert!(cipher.decrypt((&nonce).into(), actual.as_slice()).is_ok());

        let aad_result = cipher.encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext.as_slice(),
                aad: b"synthetic-aad",
            },
        );
        let mut with_aad = match aad_result {
            Ok(value) => value,
            Err(_) => panic!("AES-GCM AAD encryption failed"),
        };
        with_aad[0] ^= 1;
        assert!(
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &with_aad,
                        aad: b"synthetic-aad",
                    },
                )
                .is_err()
        );
        assert!(
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &with_aad,
                        aad: b"wrong-aad",
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn rfc_8032_ed25519_test_one() {
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let seed: [u8; 32] = match seed.try_into() {
            Ok(value) => value,
            Err(_) => panic!("invalid published Ed25519 seed"),
        };
        let signing = SigningKey::from_bytes(&seed);
        assert!(
            signing.verifying_key().as_bytes().as_slice()
                == hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        assert!(
            signing.sign(&[]).to_bytes().as_slice()
                == hex(
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                )
        );
    }

    #[test]
    fn error_strings_are_fixed_codes() {
        use super::CryptoError;

        let errors = [
            (
                CryptoError::AuthenticationFailed,
                "crypto_authentication_failed",
            ),
            (CryptoError::InvalidFormat, "crypto_invalid_format"),
            (CryptoError::InvalidInput, "crypto_invalid_input"),
            (
                CryptoError::RandomnessUnavailable,
                "crypto_randomness_unavailable",
            ),
            (
                CryptoError::StorageUnavailable,
                "secure_storage_unavailable",
            ),
            (CryptoError::StorageNotFound, "secure_storage_not_found"),
            (
                CryptoError::StorageAlreadyExists,
                "secure_storage_already_exists",
            ),
            (
                CryptoError::StorageAccessDenied,
                "secure_storage_access_denied",
            ),
            (
                CryptoError::StorageInvalidConfiguration,
                "secure_storage_invalid_configuration",
            ),
            (
                CryptoError::StorageKeychainUnavailable,
                "secure_storage_keychain_unavailable",
            ),
            (CryptoError::StorageLocked, "secure_storage_locked"),
            (
                CryptoError::StorageMissingEntitlement,
                "secure_storage_missing_entitlement",
            ),
            (
                CryptoError::StorageSessionUnavailable,
                "secure_storage_session_unavailable",
            ),
            (
                CryptoError::StoragePolicyUnsupported,
                "secure_storage_policy_unsupported",
            ),
            (
                CryptoError::StorageUnsupported,
                "secure_storage_unsupported",
            ),
        ];
        for (error, expected) in errors {
            assert_eq!(error.to_string(), expected);
        }
    }
}
