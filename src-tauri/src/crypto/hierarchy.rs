use core::fmt;

use super::{
    CRYPTO_FORMAT_VERSION,
    primitives::{
        AES_NONCE_LENGTH, CryptoError, CryptoResult, decrypt_vdk, derive_argon2id,
        derive_recovery_kek, encrypt_vdk, fill_random,
    },
    secret::{ErcEntropy, Kek, MasterPassword, MasterSalt, RecoverySalt, Vdk},
};

const AAD_PREFIX: &[u8; 8] = b"AETRNAAD";
const HKDF_PREFIX: &[u8; 12] = b"AETERNA-RKEK";
const AAD_ENCODING_VERSION: u8 = 1;
const HKDF_CONTEXT_VERSION: u8 = 1;
const AES_256_GCM_ID: u8 = 1;
const ARGON2ID_ID: u8 = 1;
const ARGON2_VERSION_13: u8 = 0x13;
const KEK_OUTPUT_LENGTH: u16 = 32;
const MIN_MEMORY_KIB: u32 = 65_536;
const MAX_MEMORY_KIB: u32 = 262_144;
const MIN_TIME_COST: u32 = 1;
const MAX_TIME_COST: u32 = 6;
const MIN_PARALLELISM: u32 = 1;
const MAX_PARALLELISM: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AeadAlgorithm {
    Aes256Gcm = AES_256_GCM_ID,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KdfAlgorithm {
    Argon2id = ARGON2ID_ID,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WrapPurpose {
    MasterVdk = 1,
    RecoveryVdk = 2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VaultId([u8; 16]);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceId([u8; 16]);

impl VaultId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl DeviceId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn storage_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for VaultId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultId([REDACTED])")
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceId([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrapContext {
    pub vault_id: VaultId,
    pub device_id: DeviceId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2Profile {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub output_length: u16,
}

impl Argon2Profile {
    pub const fn new(memory_kib: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_kib,
            time_cost,
            parallelism,
            output_length: KEK_OUTPUT_LENGTH,
        }
    }

    pub fn validate(self) -> CryptoResult<()> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_TIME_COST..=MAX_TIME_COST).contains(&self.time_cost)
            || !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism)
            || self.output_length != KEK_OUTPUT_LENGTH
        {
            return Err(CryptoError::InvalidFormat);
        }
        Ok(())
    }
}

pub struct MasterWrapper {
    pub format_version: u16,
    pub aead_algorithm: u8,
    pub purpose: u8,
    pub kdf_algorithm: u8,
    pub kdf_version: u8,
    pub profile: Argon2Profile,
    pub salt: [u8; 16],
    pub nonce: [u8; AES_NONCE_LENGTH],
    pub ciphertext_and_tag: Vec<u8>,
}

pub struct RecoveryWrapper {
    pub format_version: u16,
    pub aead_algorithm: u8,
    pub purpose: u8,
    pub nonce: [u8; AES_NONCE_LENGTH],
    pub ciphertext_and_tag: Vec<u8>,
}

fn derive_master_kek(
    password: &MasterPassword,
    salt: &[u8; 16],
    profile: Argon2Profile,
) -> CryptoResult<Kek> {
    profile.validate()?;
    derive_argon2id(
        password.expose(),
        salt,
        profile.memory_kib,
        profile.time_cost,
        profile.parallelism,
    )
}

pub fn create_master_wrapper(
    password: &MasterPassword,
    vdk: &Vdk,
    context: WrapContext,
    profile: Argon2Profile,
) -> CryptoResult<MasterWrapper> {
    let salt = MasterSalt::random()?;
    let mut nonce = [0_u8; AES_NONCE_LENGTH];
    fill_random(&mut nonce)?;
    create_master_wrapper_with_material(password, vdk, context, profile, salt, nonce)
}

pub(crate) fn create_master_wrapper_with_material(
    password: &MasterPassword,
    vdk: &Vdk,
    context: WrapContext,
    profile: Argon2Profile,
    salt: MasterSalt,
    nonce: [u8; AES_NONCE_LENGTH],
) -> CryptoResult<MasterWrapper> {
    let kek = derive_master_kek(password, salt.expose(), profile)?;
    let aad = canonical_aad(context, WrapPurpose::MasterVdk);
    let ciphertext_and_tag = encrypt_vdk(&kek, &nonce, vdk.expose(), &aad)?;
    Ok(MasterWrapper {
        format_version: CRYPTO_FORMAT_VERSION,
        aead_algorithm: AeadAlgorithm::Aes256Gcm as u8,
        purpose: WrapPurpose::MasterVdk as u8,
        kdf_algorithm: KdfAlgorithm::Argon2id as u8,
        kdf_version: ARGON2_VERSION_13,
        profile,
        salt: *salt.expose(),
        nonce,
        ciphertext_and_tag,
    })
}

pub fn unwrap_master(
    password: &MasterPassword,
    wrapper: &MasterWrapper,
    context: WrapContext,
) -> CryptoResult<Vdk> {
    validate_master_wrapper(wrapper)?;
    let kek = derive_master_kek(password, &wrapper.salt, wrapper.profile)?;
    let aad = canonical_aad(context, WrapPurpose::MasterVdk);
    decrypt_vdk(&kek, &wrapper.nonce, &wrapper.ciphertext_and_tag, &aad).map(Vdk::from_bytes)
}

pub fn rewrap_master(
    old_password: &MasterPassword,
    new_password: &MasterPassword,
    wrapper: &MasterWrapper,
    context: WrapContext,
    new_profile: Argon2Profile,
) -> CryptoResult<MasterWrapper> {
    let vdk = unwrap_master(old_password, wrapper, context)?;
    create_master_wrapper(new_password, &vdk, context, new_profile)
}

pub fn create_recovery_wrapper(
    erc: &ErcEntropy,
    recovery_salt: &RecoverySalt,
    vdk: &Vdk,
    context: WrapContext,
) -> CryptoResult<RecoveryWrapper> {
    let mut nonce = [0_u8; AES_NONCE_LENGTH];
    fill_random(&mut nonce)?;
    create_recovery_wrapper_with_nonce(erc, recovery_salt, vdk, context, nonce)
}

pub(crate) fn create_recovery_wrapper_with_nonce(
    erc: &ErcEntropy,
    recovery_salt: &RecoverySalt,
    vdk: &Vdk,
    context: WrapContext,
    nonce: [u8; AES_NONCE_LENGTH],
) -> CryptoResult<RecoveryWrapper> {
    let info = canonical_recovery_info(context);
    let kek = derive_recovery_kek(erc.expose(), recovery_salt.expose(), &info)?;
    let aad = canonical_aad(context, WrapPurpose::RecoveryVdk);
    let ciphertext_and_tag = encrypt_vdk(&kek, &nonce, vdk.expose(), &aad)?;
    Ok(RecoveryWrapper {
        format_version: CRYPTO_FORMAT_VERSION,
        aead_algorithm: AeadAlgorithm::Aes256Gcm as u8,
        purpose: WrapPurpose::RecoveryVdk as u8,
        nonce,
        ciphertext_and_tag,
    })
}

pub fn unwrap_recovery(
    erc: &ErcEntropy,
    recovery_salt: &RecoverySalt,
    wrapper: &RecoveryWrapper,
    context: WrapContext,
) -> CryptoResult<Vdk> {
    validate_recovery_wrapper(wrapper)?;
    let info = canonical_recovery_info(context);
    let kek = derive_recovery_kek(erc.expose(), recovery_salt.expose(), &info)?;
    let aad = canonical_aad(context, WrapPurpose::RecoveryVdk);
    decrypt_vdk(&kek, &wrapper.nonce, &wrapper.ciphertext_and_tag, &aad).map(Vdk::from_bytes)
}

fn validate_master_wrapper(wrapper: &MasterWrapper) -> CryptoResult<()> {
    if wrapper.format_version != CRYPTO_FORMAT_VERSION
        || wrapper.aead_algorithm != AES_256_GCM_ID
        || wrapper.purpose != WrapPurpose::MasterVdk as u8
        || wrapper.kdf_algorithm != ARGON2ID_ID
        || wrapper.kdf_version != ARGON2_VERSION_13
        || wrapper.ciphertext_and_tag.len() != 48
    {
        return Err(CryptoError::InvalidFormat);
    }
    wrapper.profile.validate()
}

fn validate_recovery_wrapper(wrapper: &RecoveryWrapper) -> CryptoResult<()> {
    if wrapper.format_version != CRYPTO_FORMAT_VERSION
        || wrapper.aead_algorithm != AES_256_GCM_ID
        || wrapper.purpose != WrapPurpose::RecoveryVdk as u8
        || wrapper.ciphertext_and_tag.len() != 48
    {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(())
}

fn canonical_aad(context: WrapContext, purpose: WrapPurpose) -> [u8; 45] {
    let mut output = [0_u8; 45];
    output[0..8].copy_from_slice(AAD_PREFIX);
    output[8] = AAD_ENCODING_VERSION;
    output[9..11].copy_from_slice(&CRYPTO_FORMAT_VERSION.to_be_bytes());
    output[11] = AES_256_GCM_ID;
    output[12] = purpose as u8;
    output[13..29].copy_from_slice(&context.vault_id.0);
    output[29..45].copy_from_slice(&context.device_id.0);
    output
}

fn canonical_recovery_info(context: WrapContext) -> [u8; 50] {
    let mut output = [0_u8; 50];
    output[0..12].copy_from_slice(HKDF_PREFIX);
    output[12] = HKDF_CONTEXT_VERSION;
    output[13..15].copy_from_slice(&CRYPTO_FORMAT_VERSION.to_be_bytes());
    output[15] = WrapPurpose::RecoveryVdk as u8;
    output[16..32].copy_from_slice(&context.vault_id.0);
    output[32..48].copy_from_slice(&context.device_id.0);
    output[48..50].copy_from_slice(&KEK_OUTPUT_LENGTH.to_be_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> WrapContext {
        WrapContext {
            vault_id: VaultId::new([0x11; 16]),
            device_id: DeviceId::new([0x22; 16]),
        }
    }

    fn password(value: u8) -> MasterPassword {
        match MasterPassword::new(vec![value; 16]) {
            Ok(value) => value,
            Err(_) => panic!("synthetic password is valid"),
        }
    }

    fn profile() -> Argon2Profile {
        Argon2Profile::new(MIN_MEMORY_KIB, 1, 1)
    }

    #[test]
    fn dual_wrappers_recover_the_same_vdk_and_use_distinct_purposes() {
        let vdk = Vdk::from_bytes([0x33; 32]);
        let erc = ErcEntropy::from_bytes([0x44; 16]);
        let recovery_salt = RecoverySalt::from_bytes([0x55; 32]);
        let master = create_master_wrapper_with_material(
            &password(0x66),
            &vdk,
            context(),
            profile(),
            MasterSalt::from_bytes([0x77; 16]),
            [0x88; 12],
        );
        let recovery =
            create_recovery_wrapper_with_nonce(&erc, &recovery_salt, &vdk, context(), [0x99; 12]);
        let (master, recovery) = match (master, recovery) {
            (Ok(master), Ok(recovery)) => (master, recovery),
            _ => panic!("synthetic wrappers should be created"),
        };
        let from_master = unwrap_master(&password(0x66), &master, context());
        let from_recovery = unwrap_recovery(&erc, &recovery_salt, &recovery, context());
        assert!(matches!(from_master, Ok(value) if value.expose() == vdk.expose()));
        assert!(matches!(from_recovery, Ok(value) if value.expose() == vdk.expose()));
        assert_ne!(master.nonce, recovery.nonce);
        assert_ne!(master.purpose, recovery.purpose);
    }

    #[test]
    fn every_master_wrong_input_and_tamper_case_fails_closed() {
        let vdk = Vdk::from_bytes([3; 32]);
        let mut wrapper = match create_master_wrapper_with_material(
            &password(4),
            &vdk,
            context(),
            profile(),
            MasterSalt::from_bytes([5; 16]),
            [6; 12],
        ) {
            Ok(value) => value,
            Err(_) => panic!("synthetic master wrapper should be created"),
        };
        assert!(matches!(
            unwrap_master(&password(9), &wrapper, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        let wrong_vault = WrapContext {
            vault_id: VaultId::new([0; 16]),
            ..context()
        };
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, wrong_vault),
            Err(CryptoError::AuthenticationFailed)
        ));
        let wrong_device = WrapContext {
            device_id: DeviceId::new([0; 16]),
            ..context()
        };
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, wrong_device),
            Err(CryptoError::AuthenticationFailed)
        ));

        wrapper.nonce[0] ^= 1;
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        wrapper.nonce[0] ^= 1;
        wrapper.ciphertext_and_tag[0] ^= 1;
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        wrapper.ciphertext_and_tag[0] ^= 1;
        wrapper.ciphertext_and_tag[47] ^= 1;
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        wrapper.ciphertext_and_tag[47] ^= 1;

        wrapper.format_version = 2;
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
        wrapper.format_version = 1;
        wrapper.aead_algorithm = 99;
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
        wrapper.aead_algorithm = 1;
        wrapper.purpose = WrapPurpose::RecoveryVdk as u8;
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
        wrapper.purpose = WrapPurpose::MasterVdk as u8;
        wrapper.kdf_algorithm = 99;
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
        wrapper.kdf_algorithm = 1;
        wrapper.kdf_version = 0x10;
        assert!(matches!(
            unwrap_master(&password(4), &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
    }

    #[test]
    fn recovery_requires_both_erc_and_independent_salt() {
        let vdk = Vdk::from_bytes([1; 32]);
        let erc = ErcEntropy::from_bytes([2; 16]);
        let salt = RecoverySalt::from_bytes([3; 32]);
        let wrapper = create_recovery_wrapper_with_nonce(&erc, &salt, &vdk, context(), [4; 12]);
        let wrapper = match wrapper {
            Ok(value) => value,
            Err(_) => panic!("synthetic recovery wrapper should be created"),
        };
        assert!(matches!(
            unwrap_recovery(&ErcEntropy::from_bytes([9; 16]), &salt, &wrapper, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(matches!(
            unwrap_recovery(
                &erc,
                &RecoverySalt::from_bytes([9; 32]),
                &wrapper,
                context()
            ),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn every_recovery_metadata_context_and_tamper_case_fails_closed() {
        let vdk = Vdk::from_bytes([0x10; 32]);
        let erc = ErcEntropy::from_bytes([0x20; 16]);
        let recovery_salt = RecoverySalt::from_bytes([0x30; 32]);
        let mut wrapper = match create_recovery_wrapper_with_nonce(
            &erc,
            &recovery_salt,
            &vdk,
            context(),
            [0x40; 12],
        ) {
            Ok(value) => value,
            Err(_) => panic!("synthetic recovery wrapper should be created"),
        };
        let wrong_vault = WrapContext {
            vault_id: VaultId::new([0; 16]),
            ..context()
        };
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, wrong_vault),
            Err(CryptoError::AuthenticationFailed)
        ));
        let wrong_device = WrapContext {
            device_id: DeviceId::new([0; 16]),
            ..context()
        };
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, wrong_device),
            Err(CryptoError::AuthenticationFailed)
        ));
        wrapper.nonce[0] ^= 1;
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        wrapper.nonce[0] ^= 1;
        wrapper.ciphertext_and_tag[0] ^= 1;
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        wrapper.ciphertext_and_tag[0] ^= 1;
        wrapper.ciphertext_and_tag[47] ^= 1;
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        wrapper.ciphertext_and_tag[47] ^= 1;
        wrapper.ciphertext_and_tag.pop();
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
        wrapper.ciphertext_and_tag.push(0);
        wrapper.format_version = 2;
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
        wrapper.format_version = 1;
        wrapper.aead_algorithm = 99;
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
        wrapper.aead_algorithm = 1;
        wrapper.purpose = WrapPurpose::MasterVdk as u8;
        assert!(matches!(
            unwrap_recovery(&erc, &recovery_salt, &wrapper, context()),
            Err(CryptoError::InvalidFormat)
        ));
    }

    #[test]
    fn hostile_profiles_are_rejected_before_argon2_allocation() {
        let invalid = [
            Argon2Profile::new(MIN_MEMORY_KIB - 1, 1, 1),
            Argon2Profile::new(MAX_MEMORY_KIB + 1, 1, 1),
            Argon2Profile::new(MIN_MEMORY_KIB, 0, 1),
            Argon2Profile::new(MIN_MEMORY_KIB, MAX_TIME_COST + 1, 1),
            Argon2Profile::new(MIN_MEMORY_KIB, 1, 0),
            Argon2Profile::new(MIN_MEMORY_KIB, 1, MAX_PARALLELISM + 1),
        ];
        for profile in invalid {
            assert!(matches!(
                profile.validate(),
                Err(CryptoError::InvalidFormat)
            ));
        }
        let mut wrong_output = profile();
        wrong_output.output_length = 31;
        assert!(matches!(
            wrong_output.validate(),
            Err(CryptoError::InvalidFormat)
        ));
    }

    #[test]
    fn password_rewrap_changes_only_the_master_wrapper() {
        let vdk = Vdk::from_bytes([7; 32]);
        let erc = ErcEntropy::from_bytes([8; 16]);
        let recovery_salt = RecoverySalt::from_bytes([9; 32]);
        let recovery =
            create_recovery_wrapper_with_nonce(&erc, &recovery_salt, &vdk, context(), [10; 12]);
        let old = create_master_wrapper_with_material(
            &password(11),
            &vdk,
            context(),
            profile(),
            MasterSalt::from_bytes([12; 16]),
            [13; 12],
        );
        let (recovery, old) = match (recovery, old) {
            (Ok(recovery), Ok(old)) => (recovery, old),
            _ => panic!("synthetic wrappers should be created"),
        };
        let new = rewrap_master(&password(11), &password(14), &old, context(), profile());
        let new = match new {
            Ok(value) => value,
            Err(_) => panic!("master wrapper should be replaced"),
        };
        assert!(
            matches!(unwrap_master(&password(14), &new, context()), Ok(value) if value.expose() == vdk.expose())
        );
        assert!(matches!(
            unwrap_master(&password(11), &new, context()),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(
            matches!(unwrap_recovery(&erc, &recovery_salt, &recovery, context()), Ok(value) if value.expose() == vdk.expose())
        );
    }

    #[test]
    fn generated_salts_and_nonces_are_unique_in_a_bounded_sample() {
        let mut salts = std::collections::BTreeSet::new();
        let mut nonces = std::collections::BTreeSet::new();
        for _ in 0..32 {
            let salt = MasterSalt::random();
            let salt = match salt {
                Ok(value) => value,
                Err(_) => panic!("OS randomness should be available"),
            };
            let mut nonce = [0_u8; AES_NONCE_LENGTH];
            assert!(fill_random(&mut nonce).is_ok());
            assert!(salts.insert(*salt.expose()));
            assert!(nonces.insert(nonce));
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        fixture_name: String,
        format_version: u16,
        memory_kib: u32,
        time_cost: u32,
        parallelism: u32,
        password_hex: String,
        vdk_hex: String,
        erc_entropy_hex: String,
        recovery_salt_hex: String,
        master_salt_hex: String,
        master_nonce_hex: String,
        recovery_nonce_hex: String,
        vault_id_hex: String,
        device_id_hex: String,
        master_ciphertext_and_tag_hex: String,
        recovery_ciphertext_and_tag_hex: String,
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        if !value.len().is_multiple_of(2) {
            panic!("synthetic fixture contains invalid hex length");
        }
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = core::str::from_utf8(pair).unwrap_or_default();
                u8::from_str_radix(text, 16).unwrap_or_default()
            })
            .collect()
    }

    fn fixture_array<const LENGTH: usize>(value: &str) -> [u8; LENGTH] {
        match decode_hex(value).try_into() {
            Ok(value) => value,
            Err(_) => panic!("synthetic fixture contains an invalid field length"),
        }
    }

    #[test]
    fn deterministic_dual_wrapper_fixture_matches_exact_bytes() {
        let fixture: Fixture = match serde_json::from_str(include_str!(
            "../../tests/fixtures/i02-dual-wrapper-v1.json"
        )) {
            Ok(value) => value,
            Err(_) => panic!("synthetic fixture JSON should parse"),
        };
        assert_eq!(
            fixture.fixture_name,
            "CONSPICUOUSLY-SYNTHETIC-I02-DUAL-WRAPPER-V1"
        );
        assert_eq!(fixture.format_version, CRYPTO_FORMAT_VERSION);
        let fixture_context = WrapContext {
            vault_id: VaultId::new(fixture_array(&fixture.vault_id_hex)),
            device_id: DeviceId::new(fixture_array(&fixture.device_id_hex)),
        };
        let fixture_password = match MasterPassword::new(decode_hex(&fixture.password_hex)) {
            Ok(value) => value,
            Err(_) => panic!("synthetic fixture password should be valid"),
        };
        let fixture_vdk = Vdk::from_bytes(fixture_array(&fixture.vdk_hex));
        let master = create_master_wrapper_with_material(
            &fixture_password,
            &fixture_vdk,
            fixture_context,
            Argon2Profile::new(fixture.memory_kib, fixture.time_cost, fixture.parallelism),
            MasterSalt::from_bytes(fixture_array(&fixture.master_salt_hex)),
            fixture_array(&fixture.master_nonce_hex),
        );
        let recovery = create_recovery_wrapper_with_nonce(
            &ErcEntropy::from_bytes(fixture_array(&fixture.erc_entropy_hex)),
            &RecoverySalt::from_bytes(fixture_array(&fixture.recovery_salt_hex)),
            &fixture_vdk,
            fixture_context,
            fixture_array(&fixture.recovery_nonce_hex),
        );
        let (master, recovery) = match (master, recovery) {
            (Ok(master), Ok(recovery)) => (master, recovery),
            _ => panic!("synthetic fixture wrappers should be created"),
        };
        assert!(master.ciphertext_and_tag == decode_hex(&fixture.master_ciphertext_and_tag_hex));
        assert!(
            recovery.ciphertext_and_tag == decode_hex(&fixture.recovery_ciphertext_and_tag_hex)
        );
        assert!(
            matches!(unwrap_master(&fixture_password, &master, fixture_context), Ok(value) if value.expose() == fixture_vdk.expose())
        );
        assert!(matches!(unwrap_recovery(
                &ErcEntropy::from_bytes(fixture_array(&fixture.erc_entropy_hex)),
                &RecoverySalt::from_bytes(fixture_array(&fixture.recovery_salt_hex)),
                &recovery,
                fixture_context,
            ), Ok(value) if value.expose() == fixture_vdk.expose()));
    }
}
