//! Versioned cryptographic risk-prototype building blocks.
//!
//! These modules intentionally expose no Tauri command. They prove bounded,
//! typed backend behavior for I02 and are not a production vault format.

mod benchmark;
mod erc;
mod hierarchy;
mod primitives;
mod secret;
mod signing;

pub use benchmark::{
    Argon2BenchmarkResult, BENCHMARK_SAMPLES, BENCHMARK_WARMUPS, benchmark_argon2_profile,
};
pub use erc::{decode_erc, encode_erc, format_erc_for_display, generate_erc};
pub use hierarchy::{
    AeadAlgorithm, Argon2Profile, DeviceId, KdfAlgorithm, MasterWrapper, RecoveryWrapper, VaultId,
    WrapContext, WrapPurpose, create_master_wrapper, create_recovery_wrapper, rewrap_master,
    unwrap_master, unwrap_recovery,
};
pub use primitives::{CryptoError, CryptoResult};
pub use secret::{ErcEntropy, MasterPassword, RecoverySalt, SigningSecret, Vdk};
pub use signing::{
    DevicePublicKey, DeviceSignature, generate_signing_secret, public_key, sign_message,
    verify_message,
};

pub const CRYPTO_FORMAT_VERSION: u16 = 1;
pub const ERC_FORMAT_VERSION: u8 = 1;
