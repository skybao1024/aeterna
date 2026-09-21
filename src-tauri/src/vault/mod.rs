//! Versioned, local-only encrypted vault persistence.
//!
//! The repository exposes only typed operations. It deliberately provides no
//! Tauri command, raw SQL handle, raw key, or generic filesystem capability.

mod error;
mod format;
mod migration;
mod repository;

pub use error::{VaultError, VaultResult};
pub use format::MAX_PLAINTEXT_LENGTH;
pub use repository::{
    DecryptedRecord, RecordId, RecordVersion, RecoveryMaterial, UnlockedVault, VaultBootstrap,
    VaultRepository,
};
