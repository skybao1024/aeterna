//! Versioned, local-only encrypted vault persistence.
//!
//! The repository exposes only typed operations. It deliberately provides no
//! Tauri command, raw SQL handle, raw key, or generic filesystem capability.

mod error;
mod format;
mod item;
mod migration;
mod repository;

pub use error::{VaultError, VaultResult};
pub use format::MAX_PLAINTEXT_LENGTH;
pub(crate) use item::validate_attachment_input;
pub use item::{
    AttachmentId, ItemDraft, ItemKind, ItemSummary, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_COUNT,
    MAX_BODY_BYTES, MAX_CATEGORY_BYTES, MAX_CONTACT_EXPLANATION_BYTES, MAX_FILENAME_BYTES,
    MAX_MEDIA_TYPE_BYTES, MAX_TITLE_BYTES, VaultAttachment, VaultItem,
};
pub use repository::{
    DecryptedRecord, RecordId, RecordVersion, RecoveryMaterial, UnlockedVault, VaultBootstrap,
    VaultRepository,
};
