use core::fmt;

use rusqlite::{Error as SqliteError, ErrorCode};

use crate::crypto::CryptoError;

pub type VaultResult<T> = Result<T, VaultError>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum VaultError {
    AuthenticationFailed,
    AlreadyInitialized,
    AlreadyExists,
    AttachmentNotFound,
    AttachmentTooLarge,
    Busy,
    Conflict,
    Corrupt,
    Internal,
    InvalidFormat,
    InvalidInput,
    ItemInvalidFormat,
    ItemUnsupportedVersion,
    Io,
    Locked,
    NotFound,
    RandomnessUnavailable,
    Uninitialized,
    UnsupportedVersion,
    UploadNotFound,
    UploadPending,
}

impl VaultError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "crypto_authentication_failed",
            Self::AlreadyInitialized => "vault_already_initialized",
            Self::AlreadyExists => "vault_already_exists",
            Self::AttachmentNotFound => "vault_attachment_not_found",
            Self::AttachmentTooLarge => "vault_attachment_too_large",
            Self::Busy => "vault_busy",
            Self::Conflict => "vault_conflict",
            Self::Corrupt => "vault_corrupt",
            Self::Internal => "vault_internal_error",
            Self::InvalidFormat => "vault_invalid_format",
            Self::InvalidInput => "vault_invalid_input",
            Self::ItemInvalidFormat => "vault_item_invalid_format",
            Self::ItemUnsupportedVersion => "vault_item_unsupported_version",
            Self::Io => "vault_io_error",
            Self::Locked => "vault_locked",
            Self::NotFound => "vault_not_found",
            Self::RandomnessUnavailable => "crypto_randomness_unavailable",
            Self::Uninitialized => "vault_uninitialized",
            Self::UnsupportedVersion => "vault_unsupported_version",
            Self::UploadNotFound => "vault_upload_not_found",
            Self::UploadPending => "vault_upload_pending",
        }
    }
}

impl fmt::Debug for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for VaultError {}

impl From<CryptoError> for VaultError {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::AuthenticationFailed => Self::AuthenticationFailed,
            CryptoError::InvalidFormat => Self::InvalidFormat,
            CryptoError::InvalidInput => Self::InvalidInput,
            CryptoError::RandomnessUnavailable => Self::RandomnessUnavailable,
            _ => Self::Io,
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            std::io::ErrorKind::NotFound => Self::NotFound,
            _ => Self::Io,
        }
    }
}

impl From<SqliteError> for VaultError {
    fn from(error: SqliteError) -> Self {
        match error {
            SqliteError::SqliteFailure(inner, _) => match inner.code {
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => Self::Busy,
                ErrorCode::ConstraintViolation => Self::Conflict,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => Self::Corrupt,
                ErrorCode::CannotOpen => Self::Io,
                _ => Self::Corrupt,
            },
            SqliteError::QueryReturnedNoRows => Self::Corrupt,
            _ => Self::Corrupt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VaultError;

    #[test]
    fn errors_are_fixed_and_redacted() {
        for error in [
            VaultError::AuthenticationFailed,
            VaultError::AlreadyInitialized,
            VaultError::AlreadyExists,
            VaultError::AttachmentNotFound,
            VaultError::AttachmentTooLarge,
            VaultError::Busy,
            VaultError::Conflict,
            VaultError::Corrupt,
            VaultError::Internal,
            VaultError::InvalidFormat,
            VaultError::InvalidInput,
            VaultError::ItemInvalidFormat,
            VaultError::ItemUnsupportedVersion,
            VaultError::Io,
            VaultError::Locked,
            VaultError::NotFound,
            VaultError::RandomnessUnavailable,
            VaultError::Uninitialized,
            VaultError::UnsupportedVersion,
            VaultError::UploadNotFound,
            VaultError::UploadPending,
        ] {
            assert_eq!(format!("{error:?}"), error.code());
            assert_eq!(format!("{error}"), error.code());
        }
    }
}
