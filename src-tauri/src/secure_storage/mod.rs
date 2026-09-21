//! Narrow device-signing-key storage boundary for the I02 prototype.

use core::fmt;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use crate::crypto::CryptoError;
use crate::crypto::{CryptoResult, DeviceId, SigningSecret};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub const KEYCHAIN_SERVICE: &str = "dev.aeterna.desktop.i02.device-signing";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteOutcome {
    Deleted,
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageBackend {
    MacOsDataProtectionKeychain,
    WindowsCredentialManager,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageProtection {
    WhenUnlockedThisDeviceOnly,
    CurrentUserLocalMachine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRoaming {
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageMetadata {
    pub backend: StorageBackend,
    pub protection: StorageProtection,
    pub roaming: StorageRoaming,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct KeyIdentity {
    account: String,
}

impl KeyIdentity {
    pub fn for_device(device_id: DeviceId) -> Self {
        let mut account = String::with_capacity(35);
        account.push_str("v1:");
        for byte in device_id_bytes(device_id) {
            use core::fmt::Write as _;
            let _ = write!(account, "{byte:02x}");
        }
        Self { account }
    }

    pub(crate) fn account(&self) -> &str {
        &self.account
    }
}

impl fmt::Debug for KeyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyIdentity([REDACTED])")
    }
}

fn device_id_bytes(device_id: DeviceId) -> [u8; 16] {
    device_id.storage_bytes()
}

pub trait DeviceSecretStore {
    fn create(&self, identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()>;
    fn retrieve(&self, identity: &KeyIdentity) -> CryptoResult<SigningSecret>;
    fn replace(&self, identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()>;
    fn delete(&self, identity: &KeyIdentity) -> CryptoResult<DeleteOutcome>;
    fn metadata(&self, identity: &KeyIdentity) -> CryptoResult<StorageMetadata>;
}

#[cfg(target_os = "macos")]
pub use macos::MacOsKeychain as PlatformKeychain;

#[cfg(target_os = "windows")]
pub use windows::WindowsCredentialManager as PlatformKeychain;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub struct PlatformKeychain;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl PlatformKeychain {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl Default for PlatformKeychain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl DeviceSecretStore for PlatformKeychain {
    fn create(&self, _: &KeyIdentity, _: &SigningSecret) -> CryptoResult<()> {
        Err(CryptoError::StorageUnsupported)
    }

    fn retrieve(&self, _: &KeyIdentity) -> CryptoResult<SigningSecret> {
        Err(CryptoError::StorageUnsupported)
    }

    fn replace(&self, _: &KeyIdentity, _: &SigningSecret) -> CryptoResult<()> {
        Err(CryptoError::StorageUnsupported)
    }

    fn delete(&self, _: &KeyIdentity) -> CryptoResult<DeleteOutcome> {
        Err(CryptoError::StorageUnsupported)
    }

    fn metadata(&self, _: &KeyIdentity) -> CryptoResult<StorageMetadata> {
        Err(CryptoError::StorageUnsupported)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use zeroize::Zeroizing;

    use super::*;
    use crate::crypto::{CryptoError, DeviceId, public_key};

    #[derive(Default)]
    struct FakeStore {
        entries: Mutex<HashMap<KeyIdentity, Zeroizing<[u8; 32]>>>,
    }

    impl DeviceSecretStore for FakeStore {
        fn create(&self, identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()> {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| CryptoError::StorageUnavailable)?;
            if entries.contains_key(identity) {
                return Err(CryptoError::StorageAlreadyExists);
            }
            entries.insert(identity.clone(), Zeroizing::new(*secret.storage_bytes()));
            Ok(())
        }

        fn retrieve(&self, identity: &KeyIdentity) -> CryptoResult<SigningSecret> {
            let entries = self
                .entries
                .lock()
                .map_err(|_| CryptoError::StorageUnavailable)?;
            entries
                .get(identity)
                .map(|bytes| SigningSecret::from_storage_bytes(**bytes))
                .ok_or(CryptoError::StorageNotFound)
        }

        fn replace(&self, identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()> {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| CryptoError::StorageUnavailable)?;
            let entry = entries
                .get_mut(identity)
                .ok_or(CryptoError::StorageNotFound)?;
            **entry = *secret.storage_bytes();
            Ok(())
        }

        fn delete(&self, identity: &KeyIdentity) -> CryptoResult<DeleteOutcome> {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| CryptoError::StorageUnavailable)?;
            Ok(if entries.remove(identity).is_some() {
                DeleteOutcome::Deleted
            } else {
                DeleteOutcome::NotFound
            })
        }

        fn metadata(&self, identity: &KeyIdentity) -> CryptoResult<StorageMetadata> {
            let entries = self
                .entries
                .lock()
                .map_err(|_| CryptoError::StorageUnavailable)?;
            if !entries.contains_key(identity) {
                return Err(CryptoError::StorageNotFound);
            }
            Ok(StorageMetadata {
                backend: StorageBackend::MacOsDataProtectionKeychain,
                protection: StorageProtection::WhenUnlockedThisDeviceOnly,
                roaming: StorageRoaming::Disabled,
            })
        }
    }

    #[test]
    fn fake_store_exercises_create_read_replace_delete_and_not_found() {
        let store = FakeStore::default();
        let identity = KeyIdentity::for_device(DeviceId::new([1; 16]));
        let first = SigningSecret::from_storage_bytes([2; 32]);
        let second = SigningSecret::from_storage_bytes([3; 32]);
        assert!(store.create(&identity, &first).is_ok());
        assert!(matches!(
            store.create(&identity, &first),
            Err(CryptoError::StorageAlreadyExists)
        ));
        assert!(
            matches!(store.retrieve(&identity), Ok(value) if public_key(&value) == public_key(&first))
        );
        assert!(store.replace(&identity, &second).is_ok());
        assert!(
            matches!(store.retrieve(&identity), Ok(value) if public_key(&value) == public_key(&second))
        );
        assert!(
            matches!(store.metadata(&identity), Ok(value) if value == StorageMetadata {
                backend: StorageBackend::MacOsDataProtectionKeychain,
                protection: StorageProtection::WhenUnlockedThisDeviceOnly,
                roaming: StorageRoaming::Disabled,
            })
        );
        assert!(matches!(
            store.delete(&identity),
            Ok(DeleteOutcome::Deleted)
        ));
        assert!(matches!(
            store.delete(&identity),
            Ok(DeleteOutcome::NotFound)
        ));
        assert!(matches!(
            store.retrieve(&identity),
            Err(CryptoError::StorageNotFound)
        ));
    }

    #[test]
    fn platform_metadata_types_do_not_claim_equivalent_protection() {
        let macos = StorageMetadata {
            backend: StorageBackend::MacOsDataProtectionKeychain,
            protection: StorageProtection::WhenUnlockedThisDeviceOnly,
            roaming: StorageRoaming::Disabled,
        };
        let windows = StorageMetadata {
            backend: StorageBackend::WindowsCredentialManager,
            protection: StorageProtection::CurrentUserLocalMachine,
            roaming: StorageRoaming::Disabled,
        };
        assert_ne!(macos, windows);
    }
}
