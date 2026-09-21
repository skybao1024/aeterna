use core::ffi::c_void;
use std::ptr::{self, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BAD_USERNAME, ERROR_INVALID_DATA, ERROR_INVALID_FLAGS,
    ERROR_INVALID_PARAMETER, ERROR_NO_SUCH_LOGON_SESSION, ERROR_NOT_FOUND, GetLastError,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_MAX_USERNAME_LENGTH,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CRED_TYPE_MAXIMUM, CREDENTIALW, CredDeleteW,
    CredFree, CredGetSessionTypes, CredReadW, CredWriteW,
};
use zeroize::{Zeroize, Zeroizing};

use super::{
    DeleteOutcome, DeviceSecretStore, KEYCHAIN_SERVICE, KeyIdentity, StorageBackend,
    StorageMetadata, StorageProtection, StorageRoaming,
};
use crate::crypto::{CryptoError, CryptoResult, SigningSecret, public_key};

const CREDENTIAL_USERNAME: &str = "aeterna-device-signing-v1";
const SIGNING_SECRET_SIZE: usize = 32;

pub struct WindowsCredentialManager;

impl WindowsCredentialManager {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for WindowsCredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceSecretStore for WindowsCredentialManager {
    fn create(&self, identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()> {
        match read_secret(identity) {
            Ok(_) => return Err(CryptoError::StorageAlreadyExists),
            Err(CryptoError::StorageNotFound) => {}
            Err(error) => return Err(error),
        }
        write_secret(identity, secret)?;
        verify_written_secret(identity, secret)
    }

    fn retrieve(&self, identity: &KeyIdentity) -> CryptoResult<SigningSecret> {
        read_secret(identity)
    }

    fn replace(&self, identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()> {
        let existing = read_secret(identity)?;
        drop(existing);
        write_secret(identity, secret)?;
        verify_written_secret(identity, secret)
    }

    fn delete(&self, identity: &KeyIdentity) -> CryptoResult<DeleteOutcome> {
        let target = target_name(identity)?;
        // SAFETY: `target` is a live null-terminated UTF-16 string, the type and
        // flags are the exact values used for every operation in this adapter.
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(DeleteOutcome::Deleted);
        }
        // SAFETY: the failed Win32 call above sets the calling thread's error.
        let error = unsafe { GetLastError() };
        if error == ERROR_NOT_FOUND {
            Ok(DeleteOutcome::NotFound)
        } else {
            Err(classify_error(error))
        }
    }

    fn metadata(&self, identity: &KeyIdentity) -> CryptoResult<StorageMetadata> {
        let secret = read_secret(identity)?;
        drop(secret);
        Ok(StorageMetadata {
            backend: StorageBackend::WindowsCredentialManager,
            protection: StorageProtection::CurrentUserLocalMachine,
            roaming: StorageRoaming::Disabled,
        })
    }
}

struct OwnedCredential {
    pointer: *mut CREDENTIALW,
}

impl OwnedCredential {
    fn get(&self) -> CryptoResult<&CREDENTIALW> {
        // SAFETY: CredReadW returned this non-null pointer and this owner keeps
        // the allocation live until Drop.
        unsafe { self.pointer.as_ref() }.ok_or(CryptoError::StorageUnavailable)
    }
}

impl Drop for OwnedCredential {
    fn drop(&mut self) {
        if self.pointer.is_null() {
            return;
        }
        // SAFETY: the credential allocation stays live until CredFree below.
        // The blob is writable according to CREDENTIALW and is bounded before a
        // mutable slice is constructed.
        unsafe {
            let credential = &mut *self.pointer;
            if !credential.CredentialBlob.is_null()
                && credential.CredentialBlobSize <= CRED_MAX_CREDENTIAL_BLOB_SIZE
                && let Ok(length) = usize::try_from(credential.CredentialBlobSize)
            {
                std::slice::from_raw_parts_mut(credential.CredentialBlob, length).zeroize();
            }
            CredFree(self.pointer.cast::<c_void>());
        }
    }
}

fn target_name(identity: &KeyIdentity) -> CryptoResult<Vec<u16>> {
    let device_hex = identity
        .account()
        .strip_prefix("v1:")
        .filter(|value| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(CryptoError::StorageInvalidConfiguration)?;
    wide_string(&format!("{KEYCHAIN_SERVICE}/v1/{device_hex}"))
}

fn wide_string(value: &str) -> CryptoResult<Vec<u16>> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(CryptoError::StorageInvalidConfiguration);
    }
    let mut encoded: Vec<u16> = value.encode_utf16().collect();
    encoded.push(0);
    Ok(encoded)
}

fn wide_value_matches(pointer: *const u16, expected: &[u16], maximum_units: u32) -> bool {
    if pointer.is_null()
        || expected.is_empty()
        || expected.len() > usize::try_from(maximum_units).unwrap_or(0) + 1
    {
        return false;
    }
    expected.iter().enumerate().all(|(index, expected_unit)| {
        // SAFETY: Windows owns this NUL-terminated field. Reads are bounded by
        // the smaller exact expected value and the documented field maximum.
        unsafe { pointer.add(index).read() == *expected_unit }
    })
}

fn ensure_persistence_supported() -> CryptoResult<()> {
    let mut maximum_persistence = [0_u32; CRED_TYPE_MAXIMUM as usize];
    // SAFETY: the array has exactly the count passed and remains writable for
    // the synchronous query.
    if unsafe {
        CredGetSessionTypes(
            maximum_persistence.len() as u32,
            maximum_persistence.as_mut_ptr(),
        )
    } == 0
    {
        // SAFETY: the failed Win32 call above sets the calling thread's error.
        return Err(classify_error(unsafe { GetLastError() }));
    }
    if maximum_persistence[CRED_TYPE_GENERIC as usize] < CRED_PERSIST_LOCAL_MACHINE {
        return Err(CryptoError::StoragePolicyUnsupported);
    }
    Ok(())
}

fn write_secret(identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()> {
    ensure_persistence_supported()?;
    let mut target = target_name(identity)?;
    let mut username = wide_string(CREDENTIAL_USERNAME)?;
    let mut blob = Zeroizing::new(*secret.storage_bytes());
    let credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        Comment: null_mut(),
        LastWritten: Default::default(),
        CredentialBlobSize: SIGNING_SECRET_SIZE as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: null_mut(),
        TargetAlias: null_mut(),
        UserName: username.as_mut_ptr(),
    };
    // SAFETY: every pointer in `credential` refers to a live buffer for this
    // synchronous call. Optional fields are null and all sizes are exact.
    if unsafe { CredWriteW(&credential, 0) } == 0 {
        // SAFETY: the failed Win32 call above sets the calling thread's error.
        return Err(classify_error(unsafe { GetLastError() }));
    }
    Ok(())
}

fn read_secret(identity: &KeyIdentity) -> CryptoResult<SigningSecret> {
    let target = target_name(identity)?;
    let expected_username = wide_string(CREDENTIAL_USERNAME)?;
    let mut pointer = null_mut();
    // SAFETY: `target` is live and null-terminated; `pointer` is writable and is
    // wrapped immediately on a successful call.
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pointer) } == 0 {
        // SAFETY: the failed Win32 call above sets the calling thread's error.
        return Err(classify_error(unsafe { GetLastError() }));
    }
    let owned = OwnedCredential { pointer };
    let credential = owned.get()?;
    let valid = credential.Flags == 0
        && credential.Type == CRED_TYPE_GENERIC
        && credential.Persist == CRED_PERSIST_LOCAL_MACHINE
        && credential.AttributeCount == 0
        && credential.Attributes.is_null()
        && credential.Comment.is_null()
        && credential.TargetAlias.is_null()
        && credential.CredentialBlobSize == SIGNING_SECRET_SIZE as u32
        && !credential.CredentialBlob.is_null()
        && wide_value_matches(
            credential.TargetName,
            &target,
            CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
        )
        && wide_value_matches(
            credential.UserName,
            &expected_username,
            CRED_MAX_USERNAME_LENGTH,
        );
    if !valid {
        return Err(CryptoError::StorageInvalidConfiguration);
    }

    let mut bytes = Zeroizing::new([0_u8; SIGNING_SECRET_SIZE]);
    // SAFETY: validation above proves the native blob contains exactly 32 bytes
    // and both source and destination are non-overlapping live allocations.
    unsafe {
        ptr::copy_nonoverlapping(
            credential.CredentialBlob,
            bytes.as_mut_ptr(),
            SIGNING_SECRET_SIZE,
        )
    };
    Ok(SigningSecret::from_storage_bytes(*bytes))
}

fn verify_written_secret(identity: &KeyIdentity, expected: &SigningSecret) -> CryptoResult<()> {
    let actual = read_secret(identity)?;
    if public_key(&actual) == public_key(expected) {
        Ok(())
    } else {
        Err(CryptoError::StorageUnavailable)
    }
}

fn classify_error(error: u32) -> CryptoError {
    match error {
        ERROR_NOT_FOUND => CryptoError::StorageNotFound,
        ERROR_ACCESS_DENIED => CryptoError::StorageAccessDenied,
        ERROR_NO_SUCH_LOGON_SESSION => CryptoError::StorageSessionUnavailable,
        ERROR_BAD_USERNAME | ERROR_INVALID_DATA | ERROR_INVALID_FLAGS | ERROR_INVALID_PARAMETER => {
            CryptoError::StorageInvalidConfiguration
        }
        _ => CryptoError::StorageUnavailable,
    }
}
