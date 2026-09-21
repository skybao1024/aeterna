use std::ptr;

use core_foundation::string::CFStringRef;
use core_foundation::{
    base::{CFEqual, CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryGetValueIfPresent},
    string::CFString,
};
use security_framework_sys::{
    access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    base::{
        errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecDuplicateItem as ERR_SEC_DUPLICATE_ITEM,
        errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND, errSecParam as ERR_SEC_PARAM,
        errSecSuccess as ERR_SEC_SUCCESS,
    },
    item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnAttributes, kSecReturnData,
        kSecUseDataProtectionKeychain, kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate},
};

use super::{
    DeleteOutcome, DeviceSecretStore, KEYCHAIN_SERVICE, KeyIdentity, StorageBackend,
    StorageMetadata, StorageProtection, StorageRoaming,
};
use crate::crypto::{CryptoError, CryptoResult, SigningSecret};

const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;

// SAFETY CONTRACT: this declaration matches the public Security.framework
// `CFStringRef` symbol from SecItem.h on every supported macOS target.
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
}

macro_rules! security_constant {
    ($constant:ident) => {{
        // SAFETY: Security.framework exports these process-lifetime CFString
        // constants on the supported macOS target; callers retain them before
        // storing them in an owned Core Foundation object.
        unsafe { $constant }
    }};
}

pub struct MacOsKeychain;

impl MacOsKeychain {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for MacOsKeychain {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceSecretStore for MacOsKeychain {
    fn create(&self, identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()> {
        let query = item_dictionary(identity, Some(secret), true);
        // SAFETY: `query` owns every key/value for the duration of the call. No
        // result object is requested, so the null output pointer is permitted.
        let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut()) };
        match status {
            ERR_SEC_SUCCESS => Ok(()),
            ERR_SEC_DUPLICATE_ITEM => Err(CryptoError::StorageAlreadyExists),
            other => Err(classify_status(other)),
        }
    }

    fn retrieve(&self, identity: &KeyIdentity) -> CryptoResult<SigningSecret> {
        let query = retrieval_dictionary(identity, false);
        let value = copy_matching(&query)?;
        let data = value
            .downcast::<CFData>()
            .ok_or(CryptoError::StorageUnavailable)?;
        let bytes: [u8; 32] = data
            .bytes()
            .try_into()
            .map_err(|_| CryptoError::StorageUnavailable)?;
        Ok(SigningSecret::from_storage_bytes(bytes))
    }

    fn replace(&self, identity: &KeyIdentity, secret: &SigningSecret) -> CryptoResult<()> {
        let query = identity_dictionary(identity);
        let updates = update_dictionary(secret);
        // SAFETY: both dictionaries own their objects for the duration of the
        // synchronous SecItemUpdate call and contain only supported attributes.
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), updates.as_concrete_TypeRef()) };
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(classify_status(status))
        }
    }

    fn delete(&self, identity: &KeyIdentity) -> CryptoResult<DeleteOutcome> {
        let query = identity_dictionary(identity);
        // SAFETY: `query` remains alive for the synchronous delete operation.
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        match status {
            ERR_SEC_SUCCESS => Ok(DeleteOutcome::Deleted),
            ERR_SEC_ITEM_NOT_FOUND => Ok(DeleteOutcome::NotFound),
            other => Err(classify_status(other)),
        }
    }

    fn metadata(&self, identity: &KeyIdentity) -> CryptoResult<StorageMetadata> {
        let query = retrieval_dictionary(identity, true);
        let value = copy_matching(&query)?;
        let attributes = value
            .downcast::<CFDictionary>()
            .ok_or(CryptoError::StorageUnavailable)?;
        let accessible = dictionary_value_matches(
            &attributes,
            static_string(security_constant!(kSecAttrAccessible)),
            static_string(security_constant!(
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            )),
        );
        let synchronizable = dictionary_value_matches(
            &attributes,
            static_string(security_constant!(kSecAttrSynchronizable)),
            CFBoolean::true_value().into_CFType(),
        );
        if !accessible || synchronizable {
            return Err(CryptoError::StorageInvalidConfiguration);
        }
        Ok(StorageMetadata {
            backend: StorageBackend::MacOsDataProtectionKeychain,
            protection: StorageProtection::WhenUnlockedThisDeviceOnly,
            roaming: StorageRoaming::Disabled,
        })
    }
}

fn identity_dictionary(identity: &KeyIdentity) -> CFDictionary<CFType, CFType> {
    dictionary(vec![
        static_pair(
            security_constant!(kSecClass),
            security_constant!(kSecClassGenericPassword),
        ),
        (
            static_string(security_constant!(kSecUseDataProtectionKeychain)),
            CFBoolean::true_value().into_CFType(),
        ),
        (
            static_string(security_constant!(kSecAttrService)),
            CFString::new(KEYCHAIN_SERVICE).into_CFType(),
        ),
        (
            static_string(security_constant!(kSecAttrAccount)),
            CFString::new(identity.account()).into_CFType(),
        ),
    ])
}

fn item_dictionary(
    identity: &KeyIdentity,
    secret: Option<&SigningSecret>,
    include_policy: bool,
) -> CFDictionary<CFType, CFType> {
    let mut pairs = identity_pairs(identity);
    if include_policy {
        pairs.push(static_pair(
            security_constant!(kSecAttrAccessible),
            security_constant!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
        ));
        pairs.push((
            static_string(security_constant!(kSecAttrSynchronizable)),
            CFBoolean::false_value().into_CFType(),
        ));
    }
    if let Some(secret) = secret {
        pairs.push((
            static_string(security_constant!(kSecValueData)),
            CFData::from_buffer(secret.storage_bytes()).into_CFType(),
        ));
    }
    dictionary(pairs)
}

fn retrieval_dictionary(identity: &KeyIdentity, attributes: bool) -> CFDictionary<CFType, CFType> {
    let mut pairs = identity_pairs(identity);
    pairs.push((
        static_string(if attributes {
            security_constant!(kSecReturnAttributes)
        } else {
            security_constant!(kSecReturnData)
        }),
        CFBoolean::true_value().into_CFType(),
    ));
    dictionary(pairs)
}

fn update_dictionary(secret: &SigningSecret) -> CFDictionary<CFType, CFType> {
    dictionary(vec![
        (
            static_string(security_constant!(kSecValueData)),
            CFData::from_buffer(secret.storage_bytes()).into_CFType(),
        ),
        static_pair(
            security_constant!(kSecAttrAccessible),
            security_constant!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
        ),
        (
            static_string(security_constant!(kSecAttrSynchronizable)),
            CFBoolean::false_value().into_CFType(),
        ),
    ])
}

fn identity_pairs(identity: &KeyIdentity) -> Vec<(CFType, CFType)> {
    vec![
        static_pair(
            security_constant!(kSecClass),
            security_constant!(kSecClassGenericPassword),
        ),
        (
            static_string(security_constant!(kSecUseDataProtectionKeychain)),
            CFBoolean::true_value().into_CFType(),
        ),
        (
            static_string(security_constant!(kSecAttrService)),
            CFString::new(KEYCHAIN_SERVICE).into_CFType(),
        ),
        (
            static_string(security_constant!(kSecAttrAccount)),
            CFString::new(identity.account()).into_CFType(),
        ),
    ]
}

fn dictionary(pairs: Vec<(CFType, CFType)>) -> CFDictionary<CFType, CFType> {
    CFDictionary::from_CFType_pairs(&pairs)
}

fn static_pair(key: CFStringRef, value: CFStringRef) -> (CFType, CFType) {
    (static_string(key), static_string(value))
}

fn static_string(reference: core_foundation::string::CFStringRef) -> CFType {
    // SAFETY: Security.framework exports immortal CFString constants. The get
    // rule wrapper retains a reference which CFType releases exactly once.
    unsafe { CFString::wrap_under_get_rule(reference) }.into_CFType()
}

fn copy_matching(query: &CFDictionary<CFType, CFType>) -> CryptoResult<CFType> {
    let mut result = ptr::null();
    // SAFETY: the output starts null. On success SecItemCopyMatching returns a
    // Copy-rule object which is wrapped exactly once below; on failure Apple
    // returns no owned object and it is not dereferenced.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status != ERR_SEC_SUCCESS {
        return Err(classify_status(status));
    }
    if result.is_null() {
        return Err(CryptoError::StorageUnavailable);
    }
    // SAFETY: successful Copy-rule result is non-null and transferred to this
    // one owning wrapper.
    Ok(unsafe { CFType::wrap_under_create_rule(result) })
}

fn dictionary_value_matches(dictionary: &CFDictionary, key: CFType, expected: CFType) -> bool {
    let mut value = ptr::null();
    // SAFETY: the dictionary and key remain owned for the lookup. The returned
    // value is borrowed from the dictionary and is not released here.
    let found = unsafe {
        CFDictionaryGetValueIfPresent(
            dictionary.as_concrete_TypeRef(),
            key.as_concrete_TypeRef().cast(),
            &mut value,
        )
    };
    found != 0
        && !value.is_null()
        // SAFETY: both values are valid CF objects owned for this comparison.
        && unsafe { CFEqual(value.cast(), expected.as_concrete_TypeRef()) != 0 }
}

fn classify_status(status: i32) -> CryptoError {
    match status {
        ERR_SEC_ITEM_NOT_FOUND => CryptoError::StorageNotFound,
        ERR_SEC_DUPLICATE_ITEM => CryptoError::StorageAlreadyExists,
        ERR_SEC_AUTH_FAILED => CryptoError::StorageAccessDenied,
        ERR_SEC_INTERACTION_NOT_ALLOWED => CryptoError::StorageLocked,
        ERR_SEC_MISSING_ENTITLEMENT => CryptoError::StorageMissingEntitlement,
        ERR_SEC_NOT_AVAILABLE => CryptoError::StorageKeychainUnavailable,
        ERR_SEC_PARAM => CryptoError::StorageInvalidConfiguration,
        _ => CryptoError::StorageUnavailable,
    }
}
