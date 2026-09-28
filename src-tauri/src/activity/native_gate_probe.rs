//! Fixed-surface native evidence operations for the synthetic I08 activity gate.
//!
//! This module is compiled only into an explicitly feature-gated test build.
//! Production application builds cannot update or delete the gate.

/// Verifies the complete gate identity, value, and metadata without returning
/// any Keychain value or access-group material.
pub fn verify_metadata() -> Result<(), &'static str> {
    super::macos::native_probe_verify_metadata()
}

/// Replaces only the public gate value with the same canonical value, then
/// performs a complete read-back validation.
pub fn update_same_value() -> Result<(), &'static str> {
    super::macos::native_probe_update_same_value()
}

/// Deletes only the exact synthetic gate identity.
///
/// `true` means the item was deleted and `false` means it was already absent.
pub fn delete_exact() -> Result<bool, String> {
    super::macos::native_probe_delete_exact()
}
