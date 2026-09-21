use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::{
    primitives::{CryptoError, CryptoResult},
    secret::SigningSecret,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevicePublicKey([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSignature([u8; 64]);

impl DevicePublicKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl DeviceSignature {
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

pub fn generate_signing_secret() -> CryptoResult<SigningSecret> {
    SigningSecret::generate()
}

pub fn public_key(secret: &SigningSecret) -> DevicePublicKey {
    let signing = SigningKey::from_bytes(secret.expose());
    DevicePublicKey(*signing.verifying_key().as_bytes())
}

pub fn sign_message(secret: &SigningSecret, message: &[u8]) -> DeviceSignature {
    let signing = SigningKey::from_bytes(secret.expose());
    DeviceSignature(signing.sign(message).to_bytes())
}

pub fn verify_message(
    public_key: &DevicePublicKey,
    message: &[u8],
    signature: &DeviceSignature,
) -> CryptoResult<()> {
    let verifying = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    verifying
        .verify_strict(message, &signature)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_signing_rejects_modified_inputs_and_separates_keys() {
        let first = SigningSecret::from_bytes([1; 32]);
        let second = SigningSecret::from_bytes([2; 32]);
        let public = public_key(&first);
        let other_public = public_key(&second);
        let signature = sign_message(&first, b"synthetic request");
        assert!(verify_message(&public, b"synthetic request", &signature).is_ok());
        assert!(verify_message(&public, b"modified request", &signature).is_err());
        assert!(verify_message(&other_public, b"synthetic request", &signature).is_err());
        let mut modified = *signature.as_bytes();
        modified[0] ^= 1;
        assert!(
            verify_message(
                &public,
                b"synthetic request",
                &DeviceSignature::from_bytes(modified)
            )
            .is_err()
        );
        assert_ne!(public, other_public);
    }
}
