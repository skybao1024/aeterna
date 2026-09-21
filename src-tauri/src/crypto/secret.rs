use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::primitives::{CryptoError, CryptoResult, fill_random};

const MAX_PASSWORD_BYTES: usize = 1_024;

macro_rules! fixed_secret {
    ($name:ident, $length:expr, $label:literal) => {
        pub struct $name(Zeroizing<[u8; $length]>);

        impl $name {
            pub(crate) fn from_bytes(bytes: [u8; $length]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            pub(crate) fn expose(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "([REDACTED])"))
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl ZeroizeOnDrop for $name {}
    };
}

fixed_secret!(Vdk, 32, "Vdk");
fixed_secret!(Kek, 32, "Kek");
fixed_secret!(ErcEntropy, 16, "ErcEntropy");
fixed_secret!(RecoverySalt, 32, "RecoverySalt");
fixed_secret!(MasterSalt, 16, "MasterSalt");
fixed_secret!(SigningSecret, 32, "SigningSecret");

fn random_secret<const LENGTH: usize>() -> CryptoResult<[u8; LENGTH]> {
    let mut bytes = [0_u8; LENGTH];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

impl Vdk {
    pub fn generate() -> CryptoResult<Self> {
        random_secret().map(Self::from_bytes)
    }
}

impl ErcEntropy {
    pub fn generate() -> CryptoResult<Self> {
        random_secret().map(Self::from_bytes)
    }
}

impl RecoverySalt {
    pub fn generate() -> CryptoResult<Self> {
        random_secret().map(Self::from_bytes)
    }
}

impl SigningSecret {
    pub fn generate() -> CryptoResult<Self> {
        random_secret().map(Self::from_bytes)
    }

    pub(crate) fn from_storage_bytes(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }

    pub(crate) fn storage_bytes(&self) -> &[u8; 32] {
        self.expose()
    }
}

impl MasterSalt {
    pub(crate) fn random() -> CryptoResult<Self> {
        random_secret().map(Self::from_bytes)
    }
}

pub struct MasterPassword(Zeroizing<Vec<u8>>);

impl MasterPassword {
    pub fn new(mut bytes: Vec<u8>) -> CryptoResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PASSWORD_BYTES {
            bytes.zeroize();
            return Err(CryptoError::InvalidInput);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MasterPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterPassword([REDACTED])")
    }
}

impl Zeroize for MasterPassword {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for MasterPassword {}

#[cfg(test)]
mod tests {
    use super::{ErcEntropy, MasterPassword, SigningSecret, Vdk};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[test]
    fn secret_debug_output_is_redacted() {
        assert_eq!(format!("{:?}", Vdk::from_bytes([7; 32])), "Vdk([REDACTED])");
        assert_eq!(
            format!("{:?}", ErcEntropy::from_bytes([8; 16])),
            "ErcEntropy([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", SigningSecret::from_bytes([9; 32])),
            "SigningSecret([REDACTED])"
        );
        let password = MasterPassword::new(vec![1, 2, 3]);
        assert!(
            matches!(password, Ok(value) if format!("{value:?}") == "MasterPassword([REDACTED])")
        );
    }

    #[test]
    fn master_password_bounds_are_checked_before_derivation() {
        assert!(MasterPassword::new(Vec::new()).is_err());
        assert!(MasterPassword::new(vec![0; 1_025]).is_err());
        assert!(MasterPassword::new(vec![0; 1_024]).is_ok());
    }

    #[test]
    fn secret_wrappers_support_explicit_zeroization_and_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<Vdk>();
        assert_zeroize_on_drop::<ErcEntropy>();
        assert_zeroize_on_drop::<SigningSecret>();
        assert_zeroize_on_drop::<MasterPassword>();

        let mut value = Vdk::from_bytes([0x5a; 32]);
        value.zeroize();
        assert!(value.expose().iter().all(|byte| *byte == 0));
        let mut password = match MasterPassword::new(vec![0x5a; 32]) {
            Ok(value) => value,
            Err(_) => panic!("synthetic password should be valid"),
        };
        password.zeroize();
        assert!(password.expose().is_empty());
    }
}
