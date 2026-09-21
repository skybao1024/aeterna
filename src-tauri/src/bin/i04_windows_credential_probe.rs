#[cfg(target_os = "windows")]
mod windows_probe {
    use std::{thread, time::Duration};

    use aeterna_lib::{
        crypto::{
            CryptoError, DeviceId, generate_signing_secret, public_key, sign_message,
            verify_message,
        },
        secure_storage::{
            DeleteOutcome, DeviceSecretStore, KeyIdentity, PlatformKeychain, StorageBackend,
            StorageProtection, StorageRoaming,
        },
    };

    const SYNTHETIC_MESSAGE: &[u8] = b"Aeterna I04 synthetic Credential Manager probe";

    fn identity() -> KeyIdentity {
        KeyIdentity::for_device(DeviceId::new([0xc4; 16]))
    }

    fn wrong_identity() -> KeyIdentity {
        KeyIdentity::for_device(DeviceId::new([0xd5; 16]))
    }

    fn create(store: &PlatformKeychain) -> Result<(), CryptoError> {
        let secret = generate_signing_secret()?;
        store.create(&identity(), &secret)?;
        println!("created=true");
        Ok(())
    }

    fn sign(store: &PlatformKeychain) -> Result<(), CryptoError> {
        let secret = store.retrieve(&identity())?;
        let public = public_key(&secret);
        let signature = sign_message(&secret, SYNTHETIC_MESSAGE);
        verify_message(&public, SYNTHETIC_MESSAGE, &signature)?;
        println!("retrieved=true,signature_verified=true");
        Ok(())
    }

    fn wrong(store: &PlatformKeychain) -> Result<(), CryptoError> {
        match store.retrieve(&wrong_identity()) {
            Err(CryptoError::StorageNotFound) => {
                println!("wrong_identity_not_found=true,fallback=false");
                Ok(())
            }
            Err(error) => Err(error),
            Ok(_) => Err(CryptoError::StorageUnavailable),
        }
    }

    fn replace(store: &PlatformKeychain) -> Result<(), CryptoError> {
        let old = store.retrieve(&identity())?;
        let old_public = public_key(&old);
        let replacement = generate_signing_secret()?;
        store.replace(&identity(), &replacement)?;
        let persisted = store.retrieve(&identity())?;
        if old_public == public_key(&persisted)
            || public_key(&replacement) != public_key(&persisted)
        {
            return Err(CryptoError::StorageUnavailable);
        }
        println!("replaced=true,replacement_verified=true");
        Ok(())
    }

    fn metadata(store: &PlatformKeychain) -> Result<(), CryptoError> {
        let metadata = store.metadata(&identity())?;
        let valid = metadata.backend == StorageBackend::WindowsCredentialManager
            && metadata.protection == StorageProtection::CurrentUserLocalMachine
            && metadata.roaming == StorageRoaming::Disabled;
        println!("metadata_valid={valid},roaming=false");
        if valid {
            Ok(())
        } else {
            Err(CryptoError::StorageInvalidConfiguration)
        }
    }

    fn lock_cycle(store: &PlatformKeychain) -> Result<(), CryptoError> {
        let expected = public_key(&store.retrieve(&identity())?);
        println!("lock_cycle_ready=true,delay_seconds=15");
        thread::sleep(Duration::from_secs(15));
        match store.retrieve(&identity()) {
            Ok(secret) => {
                let same_secret = public_key(&secret) == expected;
                println!("locked_read_result=available,same_public_key={same_secret}");
                if same_secret {
                    Ok(())
                } else {
                    Err(CryptoError::StorageUnavailable)
                }
            }
            Err(CryptoError::StorageAccessDenied | CryptoError::StorageSessionUnavailable) => {
                println!("locked_read_result=denied");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn delete(store: &PlatformKeychain) -> Result<(), CryptoError> {
        let first = store.delete(&identity())?;
        let second = store.delete(&identity())?;
        let valid = first == DeleteOutcome::Deleted && second == DeleteOutcome::NotFound;
        println!("deleted_and_not_found={valid}");
        if valid {
            Ok(())
        } else {
            Err(CryptoError::StorageUnavailable)
        }
    }

    pub fn run() -> i32 {
        let mut arguments = std::env::args();
        let _program = arguments.next();
        let action = arguments.next();
        if arguments.next().is_some() {
            eprintln!(
                "usage: i04_windows_credential_probe <create|sign|wrong-identity|replace|metadata|lock-cycle|delete>"
            );
            return 2;
        }
        let store = PlatformKeychain::new();
        let result = match action.as_deref() {
            Some("create") => create(&store),
            Some("sign") => sign(&store),
            Some("wrong-identity") => wrong(&store),
            Some("replace") => replace(&store),
            Some("metadata") => metadata(&store),
            Some("lock-cycle") => lock_cycle(&store),
            Some("delete") => delete(&store),
            _ => {
                eprintln!(
                    "usage: i04_windows_credential_probe <create|sign|wrong-identity|replace|metadata|lock-cycle|delete>"
                );
                return 2;
            }
        };
        match result {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("credential_probe_failed={}", error.code());
                1
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(windows_probe::run());
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("i04_windows_credential_probe is supported only on Windows.");
    std::process::exit(2);
}
