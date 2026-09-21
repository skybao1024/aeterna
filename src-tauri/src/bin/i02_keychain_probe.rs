use std::{thread, time::Duration};

use aeterna_lib::{
    crypto::{
        CryptoError, DeviceId, DevicePublicKey, generate_signing_secret, public_key, sign_message,
        verify_message,
    },
    secure_storage::{
        DeleteOutcome, DeviceSecretStore, KeyIdentity, PlatformKeychain, StorageBackend,
        StorageProtection, StorageRoaming,
    },
};

const SYNTHETIC_MESSAGE: &[u8] = b"Aeterna I02 synthetic Keychain probe";

fn identity() -> KeyIdentity {
    KeyIdentity::for_device(DeviceId::new([0xa2; 16]))
}

fn wrong_identity() -> KeyIdentity {
    KeyIdentity::for_device(DeviceId::new([0xb3; 16]))
}

fn public_hex(public: &DevicePublicKey) -> String {
    public
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn create(store: &PlatformKeychain) -> Result<(), CryptoError> {
    let secret = generate_signing_secret()?;
    store.create(&identity(), &secret)?;
    println!(
        "created=true,public_key={}",
        public_hex(&public_key(&secret))
    );
    Ok(())
}

fn sign(store: &PlatformKeychain) -> Result<(), CryptoError> {
    let secret = store.retrieve(&identity())?;
    let public = public_key(&secret);
    let signature = sign_message(&secret, SYNTHETIC_MESSAGE);
    verify_message(&public, SYNTHETIC_MESSAGE, &signature)?;
    println!(
        "retrieved=true,verified=true,public_key={}",
        public_hex(&public)
    );
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
    let old_signature = sign_message(&old, SYNTHETIC_MESSAGE);
    let replacement = generate_signing_secret()?;
    store.replace(&identity(), &replacement)?;
    let persisted = store.retrieve(&identity())?;
    let new_public = public_key(&persisted);
    let new_signature = sign_message(&persisted, SYNTHETIC_MESSAGE);
    if old_public == new_public
        || verify_message(&new_public, SYNTHETIC_MESSAGE, &old_signature).is_ok()
        || verify_message(&new_public, SYNTHETIC_MESSAGE, &new_signature).is_err()
    {
        return Err(CryptoError::StorageUnavailable);
    }
    println!(
        "replaced=true,old_signature_rejected=true,new_signature_verified=true,public_key={}",
        public_hex(&new_public)
    );
    Ok(())
}

fn metadata(store: &PlatformKeychain) -> Result<(), CryptoError> {
    let metadata = store.metadata(&identity())?;
    println!(
        "backend={:?},protection={:?},roaming={:?}",
        metadata.backend, metadata.protection, metadata.roaming,
    );
    if metadata.backend != StorageBackend::MacOsDataProtectionKeychain
        || metadata.protection != StorageProtection::WhenUnlockedThisDeviceOnly
        || metadata.roaming != StorageRoaming::Disabled
    {
        return Err(CryptoError::StorageUnavailable);
    }
    Ok(())
}

fn delete(store: &PlatformKeychain) -> Result<(), CryptoError> {
    let first = store.delete(&identity())?;
    let second = store.delete(&identity())?;
    println!(
        "first_delete={},second_delete={}",
        matches!(first, DeleteOutcome::Deleted),
        matches!(second, DeleteOutcome::NotFound),
    );
    if !matches!(first, DeleteOutcome::Deleted) || !matches!(second, DeleteOutcome::NotFound) {
        return Err(CryptoError::StorageUnavailable);
    }
    Ok(())
}

fn lock_cycle(store: &PlatformKeychain) -> Result<(), CryptoError> {
    let initial = store.retrieve(&identity())?;
    let expected_public = public_key(&initial);
    drop(initial);
    println!("lock_cycle_ready=true,timeout_seconds=180");
    let mut saw_denial = false;
    for _ in 0..180 {
        match store.retrieve(&identity()) {
            Ok(secret) if saw_denial => {
                let recovered = public_key(&secret) == expected_public;
                println!("unlocked_access_recovered={recovered},same_public_key={recovered}");
                return if recovered {
                    Ok(())
                } else {
                    Err(CryptoError::StorageUnavailable)
                };
            }
            Ok(_) => {}
            Err(CryptoError::StorageLocked | CryptoError::StorageAccessDenied) => {
                if !saw_denial {
                    saw_denial = true;
                    println!("locked_access_denied=true");
                }
            }
            Err(error) => return Err(error),
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(CryptoError::StorageUnavailable)
}

fn main() {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    let action = arguments.next();
    if arguments.next().is_some() {
        eprintln!(
            "usage: i02_keychain_probe <create|sign|wrong-identity|replace|metadata|delete|lock-cycle>"
        );
        std::process::exit(2);
    }
    let store = PlatformKeychain::new();
    let result = match action.as_deref() {
        Some("create") => create(&store),
        Some("sign") => sign(&store),
        Some("wrong-identity") => wrong(&store),
        Some("replace") => replace(&store),
        Some("metadata") => metadata(&store),
        Some("delete") => delete(&store),
        Some("lock-cycle") => lock_cycle(&store),
        _ => {
            eprintln!(
                "usage: i02_keychain_probe <create|sign|wrong-identity|replace|metadata|delete|lock-cycle>"
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("keychain_probe_failed={}", error.code());
        std::process::exit(1);
    }
}
