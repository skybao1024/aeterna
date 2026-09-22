use core::fmt;
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, TransactionBehavior, config::DbConfig, limits::Limit,
    params,
};
use zeroize::Zeroizing;

use crate::crypto::{
    Argon2Profile, DeviceId, ErcEntropy, MasterPassword, MasterSalt, MasterWrapper, RecoverySalt,
    RecoveryWrapper, VaultId, Vdk, WrapContext, create_master_wrapper_with_material,
    create_recovery_wrapper_with_nonce, decrypt_payload, encrypt_payload, fill_random,
    unwrap_master, unwrap_recovery,
};

use super::{
    VaultError, VaultResult,
    format::{
        self, HeaderRow, MasterRow, RecoveryRow, decode_frame, encode_frame, header_aad,
        read_array, record_aad, wrapper_digest,
    },
    migration::{self, to_sql_integer},
};

const MAX_VAULT_FILE_BYTES: u64 = 1_073_741_824;
const SQLITE_VALUE_LIMIT: i32 = 1_100_000;
const NONCE_ATTEMPTS: usize = 16;
const RANDOM_ID_ATTEMPTS: usize = 16;
const MASTER_NONCE_PURPOSE: i64 = 1;
const RECOVERY_NONCE_PURPOSE: i64 = 2;
const HEADER_NONCE_PURPOSE: i64 = 3;
const RECORD_NONCE_PURPOSE: i64 = 4;

trait RandomSource: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> VaultResult<()>;
}

struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&self, output: &mut [u8]) -> VaultResult<()> {
        fill_random(output).map_err(Into::into)
    }
}

trait Clock: Send + Sync {
    fn now_ms(&self) -> VaultResult<u64>;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> VaultResult<u64> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VaultError::InvalidInput)?;
        u64::try_from(duration.as_millis()).map_err(|_| VaultError::InvalidInput)
    }
}

struct Runtime {
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl Runtime {
    fn production() -> Arc<Self> {
        Arc::new(Self {
            random: Arc::new(SystemRandom),
            clock: Arc::new(SystemClock),
        })
    }
}

#[derive(Clone)]
pub struct VaultRepository {
    path: PathBuf,
    runtime: Arc<Runtime>,
}

impl fmt::Debug for VaultRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultRepository([REDACTED PATH])")
    }
}

pub struct RecoveryMaterial {
    erc: ErcEntropy,
    recovery_salt: RecoverySalt,
}

impl RecoveryMaterial {
    pub fn erc(&self) -> &ErcEntropy {
        &self.erc
    }

    pub fn recovery_salt(&self) -> &RecoverySalt {
        &self.recovery_salt
    }
}

impl fmt::Debug for RecoveryMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryMaterial([REDACTED])")
    }
}

pub struct VaultBootstrap {
    repository: VaultRepository,
    recovery_material: RecoveryMaterial,
}

impl VaultBootstrap {
    pub fn repository(&self) -> &VaultRepository {
        &self.repository
    }

    pub fn recovery_material(&self) -> &RecoveryMaterial {
        &self.recovery_material
    }

    pub fn into_parts(self) -> (VaultRepository, RecoveryMaterial) {
        (self.repository, self.recovery_material)
    }
}

impl fmt::Debug for VaultBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultBootstrap([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RecordId([u8; 16]);

impl RecordId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecordId([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordVersion {
    pub id: RecordId,
    pub generation: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

pub struct DecryptedRecord {
    pub id: RecordId,
    pub generation: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

impl DecryptedRecord {
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

impl fmt::Debug for DecryptedRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedRecord")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

pub struct UnlockedVault {
    repository: VaultRepository,
    vdk: Vdk,
    vault_id: [u8; 16],
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnlockedVault([REDACTED])")
    }
}

struct VaultMetadata {
    header: HeaderRow,
    master: MasterRow,
    recovery: RecoveryRow,
}

impl VaultRepository {
    pub fn initialize(
        path: impl AsRef<Path>,
        password: &MasterPassword,
        profile: Argon2Profile,
    ) -> VaultResult<VaultBootstrap> {
        profile.validate()?;
        Self::initialize_with_runtime(path.as_ref(), password, profile, Runtime::production())
    }

    pub fn open(path: impl AsRef<Path>) -> VaultResult<Self> {
        Self::open_with_runtime(path.as_ref(), Runtime::production())
    }

    fn open_with_runtime(path: &Path, runtime: Arc<Runtime>) -> VaultResult<Self> {
        preflight_vault_files(path)?;
        let repository = Self {
            path: path.to_path_buf(),
            runtime,
        };
        let connection = repository.connection()?;
        let metadata = load_metadata(&connection)?;
        validate_header_versions(&metadata.header)?;
        Ok(repository)
    }

    fn initialize_with_runtime(
        path: &Path,
        password: &MasterPassword,
        profile: Argon2Profile,
        runtime: Arc<Runtime>,
    ) -> VaultResult<VaultBootstrap> {
        ensure_target_absent(path)?;
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let (staging_path, staging_file) = create_staging_file(parent, runtime.random.as_ref())?;
        drop(staging_file);

        let initialization =
            initialize_staging_database(&staging_path, password, profile, runtime.as_ref());
        let recovery_material = match initialization {
            Ok(value) => value,
            Err(error) => {
                cleanup_owned_staging_files(&staging_path);
                return Err(error);
            }
        };

        let staging_sync = File::open(&staging_path).and_then(|file| file.sync_all());
        if let Err(error) = staging_sync {
            cleanup_owned_staging_files(&staging_path);
            return Err(error.into());
        }
        match fs::hard_link(&staging_path, path) {
            Ok(()) => {}
            Err(error) => {
                cleanup_owned_staging_files(&staging_path);
                return Err(error.into());
            }
        }
        sync_directory(parent)?;
        fs::remove_file(&staging_path)?;
        sync_directory(parent)?;

        let repository = Self::open_with_runtime(path, runtime)?;
        Ok(VaultBootstrap {
            repository,
            recovery_material,
        })
    }

    pub fn unlock(&self, password: &MasterPassword) -> VaultResult<UnlockedVault> {
        let connection = self.connection()?;
        let metadata = load_metadata(&connection)?;
        validate_header_versions(&metadata.header)?;
        let context = wrapper_context(&metadata.header);
        let vdk = unwrap_master(password, &metadata.master.wrapper, context)?;
        verify_header_authentication(&metadata, &vdk)?;
        Ok(UnlockedVault {
            repository: self.clone(),
            vdk,
            vault_id: metadata.header.vault_id,
        })
    }

    pub fn unlock_recovery(
        &self,
        recovery_material: &RecoveryMaterial,
    ) -> VaultResult<UnlockedVault> {
        let connection = self.connection()?;
        let metadata = load_metadata(&connection)?;
        validate_header_versions(&metadata.header)?;
        let context = wrapper_context(&metadata.header);
        let vdk = unwrap_recovery(
            recovery_material.erc(),
            recovery_material.recovery_salt(),
            &metadata.recovery.wrapper,
            context,
        )?;
        verify_header_authentication(&metadata, &vdk)?;
        Ok(UnlockedVault {
            repository: self.clone(),
            vdk,
            vault_id: metadata.header.vault_id,
        })
    }

    pub fn change_master_password(
        &self,
        old_password: &MasterPassword,
        new_password: &MasterPassword,
        new_profile: Argon2Profile,
    ) -> VaultResult<()> {
        new_profile.validate()?;
        let unlocked = self.unlock(old_password)?;
        let connection = self.connection()?;
        let metadata = load_metadata(&connection)?;
        verify_header_authentication(&metadata, &unlocked.vdk)?;

        let master_nonce = self.reserve_nonce(MASTER_NONCE_PURPOSE)?;
        let header_nonce = self.reserve_nonce(HEADER_NONCE_PURPOSE)?;
        let mut salt = [0_u8; 16];
        self.runtime.random.fill(&mut salt)?;
        let updated_at_ms = self
            .runtime
            .clock
            .now_ms()?
            .max(metadata.header.updated_at_ms);
        let revision = metadata
            .master
            .revision
            .checked_add(1)
            .ok_or(VaultError::InvalidInput)?;
        let wrapper = create_master_wrapper_with_material(
            new_password,
            &unlocked.vdk,
            wrapper_context(&metadata.header),
            new_profile,
            MasterSalt::from_bytes(salt),
            master_nonce,
        )?;
        let replacement_master = MasterRow {
            revision,
            wrapper,
            created_at_ms: metadata.master.created_at_ms,
            updated_at_ms,
        };
        let replacement_header = HeaderRow {
            auth_nonce: header_nonce,
            auth_tag: [0; 16],
            updated_at_ms,
            ..metadata.header
        };
        let digest = wrapper_digest(
            replacement_header.vault_id,
            &replacement_master,
            &metadata.recovery,
        )?;
        let aad = header_aad(&replacement_header, digest);
        let tag = encrypt_payload(&unlocked.vdk, &header_nonce, &[], &aad)?;
        let tag: [u8; 16] = read_array(&tag)?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let master_changed = transaction.execute(
            "UPDATE master_wrapper SET revision = ?1, format_version = ?2, aead_algorithm = ?3, purpose = ?4, kdf_algorithm = ?5, kdf_version = ?6, memory_kib = ?7, time_cost = ?8, parallelism = ?9, output_length = ?10, salt = ?11, nonce = ?12, ciphertext_and_tag = ?13, updated_at_ms = ?14 WHERE singleton = 1 AND revision = ?15",
            params![
                to_sql_integer(replacement_master.revision)?,
                i64::from(replacement_master.wrapper.format_version),
                i64::from(replacement_master.wrapper.aead_algorithm),
                i64::from(replacement_master.wrapper.purpose),
                i64::from(replacement_master.wrapper.kdf_algorithm),
                i64::from(replacement_master.wrapper.kdf_version),
                i64::from(replacement_master.wrapper.profile.memory_kib),
                i64::from(replacement_master.wrapper.profile.time_cost),
                i64::from(replacement_master.wrapper.profile.parallelism),
                i64::from(replacement_master.wrapper.profile.output_length),
                replacement_master.wrapper.salt.as_slice(),
                replacement_master.wrapper.nonce.as_slice(),
                replacement_master.wrapper.ciphertext_and_tag.as_slice(),
                to_sql_integer(updated_at_ms)?,
                to_sql_integer(metadata.master.revision)?,
            ],
        )?;
        if master_changed != 1 {
            return Err(VaultError::Conflict);
        }
        let header_changed = transaction.execute(
            "UPDATE vault_header SET header_auth_nonce = ?1, header_auth_tag = ?2, updated_at_ms = ?3 WHERE singleton = 1 AND updated_at_ms = ?4",
            params![
                header_nonce.as_slice(),
                tag.as_slice(),
                to_sql_integer(updated_at_ms)?,
                to_sql_integer(metadata.header.updated_at_ms)?,
            ],
        )?;
        if header_changed != 1 {
            return Err(VaultError::Conflict);
        }
        transaction.commit()?;
        Ok(())
    }

    fn connection(&self) -> VaultResult<Connection> {
        preflight_vault_files(&self.path)?;
        let connection = open_connection(&self.path, false)?;
        migration::verify_schema(&connection)?;
        Ok(connection)
    }

    fn reserve_nonce(&self, purpose: i64) -> VaultResult<[u8; 12]> {
        let mut connection = self.connection()?;
        for _ in 0..NONCE_ATTEMPTS {
            let mut nonce = [0_u8; 12];
            self.runtime.random.fill(&mut nonce)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO nonce_reservations (nonce, purpose, reserved_at_ms) VALUES (?1, ?2, ?3)",
                params![
                    nonce.as_slice(),
                    purpose,
                    to_sql_integer(self.runtime.clock.now_ms()?)?
                ],
            )?;
            transaction.commit()?;
            if inserted == 1 {
                return Ok(nonce);
            }
        }
        Err(VaultError::RandomnessUnavailable)
    }
}

impl UnlockedVault {
    pub fn create_record(&self, plaintext: &[u8]) -> VaultResult<RecordVersion> {
        validate_plaintext_length(plaintext)?;
        let mut record_id = [0_u8; 16];
        self.repository.runtime.random.fill(&mut record_id)?;
        let nonce = self.repository.reserve_nonce(RECORD_NONCE_PURPOSE)?;
        let now = self.repository.runtime.clock.now_ms()?;
        let aad = record_aad(self.vault_id, record_id, 1, now, now, plaintext.len())?;
        let encrypted = encrypt_payload(&self.vdk, &nonce, plaintext, &aad)?;
        let frame = encode_frame(nonce, &encrypted)?;
        let mut connection = self.repository.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = transaction.execute(
            "INSERT INTO vault_records (record_id, singleton, generation, frame, created_at_ms, updated_at_ms) VALUES (?1, 1, 1, ?2, ?3, ?3)",
            params![record_id.as_slice(), frame, to_sql_integer(now)?],
        );
        match result {
            Ok(1) => transaction.commit()?,
            Ok(_) => return Err(VaultError::Conflict),
            Err(error) => return Err(error.into()),
        }
        Ok(RecordVersion {
            id: RecordId(record_id),
            generation: 1,
            created_at_ms: now,
            updated_at_ms: now,
        })
    }

    pub fn read_record(&self, id: RecordId) -> VaultResult<DecryptedRecord> {
        let connection = self.repository.connection()?;
        let stored = connection
            .query_row(
                "SELECT generation, frame, created_at_ms, updated_at_ms FROM vault_records WHERE record_id = ?1",
                [id.0.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((generation, frame, created_at_ms, updated_at_ms)) = stored else {
            return Err(VaultError::NotFound);
        };
        let generation = positive_u64(generation)?;
        let created_at_ms = nonnegative_u64(created_at_ms)?;
        let updated_at_ms = nonnegative_u64(updated_at_ms)?;
        if updated_at_ms < created_at_ms {
            return Err(VaultError::InvalidFormat);
        }
        let decoded = decode_frame(&frame)?;
        verify_reserved_nonce(&connection, &decoded.nonce, RECORD_NONCE_PURPOSE)?;
        let aad = record_aad(
            self.vault_id,
            id.0,
            generation,
            created_at_ms,
            updated_at_ms,
            decoded.plaintext_length,
        )?;
        let plaintext =
            decrypt_payload(&self.vdk, &decoded.nonce, decoded.ciphertext_and_tag, &aad)?;
        if plaintext.len() != decoded.plaintext_length {
            return Err(VaultError::InvalidFormat);
        }
        Ok(DecryptedRecord {
            id,
            generation,
            created_at_ms,
            updated_at_ms,
            plaintext,
        })
    }

    pub(super) fn map_records<T>(
        &self,
        mut map: impl FnMut(DecryptedRecord) -> VaultResult<T>,
    ) -> VaultResult<Vec<T>> {
        let connection = self.repository.connection()?;
        let mut statement = connection.prepare(
            "SELECT record_id, generation, frame, created_at_ms, updated_at_ms
             FROM vault_records
             ORDER BY updated_at_ms DESC, record_id ASC",
        )?;
        let mut rows = statement.query([])?;
        let mut output = Vec::new();
        while let Some(row) = rows.next()? {
            let record_id = row.get::<_, Vec<u8>>(0)?;
            let id = RecordId(read_array(&record_id)?);
            let generation = positive_u64(row.get(1)?)?;
            let frame = row.get::<_, Vec<u8>>(2)?;
            let created_at_ms = nonnegative_u64(row.get(3)?)?;
            let updated_at_ms = nonnegative_u64(row.get(4)?)?;
            if updated_at_ms < created_at_ms {
                return Err(VaultError::InvalidFormat);
            }
            let decoded = decode_frame(&frame)?;
            verify_reserved_nonce(&connection, &decoded.nonce, RECORD_NONCE_PURPOSE)?;
            let aad = record_aad(
                self.vault_id,
                id.0,
                generation,
                created_at_ms,
                updated_at_ms,
                decoded.plaintext_length,
            )?;
            let plaintext =
                decrypt_payload(&self.vdk, &decoded.nonce, decoded.ciphertext_and_tag, &aad)?;
            if plaintext.len() != decoded.plaintext_length {
                return Err(VaultError::InvalidFormat);
            }
            output.push(map(DecryptedRecord {
                id,
                generation,
                created_at_ms,
                updated_at_ms,
                plaintext,
            })?);
        }
        Ok(output)
    }

    pub(super) fn random_identifier(&self) -> VaultResult<[u8; 16]> {
        random_array(self.repository.runtime.random.as_ref())
    }

    pub fn update_record(
        &self,
        id: RecordId,
        expected_generation: u64,
        plaintext: &[u8],
    ) -> VaultResult<RecordVersion> {
        validate_plaintext_length(plaintext)?;
        if expected_generation == 0 {
            return Err(VaultError::InvalidInput);
        }
        let connection = self.repository.connection()?;
        let current = connection
            .query_row(
                "SELECT generation, created_at_ms, updated_at_ms FROM vault_records WHERE record_id = ?1",
                [id.0.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((current_generation, created_at_ms, prior_updated_at_ms)) = current else {
            return Err(VaultError::NotFound);
        };
        let current_generation = positive_u64(current_generation)?;
        if current_generation != expected_generation {
            return Err(VaultError::Conflict);
        }
        let generation = expected_generation
            .checked_add(1)
            .ok_or(VaultError::InvalidInput)?;
        let created_at_ms = nonnegative_u64(created_at_ms)?;
        let prior_updated_at_ms = nonnegative_u64(prior_updated_at_ms)?;
        let updated_at_ms = self
            .repository
            .runtime
            .clock
            .now_ms()?
            .max(prior_updated_at_ms);
        let nonce = self.repository.reserve_nonce(RECORD_NONCE_PURPOSE)?;
        let aad = record_aad(
            self.vault_id,
            id.0,
            generation,
            created_at_ms,
            updated_at_ms,
            plaintext.len(),
        )?;
        let encrypted = encrypt_payload(&self.vdk, &nonce, plaintext, &aad)?;
        let frame = encode_frame(nonce, &encrypted)?;

        let mut connection = self.repository.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE vault_records SET generation = ?1, frame = ?2, updated_at_ms = ?3 WHERE record_id = ?4 AND generation = ?5",
            params![
                to_sql_integer(generation)?,
                frame,
                to_sql_integer(updated_at_ms)?,
                id.0.as_slice(),
                to_sql_integer(expected_generation)?,
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Conflict);
        }
        transaction.commit()?;
        Ok(RecordVersion {
            id,
            generation,
            created_at_ms,
            updated_at_ms,
        })
    }

    pub fn delete_record(&self, id: RecordId, expected_generation: u64) -> VaultResult<()> {
        if expected_generation == 0 {
            return Err(VaultError::InvalidInput);
        }
        let mut connection = self.repository.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "DELETE FROM vault_records WHERE record_id = ?1 AND generation = ?2",
            params![id.0.as_slice(), to_sql_integer(expected_generation)?],
        )?;
        if changed != 1 {
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM vault_records WHERE record_id = ?1)",
                [id.0.as_slice()],
                |row| row.get(0),
            )?;
            return Err(if exists {
                VaultError::Conflict
            } else {
                VaultError::NotFound
            });
        }
        transaction.commit()?;
        Ok(())
    }
}

fn initialize_staging_database(
    path: &Path,
    password: &MasterPassword,
    profile: Argon2Profile,
    runtime: &Runtime,
) -> VaultResult<RecoveryMaterial> {
    let mut connection = open_connection(path, true)?;
    let created_at_ms = runtime.clock.now_ms()?;
    let vault_id = random_array(runtime.random.as_ref())?;
    let device_id = random_array(runtime.random.as_ref())?;
    let recovery_id = random_array(runtime.random.as_ref())?;
    let vdk = Vdk::from_bytes(random_array(runtime.random.as_ref())?);
    let erc = ErcEntropy::from_bytes(random_array(runtime.random.as_ref())?);
    let recovery_salt = RecoverySalt::from_bytes(random_array(runtime.random.as_ref())?);
    let master_salt = MasterSalt::from_bytes(random_array(runtime.random.as_ref())?);
    let [master_nonce, recovery_nonce, header_nonce] =
        unique_initial_nonces(runtime.random.as_ref())?;
    let context = WrapContext {
        vault_id: VaultId::new(vault_id),
        device_id: DeviceId::new(device_id),
    };
    let master = MasterRow {
        revision: 1,
        wrapper: create_master_wrapper_with_material(
            password,
            &vdk,
            context,
            profile,
            master_salt,
            master_nonce,
        )?,
        created_at_ms,
        updated_at_ms: created_at_ms,
    };
    let recovery = RecoveryRow {
        recovery_id,
        device_id,
        wrapper: create_recovery_wrapper_with_nonce(
            &erc,
            &recovery_salt,
            &vdk,
            context,
            recovery_nonce,
        )?,
        created_at_ms,
    };
    let mut header = HeaderRow {
        magic: format::VAULT_MAGIC,
        container_version: format::CONTAINER_VERSION,
        schema_version: format::SCHEMA_VERSION,
        crypto_version: format::CRYPTO_VERSION,
        vault_id,
        device_id,
        auth_nonce: header_nonce,
        auth_tag: [0; 16],
        created_at_ms,
        updated_at_ms: created_at_ms,
    };
    let digest = wrapper_digest(vault_id, &master, &recovery)?;
    let aad = header_aad(&header, digest);
    header.auth_tag = read_array(&encrypt_payload(&vdk, &header_nonce, &[], &aad)?)?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    migration::apply_initial_schema(&transaction, created_at_ms)?;
    insert_header(&transaction, &header)?;
    insert_master(&transaction, &master)?;
    insert_recovery(&transaction, &recovery)?;
    for (nonce, purpose) in [
        (master_nonce, MASTER_NONCE_PURPOSE),
        (recovery_nonce, RECOVERY_NONCE_PURPOSE),
        (header_nonce, HEADER_NONCE_PURPOSE),
    ] {
        transaction.execute(
            "INSERT INTO nonce_reservations (nonce, purpose, reserved_at_ms) VALUES (?1, ?2, ?3)",
            params![nonce.as_slice(), purpose, to_sql_integer(created_at_ms)?],
        )?;
    }
    transaction.commit()?;
    migration::verify_schema(&connection)?;
    let stored = load_metadata(&connection)?;
    validate_header_versions(&stored.header)?;
    verify_header_authentication(&stored, &vdk)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    Ok(RecoveryMaterial { erc, recovery_salt })
}

fn insert_header(connection: &Connection, header: &HeaderRow) -> VaultResult<()> {
    connection.execute(
        "INSERT INTO vault_header (singleton, magic, container_version, schema_version, crypto_version, vault_id, device_id, header_auth_nonce, header_auth_tag, created_at_ms, updated_at_ms) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
        params![
            header.magic.as_slice(),
            i64::from(header.container_version),
            i64::from(header.schema_version),
            i64::from(header.crypto_version),
            header.vault_id.as_slice(),
            header.device_id.as_slice(),
            header.auth_nonce.as_slice(),
            header.auth_tag.as_slice(),
            to_sql_integer(header.created_at_ms)?,
        ],
    )?;
    Ok(())
}

fn insert_master(connection: &Connection, master: &MasterRow) -> VaultResult<()> {
    connection.execute(
        "INSERT INTO master_wrapper (singleton, revision, format_version, aead_algorithm, purpose, kdf_algorithm, kdf_version, memory_kib, time_cost, parallelism, output_length, salt, nonce, ciphertext_and_tag, created_at_ms, updated_at_ms) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14)",
        params![
            to_sql_integer(master.revision)?,
            i64::from(master.wrapper.format_version),
            i64::from(master.wrapper.aead_algorithm),
            i64::from(master.wrapper.purpose),
            i64::from(master.wrapper.kdf_algorithm),
            i64::from(master.wrapper.kdf_version),
            i64::from(master.wrapper.profile.memory_kib),
            i64::from(master.wrapper.profile.time_cost),
            i64::from(master.wrapper.profile.parallelism),
            i64::from(master.wrapper.profile.output_length),
            master.wrapper.salt.as_slice(),
            master.wrapper.nonce.as_slice(),
            master.wrapper.ciphertext_and_tag.as_slice(),
            to_sql_integer(master.created_at_ms)?,
        ],
    )?;
    Ok(())
}

fn insert_recovery(connection: &Connection, recovery: &RecoveryRow) -> VaultResult<()> {
    connection.execute(
        "INSERT INTO recovery_wrapper (singleton, recovery_id, device_id, format_version, aead_algorithm, purpose, nonce, ciphertext_and_tag, created_at_ms) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            recovery.recovery_id.as_slice(),
            recovery.device_id.as_slice(),
            i64::from(recovery.wrapper.format_version),
            i64::from(recovery.wrapper.aead_algorithm),
            i64::from(recovery.wrapper.purpose),
            recovery.wrapper.nonce.as_slice(),
            recovery.wrapper.ciphertext_and_tag.as_slice(),
            to_sql_integer(recovery.created_at_ms)?,
        ],
    )?;
    Ok(())
}

fn load_metadata(connection: &Connection) -> VaultResult<VaultMetadata> {
    let header = connection.query_row(
        "SELECT magic, container_version, schema_version, crypto_version, vault_id, device_id, header_auth_nonce, header_auth_tag, created_at_ms, updated_at_ms FROM vault_header WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?, row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?,
                row.get::<_, i64>(8)?, row.get::<_, i64>(9)?,
            ))
        },
    )?;
    let header = HeaderRow {
        magic: read_array(&header.0)?,
        container_version: positive_u16(header.1)?,
        schema_version: positive_u32(header.2)?,
        crypto_version: positive_u16(header.3)?,
        vault_id: read_array(&header.4)?,
        device_id: read_array(&header.5)?,
        auth_nonce: read_array(&header.6)?,
        auth_tag: read_array(&header.7)?,
        created_at_ms: nonnegative_u64(header.8)?,
        updated_at_ms: nonnegative_u64(header.9)?,
    };
    if header.updated_at_ms < header.created_at_ms {
        return Err(VaultError::InvalidFormat);
    }

    let master = connection.query_row(
        "SELECT revision, format_version, aead_algorithm, purpose, kdf_algorithm, kdf_version, memory_kib, time_cost, parallelism, output_length, salt, nonce, ciphertext_and_tag, created_at_ms, updated_at_ms FROM master_wrapper WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?, row.get::<_, i64>(7)?, row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?, row.get::<_, Vec<u8>>(10)?, row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Vec<u8>>(12)?, row.get::<_, i64>(13)?, row.get::<_, i64>(14)?,
            ))
        },
    )?;
    let master = MasterRow {
        revision: positive_u64(master.0)?,
        wrapper: MasterWrapper {
            format_version: positive_u16(master.1)?,
            aead_algorithm: positive_u8(master.2)?,
            purpose: positive_u8(master.3)?,
            kdf_algorithm: positive_u8(master.4)?,
            kdf_version: positive_u8(master.5)?,
            profile: Argon2Profile {
                memory_kib: positive_u32(master.6)?,
                time_cost: positive_u32(master.7)?,
                parallelism: positive_u32(master.8)?,
                output_length: positive_u16(master.9)?,
            },
            salt: read_array(&master.10)?,
            nonce: read_array(&master.11)?,
            ciphertext_and_tag: master.12,
        },
        created_at_ms: nonnegative_u64(master.13)?,
        updated_at_ms: nonnegative_u64(master.14)?,
    };
    if master.updated_at_ms < master.created_at_ms {
        return Err(VaultError::InvalidFormat);
    }

    let recovery = connection.query_row(
        "SELECT recovery_id, device_id, format_version, aead_algorithm, purpose, nonce, ciphertext_and_tag, created_at_ms FROM recovery_wrapper WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?, row.get::<_, Vec<u8>>(6)?, row.get::<_, i64>(7)?,
            ))
        },
    )?;
    let recovery = RecoveryRow {
        recovery_id: read_array(&recovery.0)?,
        device_id: read_array(&recovery.1)?,
        wrapper: RecoveryWrapper {
            format_version: positive_u16(recovery.2)?,
            aead_algorithm: positive_u8(recovery.3)?,
            purpose: positive_u8(recovery.4)?,
            nonce: read_array(&recovery.5)?,
            ciphertext_and_tag: recovery.6,
        },
        created_at_ms: nonnegative_u64(recovery.7)?,
    };
    verify_reserved_nonce(connection, &master.wrapper.nonce, MASTER_NONCE_PURPOSE)?;
    verify_reserved_nonce(connection, &recovery.wrapper.nonce, RECOVERY_NONCE_PURPOSE)?;
    verify_reserved_nonce(connection, &header.auth_nonce, HEADER_NONCE_PURPOSE)?;
    Ok(VaultMetadata {
        header,
        master,
        recovery,
    })
}

fn verify_reserved_nonce(
    connection: &Connection,
    nonce: &[u8; 12],
    expected_purpose: i64,
) -> VaultResult<()> {
    let purpose: Option<i64> = connection
        .query_row(
            "SELECT purpose FROM nonce_reservations WHERE nonce = ?1",
            [nonce.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if purpose != Some(expected_purpose) {
        return Err(VaultError::Corrupt);
    }
    Ok(())
}

fn validate_header_versions(header: &HeaderRow) -> VaultResult<()> {
    if header.magic != format::VAULT_MAGIC {
        return Err(VaultError::InvalidFormat);
    }
    if header.container_version != format::CONTAINER_VERSION
        || header.schema_version != format::SCHEMA_VERSION
        || header.crypto_version != format::CRYPTO_VERSION
    {
        return Err(VaultError::UnsupportedVersion);
    }
    Ok(())
}

fn verify_header_authentication(metadata: &VaultMetadata, vdk: &Vdk) -> VaultResult<()> {
    let digest = wrapper_digest(
        metadata.header.vault_id,
        &metadata.master,
        &metadata.recovery,
    )?;
    let aad = header_aad(&metadata.header, digest);
    let plaintext = decrypt_payload(
        vdk,
        &metadata.header.auth_nonce,
        &metadata.header.auth_tag,
        &aad,
    )?;
    if !plaintext.is_empty() {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

fn wrapper_context(header: &HeaderRow) -> WrapContext {
    WrapContext {
        vault_id: VaultId::new(header.vault_id),
        device_id: DeviceId::new(header.device_id),
    }
}

fn open_connection(path: &Path, create: bool) -> VaultResult<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_EXRESCODE;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags)?;
    configure_connection(&connection, create)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection, new_database: bool) -> VaultResult<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_WRITABLE_SCHEMA, false)?;
    set_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE,
        false,
    )?;
    set_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE,
        false,
    )?;

    set_limits(connection)?;
    if new_database {
        connection.pragma_update(None, "page_size", 4096_i64)?;
        connection.pragma_update(None, "auto_vacuum", "FULL")?;
    }
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        let enabled: String =
            connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if !enabled.eq_ignore_ascii_case("wal") {
            return Err(VaultError::Corrupt);
        }
    }
    for (pragma, value) in [
        ("foreign_keys", "ON"),
        ("cell_size_check", "ON"),
        ("trusted_schema", "OFF"),
        ("synchronous", "FULL"),
        ("temp_store", "MEMORY"),
        ("secure_delete", "ON"),
        ("mmap_size", "0"),
        ("max_page_count", "262144"),
        ("wal_autocheckpoint", "256"),
        ("journal_size_limit", "16777216"),
    ] {
        connection.pragma_update(None, pragma, value)?;
    }
    verify_connection_configuration(connection)?;
    Ok(())
}

fn set_db_config(connection: &Connection, config: DbConfig, value: bool) -> VaultResult<()> {
    if connection.set_db_config(config, value)? != value || connection.db_config(config)? != value {
        return Err(VaultError::Corrupt);
    }
    Ok(())
}

fn set_limits(connection: &Connection) -> VaultResult<()> {
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, SQLITE_VALUE_LIMIT),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 32_768),
        (Limit::SQLITE_LIMIT_COLUMN, 32),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 20),
        (Limit::SQLITE_LIMIT_PARSER_DEPTH, 100),
        (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 4),
        (Limit::SQLITE_LIMIT_VDBE_OP, 100_000),
        (Limit::SQLITE_LIMIT_FUNCTION_ARG, 8),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 32),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        connection.set_limit(limit, value)?;
        if connection.limit(limit)? != value {
            return Err(VaultError::Corrupt);
        }
    }
    Ok(())
}

fn verify_connection_configuration(connection: &Connection) -> VaultResult<()> {
    for (pragma, expected) in [
        ("page_size", 4096_i64),
        ("foreign_keys", 1_i64),
        ("cell_size_check", 1),
        ("trusted_schema", 0),
        ("synchronous", 2),
        ("temp_store", 2),
        ("secure_delete", 1),
        ("auto_vacuum", 1),
        ("mmap_size", 0),
        ("max_page_count", 262_144),
        ("wal_autocheckpoint", 256),
        ("journal_size_limit", 16_777_216),
        ("busy_timeout", 5_000),
    ] {
        let actual: i64 = connection.pragma_query_value(None, pragma, |row| row.get(0))?;
        if actual != expected {
            return Err(VaultError::Corrupt);
        }
    }
    Ok(())
}

fn ensure_target_absent(path: &Path) -> VaultResult<()> {
    for candidate in [
        path.to_path_buf(),
        suffixed_path(path, "-wal"),
        suffixed_path(path, "-shm"),
        suffixed_path(path, "-journal"),
    ] {
        match fs::symlink_metadata(candidate) {
            Ok(_) => return Err(VaultError::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn preflight_vault_files(path: &Path) -> VaultResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_VAULT_FILE_BYTES
    {
        return Err(VaultError::InvalidFormat);
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = suffixed_path(path, suffix);
        match fs::symlink_metadata(sidecar) {
            Ok(value)
                if value.file_type().is_symlink()
                    || !value.is_file()
                    || value.len() > MAX_VAULT_FILE_BYTES =>
            {
                return Err(VaultError::InvalidFormat);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn create_staging_file(parent: &Path, random: &dyn RandomSource) -> VaultResult<(PathBuf, File)> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let random_name: [u8; 16] = random_array(random)?;
        let mut encoded = String::with_capacity(32);
        for byte in random_name {
            use core::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").map_err(|_| VaultError::Io)?;
        }
        let path = parent.join(format!(".aeterna-{encoded}.stage"));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => {
                let has_unknown_sidecar = ["-wal", "-shm", "-journal"]
                    .iter()
                    .any(|suffix| fs::symlink_metadata(suffixed_path(&path, suffix)).is_ok());
                if has_unknown_sidecar {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    continue;
                }
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(VaultError::RandomnessUnavailable)
}

fn cleanup_owned_staging_files(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        suffixed_path(path, "-wal"),
        suffixed_path(path, "-shm"),
        suffixed_path(path, "-journal"),
    ] {
        let _ = fs::remove_file(candidate);
    }
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn sync_directory(path: &Path) -> VaultResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn random_array<const LENGTH: usize>(random: &dyn RandomSource) -> VaultResult<[u8; LENGTH]> {
    let mut value = [0_u8; LENGTH];
    random.fill(&mut value)?;
    Ok(value)
}

fn unique_initial_nonces(random: &dyn RandomSource) -> VaultResult<[[u8; 12]; 3]> {
    let mut nonces = [[0_u8; 12]; 3];
    let mut observed = HashSet::new();
    for nonce in &mut nonces {
        let mut accepted = false;
        for _ in 0..NONCE_ATTEMPTS {
            random.fill(nonce)?;
            if observed.insert(*nonce) {
                accepted = true;
                break;
            }
        }
        if !accepted {
            return Err(VaultError::RandomnessUnavailable);
        }
    }
    Ok(nonces)
}

fn validate_plaintext_length(plaintext: &[u8]) -> VaultResult<()> {
    if plaintext.len() > format::MAX_PLAINTEXT_LENGTH {
        return Err(VaultError::InvalidInput);
    }
    Ok(())
}

fn positive_u8(value: i64) -> VaultResult<u8> {
    let value = u8::try_from(value).map_err(|_| VaultError::InvalidFormat)?;
    if value == 0 {
        return Err(VaultError::UnsupportedVersion);
    }
    Ok(value)
}

fn positive_u16(value: i64) -> VaultResult<u16> {
    let value = u16::try_from(value).map_err(|_| VaultError::InvalidFormat)?;
    if value == 0 {
        return Err(VaultError::UnsupportedVersion);
    }
    Ok(value)
}

fn positive_u32(value: i64) -> VaultResult<u32> {
    let value = u32::try_from(value).map_err(|_| VaultError::InvalidFormat)?;
    if value == 0 {
        return Err(VaultError::UnsupportedVersion);
    }
    Ok(value)
}

fn positive_u64(value: i64) -> VaultResult<u64> {
    let value = nonnegative_u64(value)?;
    if value == 0 {
        return Err(VaultError::InvalidFormat);
    }
    Ok(value)
}

fn nonnegative_u64(value: i64) -> VaultResult<u64> {
    u64::try_from(value).map_err(|_| VaultError::InvalidFormat)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        process::Command,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    use super::*;

    struct SequenceRandom {
        values: Mutex<VecDeque<Vec<u8>>>,
        fallback: AtomicU64,
    }

    impl SequenceRandom {
        fn with_values(values: Vec<Vec<u8>>) -> Self {
            Self {
                values: Mutex::new(values.into()),
                fallback: AtomicU64::new(1),
            }
        }
    }

    impl RandomSource for SequenceRandom {
        fn fill(&self, output: &mut [u8]) -> VaultResult<()> {
            let mut values = self.values.lock().map_err(|_| VaultError::Io)?;
            if let Some(value) = values.pop_front() {
                if value.len() != output.len() {
                    return Err(VaultError::InvalidInput);
                }
                output.copy_from_slice(&value);
            } else {
                let value = self.fallback.fetch_add(1, Ordering::Relaxed).to_be_bytes();
                for (index, byte) in output.iter_mut().enumerate() {
                    *byte = value[index % value.len()];
                }
            }
            Ok(())
        }
    }

    struct FixedClock(AtomicU64);

    impl Clock for FixedClock {
        fn now_ms(&self) -> VaultResult<u64> {
            Ok(self.0.fetch_add(1, Ordering::Relaxed))
        }
    }

    fn temporary_path(label: &str) -> PathBuf {
        let mut random = [0_u8; 8];
        assert!(fill_random(&mut random).is_ok());
        let token = u64::from_be_bytes(random);
        let directory = match fs::canonicalize(std::env::temp_dir()) {
            Ok(value) => value,
            Err(_) => panic!("temporary directory should resolve"),
        };
        directory.join(format!("aeterna-{label}-{token:016x}.sqlite"))
    }

    fn test_runtime(random: Arc<dyn RandomSource>) -> Arc<Runtime> {
        Arc::new(Runtime {
            random,
            clock: Arc::new(FixedClock(AtomicU64::new(1_700_000_000_000))),
        })
    }

    fn password(byte: u8) -> MasterPassword {
        match MasterPassword::new(vec![byte; 16]) {
            Ok(value) => value,
            Err(_) => panic!("synthetic password is valid"),
        }
    }

    fn profile() -> Argon2Profile {
        Argon2Profile::new(65_536, 1, 1)
    }

    #[test]
    fn deterministic_nonce_collision_is_retried_and_consumed() {
        let path = temporary_path("nonce-collision");
        let runtime = test_runtime(Arc::new(SequenceRandom::with_values(Vec::new())));
        let bootstrap = VaultRepository::initialize_with_runtime(
            &path,
            &password(1),
            profile(),
            Arc::clone(&runtime),
        );
        let bootstrap = match bootstrap {
            Ok(value) => value,
            Err(error) => panic!("vault initialization failed: {error}"),
        };
        let repository = bootstrap.repository();
        let connection = match repository.connection() {
            Ok(value) => value,
            Err(error) => panic!("vault connection failed: {error}"),
        };
        assert!(
            connection
                .execute("ATTACH DATABASE ':memory:' AS forbidden", [])
                .is_err()
        );
        let existing: Vec<u8> = match connection.query_row(
            "SELECT nonce FROM nonce_reservations ORDER BY nonce LIMIT 1",
            [],
            |row| row.get(0),
        ) {
            Ok(value) => value,
            Err(error) => panic!("nonce lookup failed: {error}"),
        };
        drop(connection);

        let unique = vec![0xfe; 12];
        let collision_runtime = test_runtime(Arc::new(SequenceRandom::with_values(vec![
            existing,
            unique.clone(),
        ])));
        let repository = VaultRepository {
            path: path.clone(),
            runtime: collision_runtime,
        };
        let reserved = repository.reserve_nonce(RECORD_NONCE_PURPOSE);
        assert!(matches!(reserved, Ok(value) if value.as_slice() == unique));
        cleanup_owned_staging_files(&path);
    }

    #[test]
    fn public_debug_output_redacts_paths_secrets_ids_and_plaintext() {
        let repository = VaultRepository {
            path: PathBuf::from("/sensitive/example.sqlite"),
            runtime: Runtime::production(),
        };
        assert_eq!(
            format!("{repository:?}"),
            "VaultRepository([REDACTED PATH])"
        );
        assert_eq!(format!("{:?}", RecordId([7; 16])), "RecordId([REDACTED])");
        let record = DecryptedRecord {
            id: RecordId([1; 16]),
            generation: 1,
            created_at_ms: 1,
            updated_at_ms: 1,
            plaintext: Zeroizing::new(b"secret marker".to_vec()),
        };
        assert!(!format!("{record:?}").contains("secret marker"));
    }

    #[test]
    fn staging_database_contains_no_password_marker() {
        let target = temporary_path("staging-privacy");
        let parent = target.parent().unwrap_or(Path::new("."));
        let runtime = test_runtime(Arc::new(SequenceRandom::with_values(Vec::new())));
        let (staging_path, file) = match create_staging_file(parent, runtime.random.as_ref()) {
            Ok(value) => value,
            Err(error) => panic!("staging create failed: {error}"),
        };
        drop(file);
        let marker = b"i05-staging-password-marker";
        let password = match MasterPassword::new(marker.to_vec()) {
            Ok(value) => value,
            Err(_) => panic!("synthetic password is valid"),
        };
        assert!(
            initialize_staging_database(&staging_path, &password, profile(), runtime.as_ref())
                .is_ok()
        );
        let connection = match open_connection(&staging_path, false) {
            Ok(value) => value,
            Err(error) => panic!("staging reopen failed: {error}"),
        };
        assert!(
            connection
                .execute_batch(
                    "CREATE TEMP TABLE temp_ciphertext AS
                     SELECT nonce FROM nonce_reservations ORDER BY nonce;"
                )
                .is_ok()
        );
        let temp_file: rusqlite::Result<String> = connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'temp'",
            [],
            |row| row.get(0),
        );
        assert!(matches!(temp_file, Ok(value) if value.is_empty()));
        drop(connection);
        for candidate in [
            staging_path.clone(),
            suffixed_path(&staging_path, "-wal"),
            suffixed_path(&staging_path, "-shm"),
            suffixed_path(&staging_path, "-journal"),
        ] {
            if let Ok(bytes) = fs::read(candidate) {
                assert!(!bytes.windows(marker.len()).any(|window| window == marker));
            }
        }
        cleanup_owned_staging_files(&staging_path);
    }

    #[test]
    fn abrupt_exit_after_nonce_reservation_child() {
        let Ok(path) = std::env::var("AETERNA_I05_CRASH_AFTER_RESERVATION") else {
            return;
        };
        let repository = match VaultRepository::open(&path) {
            Ok(value) => value,
            Err(_) => std::process::exit(74),
        };
        if repository.reserve_nonce(RECORD_NONCE_PURPOSE).is_err() {
            std::process::exit(75);
        }
        std::process::exit(73);
    }

    #[test]
    fn nonce_reservation_survives_abrupt_exit_and_restart() {
        let path = temporary_path("abrupt-reservation");
        let bootstrap = VaultRepository::initialize(&path, &password(7), profile());
        let bootstrap = match bootstrap {
            Ok(value) => value,
            Err(error) => panic!("vault initialization failed: {error}"),
        };
        let before = nonce_count(bootstrap.repository());
        drop(bootstrap);

        let executable = match std::env::current_exe() {
            Ok(value) => value,
            Err(_) => panic!("test executable should resolve"),
        };
        let status = Command::new(executable)
            .arg("--exact")
            .arg("vault::repository::tests::abrupt_exit_after_nonce_reservation_child")
            .arg("--nocapture")
            .env("AETERNA_I05_CRASH_AFTER_RESERVATION", &path)
            .status();
        assert!(matches!(status, Ok(value) if value.code() == Some(73)));

        let repository = match VaultRepository::open(&path) {
            Ok(value) => value,
            Err(error) => panic!("vault reopen failed: {error}"),
        };
        assert_eq!(nonce_count(&repository), before + 1);
        cleanup_owned_staging_files(&path);
    }

    fn nonce_count(repository: &VaultRepository) -> i64 {
        let connection = match repository.connection() {
            Ok(value) => value,
            Err(error) => panic!("vault connection failed: {error}"),
        };
        match connection.query_row("SELECT COUNT(*) FROM nonce_reservations", [], |row| {
            row.get(0)
        }) {
            Ok(value) => value,
            Err(error) => panic!("nonce count failed: {error}"),
        }
    }
}
