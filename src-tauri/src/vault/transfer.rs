use core::fmt;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::crypto::{
    Argon2Profile, DeviceId, MasterPassword, MasterWrapper, RecoveryWrapper, VaultId, Vdk,
    WrapContext, decrypt_payload, export_authentication_tag, fill_random, unwrap_master,
    verify_export_authentication_tag,
};

use super::{
    UnlockedVault, VaultError, VaultRepository,
    format::{self, HeaderRow, MasterRow, RecoveryRow, decode_frame, read_array, record_aad},
    item::{ITEM_PAYLOAD_VERSION, validate_item_payload},
    migration,
    repository::{
        VaultMetadata, cleanup_owned_staging_files, load_metadata, nonnegative_u64,
        open_connection, positive_u64, preflight_vault_files, validate_header_versions,
        verify_header_authentication,
    },
};

#[cfg(target_os = "macos")]
use super::macos_fs::{
    Directory, effective_uid, file_size, private_regular_identity, recheck_identity,
    source_identity, split_path, verify_private_regular,
};

const PACKAGE_MAGIC: [u8; 16] = *b"AETERNA-EXPORT\0\0";
const ENTRY_MAGIC: [u8; 4] = *b"AENT";
const MANIFEST_MAGIC: [u8; 16] = *b"AETERNA-MANIFEST";
const TRAILER_MAGIC: [u8; 16] = *b"AETERNA-COMPLETE";
const EXPORT_KEY_DOMAIN: [u8; 18] = *b"AETERNA-EXPORT-KEY";
const EXPORT_AUTH_DOMAIN: [u8; 19] = *b"AETERNA-EXPORT-AUTH";
const PACKAGE_VERSION: u16 = 1;
const MANIFEST_VERSION: u16 = 1;
const AUTHENTICATION_VERSION: u16 = 1;
const ENTRY_VERSION: u16 = 1;
const TRAILER_VERSION: u16 = 1;
const AUTHENTICATION_ALGORITHM: u8 = 1;
const AUTHENTICATION_PURPOSE: u8 = 1;
const WRAPPER_SET_ENCODING_VERSION: u8 = 1;
const PREAMBLE_LENGTH: usize = 96;
const ENTRY_PREFIX_LENGTH: usize = 56;
const HEADER_PAYLOAD_LENGTH: usize = 96;
const MASTER_PAYLOAD_LENGTH: usize = 120;
const RECOVERY_PAYLOAD_LENGTH: usize = 104;
const SCHEMA_PAYLOAD_LENGTH: usize = 98;
const NONCE_PAYLOAD_LENGTH: usize = 21;
const RECORD_PREFIX_LENGTH: usize = 44;
const MANIFEST_LENGTH: usize = 128;
const TRAILER_LENGTH: usize = 64;
const FIXED_PACKAGE_OVERHEAD: u64 =
    PREAMBLE_LENGTH as u64 + MANIFEST_LENGTH as u64 + TRAILER_LENGTH as u64;
const MIN_BODY_LENGTH: u64 = 873;
pub(super) const MIN_PACKAGE_LENGTH: u64 = 1_161;
pub(super) const MAX_PACKAGE_LENGTH: u64 = 1_073_741_824;
const MAX_BODY_LENGTH: u64 = MAX_PACKAGE_LENGTH - FIXED_PACKAGE_OVERHEAD;
const MAX_RECORDS: u32 = 65_536;
const MAX_NONCES: u32 = 131_072;
const MAX_ENTRIES: u32 = 196_612;
const MAX_RECORD_PAYLOAD: usize = RECORD_PREFIX_LENGTH + format::MAX_FRAME_LENGTH;
const STREAM_CHUNK: usize = 65_536;
const FILE_ATTEMPTS: usize = 16;
const MASTER_NONCE_PURPOSE: u8 = 1;
const RECOVERY_NONCE_PURPOSE: u8 = 2;
const HEADER_NONCE_PURPOSE: u8 = 3;
const RECORD_NONCE_PURPOSE: u8 = 4;

#[cfg(test)]
mod fault_injection {
    use std::{cell::Cell, io};

    pub(super) const CRASH_EXIT_CODE: i32 = 86;
    const CRASH_POINT_ENV: &str = "AETERNA_I07_CRASH_POINT";

    #[derive(Clone, Copy)]
    pub(super) enum Mode {
        Errno(i32),
        ShortWrite,
    }

    #[derive(Clone, Copy)]
    struct Fault {
        point: &'static str,
        mode: Mode,
    }

    thread_local! {
        static FAULT: Cell<Option<Fault>> = const { Cell::new(None) };
    }

    pub(super) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAULT.set(None);
        }
    }

    pub(super) fn install(point: &'static str, mode: Mode) -> Guard {
        FAULT.set(Some(Fault { point, mode }));
        Guard
    }

    pub(super) fn short_write(point: &str) -> bool {
        matches!(
            FAULT.get(),
            Some(Fault {
                point: configured,
                mode: Mode::ShortWrite,
            }) if configured == point
        )
    }

    pub(super) fn checkpoint(point: &str) -> io::Result<()> {
        if std::env::var_os(CRASH_POINT_ENV).is_some_and(|value| value == point) {
            std::process::exit(CRASH_EXIT_CODE);
        }
        match FAULT.get() {
            Some(Fault {
                point: configured,
                mode: Mode::Errno(errno),
            }) if configured == point => Err(io::Error::from_raw_os_error(errno)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
fn io_checkpoint(point: &str) -> std::io::Result<()> {
    fault_injection::checkpoint(point)
}

#[cfg(not(test))]
fn io_checkpoint(_point: &str) -> std::io::Result<()> {
    Ok(())
}

fn transfer_write_all(file: &mut File, bytes: &[u8], point: &str) -> Result<(), TransferError> {
    #[cfg(test)]
    if fault_injection::short_write(point) {
        let partial = bytes.len().clamp(1, bytes.len().saturating_sub(1).max(1));
        file.write_all(&bytes[..partial])
            .map_err(|_| TransferError::Io)?;
        return Err(TransferError::Io);
    }
    io_checkpoint(point).map_err(|_| TransferError::Io)?;
    file.write_all(bytes).map_err(|_| TransferError::Io)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum TransferError {
    AuthenticationFailed,
    Cancelled,
    ExportLimitExceeded,
    ExportTargetExists,
    ImportInvalidPackage,
    ImportLimitExceeded,
    ImportTargetExists,
    ImportUnsupportedVersion,
    Io,
    PathRejected,
    #[cfg(not(target_os = "macos"))]
    PlatformUnsupported,
    Vault(VaultError),
}

impl TransferError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "crypto_authentication_failed",
            Self::Cancelled => "vault_operation_cancelled",
            Self::ExportLimitExceeded => "vault_export_limit_exceeded",
            Self::ExportTargetExists => "vault_export_target_exists",
            Self::ImportInvalidPackage => "vault_import_invalid_package",
            Self::ImportLimitExceeded => "vault_import_limit_exceeded",
            Self::ImportTargetExists => "vault_import_target_exists",
            Self::ImportUnsupportedVersion => "vault_import_unsupported_version",
            Self::Io => "vault_io_error",
            Self::PathRejected => "vault_path_rejected",
            #[cfg(not(target_os = "macos"))]
            Self::PlatformUnsupported => "vault_platform_unsupported",
            Self::Vault(error) => error.code(),
        }
    }
}

impl fmt::Debug for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for TransferError {}

impl From<VaultError> for TransferError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

pub(crate) trait TransferObserver: Send + Sync {
    fn update(&self, phase: &'static str, bytes: u64, entries: u64, cancellable: bool);
    fn is_cancelled(&self) -> bool;
}

#[derive(Clone, Copy)]
struct Preamble {
    package_id: [u8; 16],
    salt: [u8; 32],
    entry_count: u32,
    record_count: u32,
    nonce_count: u32,
    body_length: u64,
}

struct PackageMetadata {
    preamble: Preamble,
    manifest_bytes: [u8; MANIFEST_LENGTH],
    metadata: VaultMetadata,
    migration_applied_at_ms: u64,
    nonces: HashMap<[u8; 12], u8>,
}

struct ValidatedPackage {
    package: PackageMetadata,
    vdk: Vdk,
}

#[cfg(target_os = "macos")]
struct QuarantinedPackage {
    leaf: std::ffi::CString,
    file: File,
}

#[cfg(target_os = "macos")]
pub(crate) fn export_vault(
    vault: &UnlockedVault,
    target: &Path,
    observer: &dyn TransferObserver,
) -> Result<(), TransferError> {
    require_extension(target)?;
    observer.update("preparing", 0, 0, true);
    check_cancel(observer)?;
    let (parent, target_leaf) = split_path(target).map_err(map_path_error)?;
    let directory = Directory::open(parent).map_err(map_path_error)?;
    cleanup_stale_files(parent, &directory, StaleFileKind::Export, Some(&vault.vdk));
    directory
        .require_absent(&target_leaf)
        .map_err(|error| map_target_error(error, true))?;

    io_checkpoint("export-before-temp-create").map_err(|_| TransferError::Io)?;
    let (package_id, salt, authentication_nonce, temporary_leaf, mut file) =
        create_export_temp(&directory)?;
    let preparation_result = (|| {
        io_checkpoint("export-after-temp-create").map_err(|_| TransferError::Io)?;
        export_to_file(
            vault,
            &mut file,
            package_id,
            salt,
            authentication_nonce,
            observer,
        )?;
        io_checkpoint("export-before-file-sync").map_err(|_| TransferError::Io)?;
        file.sync_all().map_err(|_| TransferError::Io)?;
        io_checkpoint("export-after-file-sync").map_err(|_| TransferError::Io)?;
        verify_private_regular(&file, Some(1)).map_err(|_| TransferError::PathRejected)?;
        let completed_length = file.metadata().map_err(|_| TransferError::Io)?.len();
        io_checkpoint("export-after-file-verify").map_err(|_| TransferError::Io)?;
        check_cancel(observer)?;
        Ok(completed_length)
    })();
    let completed_length = match preparation_result {
        Ok(value) => value,
        Err(error) => {
            drop(file);
            let _ = directory.unlink(&temporary_leaf);
            let _ = directory.sync();
            return Err(error);
        }
    };
    drop(file);

    observer.update("publishing", completed_length, 0, false);
    if io_checkpoint("export-before-link").is_err() {
        let _ = directory.unlink(&temporary_leaf);
        let _ = directory.sync();
        return Err(TransferError::Io);
    }
    if directory.recheck_path(parent).is_err() {
        let _ = directory.unlink(&temporary_leaf);
        let _ = directory.sync();
        return Err(TransferError::PathRejected);
    }
    if let Err(error) = directory.link_no_replace(&temporary_leaf, &target_leaf) {
        let _ = directory.unlink(&temporary_leaf);
        let _ = directory.sync();
        return Err(map_target_error(error, true));
    }
    io_checkpoint("export-after-link").map_err(|_| TransferError::Io)?;
    if let Err(error) =
        io_checkpoint("export-before-publish-dir-sync").and_then(|()| directory.sync())
    {
        let target_file = directory
            .open_readonly(&target_leaf)
            .map_err(|_| TransferError::Io)?;
        verify_private_regular(&target_file, Some(2)).map_err(|_| TransferError::Io)?;
        if target_file.metadata().map_err(|_| TransferError::Io)?.len() < MIN_PACKAGE_LENGTH {
            return Err(TransferError::Io);
        }
        let _ = error;
    }
    io_checkpoint("export-after-publish-dir-sync").map_err(|_| TransferError::Io)?;
    io_checkpoint("export-before-temp-unlink").map_err(|_| TransferError::Io)?;
    directory
        .unlink(&temporary_leaf)
        .map_err(|_| TransferError::Io)?;
    io_checkpoint("export-after-temp-unlink").map_err(|_| TransferError::Io)?;
    io_checkpoint("export-before-clean-dir-sync").map_err(|_| TransferError::Io)?;
    directory.sync().map_err(|_| TransferError::Io)?;
    io_checkpoint("export-after-clean-dir-sync").map_err(|_| TransferError::Io)?;
    observer.update("completed", 0, 0, false);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn export_vault(
    _vault: &UnlockedVault,
    _target: &Path,
    _observer: &dyn TransferObserver,
) -> Result<(), TransferError> {
    Err(TransferError::PlatformUnsupported)
}

#[cfg(target_os = "macos")]
pub(crate) fn import_vault(
    source: &Path,
    target: &Path,
    password: &MasterPassword,
    observer: &dyn TransferObserver,
) -> Result<(), TransferError> {
    require_extension(source)?;
    require_target_absent(target)?;
    observer.update("copying", 0, 0, true);
    let target_parent = target.parent().ok_or(TransferError::PathRejected)?;
    let target_directory = Directory::open(target_parent).map_err(map_path_error)?;
    require_target_absent_in(target, &target_directory)?;
    let mut quarantine = copy_to_quarantine(source, target_parent, &target_directory, observer)?;
    let result = import_quarantine(
        &mut quarantine.file,
        target,
        &target_directory,
        password,
        observer,
    );
    drop(quarantine.file);
    if io_checkpoint("import-before-quarantine-unlink").is_ok() {
        let _ = target_directory.unlink(&quarantine.leaf);
    }
    if io_checkpoint("import-before-quarantine-dir-sync").is_ok() {
        let _ = target_directory.sync();
    }
    result
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn import_vault(
    _source: &Path,
    _target: &Path,
    _password: &MasterPassword,
    _observer: &dyn TransferObserver,
) -> Result<(), TransferError> {
    Err(TransferError::PlatformUnsupported)
}

#[cfg(target_os = "macos")]
pub(crate) fn cleanup_stale_import_artifacts(target: &Path) {
    let Some(parent) = target.parent() else {
        return;
    };
    let Ok(directory) = Directory::open(parent) else {
        return;
    };
    cleanup_stale_files(parent, &directory, StaleFileKind::Import, None);
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn cleanup_stale_import_artifacts(_target: &Path) {}

#[cfg(target_os = "macos")]
fn export_to_file(
    vault: &UnlockedVault,
    file: &mut File,
    package_id: [u8; 16],
    salt: [u8; 32],
    authentication_nonce: [u8; 12],
    observer: &dyn TransferObserver,
) -> Result<(), TransferError> {
    observer.update("snapshotting", 0, 0, true);
    io_checkpoint("export-before-snapshot").map_err(|_| TransferError::Io)?;
    let mut connection = vault.repository.connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(VaultError::from)?;
    let metadata = load_metadata(&transaction)?;
    validate_header_versions(&metadata.header)?;
    verify_header_authentication(&metadata, &vault.vdk)?;
    let migration_applied_at_ms = migration_applied_at_ms(&transaction)?;
    let record_count = query_count(&transaction, "vault_records")?;
    let nonce_count = query_count(&transaction, "nonce_reservations")?;
    validate_counts(record_count, nonce_count, true)?;
    let frame_bytes: u64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(length(frame)), 0) FROM vault_records",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(VaultError::from)
        .and_then(nonnegative_u64)?;
    let entry_count = 4_u32
        .checked_add(record_count)
        .and_then(|value| value.checked_add(nonce_count))
        .ok_or(TransferError::ExportLimitExceeded)?;
    let body_length = body_length(record_count, nonce_count, frame_bytes)
        .ok_or(TransferError::ExportLimitExceeded)?;
    if !(MIN_BODY_LENGTH..=MAX_BODY_LENGTH).contains(&body_length) {
        return Err(TransferError::ExportLimitExceeded);
    }
    let preamble = Preamble {
        package_id,
        salt,
        entry_count,
        record_count,
        nonce_count,
        body_length,
    };
    let preamble_bytes = encode_preamble(preamble);
    transfer_write_all(file, &preamble_bytes, "export-write-preamble")?;
    io_checkpoint("export-after-preamble-write").map_err(|_| TransferError::Io)?;
    let mut body_digest = Sha256::new();
    let mut ordinal = 0_u32;
    let mut bytes_written = PREAMBLE_LENGTH as u64;
    observer.update("writing", bytes_written, 0, true);

    for (entry_type, payload) in [
        (1, encode_header(&metadata.header).to_vec()),
        (2, encode_master(&metadata.master)?.to_vec()),
        (3, encode_recovery(&metadata.recovery)?.to_vec()),
        (4, encode_schema(migration_applied_at_ms).to_vec()),
    ] {
        write_entry(
            file,
            &mut body_digest,
            entry_type,
            ordinal,
            &payload,
            "export-write-metadata-entry",
        )?;
        ordinal = ordinal
            .checked_add(1)
            .ok_or(TransferError::ExportLimitExceeded)?;
        bytes_written = bytes_written
            .checked_add(ENTRY_PREFIX_LENGTH as u64 + payload.len() as u64)
            .ok_or(TransferError::ExportLimitExceeded)?;
        observer.update("writing", bytes_written, u64::from(ordinal), true);
        check_cancel(observer)?;
    }
    io_checkpoint("export-after-metadata-writes").map_err(|_| TransferError::Io)?;

    let mut nonce_map = HashMap::with_capacity(nonce_count as usize);
    {
        let mut statement = transaction
            .prepare(
                "SELECT nonce, purpose, reserved_at_ms FROM nonce_reservations ORDER BY nonce ASC",
            )
            .map_err(VaultError::from)?;
        let mut rows = statement.query([]).map_err(VaultError::from)?;
        while let Some(row) = rows.next().map_err(VaultError::from)? {
            let nonce = read_array::<12>(&row.get::<_, Vec<u8>>(0).map_err(VaultError::from)?)?;
            let purpose_i64 = row.get::<_, i64>(1).map_err(VaultError::from)?;
            let purpose = u8::try_from(purpose_i64).map_err(|_| VaultError::Corrupt)?;
            validate_nonce_purpose(purpose, true)?;
            let reserved_at_ms = nonnegative_u64(row.get(2).map_err(VaultError::from)?)?;
            if nonce_map.insert(nonce, purpose).is_some() {
                return Err(VaultError::Corrupt.into());
            }
            let payload = encode_nonce(nonce, purpose, reserved_at_ms);
            write_entry(
                file,
                &mut body_digest,
                5,
                ordinal,
                &payload,
                "export-write-nonce-entry",
            )?;
            ordinal += 1;
            bytes_written += (ENTRY_PREFIX_LENGTH + NONCE_PAYLOAD_LENGTH) as u64;
            observer.update("writing", bytes_written, u64::from(ordinal), true);
            check_cancel(observer)?;
        }
    }
    io_checkpoint("export-after-nonce-writes").map_err(|_| TransferError::Io)?;
    verify_active_metadata_nonces(&metadata, &nonce_map)?;

    {
        let mut active_record_nonces = HashSet::with_capacity(record_count as usize);
        let mut statement = transaction
            .prepare(
                "SELECT record_id, generation, frame, created_at_ms, updated_at_ms
                 FROM vault_records ORDER BY record_id ASC",
            )
            .map_err(VaultError::from)?;
        let mut rows = statement.query([]).map_err(VaultError::from)?;
        while let Some(row) = rows.next().map_err(VaultError::from)? {
            let record_id = read_array::<16>(&row.get::<_, Vec<u8>>(0).map_err(VaultError::from)?)?;
            let generation = positive_u64(row.get(1).map_err(VaultError::from)?)?;
            let frame = row.get::<_, Vec<u8>>(2).map_err(VaultError::from)?;
            let created_at_ms = nonnegative_u64(row.get(3).map_err(VaultError::from)?)?;
            let updated_at_ms = nonnegative_u64(row.get(4).map_err(VaultError::from)?)?;
            validate_record(
                &vault.vdk,
                RecordToValidate {
                    vault_id: metadata.header.vault_id,
                    record_id,
                    generation,
                    created_at_ms,
                    updated_at_ms,
                    frame: &frame,
                },
                &nonce_map,
            )?;
            if !active_record_nonces.insert(decode_frame(&frame)?.nonce) {
                return Err(VaultError::Corrupt.into());
            }
            let payload =
                encode_record(record_id, generation, created_at_ms, updated_at_ms, &frame)?;
            write_entry(
                file,
                &mut body_digest,
                6,
                ordinal,
                &payload,
                "export-write-record-entry",
            )?;
            ordinal += 1;
            bytes_written = bytes_written
                .checked_add(ENTRY_PREFIX_LENGTH as u64 + payload.len() as u64)
                .ok_or(TransferError::ExportLimitExceeded)?;
            observer.update("writing", bytes_written, u64::from(ordinal), true);
            check_cancel(observer)?;
        }
    }
    io_checkpoint("export-after-record-writes").map_err(|_| TransferError::Io)?;
    if ordinal != entry_count || bytes_written != PREAMBLE_LENGTH as u64 + body_length {
        return Err(VaultError::Corrupt.into());
    }
    let body_digest: [u8; 32] = body_digest.finalize().into();
    let manifest = encode_manifest(preamble, &metadata.header, body_digest);
    transfer_write_all(file, &manifest, "export-write-manifest")?;
    io_checkpoint("export-after-manifest-write").map_err(|_| TransferError::Io)?;
    let total_length = FIXED_PACKAGE_OVERHEAD
        .checked_add(body_length)
        .ok_or(TransferError::ExportLimitExceeded)?;
    let mut trailer = encode_trailer(authentication_nonce, [0; 16], total_length);
    let info = export_key_info(metadata.header.vault_id, package_id);
    let aad = export_authentication_aad(&preamble_bytes, &manifest, &trailer);
    let tag = export_authentication_tag(&vault.vdk, &salt, &info, &authentication_nonce, &aad)
        .map_err(VaultError::from)?;
    trailer[38..54].copy_from_slice(&tag);
    transfer_write_all(file, &trailer, "export-write-trailer")?;
    io_checkpoint("export-after-trailer-write").map_err(|_| TransferError::Io)?;
    io_checkpoint("export-before-flush").map_err(|_| TransferError::Io)?;
    file.flush().map_err(|_| TransferError::Io)?;
    io_checkpoint("export-after-flush").map_err(|_| TransferError::Io)?;
    if file.metadata().map_err(|_| TransferError::Io)?.len() != total_length {
        return Err(TransferError::Io);
    }
    transaction.commit().map_err(VaultError::from)?;
    io_checkpoint("export-after-snapshot-commit").map_err(|_| TransferError::Io)?;
    observer.update("verifying", total_length, u64::from(entry_count), true);
    Ok(())
}

#[cfg(target_os = "macos")]
fn import_quarantine(
    quarantine: &mut File,
    target: &Path,
    directory: &Directory,
    password: &MasterPassword,
    observer: &dyn TransferObserver,
) -> Result<(), TransferError> {
    observer.update("validating", 0, 0, true);
    io_checkpoint("import-before-package-parse").map_err(|_| TransferError::Io)?;
    let validated = parse_and_authenticate(quarantine, password, observer)?;
    io_checkpoint("import-after-package-parse").map_err(|_| TransferError::Io)?;
    observer.update("authenticating", 0, 0, true);
    io_checkpoint("import-before-record-validation").map_err(|_| TransferError::Io)?;
    validate_all_records(quarantine, &validated, observer)?;
    io_checkpoint("import-after-record-validation").map_err(|_| TransferError::Io)?;
    check_cancel(observer)?;
    observer.update("reconstructing", 0, 0, true);
    io_checkpoint("import-before-stage-create").map_err(|_| TransferError::Io)?;
    let (stage_path, stage_leaf) = create_import_stage(target, directory)?;
    if io_checkpoint("import-after-stage-create").is_err() {
        cleanup_owned_staging_files(&stage_path);
        return Err(TransferError::Io);
    }
    let construction = construct_database(quarantine, &stage_path, &validated, password, observer);
    if let Err(error) = construction {
        cleanup_owned_staging_files(&stage_path);
        return Err(error);
    }
    if let Err(error) = check_cancel(observer) {
        cleanup_owned_staging_files(&stage_path);
        return Err(error);
    }
    observer.update("publishing", 0, 0, false);
    let publication = (|| {
        let (parent, target_leaf) = split_path(target).map_err(map_path_error)?;
        directory.recheck_path(parent).map_err(map_path_error)?;
        directory
            .require_absent(&target_leaf)
            .map_err(|error| map_target_error(error, false))?;
        let stage_file = directory
            .open_readonly(&stage_leaf)
            .map_err(|_| TransferError::Io)?;
        verify_private_regular(&stage_file, Some(1)).map_err(|_| TransferError::PathRejected)?;
        drop(stage_file);
        io_checkpoint("import-before-link").map_err(|_| TransferError::Io)?;
        directory
            .link_no_replace(&stage_leaf, &target_leaf)
            .map_err(|error| map_target_error(error, false))?;
        io_checkpoint("import-after-link").map_err(|_| TransferError::Io)?;
        Ok(())
    })();
    if let Err(error) = publication {
        cleanup_owned_staging_files(&stage_path);
        return Err(error);
    }
    io_checkpoint("import-before-publish-dir-sync").map_err(|_| TransferError::Io)?;
    directory.sync().map_err(|_| TransferError::Io)?;
    io_checkpoint("import-after-publish-dir-sync").map_err(|_| TransferError::Io)?;
    io_checkpoint("import-before-stage-unlink").map_err(|_| TransferError::Io)?;
    directory
        .unlink(&stage_leaf)
        .map_err(|_| TransferError::Io)?;
    io_checkpoint("import-after-stage-unlink").map_err(|_| TransferError::Io)?;
    io_checkpoint("import-before-clean-dir-sync").map_err(|_| TransferError::Io)?;
    directory.sync().map_err(|_| TransferError::Io)?;
    io_checkpoint("import-after-clean-dir-sync").map_err(|_| TransferError::Io)?;
    cleanup_owned_staging_files(&stage_path);
    observer.update("completed", 0, 0, false);
    Ok(())
}

#[cfg(target_os = "macos")]
fn copy_to_quarantine(
    source: &Path,
    target_parent: &Path,
    target_directory: &Directory,
    observer: &dyn TransferObserver,
) -> Result<QuarantinedPackage, TransferError> {
    let (source_parent, source_leaf) = split_path(source).map_err(map_path_error)?;
    let source_directory = Directory::open(source_parent).map_err(map_path_error)?;
    let mut source_file = source_directory
        .open_readonly(&source_leaf)
        .map_err(map_path_error)?;
    let identity = source_identity(&source_file).map_err(|_| TransferError::PathRejected)?;
    let source_length = file_size(&identity).map_err(|_| TransferError::ImportInvalidPackage)?;
    if !(MIN_PACKAGE_LENGTH..=MAX_PACKAGE_LENGTH).contains(&source_length) {
        return Err(TransferError::ImportLimitExceeded);
    }
    io_checkpoint("import-before-quarantine-create").map_err(|_| TransferError::Io)?;
    let (_, quarantine_leaf, mut quarantine_file) = create_owned_temp(
        target_directory,
        target_parent,
        ".aeterna-import-package-v1-",
        ".tmp",
    )?;
    let mut buffer = [0_u8; STREAM_CHUNK];
    let mut copied = 0_u64;
    let copy_result = (|| {
        io_checkpoint("import-after-quarantine-create").map_err(|_| TransferError::Io)?;
        loop {
            check_cancel(observer)?;
            io_checkpoint("import-before-source-read").map_err(|_| TransferError::Io)?;
            let read = source_file
                .read(&mut buffer)
                .map_err(|_| TransferError::Io)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(read as u64)
                .ok_or(TransferError::ImportLimitExceeded)?;
            if copied > source_length || copied > MAX_PACKAGE_LENGTH {
                return Err(TransferError::ImportLimitExceeded);
            }
            transfer_write_all(
                &mut quarantine_file,
                &buffer[..read],
                "import-write-quarantine",
            )?;
            io_checkpoint("import-after-quarantine-write").map_err(|_| TransferError::Io)?;
            observer.update("copying", copied, 0, true);
        }
        if copied != source_length {
            return Err(TransferError::ImportInvalidPackage);
        }
        io_checkpoint("import-before-quarantine-sync").map_err(|_| TransferError::Io)?;
        quarantine_file.sync_all().map_err(|_| TransferError::Io)?;
        io_checkpoint("import-after-quarantine-sync").map_err(|_| TransferError::Io)?;
        private_regular_identity(&quarantine_file).map_err(|_| TransferError::PathRejected)?;
        recheck_identity(&source_file, &identity).map_err(|_| TransferError::PathRejected)?;
        io_checkpoint("import-after-source-recheck").map_err(|_| TransferError::Io)?;
        Ok(())
    })();
    if let Err(error) = copy_result {
        drop(quarantine_file);
        let _ = target_directory.unlink(&quarantine_leaf);
        return Err(error);
    }
    Ok(QuarantinedPackage {
        leaf: quarantine_leaf,
        file: quarantine_file,
    })
}

fn parse_and_authenticate(
    file: &mut File,
    password: &MasterPassword,
    observer: &dyn TransferObserver,
) -> Result<ValidatedPackage, TransferError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| TransferError::Io)?;
    let file_length = file.metadata().map_err(|_| TransferError::Io)?.len();
    if !(MIN_PACKAGE_LENGTH..=MAX_PACKAGE_LENGTH).contains(&file_length) {
        return Err(TransferError::ImportLimitExceeded);
    }
    let preamble_bytes = read_fixed::<PREAMBLE_LENGTH>(file)?;
    let preamble = decode_preamble(&preamble_bytes)?;
    if FIXED_PACKAGE_OVERHEAD
        .checked_add(preamble.body_length)
        .filter(|value| *value == file_length)
        .is_none()
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    let mut body_digest = Sha256::new();
    let mut header = None;
    let mut master = None;
    let mut recovery = None;
    let mut migration_applied_at_ms = None;
    let mut nonces = HashMap::with_capacity(preamble.nonce_count as usize);
    let mut prior_nonce = None;
    let mut prior_record = None;
    let mut consumed_body = 0_u64;
    for ordinal in 0..preamble.entry_count {
        check_cancel(observer)?;
        let expected_type =
            expected_entry_type(ordinal, preamble.nonce_count, preamble.record_count)?;
        let prefix = read_fixed::<ENTRY_PREFIX_LENGTH>(file)?;
        let (entry_type, payload_length, expected_digest) =
            decode_entry_prefix(&prefix, ordinal, expected_type)?;
        let payload_length =
            usize::try_from(payload_length).map_err(|_| TransferError::ImportLimitExceeded)?;
        validate_payload_length(entry_type, payload_length)?;
        consumed_body = consumed_body
            .checked_add(ENTRY_PREFIX_LENGTH as u64)
            .and_then(|value| value.checked_add(payload_length as u64))
            .ok_or(TransferError::ImportLimitExceeded)?;
        if consumed_body > preamble.body_length {
            return Err(TransferError::ImportInvalidPackage);
        }
        let payload = read_bounded(file, payload_length)?;
        if Sha256::digest(&payload).as_slice() != expected_digest {
            return Err(TransferError::ImportInvalidPackage);
        }
        body_digest.update(prefix);
        body_digest.update(&payload);
        match entry_type {
            1 => header = Some(decode_header(&payload)?),
            2 => master = Some(decode_master(&payload)?),
            3 => recovery = Some(decode_recovery(&payload)?),
            4 => migration_applied_at_ms = Some(decode_schema(&payload)?),
            5 => {
                let (nonce, purpose, _) = decode_nonce(&payload)?;
                if prior_nonce.is_some_and(|value| value >= nonce)
                    || nonces.insert(nonce, purpose).is_some()
                {
                    return Err(TransferError::ImportInvalidPackage);
                }
                prior_nonce = Some(nonce);
            }
            6 => {
                let (record_id, _, _, _, _) = decode_record(&payload)?;
                if prior_record.is_some_and(|value| value >= record_id) {
                    return Err(TransferError::ImportInvalidPackage);
                }
                prior_record = Some(record_id);
            }
            _ => return Err(TransferError::ImportUnsupportedVersion),
        }
        observer.update(
            "validating",
            PREAMBLE_LENGTH as u64 + consumed_body,
            u64::from(ordinal + 1),
            true,
        );
    }
    if consumed_body != preamble.body_length || nonces.len() != preamble.nonce_count as usize {
        return Err(TransferError::ImportInvalidPackage);
    }
    let manifest_bytes = read_fixed::<MANIFEST_LENGTH>(file)?;
    let trailer_bytes = read_fixed::<TRAILER_LENGTH>(file)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(|_| TransferError::Io)? != 0 {
        return Err(TransferError::ImportInvalidPackage);
    }
    let header = header.ok_or(TransferError::ImportInvalidPackage)?;
    let master = master.ok_or(TransferError::ImportInvalidPackage)?;
    let recovery = recovery.ok_or(TransferError::ImportInvalidPackage)?;
    let migration_applied_at_ms =
        migration_applied_at_ms.ok_or(TransferError::ImportInvalidPackage)?;
    let body_digest: [u8; 32] = body_digest.finalize().into();
    decode_manifest(&manifest_bytes, preamble, &header, body_digest)?;
    let (authentication_nonce, authentication_tag, total_length) = decode_trailer(&trailer_bytes)?;
    if total_length != file_length {
        return Err(TransferError::ImportInvalidPackage);
    }
    let metadata = VaultMetadata {
        header,
        master,
        recovery,
    };
    if metadata.recovery.device_id != metadata.header.device_id {
        return Err(TransferError::ImportInvalidPackage);
    }
    validate_header_versions(&metadata.header).map_err(map_import_vault_error)?;
    verify_active_metadata_nonces(&metadata, &nonces).map_err(map_import_vault_error)?;
    let context = WrapContext {
        vault_id: VaultId::new(metadata.header.vault_id),
        device_id: DeviceId::new(metadata.header.device_id),
    };
    let vdk = unwrap_master(password, &metadata.master.wrapper, context).map_err(|error| {
        if error.code() == "crypto_authentication_failed" {
            TransferError::AuthenticationFailed
        } else {
            TransferError::ImportInvalidPackage
        }
    })?;
    let info = export_key_info(metadata.header.vault_id, preamble.package_id);
    let aad = export_authentication_aad(&preamble_bytes, &manifest_bytes, &trailer_bytes);
    verify_export_authentication_tag(
        &vdk,
        &preamble.salt,
        &info,
        &authentication_nonce,
        &aad,
        &authentication_tag,
    )
    .map_err(|_| TransferError::AuthenticationFailed)?;
    verify_header_authentication(&metadata, &vdk).map_err(|error| {
        if error == VaultError::AuthenticationFailed {
            TransferError::AuthenticationFailed
        } else {
            TransferError::ImportInvalidPackage
        }
    })?;
    Ok(ValidatedPackage {
        package: PackageMetadata {
            preamble,
            manifest_bytes,
            metadata,
            migration_applied_at_ms,
            nonces,
        },
        vdk,
    })
}

fn validate_all_records(
    file: &mut File,
    validated: &ValidatedPackage,
    observer: &dyn TransferObserver,
) -> Result<(), TransferError> {
    file.seek(SeekFrom::Start(PREAMBLE_LENGTH as u64))
        .map_err(|_| TransferError::Io)?;
    let mut active_nonces =
        HashSet::with_capacity(validated.package.preamble.record_count as usize);
    for ordinal in 0..validated.package.preamble.entry_count {
        check_cancel(observer)?;
        let expected_type = expected_entry_type(
            ordinal,
            validated.package.preamble.nonce_count,
            validated.package.preamble.record_count,
        )?;
        let prefix = read_fixed::<ENTRY_PREFIX_LENGTH>(file)?;
        let (entry_type, payload_length, digest) =
            decode_entry_prefix(&prefix, ordinal, expected_type)?;
        let payload_length =
            usize::try_from(payload_length).map_err(|_| TransferError::ImportLimitExceeded)?;
        validate_payload_length(entry_type, payload_length)?;
        let payload = read_bounded(file, payload_length)?;
        if Sha256::digest(&payload).as_slice() != digest {
            return Err(TransferError::ImportInvalidPackage);
        }
        if entry_type == 6 {
            let (record_id, generation, created_at_ms, updated_at_ms, frame) =
                decode_record(&payload)?;
            validate_record(
                &validated.vdk,
                RecordToValidate {
                    vault_id: validated.package.metadata.header.vault_id,
                    record_id,
                    generation,
                    created_at_ms,
                    updated_at_ms,
                    frame,
                },
                &validated.package.nonces,
            )
            .map_err(map_import_vault_error)?;
            let nonce = decode_frame(frame).map_err(map_import_vault_error)?.nonce;
            if !active_nonces.insert(nonce) {
                return Err(TransferError::ImportInvalidPackage);
            }
        }
        observer.update("authenticating", 0, u64::from(ordinal + 1), true);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn construct_database(
    package_file: &mut File,
    stage_path: &Path,
    validated: &ValidatedPackage,
    password: &MasterPassword,
    observer: &dyn TransferObserver,
) -> Result<(), TransferError> {
    io_checkpoint("import-before-database-open").map_err(|_| TransferError::Io)?;
    let mut connection = open_connection(stage_path, true)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(VaultError::from)?;
    io_checkpoint("import-before-schema").map_err(|_| TransferError::Io)?;
    migration::apply_initial_schema(&transaction, validated.package.migration_applied_at_ms)?;
    io_checkpoint("import-before-metadata-insert").map_err(|_| TransferError::Io)?;
    insert_exact_metadata(&transaction, &validated.package.metadata)?;
    package_file
        .seek(SeekFrom::Start(PREAMBLE_LENGTH as u64))
        .map_err(|_| TransferError::Io)?;
    let mut body_digest = Sha256::new();
    for ordinal in 0..validated.package.preamble.entry_count {
        check_cancel(observer)?;
        let expected_type = expected_entry_type(
            ordinal,
            validated.package.preamble.nonce_count,
            validated.package.preamble.record_count,
        )?;
        let prefix = read_fixed::<ENTRY_PREFIX_LENGTH>(package_file)?;
        let (entry_type, payload_length, digest) =
            decode_entry_prefix(&prefix, ordinal, expected_type)?;
        let payload_length =
            usize::try_from(payload_length).map_err(|_| TransferError::ImportLimitExceeded)?;
        validate_payload_length(entry_type, payload_length)?;
        let payload = read_bounded(package_file, payload_length)?;
        if Sha256::digest(&payload).as_slice() != digest {
            return Err(TransferError::ImportInvalidPackage);
        }
        body_digest.update(prefix);
        body_digest.update(&payload);
        match entry_type {
            5 => {
                let (nonce, purpose, reserved_at_ms) = decode_nonce(&payload)?;
                io_checkpoint("import-before-nonce-insert").map_err(|_| TransferError::Io)?;
                transaction
                    .execute(
                        "INSERT INTO nonce_reservations (nonce, purpose, reserved_at_ms) VALUES (?1, ?2, ?3)",
                        params![
                            nonce.as_slice(),
                            i64::from(purpose),
                            migration::to_sql_integer(reserved_at_ms)?
                        ],
                    )
                    .map_err(VaultError::from)?;
            }
            6 => {
                let (record_id, generation, created_at_ms, updated_at_ms, frame) =
                    decode_record(&payload)?;
                io_checkpoint("import-before-record-insert").map_err(|_| TransferError::Io)?;
                transaction
                    .execute(
                        "INSERT INTO vault_records (record_id, singleton, generation, frame, created_at_ms, updated_at_ms) VALUES (?1, 1, ?2, ?3, ?4, ?5)",
                        params![
                            record_id.as_slice(),
                            migration::to_sql_integer(generation)?,
                            frame,
                            migration::to_sql_integer(created_at_ms)?,
                            migration::to_sql_integer(updated_at_ms)?,
                        ],
                    )
                    .map_err(VaultError::from)?;
            }
            _ => {}
        }
        observer.update("reconstructing", 0, u64::from(ordinal + 1), true);
    }
    let body_digest: [u8; 32] = body_digest.finalize().into();
    if validated.package.manifest_bytes[92..124] != body_digest {
        return Err(TransferError::ImportInvalidPackage);
    }
    io_checkpoint("import-before-database-commit").map_err(|_| TransferError::Io)?;
    transaction.commit().map_err(VaultError::from)?;
    io_checkpoint("import-after-database-commit").map_err(|_| TransferError::Io)?;
    io_checkpoint("import-before-checkpoint").map_err(|_| TransferError::Io)?;
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(VaultError::from)?;
    io_checkpoint("import-after-checkpoint").map_err(|_| TransferError::Io)?;
    drop(connection);
    io_checkpoint("import-after-database-close").map_err(|_| TransferError::Io)?;
    io_checkpoint("import-before-stage-sync").map_err(|_| TransferError::Io)?;
    File::open(stage_path)
        .and_then(|file| file.sync_all())
        .map_err(|_| TransferError::Io)?;
    io_checkpoint("import-after-stage-sync").map_err(|_| TransferError::Io)?;
    observer.update("verifying", 0, 0, true);
    io_checkpoint("import-before-stage-verify").map_err(|_| TransferError::Io)?;
    let repository = VaultRepository::open(stage_path)?;
    let unlocked = repository
        .unlock(password)
        .map_err(map_import_vault_error)?;
    let items = unlocked.list_items().map_err(map_import_vault_error)?;
    drop(items);
    preflight_vault_files(stage_path)?;
    io_checkpoint("import-after-stage-verify").map_err(|_| TransferError::Io)?;
    Ok(())
}

fn insert_exact_metadata(
    connection: &Connection,
    metadata: &VaultMetadata,
) -> Result<(), TransferError> {
    let header = &metadata.header;
    connection
        .execute(
            "INSERT INTO vault_header (singleton, magic, container_version, schema_version, crypto_version, vault_id, device_id, header_auth_nonce, header_auth_tag, created_at_ms, updated_at_ms) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                header.magic.as_slice(),
                i64::from(header.container_version),
                i64::from(header.schema_version),
                i64::from(header.crypto_version),
                header.vault_id.as_slice(),
                header.device_id.as_slice(),
                header.auth_nonce.as_slice(),
                header.auth_tag.as_slice(),
                migration::to_sql_integer(header.created_at_ms)?,
                migration::to_sql_integer(header.updated_at_ms)?,
            ],
        )
        .map_err(VaultError::from)?;
    let master = &metadata.master;
    connection
        .execute(
            "INSERT INTO master_wrapper (singleton, revision, format_version, aead_algorithm, purpose, kdf_algorithm, kdf_version, memory_kib, time_cost, parallelism, output_length, salt, nonce, ciphertext_and_tag, created_at_ms, updated_at_ms) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                migration::to_sql_integer(master.revision)?,
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
                migration::to_sql_integer(master.created_at_ms)?,
                migration::to_sql_integer(master.updated_at_ms)?,
            ],
        )
        .map_err(VaultError::from)?;
    let recovery = &metadata.recovery;
    connection
        .execute(
            "INSERT INTO recovery_wrapper (singleton, recovery_id, device_id, format_version, aead_algorithm, purpose, nonce, ciphertext_and_tag, created_at_ms) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                recovery.recovery_id.as_slice(),
                recovery.device_id.as_slice(),
                i64::from(recovery.wrapper.format_version),
                i64::from(recovery.wrapper.aead_algorithm),
                i64::from(recovery.wrapper.purpose),
                recovery.wrapper.nonce.as_slice(),
                recovery.wrapper.ciphertext_and_tag.as_slice(),
                migration::to_sql_integer(recovery.created_at_ms)?,
            ],
        )
        .map_err(VaultError::from)?;
    Ok(())
}

fn write_entry(
    writer: &mut File,
    body_digest: &mut Sha256,
    entry_type: u16,
    ordinal: u32,
    payload: &[u8],
    fault_point: &str,
) -> Result<(), TransferError> {
    let prefix = encode_entry_prefix(entry_type, ordinal, payload)?;
    transfer_write_all(writer, &prefix, fault_point)?;
    transfer_write_all(writer, payload, fault_point)?;
    body_digest.update(prefix);
    body_digest.update(payload);
    Ok(())
}

fn encode_preamble(value: Preamble) -> [u8; PREAMBLE_LENGTH] {
    let mut output = [0_u8; PREAMBLE_LENGTH];
    output[0..16].copy_from_slice(&PACKAGE_MAGIC);
    output[16..18].copy_from_slice(&PACKAGE_VERSION.to_be_bytes());
    output[18..20].copy_from_slice(&MANIFEST_VERSION.to_be_bytes());
    output[20..22].copy_from_slice(&AUTHENTICATION_VERSION.to_be_bytes());
    output[24..40].copy_from_slice(&value.package_id);
    output[40..72].copy_from_slice(&value.salt);
    output[72..76].copy_from_slice(&value.entry_count.to_be_bytes());
    output[76..80].copy_from_slice(&value.record_count.to_be_bytes());
    output[80..84].copy_from_slice(&value.nonce_count.to_be_bytes());
    output[84..92].copy_from_slice(&value.body_length.to_be_bytes());
    output[92..96].copy_from_slice(&(MANIFEST_LENGTH as u32).to_be_bytes());
    output
}

fn decode_preamble(bytes: &[u8; PREAMBLE_LENGTH]) -> Result<Preamble, TransferError> {
    if bytes[0..16] != PACKAGE_MAGIC {
        return Err(TransferError::ImportInvalidPackage);
    }
    if read_u16(&bytes[16..18])? != PACKAGE_VERSION
        || read_u16(&bytes[18..20])? != MANIFEST_VERSION
        || read_u16(&bytes[20..22])? != AUTHENTICATION_VERSION
    {
        return Err(TransferError::ImportUnsupportedVersion);
    }
    if read_u16(&bytes[22..24])? != 0 || read_u32(&bytes[92..96])? != MANIFEST_LENGTH as u32 {
        return Err(TransferError::ImportInvalidPackage);
    }
    let value = Preamble {
        package_id: read_array(&bytes[24..40]).map_err(map_import_vault_error)?,
        salt: read_array(&bytes[40..72]).map_err(map_import_vault_error)?,
        entry_count: read_u32(&bytes[72..76])?,
        record_count: read_u32(&bytes[76..80])?,
        nonce_count: read_u32(&bytes[80..84])?,
        body_length: read_u64(&bytes[84..92])?,
    };
    validate_counts(value.record_count, value.nonce_count, false)?;
    let expected_entries = 4_u32
        .checked_add(value.record_count)
        .and_then(|count| count.checked_add(value.nonce_count))
        .ok_or(TransferError::ImportLimitExceeded)?;
    if value.entry_count != expected_entries
        || value.entry_count > MAX_ENTRIES
        || !(MIN_BODY_LENGTH..=MAX_BODY_LENGTH).contains(&value.body_length)
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    Ok(value)
}

fn encode_entry_prefix(
    entry_type: u16,
    ordinal: u32,
    payload: &[u8],
) -> Result<[u8; ENTRY_PREFIX_LENGTH], TransferError> {
    let payload_length =
        u64::try_from(payload.len()).map_err(|_| TransferError::ExportLimitExceeded)?;
    let mut output = [0_u8; ENTRY_PREFIX_LENGTH];
    output[0..4].copy_from_slice(&ENTRY_MAGIC);
    output[4..6].copy_from_slice(&entry_type.to_be_bytes());
    output[6..8].copy_from_slice(&ENTRY_VERSION.to_be_bytes());
    output[8..12].copy_from_slice(&ordinal.to_be_bytes());
    output[12..20].copy_from_slice(&payload_length.to_be_bytes());
    output[20..52].copy_from_slice(&Sha256::digest(payload));
    Ok(output)
}

fn decode_entry_prefix(
    bytes: &[u8; ENTRY_PREFIX_LENGTH],
    ordinal: u32,
    expected_type: u16,
) -> Result<(u16, u64, &[u8]), TransferError> {
    if bytes[0..4] != ENTRY_MAGIC {
        return Err(TransferError::ImportInvalidPackage);
    }
    if read_u16(&bytes[6..8])? != ENTRY_VERSION {
        return Err(TransferError::ImportUnsupportedVersion);
    }
    let entry_type = read_u16(&bytes[4..6])?;
    if entry_type != expected_type
        || read_u32(&bytes[8..12])? != ordinal
        || read_u32(&bytes[52..56])? != 0
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    Ok((entry_type, read_u64(&bytes[12..20])?, &bytes[20..52]))
}

fn encode_header(value: &HeaderRow) -> [u8; HEADER_PAYLOAD_LENGTH] {
    let mut output = [0_u8; HEADER_PAYLOAD_LENGTH];
    output[0..12].copy_from_slice(&value.magic);
    output[12..14].copy_from_slice(&value.container_version.to_be_bytes());
    output[14..18].copy_from_slice(&value.schema_version.to_be_bytes());
    output[18..20].copy_from_slice(&value.crypto_version.to_be_bytes());
    output[20..36].copy_from_slice(&value.vault_id);
    output[36..52].copy_from_slice(&value.device_id);
    output[52..64].copy_from_slice(&value.auth_nonce);
    output[64..80].copy_from_slice(&value.auth_tag);
    output[80..88].copy_from_slice(&value.created_at_ms.to_be_bytes());
    output[88..96].copy_from_slice(&value.updated_at_ms.to_be_bytes());
    output
}

fn decode_header(bytes: &[u8]) -> Result<HeaderRow, TransferError> {
    if bytes.len() != HEADER_PAYLOAD_LENGTH {
        return Err(TransferError::ImportInvalidPackage);
    }
    let value = HeaderRow {
        magic: read_array(&bytes[0..12]).map_err(map_import_vault_error)?,
        container_version: read_u16(&bytes[12..14])?,
        schema_version: read_u32(&bytes[14..18])?,
        crypto_version: read_u16(&bytes[18..20])?,
        vault_id: read_array(&bytes[20..36]).map_err(map_import_vault_error)?,
        device_id: read_array(&bytes[36..52]).map_err(map_import_vault_error)?,
        auth_nonce: read_array(&bytes[52..64]).map_err(map_import_vault_error)?,
        auth_tag: read_array(&bytes[64..80]).map_err(map_import_vault_error)?,
        created_at_ms: read_u64(&bytes[80..88])?,
        updated_at_ms: read_u64(&bytes[88..96])?,
    };
    if value.updated_at_ms < value.created_at_ms {
        return Err(TransferError::ImportInvalidPackage);
    }
    Ok(value)
}

fn encode_master(value: &MasterRow) -> Result<[u8; MASTER_PAYLOAD_LENGTH], TransferError> {
    if value.wrapper.ciphertext_and_tag.len() != 48 {
        return Err(VaultError::Corrupt.into());
    }
    let mut output = [0_u8; MASTER_PAYLOAD_LENGTH];
    output[0..8].copy_from_slice(&value.revision.to_be_bytes());
    output[8..10].copy_from_slice(&value.wrapper.format_version.to_be_bytes());
    output[10] = value.wrapper.aead_algorithm;
    output[11] = value.wrapper.purpose;
    output[12] = value.wrapper.kdf_algorithm;
    output[13] = value.wrapper.kdf_version;
    output[14..18].copy_from_slice(&value.wrapper.profile.memory_kib.to_be_bytes());
    output[18..22].copy_from_slice(&value.wrapper.profile.time_cost.to_be_bytes());
    output[22..26].copy_from_slice(&value.wrapper.profile.parallelism.to_be_bytes());
    output[26..28].copy_from_slice(&value.wrapper.profile.output_length.to_be_bytes());
    output[28..44].copy_from_slice(&value.wrapper.salt);
    output[44..56].copy_from_slice(&value.wrapper.nonce);
    output[56..104].copy_from_slice(&value.wrapper.ciphertext_and_tag);
    output[104..112].copy_from_slice(&value.created_at_ms.to_be_bytes());
    output[112..120].copy_from_slice(&value.updated_at_ms.to_be_bytes());
    Ok(output)
}

fn decode_master(bytes: &[u8]) -> Result<MasterRow, TransferError> {
    if bytes.len() != MASTER_PAYLOAD_LENGTH {
        return Err(TransferError::ImportInvalidPackage);
    }
    let value = MasterRow {
        revision: read_u64(&bytes[0..8])?,
        wrapper: MasterWrapper {
            format_version: read_u16(&bytes[8..10])?,
            aead_algorithm: bytes[10],
            purpose: bytes[11],
            kdf_algorithm: bytes[12],
            kdf_version: bytes[13],
            profile: Argon2Profile {
                memory_kib: read_u32(&bytes[14..18])?,
                time_cost: read_u32(&bytes[18..22])?,
                parallelism: read_u32(&bytes[22..26])?,
                output_length: read_u16(&bytes[26..28])?,
            },
            salt: read_array(&bytes[28..44]).map_err(map_import_vault_error)?,
            nonce: read_array(&bytes[44..56]).map_err(map_import_vault_error)?,
            ciphertext_and_tag: bytes[56..104].to_vec(),
        },
        created_at_ms: read_u64(&bytes[104..112])?,
        updated_at_ms: read_u64(&bytes[112..120])?,
    };
    if value.revision == 0 || value.updated_at_ms < value.created_at_ms {
        return Err(TransferError::ImportInvalidPackage);
    }
    if value.wrapper.format_version != format::CRYPTO_VERSION
        || value.wrapper.aead_algorithm != format::AES_256_GCM_ID
        || value.wrapper.purpose != MASTER_NONCE_PURPOSE
        || value.wrapper.kdf_algorithm != 1
        || value.wrapper.kdf_version != 0x13
        || value.wrapper.profile.output_length != 32
    {
        return Err(TransferError::ImportUnsupportedVersion);
    }
    value
        .wrapper
        .profile
        .validate()
        .map_err(|_| TransferError::ImportInvalidPackage)?;
    Ok(value)
}

fn encode_recovery(value: &RecoveryRow) -> Result<[u8; RECOVERY_PAYLOAD_LENGTH], TransferError> {
    if value.wrapper.ciphertext_and_tag.len() != 48 {
        return Err(VaultError::Corrupt.into());
    }
    let mut output = [0_u8; RECOVERY_PAYLOAD_LENGTH];
    output[0..16].copy_from_slice(&value.recovery_id);
    output[16..32].copy_from_slice(&value.device_id);
    output[32..34].copy_from_slice(&value.wrapper.format_version.to_be_bytes());
    output[34] = value.wrapper.aead_algorithm;
    output[35] = value.wrapper.purpose;
    output[36..48].copy_from_slice(&value.wrapper.nonce);
    output[48..96].copy_from_slice(&value.wrapper.ciphertext_and_tag);
    output[96..104].copy_from_slice(&value.created_at_ms.to_be_bytes());
    Ok(output)
}

fn decode_recovery(bytes: &[u8]) -> Result<RecoveryRow, TransferError> {
    if bytes.len() != RECOVERY_PAYLOAD_LENGTH {
        return Err(TransferError::ImportInvalidPackage);
    }
    let value = RecoveryRow {
        recovery_id: read_array(&bytes[0..16]).map_err(map_import_vault_error)?,
        device_id: read_array(&bytes[16..32]).map_err(map_import_vault_error)?,
        wrapper: RecoveryWrapper {
            format_version: read_u16(&bytes[32..34])?,
            aead_algorithm: bytes[34],
            purpose: bytes[35],
            nonce: read_array(&bytes[36..48]).map_err(map_import_vault_error)?,
            ciphertext_and_tag: bytes[48..96].to_vec(),
        },
        created_at_ms: read_u64(&bytes[96..104])?,
    };
    if value.wrapper.format_version != format::CRYPTO_VERSION
        || value.wrapper.aead_algorithm != format::AES_256_GCM_ID
        || value.wrapper.purpose != RECOVERY_NONCE_PURPOSE
    {
        return Err(TransferError::ImportUnsupportedVersion);
    }
    Ok(value)
}

fn encode_schema(applied_at_ms: u64) -> [u8; SCHEMA_PAYLOAD_LENGTH] {
    let mut output = [0_u8; SCHEMA_PAYLOAD_LENGTH];
    output[0..4].copy_from_slice(&(format::APPLICATION_ID as u32).to_be_bytes());
    output[4..8].copy_from_slice(&format::SCHEMA_VERSION.to_be_bytes());
    output[8..20].copy_from_slice(&format::VAULT_MAGIC);
    output[20..22].copy_from_slice(&format::CONTAINER_VERSION.to_be_bytes());
    output[22..26].copy_from_slice(&format::SCHEMA_VERSION.to_be_bytes());
    output[26..28].copy_from_slice(&format::CRYPTO_VERSION.to_be_bytes());
    output[28] = format::HEADER_AAD_VERSION;
    output[29] = WRAPPER_SET_ENCODING_VERSION;
    output[30..32].copy_from_slice(&format::RECORD_FRAME_VERSION.to_be_bytes());
    output[32] = format::RECORD_AAD_VERSION;
    output[33..35].copy_from_slice(&ITEM_PAYLOAD_VERSION.to_be_bytes());
    output[35..37].copy_from_slice(&1_u16.to_be_bytes());
    output[37..41].copy_from_slice(&format::SCHEMA_VERSION.to_be_bytes());
    output[41..43].copy_from_slice(&(migration::MIGRATION_NAME.len() as u16).to_be_bytes());
    output[43..58].copy_from_slice(migration::MIGRATION_NAME.as_bytes());
    output[58..90].copy_from_slice(&migration::migration_checksum());
    output[90..98].copy_from_slice(&applied_at_ms.to_be_bytes());
    output
}

fn decode_schema(bytes: &[u8]) -> Result<u64, TransferError> {
    if bytes.len() != SCHEMA_PAYLOAD_LENGTH {
        return Err(TransferError::ImportInvalidPackage);
    }
    if read_u32(&bytes[0..4])? != format::APPLICATION_ID as u32
        || read_u32(&bytes[4..8])? != format::SCHEMA_VERSION
        || bytes[8..20] != format::VAULT_MAGIC
        || read_u16(&bytes[20..22])? != format::CONTAINER_VERSION
        || read_u32(&bytes[22..26])? != format::SCHEMA_VERSION
        || read_u16(&bytes[26..28])? != format::CRYPTO_VERSION
        || bytes[28] != format::HEADER_AAD_VERSION
        || bytes[29] != WRAPPER_SET_ENCODING_VERSION
        || read_u16(&bytes[30..32])? != format::RECORD_FRAME_VERSION
        || bytes[32] != format::RECORD_AAD_VERSION
        || read_u16(&bytes[33..35])? != ITEM_PAYLOAD_VERSION
        || read_u16(&bytes[35..37])? != 1
        || read_u32(&bytes[37..41])? != format::SCHEMA_VERSION
        || read_u16(&bytes[41..43])? != migration::MIGRATION_NAME.len() as u16
        || bytes[43..58] != *migration::MIGRATION_NAME.as_bytes()
        || bytes[58..90] != migration::migration_checksum()
    {
        return Err(TransferError::ImportUnsupportedVersion);
    }
    read_u64(&bytes[90..98])
}

fn encode_nonce(nonce: [u8; 12], purpose: u8, reserved_at_ms: u64) -> [u8; 21] {
    let mut output = [0_u8; NONCE_PAYLOAD_LENGTH];
    output[0..12].copy_from_slice(&nonce);
    output[12] = purpose;
    output[13..21].copy_from_slice(&reserved_at_ms.to_be_bytes());
    output
}

fn decode_nonce(bytes: &[u8]) -> Result<([u8; 12], u8, u64), TransferError> {
    if bytes.len() != NONCE_PAYLOAD_LENGTH {
        return Err(TransferError::ImportInvalidPackage);
    }
    let purpose = bytes[12];
    validate_nonce_purpose(purpose, false)?;
    Ok((
        read_array(&bytes[0..12]).map_err(map_import_vault_error)?,
        purpose,
        read_u64(&bytes[13..21])?,
    ))
}

fn encode_record(
    record_id: [u8; 16],
    generation: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
    frame: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let frame_length =
        u32::try_from(frame.len()).map_err(|_| TransferError::ExportLimitExceeded)?;
    let mut output = Vec::with_capacity(RECORD_PREFIX_LENGTH + frame.len());
    output.extend_from_slice(&record_id);
    output.extend_from_slice(&generation.to_be_bytes());
    output.extend_from_slice(&created_at_ms.to_be_bytes());
    output.extend_from_slice(&updated_at_ms.to_be_bytes());
    output.extend_from_slice(&frame_length.to_be_bytes());
    output.extend_from_slice(frame);
    Ok(output)
}

type DecodedRecord<'a> = ([u8; 16], u64, u64, u64, &'a [u8]);

fn decode_record(bytes: &[u8]) -> Result<DecodedRecord<'_>, TransferError> {
    if !(RECORD_PREFIX_LENGTH + format::MIN_FRAME_LENGTH..=MAX_RECORD_PAYLOAD)
        .contains(&bytes.len())
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    let frame_length = usize::try_from(read_u32(&bytes[40..44])?)
        .map_err(|_| TransferError::ImportLimitExceeded)?;
    if frame_length > format::MAX_FRAME_LENGTH
        || RECORD_PREFIX_LENGTH.checked_add(frame_length) != Some(bytes.len())
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    let generation = read_u64(&bytes[16..24])?;
    let created_at_ms = read_u64(&bytes[24..32])?;
    let updated_at_ms = read_u64(&bytes[32..40])?;
    if generation == 0 || updated_at_ms < created_at_ms {
        return Err(TransferError::ImportInvalidPackage);
    }
    Ok((
        read_array(&bytes[0..16]).map_err(map_import_vault_error)?,
        generation,
        created_at_ms,
        updated_at_ms,
        &bytes[44..],
    ))
}

fn encode_manifest(
    preamble: Preamble,
    header: &HeaderRow,
    body_digest: [u8; 32],
) -> [u8; MANIFEST_LENGTH] {
    let mut output = [0_u8; MANIFEST_LENGTH];
    output[0..16].copy_from_slice(&MANIFEST_MAGIC);
    output[16..18].copy_from_slice(&MANIFEST_VERSION.to_be_bytes());
    output[18..20].copy_from_slice(&PACKAGE_VERSION.to_be_bytes());
    output[20..22].copy_from_slice(&AUTHENTICATION_VERSION.to_be_bytes());
    output[24..40].copy_from_slice(&preamble.package_id);
    output[40..56].copy_from_slice(&header.vault_id);
    output[56..72].copy_from_slice(&header.device_id);
    output[72..76].copy_from_slice(&preamble.entry_count.to_be_bytes());
    output[76..80].copy_from_slice(&preamble.record_count.to_be_bytes());
    output[80..84].copy_from_slice(&preamble.nonce_count.to_be_bytes());
    output[84..92].copy_from_slice(&preamble.body_length.to_be_bytes());
    output[92..124].copy_from_slice(&body_digest);
    output
}

fn decode_manifest(
    bytes: &[u8; MANIFEST_LENGTH],
    preamble: Preamble,
    header: &HeaderRow,
    body_digest: [u8; 32],
) -> Result<(), TransferError> {
    if bytes[0..16] != MANIFEST_MAGIC {
        return Err(TransferError::ImportInvalidPackage);
    }
    if read_u16(&bytes[16..18])? != MANIFEST_VERSION
        || read_u16(&bytes[18..20])? != PACKAGE_VERSION
        || read_u16(&bytes[20..22])? != AUTHENTICATION_VERSION
    {
        return Err(TransferError::ImportUnsupportedVersion);
    }
    if read_u16(&bytes[22..24])? != 0
        || bytes[24..40] != preamble.package_id
        || bytes[40..56] != header.vault_id
        || bytes[56..72] != header.device_id
        || read_u32(&bytes[72..76])? != preamble.entry_count
        || read_u32(&bytes[76..80])? != preamble.record_count
        || read_u32(&bytes[80..84])? != preamble.nonce_count
        || read_u64(&bytes[84..92])? != preamble.body_length
        || bytes[92..124] != body_digest
        || bytes[124..128] != [0; 4]
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    Ok(())
}

fn encode_trailer(
    authentication_nonce: [u8; 12],
    tag: [u8; 16],
    total_length: u64,
) -> [u8; TRAILER_LENGTH] {
    let mut output = [0_u8; TRAILER_LENGTH];
    output[0..16].copy_from_slice(&TRAILER_MAGIC);
    output[16..18].copy_from_slice(&TRAILER_VERSION.to_be_bytes());
    output[18] = AUTHENTICATION_ALGORITHM;
    output[19] = AUTHENTICATION_PURPOSE;
    output[26..38].copy_from_slice(&authentication_nonce);
    output[38..54].copy_from_slice(&tag);
    output[54..62].copy_from_slice(&total_length.to_be_bytes());
    output
}

fn decode_trailer(
    bytes: &[u8; TRAILER_LENGTH],
) -> Result<([u8; 12], [u8; 16], u64), TransferError> {
    if bytes[0..16] != TRAILER_MAGIC {
        return Err(TransferError::ImportInvalidPackage);
    }
    if read_u16(&bytes[16..18])? != TRAILER_VERSION {
        return Err(TransferError::ImportUnsupportedVersion);
    }
    if bytes[18] != AUTHENTICATION_ALGORITHM
        || bytes[19] != AUTHENTICATION_PURPOSE
        || read_u16(&bytes[20..22])? != 0
        || bytes[22..26] != [0; 4]
        || bytes[62..64] != [0; 2]
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    Ok((
        read_array(&bytes[26..38]).map_err(map_import_vault_error)?,
        read_array(&bytes[38..54]).map_err(map_import_vault_error)?,
        read_u64(&bytes[54..62])?,
    ))
}

fn export_key_info(vault_id: [u8; 16], package_id: [u8; 16]) -> [u8; 56] {
    let mut output = [0_u8; 56];
    output[0..18].copy_from_slice(&EXPORT_KEY_DOMAIN);
    output[18] = 1;
    output[19..21].copy_from_slice(&format::CRYPTO_VERSION.to_be_bytes());
    output[21] = AUTHENTICATION_PURPOSE;
    output[22..38].copy_from_slice(&vault_id);
    output[38..54].copy_from_slice(&package_id);
    output[54..56].copy_from_slice(&32_u16.to_be_bytes());
    output
}

fn export_authentication_aad(
    preamble: &[u8; PREAMBLE_LENGTH],
    manifest: &[u8; MANIFEST_LENGTH],
    trailer: &[u8; TRAILER_LENGTH],
) -> [u8; 294] {
    let mut output = [0_u8; 294];
    output[0..19].copy_from_slice(&EXPORT_AUTH_DOMAIN);
    output[19] = 1;
    output[20..22].copy_from_slice(&format::CRYPTO_VERSION.to_be_bytes());
    output[22..118].copy_from_slice(preamble);
    output[118..246].copy_from_slice(manifest);
    output[246..284].copy_from_slice(&trailer[0..38]);
    output[284..294].copy_from_slice(&trailer[54..64]);
    output
}

struct RecordToValidate<'a> {
    vault_id: [u8; 16],
    record_id: [u8; 16],
    generation: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
    frame: &'a [u8],
}

fn validate_record(
    vdk: &Vdk,
    record: RecordToValidate<'_>,
    nonces: &HashMap<[u8; 12], u8>,
) -> Result<(), VaultError> {
    if record.generation == 0 || record.updated_at_ms < record.created_at_ms {
        return Err(VaultError::InvalidFormat);
    }
    let decoded = decode_frame(record.frame)?;
    if nonces.get(&decoded.nonce) != Some(&RECORD_NONCE_PURPOSE) {
        return Err(VaultError::Corrupt);
    }
    let aad = record_aad(
        record.vault_id,
        record.record_id,
        record.generation,
        record.created_at_ms,
        record.updated_at_ms,
        decoded.plaintext_length,
    )?;
    let plaintext = decrypt_payload(vdk, &decoded.nonce, decoded.ciphertext_and_tag, &aad)?;
    if plaintext.len() != decoded.plaintext_length {
        return Err(VaultError::InvalidFormat);
    }
    validate_item_payload(&plaintext)
}

fn verify_active_metadata_nonces(
    metadata: &VaultMetadata,
    nonces: &HashMap<[u8; 12], u8>,
) -> Result<(), VaultError> {
    for (nonce, purpose) in [
        (metadata.master.wrapper.nonce, MASTER_NONCE_PURPOSE),
        (metadata.recovery.wrapper.nonce, RECOVERY_NONCE_PURPOSE),
        (metadata.header.auth_nonce, HEADER_NONCE_PURPOSE),
    ] {
        if nonces.get(&nonce) != Some(&purpose) {
            return Err(VaultError::Corrupt);
        }
    }
    Ok(())
}

fn query_count(connection: &Connection, table: &str) -> Result<u32, TransferError> {
    let statement = match table {
        "vault_records" => "SELECT COUNT(*) FROM vault_records",
        "nonce_reservations" => "SELECT COUNT(*) FROM nonce_reservations",
        _ => return Err(VaultError::Internal.into()),
    };
    let count = connection
        .query_row(statement, [], |row| row.get::<_, i64>(0))
        .map_err(VaultError::from)?;
    u32::try_from(count).map_err(|_| TransferError::ExportLimitExceeded)
}

fn migration_applied_at_ms(connection: &Connection) -> Result<u64, TransferError> {
    connection
        .query_row(
            "SELECT applied_at_ms FROM schema_migrations WHERE version = ?1 AND name = ?2 AND sha256 = ?3",
            params![
                i64::from(format::SCHEMA_VERSION),
                migration::MIGRATION_NAME,
                migration::migration_checksum().as_slice()
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(VaultError::from)
        .and_then(nonnegative_u64)
        .map_err(Into::into)
}

fn body_length(record_count: u32, nonce_count: u32, frame_bytes: u64) -> Option<u64> {
    let entry_count = 4_u64
        .checked_add(u64::from(record_count))?
        .checked_add(u64::from(nonce_count))?;
    entry_count
        .checked_mul(ENTRY_PREFIX_LENGTH as u64)?
        .checked_add(HEADER_PAYLOAD_LENGTH as u64)?
        .checked_add(MASTER_PAYLOAD_LENGTH as u64)?
        .checked_add(RECOVERY_PAYLOAD_LENGTH as u64)?
        .checked_add(SCHEMA_PAYLOAD_LENGTH as u64)?
        .checked_add(u64::from(nonce_count).checked_mul(NONCE_PAYLOAD_LENGTH as u64)?)?
        .checked_add(u64::from(record_count).checked_mul(RECORD_PREFIX_LENGTH as u64)?)?
        .checked_add(frame_bytes)
}

fn validate_counts(
    record_count: u32,
    nonce_count: u32,
    exporting: bool,
) -> Result<(), TransferError> {
    if record_count > MAX_RECORDS || !(3..=MAX_NONCES).contains(&nonce_count) {
        return Err(if exporting {
            TransferError::ExportLimitExceeded
        } else {
            TransferError::ImportLimitExceeded
        });
    }
    Ok(())
}

fn expected_entry_type(
    ordinal: u32,
    nonce_count: u32,
    record_count: u32,
) -> Result<u16, TransferError> {
    let nonce_end = 4_u32
        .checked_add(nonce_count)
        .ok_or(TransferError::ImportLimitExceeded)?;
    let record_end = nonce_end
        .checked_add(record_count)
        .ok_or(TransferError::ImportLimitExceeded)?;
    match ordinal {
        0..=3 => Ok((ordinal + 1) as u16),
        value if value < nonce_end => Ok(5),
        value if value < record_end => Ok(6),
        _ => Err(TransferError::ImportInvalidPackage),
    }
}

fn validate_payload_length(entry_type: u16, length: usize) -> Result<(), TransferError> {
    let valid = match entry_type {
        1 => length == HEADER_PAYLOAD_LENGTH,
        2 => length == MASTER_PAYLOAD_LENGTH,
        3 => length == RECOVERY_PAYLOAD_LENGTH,
        4 => length == SCHEMA_PAYLOAD_LENGTH,
        5 => length == NONCE_PAYLOAD_LENGTH,
        6 => {
            (RECORD_PREFIX_LENGTH + format::MIN_FRAME_LENGTH..=MAX_RECORD_PAYLOAD).contains(&length)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else if length > MAX_RECORD_PAYLOAD {
        Err(TransferError::ImportLimitExceeded)
    } else {
        Err(TransferError::ImportInvalidPackage)
    }
}

fn validate_nonce_purpose(purpose: u8, exporting: bool) -> Result<(), TransferError> {
    if matches!(purpose, 1..=4) {
        Ok(())
    } else if exporting {
        Err(VaultError::UnsupportedVersion.into())
    } else {
        Err(TransferError::ImportUnsupportedVersion)
    }
}

fn read_fixed<const LENGTH: usize>(reader: &mut File) -> Result<[u8; LENGTH], TransferError> {
    let mut output = [0_u8; LENGTH];
    reader
        .read_exact(&mut output)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => TransferError::ImportInvalidPackage,
            _ => TransferError::Io,
        })?;
    Ok(output)
}

fn read_bounded(reader: &mut File, length: usize) -> Result<Vec<u8>, TransferError> {
    if length > MAX_RECORD_PAYLOAD {
        return Err(TransferError::ImportLimitExceeded);
    }
    let mut output = vec![0_u8; length];
    reader
        .read_exact(&mut output)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => TransferError::ImportInvalidPackage,
            _ => TransferError::Io,
        })?;
    Ok(output)
}

fn read_u16(bytes: &[u8]) -> Result<u16, TransferError> {
    read_array(bytes)
        .map(u16::from_be_bytes)
        .map_err(map_import_vault_error)
}

fn read_u32(bytes: &[u8]) -> Result<u32, TransferError> {
    read_array(bytes)
        .map(u32::from_be_bytes)
        .map_err(map_import_vault_error)
}

fn read_u64(bytes: &[u8]) -> Result<u64, TransferError> {
    read_array(bytes)
        .map(u64::from_be_bytes)
        .map_err(map_import_vault_error)
}

fn check_cancel(observer: &dyn TransferObserver) -> Result<(), TransferError> {
    if observer.is_cancelled() {
        Err(TransferError::Cancelled)
    } else {
        Ok(())
    }
}

fn require_extension(path: &Path) -> Result<(), TransferError> {
    if path.extension().and_then(|value| value.to_str()) == Some("aeterna-vault") {
        Ok(())
    } else {
        Err(TransferError::PathRejected)
    }
}

fn map_import_vault_error(error: VaultError) -> TransferError {
    match error {
        VaultError::AuthenticationFailed => TransferError::AuthenticationFailed,
        VaultError::UnsupportedVersion | VaultError::ItemUnsupportedVersion => {
            TransferError::ImportUnsupportedVersion
        }
        _ => TransferError::ImportInvalidPackage,
    }
}

#[cfg(target_os = "macos")]
fn map_path_error(error: std::io::Error) -> TransferError {
    if error.kind() == std::io::ErrorKind::InvalidInput
        || error.kind() == std::io::ErrorKind::InvalidData
        || matches!(
            error.raw_os_error(),
            Some(libc::ELOOP) | Some(libc::ENOTDIR)
        )
    {
        TransferError::PathRejected
    } else {
        TransferError::Io
    }
}

#[cfg(target_os = "macos")]
fn map_target_error(error: std::io::Error, exporting: bool) -> TransferError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        if exporting {
            TransferError::ExportTargetExists
        } else {
            TransferError::ImportTargetExists
        }
    } else {
        map_path_error(error)
    }
}

#[cfg(target_os = "macos")]
type ExportTemp = ([u8; 16], [u8; 32], [u8; 12], std::ffi::CString, File);

#[cfg(target_os = "macos")]
fn create_export_temp(directory: &Directory) -> Result<ExportTemp, TransferError> {
    for _ in 0..FILE_ATTEMPTS {
        let package_id = random_array()?;
        let salt = random_array()?;
        let authentication_nonce = random_array()?;
        let leaf = std::ffi::CString::new(format!(".aeterna-export-v1-{}.tmp", hex_id(package_id)))
            .map_err(|_| TransferError::PathRejected)?;
        match directory.create_private(&leaf) {
            Ok(file) => return Ok((package_id, salt, authentication_nonce, leaf, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(TransferError::Io),
        }
    }
    Err(VaultError::RandomnessUnavailable.into())
}

#[cfg(target_os = "macos")]
fn create_owned_temp(
    directory: &Directory,
    parent: &Path,
    prefix: &str,
    suffix: &str,
) -> Result<(PathBuf, std::ffi::CString, File), TransferError> {
    for _ in 0..FILE_ATTEMPTS {
        let identifier = random_array()?;
        let leaf_string = format!("{prefix}{}{suffix}", hex_id(identifier));
        let leaf = std::ffi::CString::new(leaf_string.as_bytes())
            .map_err(|_| TransferError::PathRejected)?;
        match directory.create_private(&leaf) {
            Ok(file) => return Ok((parent.join(leaf_string), leaf, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(TransferError::Io),
        }
    }
    Err(VaultError::RandomnessUnavailable.into())
}

#[cfg(target_os = "macos")]
fn create_import_stage(
    target: &Path,
    directory: &Directory,
) -> Result<(PathBuf, std::ffi::CString), TransferError> {
    let parent = target.parent().ok_or(TransferError::PathRejected)?;
    let (path, leaf, file) =
        create_owned_temp(directory, parent, ".aeterna-import-vault-v1-", ".stage")?;
    drop(file);
    Ok((path, leaf))
}

#[cfg(target_os = "macos")]
fn require_target_absent(target: &Path) -> Result<(), TransferError> {
    let (parent, leaf) = split_path(target).map_err(map_path_error)?;
    let directory = Directory::open(parent).map_err(map_path_error)?;
    cleanup_stale_files(parent, &directory, StaleFileKind::Import, None);
    require_target_absent_in_with_leaf(&directory, &leaf)
}

#[cfg(target_os = "macos")]
fn require_target_absent_in(target: &Path, directory: &Directory) -> Result<(), TransferError> {
    let (parent, leaf) = split_path(target).map_err(map_path_error)?;
    directory.recheck_path(parent).map_err(map_path_error)?;
    require_target_absent_in_with_leaf(directory, &leaf)
}

#[cfg(target_os = "macos")]
fn require_target_absent_in_with_leaf(
    directory: &Directory,
    leaf: &std::ffi::CStr,
) -> Result<(), TransferError> {
    directory
        .require_absent(leaf)
        .map_err(|error| map_target_error(error, false))?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = std::ffi::CString::new(format!("{}{suffix}", leaf.to_string_lossy()))
            .map_err(|_| TransferError::PathRejected)?;
        directory
            .require_absent(&sidecar)
            .map_err(|error| map_target_error(error, false))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
enum StaleFileKind {
    Export,
    Import,
}

#[cfg(target_os = "macos")]
fn cleanup_stale_files(
    parent: &Path,
    directory: &Directory,
    kind: StaleFileKind,
    export_vdk: Option<&Vdk>,
) {
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, SystemTime};

    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let identifier = match kind {
            StaleFileKind::Export => stale_identifier(name, ".aeterna-export-v1-", ".tmp"),
            StaleFileKind::Import => stale_identifier(name, ".aeterna-import-package-v1-", ".tmp")
                .or_else(|| stale_identifier(name, ".aeterna-import-vault-v1-", ".stage"))
                .or_else(|| stale_identifier(name, ".aeterna-import-vault-v1-", ".stage-wal"))
                .or_else(|| stale_identifier(name, ".aeterna-import-vault-v1-", ".stage-shm"))
                .or_else(|| stale_identifier(name, ".aeterna-import-vault-v1-", ".stage-journal")),
        };
        let Some(identifier) = identifier else {
            continue;
        };
        let Ok(leaf) = std::ffi::CString::new(name) else {
            continue;
        };
        let Ok(mut file) = directory.open_readonly(&leaf) else {
            continue;
        };
        let Ok(metadata) = file.metadata() else {
            continue;
        };
        let old_enough = metadata.modified().ok().and_then(|modified| {
            SystemTime::now()
                .duration_since(modified)
                .ok()
                .map(|age| age >= Duration::from_secs(24 * 60 * 60))
        }) == Some(true);
        if !old_enough
            || !metadata.is_file()
            || metadata.uid() != effective_uid()
            || metadata.mode() & 0o077 != 0
            || !matches!(metadata.nlink(), 1 | 2)
            || metadata.len() > MAX_PACKAGE_LENGTH
        {
            continue;
        }
        if matches!(kind, StaleFileKind::Export) {
            let mut prefix = [0_u8; 40];
            if file.read_exact(&mut prefix).is_err()
                || prefix[0..16] != PACKAGE_MAGIC
                || prefix[24..40] != identifier
            {
                continue;
            }
            if metadata.len() >= TRAILER_LENGTH as u64 {
                let mut trailer_magic = [0_u8; 16];
                if file
                    .seek(SeekFrom::End(-(TRAILER_LENGTH as i64)))
                    .and_then(|_| file.read_exact(&mut trailer_magic))
                    .is_err()
                {
                    continue;
                }
                if trailer_magic == TRAILER_MAGIC
                    && export_vdk.is_none_or(|vdk| {
                        verify_completed_export_candidate(&mut file, identifier, vdk).is_err()
                    })
                {
                    continue;
                }
            }
        }
        if verify_private_regular(&file, None).is_ok() {
            let _ = directory.unlink(&leaf);
        }
    }
}

#[cfg(target_os = "macos")]
fn verify_completed_export_candidate(
    file: &mut File,
    expected_package_id: [u8; 16],
    vdk: &Vdk,
) -> Result<(), TransferError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| TransferError::Io)?;
    let file_length = file.metadata().map_err(|_| TransferError::Io)?.len();
    if !(MIN_PACKAGE_LENGTH..=MAX_PACKAGE_LENGTH).contains(&file_length) {
        return Err(TransferError::ImportInvalidPackage);
    }
    let preamble_bytes = read_fixed::<PREAMBLE_LENGTH>(file)?;
    let preamble = decode_preamble(&preamble_bytes)?;
    if preamble.package_id != expected_package_id
        || FIXED_PACKAGE_OVERHEAD.checked_add(preamble.body_length) != Some(file_length)
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    let mut digest = Sha256::new();
    let mut remaining = preamble.body_length;
    let mut buffer = [0_u8; STREAM_CHUNK];
    while remaining != 0 {
        let length = usize::try_from(remaining.min(STREAM_CHUNK as u64))
            .map_err(|_| TransferError::ImportLimitExceeded)?;
        file.read_exact(&mut buffer[..length])
            .map_err(|_| TransferError::ImportInvalidPackage)?;
        digest.update(&buffer[..length]);
        remaining -= length as u64;
    }
    let manifest = read_fixed::<MANIFEST_LENGTH>(file)?;
    let trailer = read_fixed::<TRAILER_LENGTH>(file)?;
    let body_digest: [u8; 32] = digest.finalize().into();
    if manifest[0..16] != MANIFEST_MAGIC
        || read_u16(&manifest[16..18])? != MANIFEST_VERSION
        || read_u16(&manifest[18..20])? != PACKAGE_VERSION
        || read_u16(&manifest[20..22])? != AUTHENTICATION_VERSION
        || read_u16(&manifest[22..24])? != 0
        || manifest[24..40] != preamble.package_id
        || read_u32(&manifest[72..76])? != preamble.entry_count
        || read_u32(&manifest[76..80])? != preamble.record_count
        || read_u32(&manifest[80..84])? != preamble.nonce_count
        || read_u64(&manifest[84..92])? != preamble.body_length
        || manifest[92..124] != body_digest
        || manifest[124..128] != [0; 4]
    {
        return Err(TransferError::ImportInvalidPackage);
    }
    let (nonce, tag, total_length) = decode_trailer(&trailer)?;
    if total_length != file_length {
        return Err(TransferError::ImportInvalidPackage);
    }
    let vault_id = read_array::<16>(&manifest[40..56]).map_err(map_import_vault_error)?;
    let info = export_key_info(vault_id, preamble.package_id);
    let aad = export_authentication_aad(&preamble_bytes, &manifest, &trailer);
    verify_export_authentication_tag(vdk, &preamble.salt, &info, &nonce, &aad, &tag)
        .map_err(|_| TransferError::AuthenticationFailed)
}

#[cfg(target_os = "macos")]
fn stale_identifier(name: &str, prefix: &str, suffix: &str) -> Option<[u8; 16]> {
    let encoded = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if encoded.len() != 32
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        let pair = &encoded.as_bytes()[index * 2..index * 2 + 2];
        let text = core::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(text, 16).ok()?;
    }
    Some(output)
}

fn random_array<const LENGTH: usize>() -> Result<[u8; LENGTH], TransferError> {
    let mut value = [0_u8; LENGTH];
    fill_random(&mut value).map_err(VaultError::from)?;
    Ok(value)
}

fn hex_id(value: [u8; 16]) -> String {
    use core::fmt::Write as _;
    let mut output = String::with_capacity(32);
    for byte in value {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    struct TestObserver;

    #[cfg(target_os = "macos")]
    impl TransferObserver for TestObserver {
        fn update(&self, _phase: &'static str, _bytes: u64, _entries: u64, _cancellable: bool) {}

        fn is_cancelled(&self) -> bool {
            false
        }
    }

    #[cfg(target_os = "macos")]
    struct CancelAfterFirstEntry(std::sync::atomic::AtomicU64);

    #[cfg(target_os = "macos")]
    impl TransferObserver for CancelAfterFirstEntry {
        fn update(&self, _phase: &'static str, _bytes: u64, entries: u64, _cancellable: bool) {
            self.0.store(entries, std::sync::atomic::Ordering::Release);
        }

        fn is_cancelled(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::Acquire) >= 1
        }
    }

    #[cfg(target_os = "macos")]
    struct CancelOnPhase {
        phase: &'static str,
        cancelled: std::sync::atomic::AtomicBool,
    }

    #[cfg(target_os = "macos")]
    impl CancelOnPhase {
        fn new(phase: &'static str) -> Self {
            Self {
                phase,
                cancelled: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[cfg(target_os = "macos")]
    impl TransferObserver for CancelOnPhase {
        fn update(&self, phase: &'static str, _bytes: u64, _entries: u64, cancellable: bool) {
            if cancellable && phase == self.phase {
                self.cancelled
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }

        fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    #[cfg(target_os = "macos")]
    struct PauseAtFirstWrite {
        paused: std::sync::atomic::AtomicBool,
        started: std::sync::mpsc::Sender<()>,
        resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    #[cfg(target_os = "macos")]
    struct PauseOnPhase {
        phase: &'static str,
        paused: std::sync::atomic::AtomicBool,
        started: std::sync::mpsc::Sender<()>,
        resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    #[cfg(target_os = "macos")]
    impl TransferObserver for PauseOnPhase {
        fn update(&self, phase: &'static str, _bytes: u64, _entries: u64, _cancellable: bool) {
            if phase == self.phase && !self.paused.swap(true, std::sync::atomic::Ordering::AcqRel) {
                let _ = self.started.send(());
                if let Ok(receiver) = self.resume.lock() {
                    let _ = receiver.recv_timeout(std::time::Duration::from_secs(10));
                }
            }
        }

        fn is_cancelled(&self) -> bool {
            false
        }
    }

    #[cfg(target_os = "macos")]
    impl TransferObserver for PauseAtFirstWrite {
        fn update(&self, phase: &'static str, _bytes: u64, _entries: u64, _cancellable: bool) {
            if phase == "writing" && !self.paused.swap(true, std::sync::atomic::Ordering::AcqRel) {
                let _ = self.started.send(());
                if let Ok(receiver) = self.resume.lock() {
                    let _ = receiver.recv_timeout(std::time::Duration::from_secs(10));
                }
            }
        }

        fn is_cancelled(&self) -> bool {
            false
        }
    }

    #[cfg(target_os = "macos")]
    type StoredRecord = (Vec<u8>, i64, Vec<u8>, i64, i64);

    #[cfg(target_os = "macos")]
    struct TestDirectory(PathBuf);

    #[cfg(target_os = "macos")]
    impl TestDirectory {
        fn new() -> Self {
            let root =
                fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
            let identifier = random_array::<16>().unwrap_or([0x5a; 16]);
            let path = root.join(format!("aeterna-i07-{}", hex_id(identifier)));
            assert!(fs::create_dir(&path).is_ok());
            Self(path)
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "macos")]
    fn nonce_rows(path: &Path) -> Vec<(Vec<u8>, i64, i64)> {
        let connection = Connection::open(path).unwrap_or_else(|error| {
            panic!("test database open failed: {error}");
        });
        let mut statement = connection
            .prepare("SELECT nonce, purpose, reserved_at_ms FROM nonce_reservations ORDER BY nonce")
            .unwrap_or_else(|error| panic!("test nonce query prepare failed: {error}"));
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap_or_else(|error| panic!("test nonce query failed: {error}"))
            .map(|row| row.unwrap_or_else(|error| panic!("test nonce row failed: {error}")))
            .collect()
    }

    #[cfg(target_os = "macos")]
    fn record_rows(path: &Path) -> Vec<StoredRecord> {
        let connection = Connection::open(path).unwrap_or_else(|error| {
            panic!("test database open failed: {error}");
        });
        let mut statement = connection
            .prepare(
                "SELECT record_id, generation, frame, created_at_ms, updated_at_ms FROM vault_records ORDER BY record_id",
            )
            .unwrap_or_else(|error| panic!("test record query prepare failed: {error}"));
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap_or_else(|error| panic!("test record query failed: {error}"))
            .map(|row| row.unwrap_or_else(|error| panic!("test record row failed: {error}")))
            .collect()
    }

    #[cfg(target_os = "macos")]
    fn metadata_encodings(path: &Path) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let connection = Connection::open(path).unwrap_or_else(|error| {
            panic!("test database open failed: {error}");
        });
        let metadata = load_metadata(&connection)
            .unwrap_or_else(|error| panic!("test metadata load failed: {error}"));
        let master = encode_master(&metadata.master)
            .unwrap_or_else(|error| panic!("test master encoding failed: {error}"));
        let recovery = encode_recovery(&metadata.recovery)
            .unwrap_or_else(|error| panic!("test recovery encoding failed: {error}"));
        (
            encode_header(&metadata.header).to_vec(),
            master.to_vec(),
            recovery.to_vec(),
        )
    }

    #[cfg(target_os = "macos")]
    fn assert_no_marker_in_directory(directory: &Path, markers: &[&[u8]]) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("test directory read failed: {error}"));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| panic!("test entry read failed: {error}"));
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();
            let metadata = entry
                .metadata()
                .unwrap_or_else(|error| panic!("test metadata read failed: {error}"));
            let bytes = if metadata.is_file() {
                fs::read(entry.path())
                    .unwrap_or_else(|error| panic!("test artifact read failed: {error}"))
            } else {
                Vec::new()
            };
            for marker in markers {
                if let Ok(marker_text) = core::str::from_utf8(marker) {
                    assert!(!filename.contains(marker_text));
                }
                assert!(!bytes.windows(marker.len()).any(|window| window == *marker));
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn assert_package_rejected(path: &Path, bytes: &[u8], password: &MasterPassword) {
        fs::write(path, bytes)
            .unwrap_or_else(|error| panic!("test mutation write failed: {error}"));
        let mut file =
            File::open(path).unwrap_or_else(|error| panic!("test mutation open failed: {error}"));
        assert!(parse_and_authenticate(&mut file, password, &TestObserver).is_err());
    }

    #[cfg(target_os = "macos")]
    fn assert_no_transfer_staging_files(directory: &Path) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("test directory read failed: {error}"));
        for entry in entries {
            let name = entry
                .unwrap_or_else(|error| panic!("test entry read failed: {error}"))
                .file_name();
            let name = name.to_string_lossy();
            assert!(!name.starts_with(".aeterna-export-v1-"));
            assert!(!name.starts_with(".aeterna-import-package-v1-"));
            assert!(!name.starts_with(".aeterna-import-vault-v1-"));
        }
    }

    #[test]
    fn approved_fixed_layouts_have_exact_offsets() {
        let preamble = Preamble {
            package_id: [0x11; 16],
            salt: [0x22; 32],
            entry_count: 7,
            record_count: 0,
            nonce_count: 3,
            body_length: MIN_BODY_LENGTH,
        };
        let encoded = encode_preamble(preamble);
        assert_eq!(&encoded[0..16], &PACKAGE_MAGIC);
        assert_eq!(&encoded[24..40], &[0x11; 16]);
        assert_eq!(&encoded[40..72], &[0x22; 32]);
        assert_eq!(&encoded[84..92], &MIN_BODY_LENGTH.to_be_bytes());
        assert_eq!(
            decode_preamble(&encoded).map(|value| value.entry_count),
            Ok(7)
        );

        let schema = encode_schema(9);
        assert_eq!(schema.len(), 98);
        assert_eq!(&schema[41..43], &15_u16.to_be_bytes());
        assert_eq!(&schema[43..58], b"create_vault_v1");
        assert_eq!(&schema[90..98], &9_u64.to_be_bytes());
        assert_eq!(decode_schema(&schema), Ok(9));

        let info = export_key_info([0x33; 16], [0x44; 16]);
        assert_eq!(&info[0..18], b"AETERNA-EXPORT-KEY");
        assert_eq!(&info[22..38], &[0x33; 16]);
        assert_eq!(&info[38..54], &[0x44; 16]);
    }

    #[test]
    fn count_and_length_limits_are_checked_without_allocation() {
        assert!(validate_counts(MAX_RECORDS, MAX_NONCES, false).is_ok());
        assert_eq!(
            validate_counts(MAX_RECORDS + 1, 3, false),
            Err(TransferError::ImportLimitExceeded)
        );
        assert_eq!(
            validate_counts(0, 2, false),
            Err(TransferError::ImportLimitExceeded)
        );
        assert_eq!(
            validate_payload_length(6, MAX_RECORD_PAYLOAD + 1),
            Err(TransferError::ImportLimitExceeded)
        );
        assert_eq!(body_length(0, 3, 0), Some(MIN_BODY_LENGTH));
        let maximum_count_body = body_length(
            MAX_RECORDS,
            MAX_NONCES,
            u64::from(MAX_RECORDS) * format::MIN_FRAME_LENGTH as u64,
        )
        .unwrap_or_else(|| panic!("maximum count body arithmetic overflowed"));
        assert!(maximum_count_body <= MAX_BODY_LENGTH);
        let maximum_count_preamble = encode_preamble(Preamble {
            package_id: [0x51; 16],
            salt: [0x52; 32],
            entry_count: MAX_ENTRIES,
            record_count: MAX_RECORDS,
            nonce_count: MAX_NONCES,
            body_length: maximum_count_body,
        });
        assert_eq!(
            decode_preamble(&maximum_count_preamble).map(|value| value.entry_count),
            Ok(MAX_ENTRIES)
        );
        let mut excessive_entries = maximum_count_preamble;
        excessive_entries[72..76].copy_from_slice(&(MAX_ENTRIES + 1).to_be_bytes());
        assert_eq!(
            decode_preamble(&excessive_entries).map(|_| ()),
            Err(TransferError::ImportInvalidPackage)
        );
    }

    #[test]
    fn trailer_and_aad_exclude_only_the_tag() {
        let preamble = [0x11; PREAMBLE_LENGTH];
        let manifest = [0x22; MANIFEST_LENGTH];
        let trailer = encode_trailer([0x33; 12], [0x44; 16], 1_161);
        let aad = export_authentication_aad(&preamble, &manifest, &trailer);
        assert_eq!(&aad[0..19], b"AETERNA-EXPORT-AUTH");
        assert_eq!(&aad[22..118], &preamble);
        assert_eq!(&aad[118..246], &manifest);
        assert_eq!(&aad[246..284], &trailer[0..38]);
        assert_eq!(&aad[284..294], &trailer[54..64]);
        assert!(!aad.windows(16).any(|window| window == [0x44; 16]));
    }

    #[test]
    fn parser_rejects_versions_flags_counts_and_hostile_payload_lengths() {
        let mut bytes = encode_preamble(Preamble {
            package_id: [1; 16],
            salt: [2; 32],
            entry_count: 7,
            record_count: 0,
            nonce_count: 3,
            body_length: MIN_BODY_LENGTH,
        });
        for index in [16, 18, 20, 22, 92] {
            let original = bytes[index];
            bytes[index] ^= 1;
            assert!(decode_preamble(&bytes).is_err());
            bytes[index] = original;
        }
        let payload = [7_u8; NONCE_PAYLOAD_LENGTH];
        let mut prefix = encode_entry_prefix(5, 4, &payload).unwrap_or([0; ENTRY_PREFIX_LENGTH]);
        prefix[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            decode_entry_prefix(&prefix, 4, 5),
            Ok((5, u64::MAX, _))
        ));
        assert!(usize::try_from(u64::MAX).map_or(true, |value| value > MAX_RECORD_PAYLOAD));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_vault_round_trip_two_copy_and_tamper_boundaries() {
        use crate::vault::{ItemDraft, ItemKind, MAX_ATTACHMENT_BYTES};

        let directory = TestDirectory::new();
        let source_path = directory.0.join("source.sqlite3");
        let password = MasterPassword::new(b"synthetic-i07-password".to_vec());
        let password = match password {
            Ok(value) => value,
            Err(_) => panic!("synthetic password is valid"),
        };
        let bootstrap =
            VaultRepository::initialize(&source_path, &password, Argon2Profile::new(65_536, 1, 1));
        let bootstrap = match bootstrap {
            Ok(value) => value,
            Err(error) => panic!("source initialization failed: {error}"),
        };
        let (source_repository, recovery) = bootstrap.into_parts();
        drop(recovery);
        let source = match source_repository.unlock(&password) {
            Ok(value) => std::sync::Arc::new(value),
            Err(error) => panic!("source unlock failed: {error}"),
        };
        let draft = ItemDraft::new(
            ItemKind::Instruction,
            "I07 synthetic title".to_owned(),
            "Synthetic category".to_owned(),
            "Synthetic contact".to_owned(),
            "Synthetic body with composed é and decomposed e\u{301}".to_owned(),
        );
        let mut created = match draft.and_then(|value| source.create_item(value)) {
            Ok(value) => value,
            Err(error) => panic!("source item failed: {error}"),
        };
        created = source
            .add_attachment(
                created.id,
                created.revision,
                "empty-synthetic.txt".to_owned(),
                "text/plain".to_owned(),
                Vec::new(),
            )
            .unwrap_or_else(|error| panic!("empty attachment failed: {error}"));
        created = source
            .add_attachment(
                created.id,
                created.revision,
                "boundary-synthetic.bin".to_owned(),
                "application/octet-stream".to_owned(),
                vec![0xa5; MAX_ATTACHMENT_BYTES],
            )
            .unwrap_or_else(|error| panic!("boundary attachment failed: {error}"));

        let first_package = directory.0.join("first.aeterna-vault");
        let second_package = directory.0.join("second.aeterna-vault");
        assert!(export_vault(&source, &first_package, &TestObserver).is_ok());
        assert!(export_vault(&source, &second_package, &TestObserver).is_ok());
        let first = fs::read(&first_package).unwrap_or_default();
        let second = fs::read(&second_package).unwrap_or_default();
        assert_eq!(first.len(), second.len());
        assert_ne!(&first[24..72], &second[24..72]);
        let body_length = u64::from_be_bytes(first[84..92].try_into().unwrap_or([0; 8]));
        let body_end = PREAMBLE_LENGTH + usize::try_from(body_length).unwrap_or_default();
        assert_eq!(
            &first[PREAMBLE_LENGTH..body_end],
            &second[PREAMBLE_LENGTH..body_end]
        );
        for marker in [
            b"I07 synthetic title".as_slice(),
            b"Synthetic contact".as_slice(),
            b"Synthetic body".as_slice(),
            b"empty-synthetic.txt".as_slice(),
            b"boundary-synthetic.bin".as_slice(),
            b"synthetic-i07-password".as_slice(),
        ] {
            assert!(!first.windows(marker.len()).any(|window| window == marker));
        }

        let original_first = first.clone();
        assert_eq!(
            export_vault(&source, &first_package, &TestObserver),
            Err(TransferError::ExportTargetExists)
        );
        assert_eq!(fs::read(&first_package).unwrap_or_default(), original_first);

        let symlink_target = directory.0.join("symlink.aeterna-vault");
        assert!(std::os::unix::fs::symlink(&first_package, &symlink_target).is_ok());
        assert_eq!(
            export_vault(&source, &symlink_target, &TestObserver),
            Err(TransferError::ExportTargetExists)
        );
        assert!(fs::remove_file(&symlink_target).is_ok());

        let hard_link_target = directory.0.join("hard-link.aeterna-vault");
        assert!(fs::hard_link(&first_package, &hard_link_target).is_ok());
        assert_eq!(
            export_vault(&source, &hard_link_target, &TestObserver),
            Err(TransferError::ExportTargetExists)
        );
        assert!(fs::remove_file(&hard_link_target).is_ok());

        let export_race_target = directory.0.join("export-race.aeterna-vault");
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (resume_sender, resume_receiver) = std::sync::mpsc::channel();
        let race_observer = PauseOnPhase {
            phase: "publishing",
            paused: std::sync::atomic::AtomicBool::new(false),
            started: started_sender,
            resume: std::sync::Mutex::new(resume_receiver),
        };
        let race_target_for_worker = export_race_target.clone();
        let source_for_worker = std::sync::Arc::clone(&source);
        let race_worker = std::thread::spawn(move || {
            export_vault(&source_for_worker, &race_target_for_worker, &race_observer)
        });
        assert!(
            started_receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok()
        );
        assert!(fs::write(&export_race_target, b"race sentinel").is_ok());
        assert!(resume_sender.send(()).is_ok());
        assert_eq!(
            race_worker
                .join()
                .unwrap_or_else(|_| panic!("export race worker panicked")),
            Err(TransferError::ExportTargetExists)
        );
        assert_eq!(
            fs::read(&export_race_target).unwrap_or_default(),
            b"race sentinel"
        );
        assert_no_transfer_staging_files(&directory.0);

        let mutation_path = directory.0.join("mutation.aeterna-vault");
        let mut seed = 0x7a6d_3c19_8421_55e3_u64;
        for _ in 0..64 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut mutated = first.clone();
            let index = PREAMBLE_LENGTH + usize::try_from(seed % body_length).unwrap_or_default();
            mutated[index] ^= 1_u8 << (seed as u8 & 7);
            assert!(fs::write(&mutation_path, mutated).is_ok());
            let mut mutation_file = match File::open(&mutation_path) {
                Ok(value) => value,
                Err(error) => panic!("mutation open failed: {error}"),
            };
            assert!(parse_and_authenticate(&mut mutation_file, &password, &TestObserver).is_err());
        }

        for index in [24, 40, body_end, body_end + 92, body_end + 128] {
            let mut mutated = first.clone();
            mutated[index] ^= 1;
            assert_package_rejected(&mutation_path, &mutated, &password);
        }
        let trailer_start = body_end + MANIFEST_LENGTH;
        for trailer_offset in [16, 18, 19, 20, 22, 26, 38, 54, 62] {
            let mut mutated = first.clone();
            mutated[trailer_start + trailer_offset] ^= 1;
            assert_package_rejected(&mutation_path, &mutated, &password);
        }
        assert_package_rejected(&mutation_path, &first[..first.len() - 1], &password);
        let mut appended = first.clone();
        appended.push(0);
        assert_package_rejected(&mutation_path, &appended, &password);

        let master_payload_start =
            PREAMBLE_LENGTH + ENTRY_PREFIX_LENGTH + HEADER_PAYLOAD_LENGTH + ENTRY_PREFIX_LENGTH;
        let master_payload_end = master_payload_start + MASTER_PAYLOAD_LENGTH;
        let master_payload = &first[master_payload_start..master_payload_end];
        for index in [8, 10, 11, 12, 13, 26] {
            let mut mutated = master_payload.to_vec();
            mutated[index] ^= 1;
            assert!(decode_master(&mutated).is_err());
        }
        let mut invalid_kdf_bounds = master_payload.to_vec();
        invalid_kdf_bounds[14..18].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            decode_master(&invalid_kdf_bounds).map(|_| ()),
            Err(TransferError::ImportInvalidPackage)
        );

        let schema_payload_start = master_payload_end
            + ENTRY_PREFIX_LENGTH
            + RECOVERY_PAYLOAD_LENGTH
            + ENTRY_PREFIX_LENGTH;
        let schema_payload_end = schema_payload_start + SCHEMA_PAYLOAD_LENGTH;
        let schema_payload = &first[schema_payload_start..schema_payload_end];
        for index in [0, 4, 8, 20, 22, 26, 28, 29, 30, 32, 33, 35, 37, 41, 43, 58] {
            let mut mutated = schema_payload.to_vec();
            mutated[index] ^= 1;
            assert_eq!(
                decode_schema(&mutated),
                Err(TransferError::ImportUnsupportedVersion)
            );
        }

        let cancelled_package = directory.0.join("cancelled.aeterna-vault");
        let cancel_observer = CancelAfterFirstEntry(std::sync::atomic::AtomicU64::new(0));
        assert_eq!(
            export_vault(&source, &cancelled_package, &cancel_observer),
            Err(TransferError::Cancelled)
        );
        assert!(!cancelled_package.exists());
        assert!(
            fs::read_dir(&directory.0)
                .into_iter()
                .flatten()
                .flatten()
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".aeterna-export-v1-"))
        );
        for (index, phase) in ["preparing", "snapshotting", "writing", "verifying"]
            .into_iter()
            .enumerate()
        {
            let target = directory.0.join(format!("cancel-{index}.aeterna-vault"));
            assert_eq!(
                export_vault(&source, &target, &CancelOnPhase::new(phase)),
                Err(TransferError::Cancelled)
            );
            assert!(!target.exists());
            assert_no_transfer_staging_files(&directory.0);
        }

        for (index, phase) in [
            "copying",
            "validating",
            "authenticating",
            "reconstructing",
            "verifying",
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory.0.join(format!("cancel-import-{index}.sqlite3"));
            assert_eq!(
                import_vault(
                    &first_package,
                    &target,
                    &password,
                    &CancelOnPhase::new(phase),
                ),
                Err(TransferError::Cancelled)
            );
            assert!(!target.exists());
            assert_no_transfer_staging_files(&directory.0);
        }

        let changing_package = directory.0.join("changing.aeterna-vault");
        assert!(fs::copy(&first_package, &changing_package).is_ok());
        let changing_target = directory.0.join("changing.sqlite3");
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (resume_sender, resume_receiver) = std::sync::mpsc::channel();
        let changing_observer = PauseOnPhase {
            phase: "copying",
            paused: std::sync::atomic::AtomicBool::new(false),
            started: started_sender,
            resume: std::sync::Mutex::new(resume_receiver),
        };
        let changing_package_for_worker = changing_package.clone();
        let changing_target_for_worker = changing_target.clone();
        let password_for_worker = MasterPassword::new(b"synthetic-i07-password".to_vec())
            .unwrap_or_else(|_| panic!("synthetic password is valid"));
        let changing_worker = std::thread::spawn(move || {
            import_vault(
                &changing_package_for_worker,
                &changing_target_for_worker,
                &password_for_worker,
                &changing_observer,
            )
        });
        assert!(
            started_receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok()
        );
        let changing_file = fs::OpenOptions::new().append(true).open(&changing_package);
        let mut changing_file =
            changing_file.unwrap_or_else(|error| panic!("changing package open failed: {error}"));
        assert!(changing_file.write_all(&[0]).is_ok());
        assert!(changing_file.sync_all().is_ok());
        drop(changing_file);
        assert!(resume_sender.send(()).is_ok());
        assert!(
            changing_worker
                .join()
                .unwrap_or_else(|_| panic!("changing source worker panicked"))
                .is_err()
        );
        assert!(!changing_target.exists());
        assert_no_transfer_staging_files(&directory.0);

        let restored_path = directory.0.join("restored.sqlite3");
        assert!(import_vault(&first_package, &restored_path, &password, &TestObserver,).is_ok());
        let restored_repository = match VaultRepository::open(&restored_path) {
            Ok(value) => value,
            Err(error) => panic!("restored open failed: {error}"),
        };
        let restored = match restored_repository.unlock(&password) {
            Ok(value) => value,
            Err(error) => panic!("restored unlock failed: {error}"),
        };
        let restored_item = match restored.get_item(created.id) {
            Ok(value) => value,
            Err(error) => panic!("restored item failed: {error}"),
        };
        assert_eq!(&*restored_item.title, "I07 synthetic title");
        assert_eq!(restored_item.revision, created.revision);
        assert_eq!(restored_item.attachments.len(), 2);
        let empty_content = restored
            .read_attachment(
                restored_item.id,
                restored_item.revision,
                restored_item.attachments[0].id,
            )
            .unwrap_or_else(|error| panic!("empty restored attachment failed: {error}"));
        assert!(empty_content.is_empty());
        let boundary_content = restored
            .read_attachment(
                restored_item.id,
                restored_item.revision,
                restored_item.attachments[1].id,
            )
            .unwrap_or_else(|error| panic!("boundary restored attachment failed: {error}"));
        assert_eq!(boundary_content.len(), MAX_ATTACHMENT_BYTES);
        assert!(boundary_content.iter().all(|byte| *byte == 0xa5));
        assert_eq!(nonce_rows(&source_path), nonce_rows(&restored_path));
        assert_eq!(record_rows(&source_path), record_rows(&restored_path));
        assert_eq!(
            metadata_encodings(&source_path),
            metadata_encodings(&restored_path)
        );

        let second_restored_path = directory.0.join("second-restored.sqlite3");
        assert!(
            import_vault(
                &second_package,
                &second_restored_path,
                &password,
                &TestObserver,
            )
            .is_ok()
        );
        let second_restored = match VaultRepository::open(&second_restored_path)
            .and_then(|repository| repository.unlock(&password))
        {
            Ok(value) => value,
            Err(error) => panic!("second restore failed: {error}"),
        };
        let second_item = match second_restored.get_item(created.id) {
            Ok(value) => value,
            Err(error) => panic!("second restored item failed: {error}"),
        };
        assert_eq!(&*second_item.body, &*restored_item.body);
        assert_eq!(second_item.revision, restored_item.revision);
        assert_eq!(nonce_rows(&source_path), nonce_rows(&second_restored_path));
        assert_eq!(
            record_rows(&source_path),
            record_rows(&second_restored_path)
        );
        assert_eq!(
            metadata_encodings(&source_path),
            metadata_encodings(&second_restored_path)
        );

        let import_race_target = directory.0.join("import-race.sqlite3");
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (resume_sender, resume_receiver) = std::sync::mpsc::channel();
        let import_race_observer = PauseOnPhase {
            phase: "publishing",
            paused: std::sync::atomic::AtomicBool::new(false),
            started: started_sender,
            resume: std::sync::Mutex::new(resume_receiver),
        };
        let package_for_worker = second_package.clone();
        let import_target_for_worker = import_race_target.clone();
        let password_for_worker = MasterPassword::new(b"synthetic-i07-password".to_vec())
            .unwrap_or_else(|_| panic!("synthetic password is valid"));
        let import_race_worker = std::thread::spawn(move || {
            import_vault(
                &package_for_worker,
                &import_target_for_worker,
                &password_for_worker,
                &import_race_observer,
            )
        });
        assert!(
            started_receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok()
        );
        assert!(fs::write(&import_race_target, b"race sentinel").is_ok());
        assert!(resume_sender.send(()).is_ok());
        assert_eq!(
            import_race_worker
                .join()
                .unwrap_or_else(|_| panic!("import race worker panicked")),
            Err(TransferError::ImportTargetExists)
        );
        assert_eq!(
            fs::read(&import_race_target).unwrap_or_default(),
            b"race sentinel"
        );
        assert_no_transfer_staging_files(&directory.0);

        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (resume_sender, resume_receiver) = std::sync::mpsc::channel();
        let snapshot_observer = PauseAtFirstWrite {
            paused: std::sync::atomic::AtomicBool::new(false),
            started: started_sender,
            resume: std::sync::Mutex::new(resume_receiver),
        };
        let snapshot_package = directory.0.join("snapshot.aeterna-vault");
        let snapshot_package_for_worker = snapshot_package.clone();
        let source_for_worker = std::sync::Arc::clone(&source);
        let snapshot_worker = std::thread::spawn(move || {
            export_vault(
                &source_for_worker,
                &snapshot_package_for_worker,
                &snapshot_observer,
            )
        });
        assert!(
            started_receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok()
        );
        let concurrent_draft = ItemDraft::new(
            ItemKind::Note,
            "Committed after snapshot".to_owned(),
            String::new(),
            String::new(),
            "Must not enter the earlier snapshot".to_owned(),
        );
        let concurrent_item = concurrent_draft
            .and_then(|draft| source.create_item(draft))
            .unwrap_or_else(|error| panic!("concurrent item failed: {error}"));
        assert!(resume_sender.send(()).is_ok());
        let snapshot_result = snapshot_worker
            .join()
            .unwrap_or_else(|_| panic!("snapshot worker panicked"));
        assert!(snapshot_result.is_ok());
        let snapshot_target = directory.0.join("snapshot-restored.sqlite3");
        assert!(
            import_vault(
                &snapshot_package,
                &snapshot_target,
                &password,
                &TestObserver,
            )
            .is_ok()
        );
        let snapshot_restored = VaultRepository::open(&snapshot_target)
            .and_then(|repository| repository.unlock(&password))
            .unwrap_or_else(|error| panic!("snapshot restore failed: {error}"));
        let snapshot_items = snapshot_restored
            .list_items()
            .unwrap_or_else(|error| panic!("snapshot item list failed: {error}"));
        assert_eq!(snapshot_items.len(), 1);
        assert!(
            snapshot_items
                .iter()
                .all(|item| item.id != concurrent_item.id)
        );

        let restored_nonces_before = nonce_rows(&restored_path);
        let restored_records_before = record_rows(&restored_path);
        drop(restored);
        let restarted_restore = VaultRepository::open(&restored_path)
            .and_then(|repository| repository.unlock(&password))
            .unwrap_or_else(|error| panic!("restored restart failed: {error}"));
        let later_draft = ItemDraft::new(
            ItemKind::Note,
            "Later restored write".to_owned(),
            String::new(),
            String::new(),
            "Fresh nonce after restart".to_owned(),
        );
        later_draft
            .and_then(|draft| restarted_restore.create_item(draft))
            .unwrap_or_else(|error| panic!("later restored write failed: {error}"));
        let restored_nonces_after = nonce_rows(&restored_path);
        assert_eq!(
            restored_nonces_after.len(),
            restored_nonces_before.len() + 1
        );
        assert!(
            restored_nonces_before
                .iter()
                .all(|row| restored_nonces_after.contains(row))
        );
        let restored_records_after = record_rows(&restored_path);
        assert_eq!(
            restored_records_after.len(),
            restored_records_before.len() + 1
        );
        assert!(
            restored_records_before
                .iter()
                .all(|row| restored_records_after.contains(row))
        );

        let wrong_target = directory.0.join("wrong.sqlite3");
        let wrong_password = MasterPassword::new(b"wrong-synthetic-password".to_vec());
        let wrong_password = match wrong_password {
            Ok(value) => value,
            Err(_) => panic!("synthetic wrong password is valid input"),
        };
        assert_eq!(
            import_vault(
                &second_package,
                &wrong_target,
                &wrong_password,
                &TestObserver,
            ),
            Err(TransferError::AuthenticationFailed)
        );
        assert!(!wrong_target.exists());

        let linked_source = directory.0.join("linked-source.aeterna-vault");
        assert!(fs::hard_link(&second_package, &linked_source).is_ok());
        let linked_target = directory.0.join("linked-source.sqlite3");
        assert_eq!(
            import_vault(&linked_source, &linked_target, &password, &TestObserver),
            Err(TransferError::PathRejected)
        );
        assert!(!linked_target.exists());
        assert!(fs::remove_file(&linked_source).is_ok());

        let symlink_source = directory.0.join("symlink-source.aeterna-vault");
        assert!(std::os::unix::fs::symlink(&second_package, &symlink_source).is_ok());
        let symlink_source_target = directory.0.join("symlink-source.sqlite3");
        assert_eq!(
            import_vault(
                &symlink_source,
                &symlink_source_target,
                &password,
                &TestObserver,
            ),
            Err(TransferError::PathRejected)
        );
        assert!(!symlink_source_target.exists());
        assert!(fs::remove_file(&symlink_source).is_ok());

        assert_eq!(
            import_vault(&second_package, &restored_path, &password, &TestObserver),
            Err(TransferError::ImportTargetExists)
        );

        let mut tampered = second;
        tampered[PREAMBLE_LENGTH + ENTRY_PREFIX_LENGTH + 1] ^= 1;
        let tampered_package = directory.0.join("tampered.aeterna-vault");
        assert!(fs::write(&tampered_package, tampered).is_ok());
        let tampered_target = directory.0.join("tampered.sqlite3");
        assert_eq!(
            import_vault(
                &tampered_package,
                &tampered_target,
                &password,
                &TestObserver,
            ),
            Err(TransferError::ImportInvalidPackage)
        );
        assert!(!tampered_target.exists());

        assert_no_marker_in_directory(
            &directory.0,
            &[
                b"I07 synthetic title",
                b"Synthetic contact",
                b"Synthetic body",
                b"empty-synthetic.txt",
                b"boundary-synthetic.bin",
                b"synthetic-i07-password",
            ],
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
mod acceptance_tests {
    use super::*;
    use crate::crypto::encrypt_payload;
    use std::{
        fs::{FileTimes, OpenOptions, Permissions},
        os::unix::fs::PermissionsExt,
        process::Command,
        sync::Arc,
        time::{Duration, SystemTime},
    };

    const TEST_PASSWORD: &[u8] = b"synthetic-i07-atomic-password";
    const CHILD_TEST: &str = "vault::transfer::acceptance_tests::crash_boundary_child";

    struct Observer;

    impl TransferObserver for Observer {
        fn update(&self, _phase: &'static str, _bytes: u64, _entries: u64, _cancellable: bool) {}

        fn is_cancelled(&self) -> bool {
            false
        }
    }

    struct PauseOnPublishing {
        paused: std::sync::atomic::AtomicBool,
        started: std::sync::mpsc::Sender<()>,
        resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl TransferObserver for PauseOnPublishing {
        fn update(&self, phase: &'static str, _bytes: u64, _entries: u64, _cancellable: bool) {
            if phase == "publishing" && !self.paused.swap(true, std::sync::atomic::Ordering::AcqRel)
            {
                let _ = self.started.send(());
                if let Ok(receiver) = self.resume.lock() {
                    let _ = receiver.recv_timeout(Duration::from_secs(10));
                }
            }
        }

        fn is_cancelled(&self) -> bool {
            false
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let root =
                fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
            let identifier = random_array::<16>().unwrap_or([0x6b; 16]);
            let path = root.join(format!("aeterna-i07-atomic-{}", hex_id(identifier)));
            assert!(fs::create_dir(&path).is_ok());
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn password() -> MasterPassword {
        MasterPassword::new(TEST_PASSWORD.to_vec())
            .unwrap_or_else(|error| panic!("test password rejected: {error}"))
    }

    fn create_source(path: &Path) -> (Arc<UnlockedVault>, MasterPassword) {
        use crate::vault::{ItemDraft, ItemKind};

        let password = password();
        let bootstrap =
            VaultRepository::initialize(path, &password, Argon2Profile::new(65_536, 1, 1))
                .unwrap_or_else(|error| panic!("test vault initialization failed: {error}"));
        let (repository, recovery) = bootstrap.into_parts();
        drop(recovery);
        let unlocked = repository
            .unlock(&password)
            .unwrap_or_else(|error| panic!("test vault unlock failed: {error}"));
        let draft = ItemDraft::new(
            ItemKind::Note,
            "Atomic fixture".to_owned(),
            String::new(),
            String::new(),
            "Synthetic crash and fault evidence".to_owned(),
        );
        draft
            .and_then(|value| unlocked.create_item(value))
            .unwrap_or_else(|error| panic!("test item creation failed: {error}"));
        (Arc::new(unlocked), password)
    }

    fn assert_valid_package(path: &Path, password: &MasterPassword) {
        let mut file =
            File::open(path).unwrap_or_else(|error| panic!("package open failed: {error}"));
        let validated = parse_and_authenticate(&mut file, password, &Observer)
            .unwrap_or_else(|error| panic!("package authentication failed: {error}"));
        validate_all_records(&mut file, &validated, &Observer)
            .unwrap_or_else(|error| panic!("package record validation failed: {error}"));
    }

    fn assert_valid_vault(path: &Path, password: &MasterPassword) {
        VaultRepository::open(path)
            .and_then(|repository| repository.unlock(password))
            .and_then(|vault| vault.list_items())
            .unwrap_or_else(|error| panic!("published vault validation failed: {error}"));
    }

    fn remove_owned_transfer_artifacts(directory: &Path) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("test directory read failed: {error}"));
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".aeterna-export-v1-")
                || name.starts_with(".aeterna-import-package-v1-")
                || name.starts_with(".aeterna-import-vault-v1-")
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn remove_vault(path: &Path) {
        cleanup_owned_staging_files(path);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn deterministic_io_failures_and_short_writes_preserve_atomicity() {
        let directory = TestDirectory::new();
        let source_path = directory.0.join("source.sqlite3");
        let (source, password) = create_source(&source_path);
        let package = directory.0.join("source.aeterna-vault");
        assert!(export_vault(&source, &package, &Observer).is_ok());

        let export_prepublication = [
            "export-before-temp-create",
            "export-after-temp-create",
            "export-before-snapshot",
            "export-write-preamble",
            "export-after-preamble-write",
            "export-write-metadata-entry",
            "export-after-metadata-writes",
            "export-write-nonce-entry",
            "export-after-nonce-writes",
            "export-write-record-entry",
            "export-after-record-writes",
            "export-write-manifest",
            "export-after-manifest-write",
            "export-write-trailer",
            "export-after-trailer-write",
            "export-before-flush",
            "export-after-flush",
            "export-after-snapshot-commit",
            "export-before-file-sync",
            "export-after-file-sync",
            "export-after-file-verify",
            "export-before-link",
        ];
        for (index, point) in export_prepublication.into_iter().enumerate() {
            let target = directory
                .0
                .join(format!("export-failure-{index}.aeterna-vault"));
            let result = {
                let _guard =
                    fault_injection::install(point, fault_injection::Mode::Errno(libc::EIO));
                export_vault(&source, &target, &Observer)
            };
            assert_eq!(result, Err(TransferError::Io), "fault point {point}");
            assert!(!target.exists(), "fault point {point}");
            remove_owned_transfer_artifacts(&directory.0);
        }

        for (index, point) in [
            "export-write-preamble",
            "export-write-metadata-entry",
            "export-write-nonce-entry",
            "export-write-record-entry",
            "export-write-manifest",
            "export-write-trailer",
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory
                .0
                .join(format!("export-short-{index}.aeterna-vault"));
            let result = {
                let _guard = fault_injection::install(point, fault_injection::Mode::ShortWrite);
                export_vault(&source, &target, &Observer)
            };
            assert_eq!(result, Err(TransferError::Io), "short write {point}");
            assert!(!target.exists(), "short write {point}");
            remove_owned_transfer_artifacts(&directory.0);
        }

        for (index, (point, errno)) in [
            ("export-write-record-entry", libc::ENOSPC),
            ("export-before-file-sync", libc::EDQUOT),
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory
                .0
                .join(format!("export-space-{index}.aeterna-vault"));
            let result = {
                let _guard = fault_injection::install(point, fault_injection::Mode::Errno(errno));
                export_vault(&source, &target, &Observer)
            };
            assert_eq!(result, Err(TransferError::Io), "space fault {point}");
            assert!(!target.exists(), "space fault {point}");
            remove_owned_transfer_artifacts(&directory.0);
        }

        let uncertain_sync = directory.0.join("export-uncertain-sync.aeterna-vault");
        let uncertain_result = {
            let _guard = fault_injection::install(
                "export-before-publish-dir-sync",
                fault_injection::Mode::Errno(libc::EIO),
            );
            export_vault(&source, &uncertain_sync, &Observer)
        };
        assert!(uncertain_result.is_ok());
        assert_valid_package(&uncertain_sync, &password);
        assert!(fs::remove_file(&uncertain_sync).is_ok());

        for (index, point) in [
            "export-after-link",
            "export-after-publish-dir-sync",
            "export-before-temp-unlink",
            "export-after-temp-unlink",
            "export-before-clean-dir-sync",
            "export-after-clean-dir-sync",
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory
                .0
                .join(format!("export-published-{index}.aeterna-vault"));
            let result = {
                let _guard =
                    fault_injection::install(point, fault_injection::Mode::Errno(libc::EIO));
                export_vault(&source, &target, &Observer)
            };
            assert_eq!(result, Err(TransferError::Io), "published fault {point}");
            assert_valid_package(&target, &password);
            assert!(fs::remove_file(&target).is_ok());
            remove_owned_transfer_artifacts(&directory.0);
        }

        let import_prepublication = [
            "import-before-quarantine-create",
            "import-after-quarantine-create",
            "import-before-source-read",
            "import-write-quarantine",
            "import-after-quarantine-write",
            "import-before-quarantine-sync",
            "import-after-quarantine-sync",
            "import-after-source-recheck",
            "import-before-package-parse",
            "import-after-package-parse",
            "import-before-record-validation",
            "import-after-record-validation",
            "import-before-stage-create",
            "import-after-stage-create",
            "import-before-database-open",
            "import-before-schema",
            "import-before-metadata-insert",
            "import-before-nonce-insert",
            "import-before-record-insert",
            "import-before-database-commit",
            "import-after-database-commit",
            "import-before-checkpoint",
            "import-after-checkpoint",
            "import-after-database-close",
            "import-before-stage-sync",
            "import-after-stage-sync",
            "import-before-stage-verify",
            "import-after-stage-verify",
            "import-before-link",
        ];
        for (index, point) in import_prepublication.into_iter().enumerate() {
            let target = directory.0.join(format!("import-failure-{index}.sqlite3"));
            let result = {
                let _guard =
                    fault_injection::install(point, fault_injection::Mode::Errno(libc::EIO));
                import_vault(&package, &target, &password, &Observer)
            };
            assert_eq!(result, Err(TransferError::Io), "fault point {point}");
            assert!(!target.exists(), "fault point {point}");
            remove_owned_transfer_artifacts(&directory.0);
            remove_vault(&target);
        }

        for (index, mode) in [
            fault_injection::Mode::ShortWrite,
            fault_injection::Mode::Errno(libc::ENOSPC),
            fault_injection::Mode::Errno(libc::EDQUOT),
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory
                .0
                .join(format!("import-write-failure-{index}.sqlite3"));
            let result = {
                let _guard = fault_injection::install("import-write-quarantine", mode);
                import_vault(&package, &target, &password, &Observer)
            };
            assert_eq!(result, Err(TransferError::Io));
            assert!(!target.exists());
            remove_owned_transfer_artifacts(&directory.0);
        }

        for (index, point) in [
            "import-after-link",
            "import-before-publish-dir-sync",
            "import-after-publish-dir-sync",
            "import-before-stage-unlink",
            "import-after-stage-unlink",
            "import-before-clean-dir-sync",
            "import-after-clean-dir-sync",
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory
                .0
                .join(format!("import-published-{index}.sqlite3"));
            let result = {
                let _guard =
                    fault_injection::install(point, fault_injection::Mode::Errno(libc::EIO));
                import_vault(&package, &target, &password, &Observer)
            };
            assert_eq!(result, Err(TransferError::Io), "published fault {point}");
            assert_valid_vault(&target, &password);
            remove_vault(&target);
            remove_owned_transfer_artifacts(&directory.0);
        }

        for (index, point) in [
            "import-before-quarantine-unlink",
            "import-before-quarantine-dir-sync",
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory.0.join(format!("import-cleanup-{index}.sqlite3"));
            let result = {
                let _guard =
                    fault_injection::install(point, fault_injection::Mode::Errno(libc::EIO));
                import_vault(&package, &target, &password, &Observer)
            };
            assert!(result.is_ok(), "cleanup fault {point}");
            assert_valid_vault(&target, &password);
            remove_vault(&target);
            remove_owned_transfer_artifacts(&directory.0);
        }
    }

    #[test]
    fn crash_boundary_child() {
        if std::env::var_os("AETERNA_I07_CRASH_CHILD").is_none() {
            return;
        }
        let action = std::env::var("AETERNA_I07_CHILD_ACTION")
            .unwrap_or_else(|error| panic!("missing child action: {error}"));
        let source = PathBuf::from(
            std::env::var_os("AETERNA_I07_CHILD_SOURCE")
                .unwrap_or_else(|| panic!("missing child source")),
        );
        let target = PathBuf::from(
            std::env::var_os("AETERNA_I07_CHILD_TARGET")
                .unwrap_or_else(|| panic!("missing child target")),
        );
        let password = password();
        match action.as_str() {
            "export" => {
                let unlocked = VaultRepository::open(&source)
                    .and_then(|repository| repository.unlock(&password))
                    .unwrap_or_else(|error| panic!("child source unlock failed: {error}"));
                let result = export_vault(&unlocked, &target, &Observer);
                panic!("export child did not crash: {result:?}");
            }
            "import" => {
                let result = import_vault(&source, &target, &password, &Observer);
                panic!("import child did not crash: {result:?}");
            }
            _ => panic!("invalid child action"),
        }
    }

    fn run_crash_child(action: &str, point: &str, source: &Path, target: &Path) {
        let output = Command::new(
            std::env::current_exe()
                .unwrap_or_else(|error| panic!("test executable missing: {error}")),
        )
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env("AETERNA_I07_CRASH_CHILD", "1")
        .env("AETERNA_I07_CHILD_ACTION", action)
        .env("AETERNA_I07_CHILD_SOURCE", source)
        .env("AETERNA_I07_CHILD_TARGET", target)
        .env("AETERNA_I07_CRASH_POINT", point)
        .output()
        .unwrap_or_else(|error| panic!("crash child failed to start: {error}"));
        assert_eq!(
            output.status.code(),
            Some(fault_injection::CRASH_EXIT_CODE),
            "child {action}/{point} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn subprocess_crashes_leave_only_absent_or_complete_targets() {
        let directory = TestDirectory::new();
        let source_path = directory.0.join("crash-source.sqlite3");
        let (source, password) = create_source(&source_path);
        let package = directory.0.join("crash-source.aeterna-vault");
        assert!(export_vault(&source, &package, &Observer).is_ok());
        drop(source);

        let export_before_publication = [
            "export-before-temp-create",
            "export-after-temp-create",
            "export-before-snapshot",
            "export-after-preamble-write",
            "export-after-metadata-writes",
            "export-after-nonce-writes",
            "export-after-record-writes",
            "export-after-manifest-write",
            "export-after-trailer-write",
            "export-after-flush",
            "export-after-snapshot-commit",
            "export-after-file-sync",
            "export-after-file-verify",
            "export-before-link",
        ];
        for (index, point) in export_before_publication.into_iter().enumerate() {
            let target = directory
                .0
                .join(format!("crash-export-before-{index}.aeterna-vault"));
            run_crash_child("export", point, &source_path, &target);
            assert!(!target.exists(), "crash point {point}");
            remove_owned_transfer_artifacts(&directory.0);
        }
        for (index, point) in [
            "export-after-link",
            "export-after-publish-dir-sync",
            "export-after-temp-unlink",
            "export-after-clean-dir-sync",
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory
                .0
                .join(format!("crash-export-after-{index}.aeterna-vault"));
            run_crash_child("export", point, &source_path, &target);
            assert_valid_package(&target, &password);
            assert!(fs::remove_file(&target).is_ok());
            remove_owned_transfer_artifacts(&directory.0);
        }

        let import_before_publication = [
            "import-after-quarantine-create",
            "import-after-quarantine-write",
            "import-after-quarantine-sync",
            "import-after-source-recheck",
            "import-after-package-parse",
            "import-after-record-validation",
            "import-after-stage-create",
            "import-before-schema",
            "import-before-metadata-insert",
            "import-before-nonce-insert",
            "import-before-record-insert",
            "import-after-database-commit",
            "import-after-checkpoint",
            "import-after-database-close",
            "import-after-stage-sync",
            "import-after-stage-verify",
            "import-before-link",
        ];
        for (index, point) in import_before_publication.into_iter().enumerate() {
            let target = directory
                .0
                .join(format!("crash-import-before-{index}.sqlite3"));
            run_crash_child("import", point, &package, &target);
            assert!(!target.exists(), "crash point {point}");
            remove_owned_transfer_artifacts(&directory.0);
            remove_vault(&target);
        }
        for (index, point) in [
            "import-after-link",
            "import-after-publish-dir-sync",
            "import-after-stage-unlink",
            "import-after-clean-dir-sync",
            "import-before-quarantine-unlink",
            "import-before-quarantine-dir-sync",
        ]
        .into_iter()
        .enumerate()
        {
            let target = directory
                .0
                .join(format!("crash-import-after-{index}.sqlite3"));
            run_crash_child("import", point, &package, &target);
            assert_valid_vault(&target, &password);
            remove_vault(&target);
            remove_owned_transfer_artifacts(&directory.0);
        }
    }

    #[test]
    fn destination_parent_swaps_are_detected_before_publication() {
        let directory = TestDirectory::new();
        let source_path = directory.0.join("swap-source.sqlite3");
        let (source, source_password) = create_source(&source_path);

        let export_parent = directory.0.join("export-parent");
        let moved_export_parent = directory.0.join("export-parent-moved");
        assert!(fs::create_dir(&export_parent).is_ok());
        let export_target = export_parent.join("swapped.aeterna-vault");
        let export_target_for_worker = export_target.clone();
        let source_for_worker = Arc::clone(&source);
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (resume_sender, resume_receiver) = std::sync::mpsc::channel();
        let export_observer = PauseOnPublishing {
            paused: std::sync::atomic::AtomicBool::new(false),
            started: started_sender,
            resume: std::sync::Mutex::new(resume_receiver),
        };
        let export_worker = std::thread::spawn(move || {
            export_vault(
                &source_for_worker,
                &export_target_for_worker,
                &export_observer,
            )
        });
        assert!(
            started_receiver
                .recv_timeout(Duration::from_secs(10))
                .is_ok()
        );
        assert!(fs::rename(&export_parent, &moved_export_parent).is_ok());
        assert!(fs::create_dir(&export_parent).is_ok());
        assert!(resume_sender.send(()).is_ok());
        assert_eq!(
            export_worker
                .join()
                .unwrap_or_else(|_| panic!("export parent-swap worker panicked")),
            Err(TransferError::PathRejected)
        );
        assert!(!export_target.exists());
        assert!(!moved_export_parent.join("swapped.aeterna-vault").exists());
        remove_owned_transfer_artifacts(&moved_export_parent);

        let package = directory.0.join("swap-source.aeterna-vault");
        assert!(export_vault(&source, &package, &Observer).is_ok());
        let import_parent = directory.0.join("import-parent");
        let moved_import_parent = directory.0.join("import-parent-moved");
        assert!(fs::create_dir(&import_parent).is_ok());
        let import_target = import_parent.join("swapped.sqlite3");
        let import_target_for_worker = import_target.clone();
        let package_for_worker = package.clone();
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (resume_sender, resume_receiver) = std::sync::mpsc::channel();
        let import_observer = PauseOnPublishing {
            paused: std::sync::atomic::AtomicBool::new(false),
            started: started_sender,
            resume: std::sync::Mutex::new(resume_receiver),
        };
        let import_worker = std::thread::spawn(move || {
            let password = password();
            import_vault(
                &package_for_worker,
                &import_target_for_worker,
                &password,
                &import_observer,
            )
        });
        assert!(
            started_receiver
                .recv_timeout(Duration::from_secs(10))
                .is_ok()
        );
        assert!(fs::rename(&import_parent, &moved_import_parent).is_ok());
        assert!(fs::create_dir(&import_parent).is_ok());
        assert!(resume_sender.send(()).is_ok());
        assert_eq!(
            import_worker
                .join()
                .unwrap_or_else(|_| panic!("import parent-swap worker panicked")),
            Err(TransferError::PathRejected)
        );
        assert!(!import_target.exists());
        assert!(!moved_import_parent.join("swapped.sqlite3").exists());
        remove_owned_transfer_artifacts(&moved_import_parent);
        drop(source_password);
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("fixture write failed: {error}"));
        fs::set_permissions(path, Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("fixture chmod failed: {error}"));
    }

    fn make_old(path: &Path) {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap_or_else(|error| panic!("fixture open failed: {error}"));
        let modified = SystemTime::now()
            .checked_sub(Duration::from_secs(25 * 60 * 60))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        file.set_times(FileTimes::new().set_modified(modified))
            .unwrap_or_else(|error| panic!("fixture timestamp failed: {error}"));
    }

    #[test]
    fn stale_cleanup_is_authenticated_exact_and_age_gated() {
        let directory = TestDirectory::new();
        let source_path = directory.0.join("stale-source.sqlite3");
        let (source, password) = create_source(&source_path);
        let package = directory.0.join("stale.aeterna-vault");
        assert!(export_vault(&source, &package, &Observer).is_ok());
        assert_valid_package(&package, &password);
        let package_bytes =
            fs::read(&package).unwrap_or_else(|error| panic!("package read failed: {error}"));
        let package_id: [u8; 16] = package_bytes[24..40].try_into().unwrap_or([0; 16]);
        let completed = directory
            .0
            .join(format!(".aeterna-export-v1-{}.tmp", hex_id(package_id)));
        write_private(&completed, &package_bytes);
        make_old(&completed);

        let incomplete_id = [0x11; 16];
        let incomplete = directory
            .0
            .join(format!(".aeterna-export-v1-{}.tmp", hex_id(incomplete_id)));
        let mut incomplete_bytes = vec![0_u8; 40];
        incomplete_bytes[0..16].copy_from_slice(&PACKAGE_MAGIC);
        incomplete_bytes[24..40].copy_from_slice(&incomplete_id);
        write_private(&incomplete, &incomplete_bytes);
        make_old(&incomplete);

        let young_id = [0x22; 16];
        let young = directory
            .0
            .join(format!(".aeterna-export-v1-{}.tmp", hex_id(young_id)));
        let mut young_bytes = vec![0_u8; 40];
        young_bytes[0..16].copy_from_slice(&PACKAGE_MAGIC);
        young_bytes[24..40].copy_from_slice(&young_id);
        write_private(&young, &young_bytes);

        let invalid_id = [0x33; 16];
        let invalid_completed = directory
            .0
            .join(format!(".aeterna-export-v1-{}.tmp", hex_id(invalid_id)));
        let mut invalid_bytes = package_bytes.clone();
        invalid_bytes[24..40].copy_from_slice(&invalid_id);
        write_private(&invalid_completed, &invalid_bytes);
        make_old(&invalid_completed);

        let wrong_mode_id = [0x44; 16];
        let wrong_mode = directory
            .0
            .join(format!(".aeterna-export-v1-{}.tmp", hex_id(wrong_mode_id)));
        let mut wrong_mode_bytes = vec![0_u8; 40];
        wrong_mode_bytes[0..16].copy_from_slice(&PACKAGE_MAGIC);
        wrong_mode_bytes[24..40].copy_from_slice(&wrong_mode_id);
        write_private(&wrong_mode, &wrong_mode_bytes);
        fs::set_permissions(&wrong_mode, Permissions::from_mode(0o644))
            .unwrap_or_else(|error| panic!("wrong-mode chmod failed: {error}"));
        make_old(&wrong_mode);

        let linked_id = [0x55; 16];
        let linked = directory
            .0
            .join(format!(".aeterna-export-v1-{}.tmp", hex_id(linked_id)));
        let mut linked_bytes = vec![0_u8; 40];
        linked_bytes[0..16].copy_from_slice(&PACKAGE_MAGIC);
        linked_bytes[24..40].copy_from_slice(&linked_id);
        write_private(&linked, &linked_bytes);
        make_old(&linked);
        assert!(fs::hard_link(&linked, directory.0.join("linked-one")).is_ok());
        assert!(fs::hard_link(&linked, directory.0.join("linked-two")).is_ok());

        let symlink_id = [0x66; 16];
        let symlink = directory
            .0
            .join(format!(".aeterna-export-v1-{}.tmp", hex_id(symlink_id)));
        assert!(std::os::unix::fs::symlink(&package, &symlink).is_ok());
        let directory_id = [0x77; 16];
        let matching_directory = directory
            .0
            .join(format!(".aeterna-export-v1-{}.tmp", hex_id(directory_id)));
        assert!(fs::create_dir(&matching_directory).is_ok());

        let import_old = directory
            .0
            .join(".aeterna-import-package-v1-88888888888888888888888888888888.tmp");
        write_private(&import_old, b"old import quarantine");
        make_old(&import_old);
        let import_young = directory
            .0
            .join(".aeterna-import-vault-v1-99999999999999999999999999999999.stage");
        write_private(&import_young, b"young import stage");
        let unrelated = directory.0.join("unrelated-user-file");
        write_private(&unrelated, b"must remain");

        let directory_handle = Directory::open(&directory.0)
            .unwrap_or_else(|error| panic!("directory open failed: {error}"));
        cleanup_stale_files(
            &directory.0,
            &directory_handle,
            StaleFileKind::Export,
            Some(&source.vdk),
        );
        cleanup_stale_files(&directory.0, &directory_handle, StaleFileKind::Import, None);

        assert!(!completed.exists());
        assert!(!incomplete.exists());
        assert!(young.exists());
        assert!(invalid_completed.exists());
        assert!(wrong_mode.exists());
        assert!(linked.exists());
        assert!(symlink.exists());
        assert!(matching_directory.exists());
        assert!(!import_old.exists());
        assert!(import_young.exists());
        assert_eq!(fs::read(&unrelated).unwrap_or_default(), b"must remain");
    }

    #[test]
    fn permissions_read_only_directories_and_special_files_fail_closed() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        fn make_fifo(path: &Path) {
            let encoded = CString::new(path.as_os_str().as_bytes())
                .unwrap_or_else(|error| panic!("FIFO path encoding failed: {error}"));
            // SAFETY: `encoded` is a live NUL-terminated path and the mode grants
            // access only to the current user. The test removes the FIFO afterward.
            let result = unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) };
            assert_eq!(
                result,
                0,
                "FIFO creation failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let directory = TestDirectory::new();
        let source_path = directory.0.join("permission-source.sqlite3");
        let (source, password) = create_source(&source_path);
        let package = directory.0.join("permission-source.aeterna-vault");
        assert!(export_vault(&source, &package, &Observer).is_ok());

        let read_only = directory.0.join("read-only");
        assert!(fs::create_dir(&read_only).is_ok());
        assert!(fs::set_permissions(&read_only, Permissions::from_mode(0o500)).is_ok());
        let export_target = read_only.join("denied.aeterna-vault");
        assert_eq!(
            export_vault(&source, &export_target, &Observer),
            Err(TransferError::Io)
        );
        let import_target = read_only.join("denied.sqlite3");
        assert_eq!(
            import_vault(&package, &import_target, &password, &Observer),
            Err(TransferError::Io)
        );
        assert!(fs::set_permissions(&read_only, Permissions::from_mode(0o700)).is_ok());
        assert!(!export_target.exists());
        assert!(!import_target.exists());

        let special_export = directory.0.join("special.aeterna-vault");
        make_fifo(&special_export);
        assert_eq!(
            export_vault(&source, &special_export, &Observer),
            Err(TransferError::ExportTargetExists)
        );
        assert!(fs::remove_file(&special_export).is_ok());

        let special_import_target = directory.0.join("special.sqlite3");
        make_fifo(&special_import_target);
        assert_eq!(
            import_vault(&package, &special_import_target, &password, &Observer),
            Err(TransferError::ImportTargetExists)
        );
        assert!(fs::remove_file(&special_import_target).is_ok());

        let special_source = directory.0.join("special-source.aeterna-vault");
        assert!(fs::create_dir(&special_source).is_ok());
        let special_source_target = directory.0.join("special-source.sqlite3");
        assert!(
            import_vault(
                &special_source,
                &special_source_target,
                &password,
                &Observer
            )
            .is_err()
        );
        assert!(!special_source_target.exists());
    }

    fn encoded_item_fixture(length: usize) -> Vec<u8> {
        use crate::vault::{
            MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_COUNT, MAX_BODY_BYTES, MAX_CATEGORY_BYTES,
            MAX_CONTACT_EXPLANATION_BYTES, MAX_FILENAME_BYTES, MAX_MEDIA_TYPE_BYTES,
            MAX_TITLE_BYTES,
        };

        let maximum_length = 30
            + MAX_TITLE_BYTES
            + MAX_CATEGORY_BYTES
            + MAX_CONTACT_EXPLANATION_BYTES
            + MAX_BODY_BYTES
            + (MAX_ATTACHMENT_COUNT * 24)
            + (MAX_ATTACHMENT_COUNT * MAX_FILENAME_BYTES)
            + (MAX_ATTACHMENT_COUNT * MAX_MEDIA_TYPE_BYTES)
            + MAX_ATTACHMENT_BYTES;
        if length != maximum_length {
            let body_length = length
                .checked_sub(31)
                .unwrap_or_else(|| panic!("fixture length is below the minimum"));
            assert!(body_length <= MAX_BODY_BYTES);
            let mut output = Vec::with_capacity(length);
            output.extend_from_slice(b"AETRITM\0");
            output.extend_from_slice(&ITEM_PAYLOAD_VERSION.to_be_bytes());
            output.extend_from_slice(&[1, 0]);
            output.extend_from_slice(&0_u16.to_be_bytes());
            output.extend_from_slice(&1_u32.to_be_bytes());
            output.extend_from_slice(&0_u32.to_be_bytes());
            output.extend_from_slice(&0_u32.to_be_bytes());
            output.extend_from_slice(&(body_length as u32).to_be_bytes());
            output.push(b't');
            output.resize(length, b'b');
            assert_eq!(output.len(), length);
            validate_item_payload(&output)
                .unwrap_or_else(|error| panic!("small item fixture rejected: {error}"));
            return output;
        }

        let media_type = format!("a/{}", "z".repeat(MAX_MEDIA_TYPE_BYTES - 2));
        let mut output = Vec::with_capacity(maximum_length);
        output.extend_from_slice(b"AETRITM\0");
        output.extend_from_slice(&ITEM_PAYLOAD_VERSION.to_be_bytes());
        output.extend_from_slice(&[2, 0]);
        output.extend_from_slice(&(MAX_ATTACHMENT_COUNT as u16).to_be_bytes());
        output.extend_from_slice(&(MAX_TITLE_BYTES as u32).to_be_bytes());
        output.extend_from_slice(&(MAX_CATEGORY_BYTES as u32).to_be_bytes());
        output.extend_from_slice(&(MAX_CONTACT_EXPLANATION_BYTES as u32).to_be_bytes());
        output.extend_from_slice(&(MAX_BODY_BYTES as u32).to_be_bytes());
        output.extend(std::iter::repeat_n(b't', MAX_TITLE_BYTES));
        output.extend(std::iter::repeat_n(b'c', MAX_CATEGORY_BYTES));
        output.extend(std::iter::repeat_n(b'e', MAX_CONTACT_EXPLANATION_BYTES));
        output.extend(std::iter::repeat_n(b'b', MAX_BODY_BYTES));
        for index in 0..MAX_ATTACHMENT_COUNT {
            output.extend_from_slice(&[u8::try_from(index + 1).unwrap_or(1); 16]);
            output.extend_from_slice(&(MAX_FILENAME_BYTES as u16).to_be_bytes());
            output.extend_from_slice(&(MAX_MEDIA_TYPE_BYTES as u16).to_be_bytes());
            let content_length = if index == 0 { MAX_ATTACHMENT_BYTES } else { 0 };
            output.extend_from_slice(&(content_length as u32).to_be_bytes());
            output.extend(std::iter::repeat_n(b'f', MAX_FILENAME_BYTES));
            output.extend_from_slice(media_type.as_bytes());
            output.extend(std::iter::repeat_n(0xa5, content_length));
        }
        assert_eq!(output.len(), maximum_length);
        validate_item_payload(&output)
            .unwrap_or_else(|error| panic!("maximum item fixture rejected: {error}"));
        output
    }

    #[test]
    #[ignore = "materializes and authenticates the exact 1 GiB package boundary"]
    fn exact_maximum_package_is_valid_and_limit_plus_one_is_rejected() {
        let directory = TestDirectory::new();
        let source_path = directory.0.join("maximum-source.sqlite3");
        let password = password();
        let bootstrap =
            VaultRepository::initialize(&source_path, &password, Argon2Profile::new(65_536, 1, 1))
                .unwrap_or_else(|error| panic!("maximum source initialization failed: {error}"));
        let (repository, recovery) = bootstrap.into_parts();
        drop(recovery);
        let source = repository
            .unlock(&password)
            .unwrap_or_else(|error| panic!("maximum source unlock failed: {error}"));

        const RECORD_COUNT: usize = 1_156;
        const MAXIMUM_PLAINTEXT: usize = 929_358;
        const FINAL_PLAINTEXT: usize = 74_385;
        let maximum_plaintext = encoded_item_fixture(MAXIMUM_PLAINTEXT);
        let final_plaintext = encoded_item_fixture(FINAL_PLAINTEXT);
        let connection = source
            .repository
            .connection()
            .unwrap_or_else(|error| panic!("maximum source connection failed: {error}"));
        let metadata = load_metadata(&connection)
            .unwrap_or_else(|error| panic!("maximum metadata load failed: {error}"));
        let migration_applied_at_ms = migration_applied_at_ms(&connection)
            .unwrap_or_else(|error| panic!("maximum migration load failed: {error}"));
        let mut nonce_rows = Vec::with_capacity(RECORD_COUNT + 3);
        {
            let mut statement = connection
                .prepare(
                    "SELECT nonce, purpose, reserved_at_ms FROM nonce_reservations ORDER BY nonce",
                )
                .unwrap_or_else(|error| panic!("nonce query prepare failed: {error}"));
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap_or_else(|error| panic!("nonce query failed: {error}"));
            for row in rows {
                let (nonce, purpose, reserved_at_ms) =
                    row.unwrap_or_else(|error| panic!("nonce row failed: {error}"));
                nonce_rows.push((
                    read_array::<12>(&nonce)
                        .unwrap_or_else(|error| panic!("nonce decoding failed: {error}")),
                    u8::try_from(purpose)
                        .unwrap_or_else(|_| panic!("nonce purpose is out of range")),
                    u64::try_from(reserved_at_ms)
                        .unwrap_or_else(|_| panic!("nonce timestamp is negative")),
                ));
            }
        }
        drop(connection);
        assert_eq!(nonce_rows.len(), 3);
        let mut used_nonces: HashSet<[u8; 12]> =
            nonce_rows.iter().map(|(nonce, _, _)| *nonce).collect();
        let mut record_nonces = Vec::with_capacity(RECORD_COUNT);
        for index in 0..RECORD_COUNT {
            let mut nonce = [0_u8; 12];
            nonce[0] = 0xa7;
            nonce[4..12].copy_from_slice(&((index as u64) + 1).to_be_bytes());
            while used_nonces.contains(&nonce) {
                nonce[1] = nonce[1]
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("deterministic nonce fixture exhausted"));
            }
            used_nonces.insert(nonce);
            record_nonces.push(nonce);
            nonce_rows.push((nonce, RECORD_NONCE_PURPOSE, (index as u64) + 1));
        }
        nonce_rows.sort_by_key(|(nonce, _, _)| *nonce);

        let frame_bytes =
            ((RECORD_COUNT - 1) * (MAXIMUM_PLAINTEXT + 46) + FINAL_PLAINTEXT + 46) as u64;
        assert_eq!(
            body_length(RECORD_COUNT as u32, (RECORD_COUNT + 3) as u32, frame_bytes),
            Some(MAX_BODY_LENGTH)
        );
        let preamble = Preamble {
            package_id: [0x41; 16],
            salt: [0x31; 32],
            entry_count: u32::try_from(4 + nonce_rows.len() + RECORD_COUNT)
                .unwrap_or_else(|_| panic!("maximum entry count overflow")),
            record_count: RECORD_COUNT as u32,
            nonce_count: nonce_rows.len() as u32,
            body_length: MAX_BODY_LENGTH,
        };
        let package = directory.0.join("maximum.aeterna-vault");
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&package)
            .unwrap_or_else(|error| panic!("maximum package create failed: {error}"));
        fs::set_permissions(&package, Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("maximum package chmod failed: {error}"));
        let preamble_bytes = encode_preamble(preamble);
        file.write_all(&preamble_bytes)
            .unwrap_or_else(|error| panic!("maximum preamble write failed: {error}"));
        let mut body_digest = Sha256::new();
        let mut ordinal = 0_u32;
        for (entry_type, payload) in [
            (1, encode_header(&metadata.header).to_vec()),
            (
                2,
                encode_master(&metadata.master)
                    .unwrap_or_else(|error| panic!("maximum master encoding failed: {error}"))
                    .to_vec(),
            ),
            (
                3,
                encode_recovery(&metadata.recovery)
                    .unwrap_or_else(|error| panic!("maximum recovery encoding failed: {error}"))
                    .to_vec(),
            ),
            (4, encode_schema(migration_applied_at_ms).to_vec()),
        ] {
            write_entry(
                &mut file,
                &mut body_digest,
                entry_type,
                ordinal,
                &payload,
                "maximum-fixture-write",
            )
            .unwrap_or_else(|error| panic!("maximum metadata write failed: {error}"));
            ordinal += 1;
        }
        for (nonce, purpose, reserved_at_ms) in &nonce_rows {
            let payload = encode_nonce(*nonce, *purpose, *reserved_at_ms);
            write_entry(
                &mut file,
                &mut body_digest,
                5,
                ordinal,
                &payload,
                "maximum-fixture-write",
            )
            .unwrap_or_else(|error| panic!("maximum nonce write failed: {error}"));
            ordinal += 1;
        }
        for (index, nonce) in record_nonces.into_iter().enumerate() {
            let mut record_id = [0_u8; 16];
            record_id[8..16].copy_from_slice(&((index as u64) + 1).to_be_bytes());
            let plaintext = if index + 1 == RECORD_COUNT {
                &final_plaintext
            } else {
                &maximum_plaintext
            };
            let timestamp = (index as u64) + 1;
            let aad = record_aad(
                source.vault_id,
                record_id,
                1,
                timestamp,
                timestamp,
                plaintext.len(),
            )
            .unwrap_or_else(|error| panic!("record AAD failed: {error}"));
            let encrypted = encrypt_payload(&source.vdk, &nonce, plaintext, &aad)
                .unwrap_or_else(|error| panic!("record encryption failed: {error}"));
            let frame = format::encode_frame(nonce, &encrypted)
                .unwrap_or_else(|error| panic!("record frame failed: {error}"));
            let payload = encode_record(record_id, 1, timestamp, timestamp, &frame)
                .unwrap_or_else(|error| panic!("maximum record encoding failed: {error}"));
            write_entry(
                &mut file,
                &mut body_digest,
                6,
                ordinal,
                &payload,
                "maximum-fixture-write",
            )
            .unwrap_or_else(|error| panic!("maximum record write failed: {error}"));
            ordinal += 1;
        }
        assert_eq!(ordinal, preamble.entry_count);
        let body_digest: [u8; 32] = body_digest.finalize().into();
        let manifest = encode_manifest(preamble, &metadata.header, body_digest);
        file.write_all(&manifest)
            .unwrap_or_else(|error| panic!("maximum manifest write failed: {error}"));
        let authentication_nonce = [0x21; 12];
        let mut trailer = encode_trailer(authentication_nonce, [0; 16], MAX_PACKAGE_LENGTH);
        let info = export_key_info(metadata.header.vault_id, preamble.package_id);
        let aad = export_authentication_aad(&preamble_bytes, &manifest, &trailer);
        let tag = export_authentication_tag(
            &source.vdk,
            &preamble.salt,
            &info,
            &authentication_nonce,
            &aad,
        )
        .unwrap_or_else(|error| panic!("maximum package authentication failed: {error}"));
        trailer[38..54].copy_from_slice(&tag);
        file.write_all(&trailer)
            .unwrap_or_else(|error| panic!("maximum trailer write failed: {error}"));
        file.sync_all()
            .unwrap_or_else(|error| panic!("maximum package sync failed: {error}"));
        drop(file);
        assert_eq!(
            fs::metadata(&package)
                .unwrap_or_else(|error| panic!("maximum package metadata failed: {error}"))
                .len(),
            MAX_PACKAGE_LENGTH
        );
        assert_valid_package(&package, &password);

        let mut plus_one = OpenOptions::new()
            .append(true)
            .open(&package)
            .unwrap_or_else(|error| panic!("maximum package append failed: {error}"));
        plus_one
            .write_all(&[0])
            .unwrap_or_else(|error| panic!("maximum package extension failed: {error}"));
        plus_one
            .sync_all()
            .unwrap_or_else(|error| panic!("maximum package extension sync failed: {error}"));
        drop(plus_one);
        let mut oversized = File::open(&package)
            .unwrap_or_else(|error| panic!("oversized package open failed: {error}"));
        assert_eq!(
            parse_and_authenticate(&mut oversized, &password, &Observer).map(|_| ()),
            Err(TransferError::ImportLimitExceeded)
        );
    }
}
