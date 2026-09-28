use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use super::strings::Locale;

const DIRECTORY_NAME: &str = "health";
const FILE_NAME: &str = "activity-health-v1.bin";
const MAGIC: &[u8; 8] = b"AETRHST\0";
const VERSION: u16 = 1;
const ENCODED_LENGTH: usize = 96;
const FUTURE_TOLERANCE_MS: u64 = 120_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HealthRecord {
    pub(crate) desired_autostart: bool,
    pub(crate) locale: Locale,
    pub(crate) generation: u64,
    pub(crate) last_server_accepted_at_ms: Option<u64>,
    pub(crate) last_stale_notification_at_ms: Option<u64>,
    pub(crate) saved_at_ms: u64,
}

impl Default for HealthRecord {
    fn default() -> Self {
        Self {
            desired_autostart: false,
            locale: Locale::En,
            generation: 0,
            last_server_accepted_at_ms: None,
            last_stale_notification_at_ms: None,
            saved_at_ms: unix_time_ms(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct HealthStore {
    directory: PathBuf,
    #[cfg(not(target_os = "macos"))]
    path: PathBuf,
    #[cfg(target_os = "macos")]
    directory_handle: Option<File>,
}

impl HealthStore {
    pub(crate) fn new(app_local_data: &Path) -> Self {
        let directory = app_local_data.join(DIRECTORY_NAME);
        Self {
            directory,
            #[cfg(not(target_os = "macos"))]
            path: app_local_data.join(DIRECTORY_NAME).join(FILE_NAME),
            #[cfg(target_os = "macos")]
            directory_handle: None,
        }
    }

    pub(crate) fn load(&mut self) -> Result<Option<HealthRecord>, HealthError> {
        #[cfg(target_os = "macos")]
        {
            self.load_unix()
        }
        #[cfg(not(target_os = "macos"))]
        {
            if !self.path.try_exists().map_err(|_| HealthError::Io)? {
                return Ok(None);
            }
            validate_directory(&self.directory)?;
            validate_regular_file(&self.path)?;
            let mut bytes = Vec::new();
            File::open(&self.path)
                .map_err(|_| HealthError::Io)?
                .take((ENCODED_LENGTH + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| HealthError::Io)?;
            decode(&bytes).map(Some)
        }
    }

    pub(crate) fn save(&mut self, record: &mut HealthRecord) -> Result<(), HealthError> {
        #[cfg(target_os = "macos")]
        {
            self.save_unix(record)
        }
        #[cfg(not(target_os = "macos"))]
        {
            ensure_directory(&self.directory)?;
            if self.path.try_exists().map_err(|_| HealthError::Io)? {
                validate_regular_file(&self.path)?;
            }
            record.generation = record
                .generation
                .checked_add(1)
                .ok_or(HealthError::Invalid)?;
            record.saved_at_ms = unix_time_ms();
            let bytes = encode(*record);
            let temporary = self.directory.join(format!(
                ".{FILE_NAME}.tmp-{}-{}",
                std::process::id(),
                record.generation
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(target_os = "macos")]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            let mut file = options.open(&temporary).map_err(|_| HealthError::Io)?;
            let result = (|| {
                file.write_all(&bytes).map_err(|_| HealthError::Io)?;
                file.sync_all().map_err(|_| HealthError::Io)?;
                fs::rename(&temporary, &self.path).map_err(|_| HealthError::Io)?;
                sync_directory(&self.directory)
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        }
    }

    pub(crate) fn reset(&mut self, record: &mut HealthRecord) -> Result<(), HealthError> {
        #[cfg(target_os = "macos")]
        {
            self.reset_unix(record)
        }
        #[cfg(not(target_os = "macos"))]
        {
            if self.path.try_exists().map_err(|_| HealthError::Io)? {
                validate_directory(&self.directory)?;
                validate_reset_target(&self.path)?;
                fs::remove_file(&self.path).map_err(|_| HealthError::Io)?;
                sync_directory(&self.directory)?;
            }
            *record = HealthRecord::default();
            self.save(record)
        }
    }
}

#[cfg(target_os = "macos")]
impl HealthStore {
    fn directory_handle(&mut self, create: bool) -> Result<Option<&File>, HealthError> {
        use std::os::unix::fs::OpenOptionsExt;
        if self.directory_handle.is_none() {
            let app_directory = self.directory.parent().ok_or(HealthError::UnsafePath)?;
            let support_directory = app_directory.parent().ok_or(HealthError::UnsafePath)?;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let support = options
                .open(support_directory)
                .map_err(|_| HealthError::Io)?;
            if !support.metadata().map_err(|_| HealthError::Io)?.is_dir() {
                return Err(HealthError::UnsafePath);
            }
            let Some(app) = open_child_directory(
                &support,
                app_directory.file_name().ok_or(HealthError::UnsafePath)?,
                create,
                false,
            )?
            else {
                return Ok(None);
            };
            let Some(directory) =
                open_child_directory(&app, std::ffi::OsStr::new(DIRECTORY_NAME), create, true)?
            else {
                return Ok(None);
            };
            self.directory_handle = Some(directory);
        }
        Ok(self.directory_handle.as_ref())
    }

    fn load_unix(&mut self) -> Result<Option<HealthRecord>, HealthError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let Some(directory) = self.directory_handle(false)? else {
            return Ok(None);
        };
        let name = std::ffi::CString::new(FILE_NAME).map_err(|_| HealthError::Invalid)?;
        // SAFETY: `directory` is a retained, validated directory descriptor and
        // `name` is a fixed single component. The returned fd is owned below.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(HealthError::UnsafePath)
            };
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        validate_regular_metadata(&file.metadata().map_err(|_| HealthError::Io)?)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((ENCODED_LENGTH + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| HealthError::Io)?;
        decode(&bytes).map(Some)
    }

    fn save_unix(&mut self, record: &mut HealthRecord) -> Result<(), HealthError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let directory_fd = self
            .directory_handle(true)?
            .ok_or(HealthError::Io)?
            .as_raw_fd();
        validate_existing_at(directory_fd, true)?;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(HealthError::Invalid)?;
        record.saved_at_ms = unix_time_ms();
        let bytes = encode(*record);
        let temporary_name = format!(
            ".{FILE_NAME}.tmp-{}-{}",
            std::process::id(),
            record.generation
        );
        let temporary = std::ffi::CString::new(temporary_name).map_err(|_| HealthError::Invalid)?;
        let destination = std::ffi::CString::new(FILE_NAME).map_err(|_| HealthError::Invalid)?;
        // SAFETY: Both names are fixed single components relative to the
        // validated retained directory descriptor.
        let fd = unsafe {
            libc::openat(
                directory_fd,
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(HealthError::Io);
        }
        // SAFETY: `fd` is the newly created regular file owned by this call.
        if unsafe { libc::fchmod(fd, 0o600) } != 0 {
            // SAFETY: Close the owned descriptor before returning.
            let _ = unsafe { libc::close(fd) };
            let _ = unsafe { libc::unlinkat(directory_fd, temporary.as_ptr(), 0) };
            return Err(HealthError::Io);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(&bytes).map_err(|_| HealthError::Io)?;
            file.sync_all().map_err(|_| HealthError::Io)?;
            // SAFETY: Source/destination stay within the same retained directory.
            if unsafe {
                libc::renameat(
                    directory_fd,
                    temporary.as_ptr(),
                    directory_fd,
                    destination.as_ptr(),
                )
            } != 0
            {
                return Err(HealthError::Io);
            }
            self.directory_handle
                .as_ref()
                .ok_or(HealthError::Io)?
                .sync_all()
                .map_err(|_| HealthError::Io)
        })();
        if result.is_err() {
            // SAFETY: Cleanup is constrained to the exact temporary leaf.
            let _ = unsafe { libc::unlinkat(directory_fd, temporary.as_ptr(), 0) };
        }
        result
    }

    fn reset_unix(&mut self, record: &mut HealthRecord) -> Result<(), HealthError> {
        use std::os::fd::AsRawFd;
        if let Some(directory) = self.directory_handle(false)? {
            let directory_fd = directory.as_raw_fd();
            if validate_existing_at(directory_fd, false)? {
                let name = std::ffi::CString::new(FILE_NAME).map_err(|_| HealthError::Invalid)?;
                // SAFETY: The exact leaf was opened with O_NOFOLLOW and checked
                // as an owned single-link regular file immediately above.
                if unsafe { libc::unlinkat(directory_fd, name.as_ptr(), 0) } != 0 {
                    return Err(HealthError::Io);
                }
                directory.sync_all().map_err(|_| HealthError::Io)?;
            }
        }
        *record = HealthRecord::default();
        self.save_unix(record)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HealthError {
    Io,
    Invalid,
    UnsafePath,
}

fn encode(record: HealthRecord) -> [u8; ENCODED_LENGTH] {
    let mut bytes = [0_u8; ENCODED_LENGTH];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    let flags = u16::from(record.desired_autostart);
    bytes[10..12].copy_from_slice(&flags.to_le_bytes());
    bytes[12] = record.locale.as_byte();
    bytes[16..24].copy_from_slice(&record.generation.to_le_bytes());
    bytes[24..32].copy_from_slice(&record.last_server_accepted_at_ms.unwrap_or(0).to_le_bytes());
    bytes[32..40].copy_from_slice(
        &record
            .last_stale_notification_at_ms
            .unwrap_or(0)
            .to_le_bytes(),
    );
    bytes[40..48].copy_from_slice(&record.saved_at_ms.to_le_bytes());
    let digest = Sha256::digest(&bytes[..64]);
    bytes[64..].copy_from_slice(&digest);
    bytes
}

fn decode(bytes: &[u8]) -> Result<HealthRecord, HealthError> {
    if bytes.len() != ENCODED_LENGTH || &bytes[..8] != MAGIC {
        return Err(HealthError::Invalid);
    }
    if read_u16(bytes, 8) != VERSION || read_u16(bytes, 10) & !1 != 0 {
        return Err(HealthError::Invalid);
    }
    if bytes[13..16].iter().any(|byte| *byte != 0) || bytes[48..64].iter().any(|byte| *byte != 0) {
        return Err(HealthError::Invalid);
    }
    let digest = Sha256::digest(&bytes[..64]);
    if digest.as_slice() != &bytes[64..] {
        return Err(HealthError::Invalid);
    }
    let locale = Locale::from_byte(bytes[12]).ok_or(HealthError::Invalid)?;
    let saved_at_ms = read_u64(bytes, 40);
    let last_server_accepted_at_ms = read_u64(bytes, 24);
    let last_stale_notification_at_ms = read_u64(bytes, 32);
    let maximum_time = unix_time_ms().saturating_add(FUTURE_TOLERANCE_MS);
    if saved_at_ms > maximum_time
        || last_server_accepted_at_ms > maximum_time
        || last_stale_notification_at_ms > maximum_time
    {
        return Err(HealthError::Invalid);
    }
    Ok(HealthRecord {
        desired_autostart: read_u16(bytes, 10) & 1 != 0,
        locale,
        generation: read_u64(bytes, 16),
        last_server_accepted_at_ms: nonzero(last_server_accepted_at_ms),
        last_stale_notification_at_ms: nonzero(last_stale_notification_at_ms),
        saved_at_ms,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

const fn nonzero(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

pub(crate) fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(target_os = "macos")]
fn open_child_directory(
    parent: &File,
    component: &std::ffi::OsStr,
    create: bool,
    private: bool,
) -> Result<Option<File>, HealthError> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };

    let name = std::ffi::CString::new(component.as_bytes()).map_err(|_| HealthError::UnsafePath)?;
    if name.as_bytes().is_empty() || name.as_bytes() == b"." || name.as_bytes() == b".." {
        return Err(HealthError::UnsafePath);
    }
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: The parent descriptor is retained and `name` is a validated
    // single path component. A successful descriptor is owned below.
    let mut fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    let mut created = false;
    if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        if !create {
            return Ok(None);
        }
        // SAFETY: Creation is relative to the retained parent descriptor.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result == 0 {
            created = true;
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(HealthError::Io);
        }
        // SAFETY: The same exact child is opened without following a symlink.
        fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => HealthError::UnsafePath,
            _ => HealthError::Io,
        });
    }
    // SAFETY: `openat` returned a new owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    // SAFETY: `directory` retains the newly created descriptor.
    if created && unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(HealthError::Io);
    }
    if created {
        parent.sync_all().map_err(|_| HealthError::Io)?;
    }
    let metadata = directory.metadata().map_err(|_| HealthError::Io)?;
    if private {
        validate_directory_metadata(&metadata)?;
    } else {
        validate_app_directory_metadata(&metadata)?;
    }
    Ok(Some(directory))
}

#[cfg(not(target_os = "macos"))]
fn ensure_directory(path: &Path) -> Result<(), HealthError> {
    fs::create_dir_all(path).map_err(|_| HealthError::Io)
}

#[cfg(not(target_os = "macos"))]
fn validate_directory(path: &Path) -> Result<(), HealthError> {
    if fs::symlink_metadata(path)
        .map_err(|_| HealthError::Io)?
        .is_dir()
    {
        Ok(())
    } else {
        Err(HealthError::UnsafePath)
    }
}

#[cfg(target_os = "macos")]
fn validate_app_directory_metadata(metadata: &fs::Metadata) -> Result<(), HealthError> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(HealthError::UnsafePath);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), HealthError> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(HealthError::UnsafePath);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_regular_metadata(metadata: &fs::Metadata) -> Result<(), HealthError> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != ENCODED_LENGTH as u64
    {
        return Err(HealthError::UnsafePath);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_existing_at(directory_fd: libc::c_int, exact: bool) -> Result<bool, HealthError> {
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::MetadataExt;
    let name = std::ffi::CString::new(FILE_NAME).map_err(|_| HealthError::Invalid)?;
    // SAFETY: The caller provides a live directory fd and the name is a fixed
    // single component. O_NOFOLLOW rejects symbolic-link substitution.
    let fd = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(HealthError::UnsafePath)
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| HealthError::Io)?;
    let safe = metadata.file_type().is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.nlink() == 1
        && (!exact
            || (metadata.mode() & 0o777 == 0o600 && metadata.len() == ENCODED_LENGTH as u64));
    if safe {
        Ok(true)
    } else {
        Err(HealthError::UnsafePath)
    }
}

#[cfg(not(target_os = "macos"))]
fn validate_regular_file(path: &Path) -> Result<(), HealthError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HealthError::Io)?;
    if metadata.is_file() && metadata.len() == ENCODED_LENGTH as u64 {
        Ok(())
    } else {
        Err(HealthError::UnsafePath)
    }
}

#[cfg(not(target_os = "macos"))]
fn validate_reset_target(path: &Path) -> Result<(), HealthError> {
    if fs::symlink_metadata(path)
        .map_err(|_| HealthError::Io)?
        .is_file()
    {
        Ok(())
    } else {
        Err(HealthError::UnsafePath)
    }
}

#[cfg(not(target_os = "macos"))]
fn sync_directory(path: &Path) -> Result<(), HealthError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| HealthError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aeterna-health-{name}-{}-{}",
            std::process::id(),
            unix_time_ms()
        ));
        fs::create_dir(&path).unwrap_or_else(|error| panic!("create test root: {error}"));
        path
    }

    #[test]
    fn format_round_trips_and_rejects_tampering() {
        let record = HealthRecord {
            desired_autostart: true,
            locale: Locale::ZhCn,
            generation: 9,
            last_server_accepted_at_ms: Some(42),
            last_stale_notification_at_ms: Some(43),
            saved_at_ms: unix_time_ms(),
        };
        let encoded = encode(record);
        assert_eq!(decode(&encoded), Ok(record));
        assert_eq!(encoded.len(), ENCODED_LENGTH);
        let mut tampered = encoded;
        tampered[20] ^= 1;
        assert_eq!(decode(&tampered), Err(HealthError::Invalid));
    }

    #[test]
    fn format_has_no_local_activity_timestamp() {
        let encoded = encode(HealthRecord::default());
        assert_eq!(&encoded[..8], MAGIC);
        assert!(encoded[48..64].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn format_rejects_unknown_version_reserved_bytes_and_future_time() {
        let encoded = encode(HealthRecord::default());
        for (offset, value) in [(8, 2_u8), (13, 1_u8)] {
            let mut invalid = encoded;
            invalid[offset] = value;
            let digest = Sha256::digest(&invalid[..64]);
            invalid[64..].copy_from_slice(&digest);
            assert_eq!(decode(&invalid), Err(HealthError::Invalid));
        }
        let future = HealthRecord {
            saved_at_ms: unix_time_ms() + FUTURE_TOLERANCE_MS + 60_000,
            ..HealthRecord::default()
        };
        assert_eq!(decode(&encode(future)), Err(HealthError::Invalid));
    }

    #[test]
    fn atomic_store_round_trips_and_uses_private_modes() {
        let root = test_root("roundtrip");
        let mut store = HealthStore::new(&root);
        let mut record = HealthRecord {
            locale: Locale::ZhCn,
            ..HealthRecord::default()
        };
        store
            .save(&mut record)
            .unwrap_or_else(|error| panic!("save health: {error:?}"));
        assert_eq!(store.load(), Ok(Some(record)));
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.join(DIRECTORY_NAME))
                    .unwrap_or_else(|error| panic!("health metadata: {error}"))
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(root.join(DIRECTORY_NAME).join(FILE_NAME))
                    .unwrap_or_else(|error| panic!("record metadata: {error}"))
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("remove test root: {error}"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn first_run_creates_a_private_app_directory_before_the_health_record() {
        use std::os::unix::fs::PermissionsExt;

        let support = test_root("first-run");
        let app_directory = support.join("app");
        let mut store = HealthStore::new(&app_directory);
        assert_eq!(store.load(), Ok(None));
        let mut record = HealthRecord::default();
        store
            .save(&mut record)
            .unwrap_or_else(|error| panic!("save first-run health: {error:?}"));
        assert_eq!(store.load(), Ok(Some(record)));
        for path in [app_directory.clone(), app_directory.join(DIRECTORY_NAME)] {
            let mode = fs::metadata(&path)
                .unwrap_or_else(|error| panic!("read first-run directory mode: {error}"))
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
        fs::remove_dir_all(&support)
            .unwrap_or_else(|error| panic!("remove first-run test root: {error}"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_directory_symlink_is_rejected_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let support = test_root("app-symlink");
        let target = support.join("target");
        fs::create_dir(&target).unwrap_or_else(|error| panic!("create symlink target: {error}"));
        symlink(&target, support.join("app"))
            .unwrap_or_else(|error| panic!("create app symlink: {error}"));
        let mut store = HealthStore::new(&support.join("app"));
        assert_eq!(store.load(), Err(HealthError::UnsafePath));
        assert_eq!(
            store.save(&mut HealthRecord::default()),
            Err(HealthError::UnsafePath)
        );
        assert!(!target.join(DIRECTORY_NAME).exists());
        fs::remove_dir_all(&support)
            .unwrap_or_else(|error| panic!("remove app-symlink test root: {error}"));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_record_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::{DirBuilderExt, symlink};
        let root = test_root("symlink");
        let health = root.join(DIRECTORY_NAME);
        let mut builder = fs::DirBuilder::new();
        builder
            .mode(0o700)
            .create(&health)
            .unwrap_or_else(|error| panic!("create health directory: {error}"));
        let target = root.join("target");
        fs::write(&target, b"unchanged").unwrap_or_else(|error| panic!("write target: {error}"));
        symlink(&target, health.join(FILE_NAME))
            .unwrap_or_else(|error| panic!("create symlink: {error}"));
        let mut store = HealthStore::new(&root);
        assert_eq!(store.load(), Err(HealthError::UnsafePath));
        assert_eq!(
            fs::read(&target).unwrap_or_else(|error| panic!("read target: {error}")),
            b"unchanged"
        );
        fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("remove test root: {error}"));
    }
}
