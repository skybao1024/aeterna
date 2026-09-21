use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier},
    thread,
    time::Instant,
};

use aeterna_lib::{
    crypto::{Argon2Profile, MasterPassword},
    vault::{MAX_PLAINTEXT_LENGTH, RecordId, VaultError, VaultRepository},
};
use rusqlite::Connection;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let mut random = [0_u8; 16];
        assert!(getrandom::fill(&mut random).is_ok());
        let root = match fs::canonicalize(std::env::temp_dir()) {
            Ok(value) => value,
            Err(_) => panic!("temporary directory should resolve"),
        };
        let encoded = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = root.join(format!("aeterna-i05-{label}-{encoded}"));
        assert!(fs::create_dir(&path).is_ok());
        Self(path)
    }

    fn vault(&self, name: &str) -> PathBuf {
        self.0.join(format!("{name}.sqlite"))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn password(byte: u8) -> MasterPassword {
    match MasterPassword::new(vec![byte; 16]) {
        Ok(value) => value,
        Err(_) => panic!("synthetic password should be accepted"),
    }
}

fn profile() -> Argon2Profile {
    Argon2Profile::new(65_536, 1, 1)
}

fn raw_frame(path: &Path, id: RecordId) -> Vec<u8> {
    let connection = match Connection::open(path) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    match connection.query_row(
        "SELECT frame FROM vault_records WHERE record_id = ?1",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test frame query failed: {error}"),
    }
}

fn checkpoint(path: &Path) {
    let connection = match Connection::open(path) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    assert!(
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .is_ok()
    );
}

fn scan_directory_for_marker(directory: &Path, marker: &[u8]) {
    let entries = match fs::read_dir(directory) {
        Ok(value) => value,
        Err(error) => panic!("test directory read failed: {error}"),
    };
    for entry in entries {
        let entry = match entry {
            Ok(value) => value,
            Err(error) => panic!("test directory entry failed: {error}"),
        };
        let metadata = match entry.metadata() {
            Ok(value) => value,
            Err(error) => panic!("test metadata read failed: {error}"),
        };
        if metadata.is_file() {
            let bytes = match fs::read(entry.path()) {
                Ok(value) => value,
                Err(error) => panic!("test artifact read failed: {error}"),
            };
            assert!(
                !bytes.windows(marker.len()).any(|window| window == marker),
                "plaintext marker appeared in a SQLite artifact"
            );
        }
    }
}

#[test]
fn initialize_restart_recovery_rewrap_records_and_artifact_privacy() {
    let directory = TestDirectory::new("lifecycle");
    let path = directory.vault("primary");
    let old_password = password(0x11);
    let new_password = password(0x22);
    let marker = b"i05-plaintext-marker-719e11a29f5348f7";

    let bootstrap = match VaultRepository::initialize(&path, &old_password, profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    assert!(matches!(
        bootstrap.repository().unlock(&password(0xff)),
        Err(VaultError::AuthenticationFailed)
    ));
    let unlocked = match bootstrap.repository().unlock(&old_password) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let empty = match unlocked.create_record(&[]) {
        Ok(value) => value,
        Err(error) => panic!("empty record create failed: {error}"),
    };
    assert!(matches!(unlocked.read_record(empty.id), Ok(value) if value.plaintext().is_empty()));

    let record = match unlocked.create_record(marker) {
        Ok(value) => value,
        Err(error) => panic!("record create failed: {error}"),
    };
    assert!(matches!(
        unlocked.read_record(record.id),
        Ok(value) if value.generation == 1 && value.plaintext() == marker
    ));
    let updated = match unlocked.update_record(record.id, 1, b"replacement") {
        Ok(value) => value,
        Err(error) => panic!("record update failed: {error}"),
    };
    assert_eq!(updated.generation, 2);
    assert!(matches!(
        unlocked.update_record(record.id, 1, b"stale"),
        Err(VaultError::Conflict)
    ));
    assert!(matches!(
        unlocked.create_record(&vec![0; MAX_PLAINTEXT_LENGTH + 1]),
        Err(VaultError::InvalidInput)
    ));
    let boundary = match unlocked.create_record(&vec![0x5a; MAX_PLAINTEXT_LENGTH]) {
        Ok(value) => value,
        Err(error) => panic!("boundary record create failed: {error}"),
    };
    assert!(matches!(
        unlocked.read_record(boundary.id),
        Ok(value) if value.plaintext().len() == MAX_PLAINTEXT_LENGTH
    ));

    let frame_before_rewrap = raw_frame(&path, record.id);
    assert!(
        bootstrap
            .repository()
            .change_master_password(&old_password, &new_password, profile())
            .is_ok()
    );
    assert!(matches!(
        bootstrap.repository().unlock(&old_password),
        Err(VaultError::AuthenticationFailed)
    ));
    assert!(bootstrap.repository().unlock(&new_password).is_ok());
    assert!(
        bootstrap
            .repository()
            .unlock_recovery(bootstrap.recovery_material())
            .is_ok()
    );
    assert_eq!(raw_frame(&path, record.id), frame_before_rewrap);

    drop(unlocked);
    let reopened_repository = match VaultRepository::open(&path) {
        Ok(value) => value,
        Err(error) => panic!("vault reopen failed: {error}"),
    };
    assert!(
        reopened_repository
            .unlock_recovery(bootstrap.recovery_material())
            .is_ok()
    );
    let reopened = match reopened_repository.unlock(&new_password) {
        Ok(value) => value,
        Err(error) => panic!("vault restart unlock failed: {error}"),
    };
    assert!(matches!(
        reopened.read_record(record.id),
        Ok(value) if value.plaintext() == b"replacement"
    ));
    assert!(reopened.delete_record(record.id, 2).is_ok());
    assert!(matches!(
        reopened.read_record(record.id),
        Err(VaultError::NotFound)
    ));

    let connection = match Connection::open(&path) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    let (total, unique): (i64, i64) = match connection.query_row(
        "SELECT COUNT(*), COUNT(DISTINCT nonce) FROM nonce_reservations",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ) {
        Ok(value) => value,
        Err(error) => panic!("nonce ledger query failed: {error}"),
    };
    assert_eq!(total, unique);
    assert!(total >= 8);
    drop(connection);
    scan_directory_for_marker(&directory.0, marker);
}

#[test]
fn tamper_and_unknown_versions_fail_closed() {
    let directory = TestDirectory::new("tamper");
    let base = directory.vault("base");
    let master_password = password(0x33);
    let bootstrap = match VaultRepository::initialize(&base, &master_password, profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let unlocked = match bootstrap.repository().unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let record = match unlocked.create_record(b"tamper target") {
        Ok(value) => value,
        Err(error) => panic!("record create failed: {error}"),
    };
    drop(unlocked);
    checkpoint(&base);

    let wrapper_tamper = directory.vault("wrapper-tamper");
    assert!(fs::copy(&base, &wrapper_tamper).is_ok());
    let connection = match Connection::open(&wrapper_tamper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    let mut wrapper: Vec<u8> = match connection.query_row(
        "SELECT ciphertext_and_tag FROM master_wrapper WHERE singleton = 1",
        [],
        |row| row.get(0),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test wrapper query failed: {error}"),
    };
    wrapper[0] ^= 1;
    assert_eq!(
        connection.execute(
            "UPDATE master_wrapper SET ciphertext_and_tag = ?1",
            [wrapper],
        ),
        Ok(1)
    );
    drop(connection);
    let repository = match VaultRepository::open(&wrapper_tamper) {
        Ok(value) => value,
        Err(error) => panic!("structural open failed unexpectedly: {error}"),
    };
    assert!(matches!(
        repository.unlock(&master_password),
        Err(VaultError::AuthenticationFailed)
    ));

    let recovery_tamper = directory.vault("recovery-tamper");
    assert!(fs::copy(&base, &recovery_tamper).is_ok());
    let connection = match Connection::open(&recovery_tamper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    let mut wrapper: Vec<u8> = match connection.query_row(
        "SELECT ciphertext_and_tag FROM recovery_wrapper WHERE singleton = 1",
        [],
        |row| row.get(0),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test recovery wrapper query failed: {error}"),
    };
    wrapper[47] ^= 1;
    assert_eq!(
        connection.execute(
            "UPDATE recovery_wrapper SET ciphertext_and_tag = ?1",
            [wrapper],
        ),
        Ok(1)
    );
    drop(connection);
    let repository = match VaultRepository::open(&recovery_tamper) {
        Ok(value) => value,
        Err(error) => panic!("structural open failed unexpectedly: {error}"),
    };
    assert!(matches!(
        repository.unlock_recovery(bootstrap.recovery_material()),
        Err(VaultError::AuthenticationFailed)
    ));

    let truncated_wrapper = directory.vault("truncated-wrapper");
    assert!(fs::copy(&base, &truncated_wrapper).is_ok());
    let connection = match Connection::open(&truncated_wrapper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    assert!(
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints=ON;
                 UPDATE master_wrapper SET ciphertext_and_tag = zeroblob(47);"
            )
            .is_ok()
    );
    drop(connection);
    assert!(matches!(
        VaultRepository::open(&truncated_wrapper),
        Err(VaultError::Corrupt)
    ));

    let header_tamper = directory.vault("header-tamper");
    assert!(fs::copy(&base, &header_tamper).is_ok());
    let connection = match Connection::open(&header_tamper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    assert_eq!(
        connection.execute(
            "UPDATE vault_header SET updated_at_ms = updated_at_ms + 1",
            [],
        ),
        Ok(1)
    );
    drop(connection);
    let repository = match VaultRepository::open(&header_tamper) {
        Ok(value) => value,
        Err(error) => panic!("structural open failed unexpectedly: {error}"),
    };
    assert!(matches!(
        repository.unlock(&master_password),
        Err(VaultError::AuthenticationFailed)
    ));

    let record_tamper = directory.vault("record-tamper");
    assert!(fs::copy(&base, &record_tamper).is_ok());
    let connection = match Connection::open(&record_tamper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    let mut frame = raw_frame(&record_tamper, record.id);
    frame[30] ^= 1;
    assert_eq!(
        connection.execute(
            "UPDATE vault_records SET frame = ?1 WHERE record_id = ?2",
            rusqlite::params![frame, record.id.as_bytes().as_slice()],
        ),
        Ok(1)
    );
    drop(connection);
    let repository = match VaultRepository::open(&record_tamper) {
        Ok(value) => value,
        Err(error) => panic!("structural open failed unexpectedly: {error}"),
    };
    let unlocked = match repository.unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("header unlock failed unexpectedly: {error}"),
    };
    assert!(matches!(
        unlocked.read_record(record.id),
        Err(VaultError::AuthenticationFailed)
    ));

    let frame_version_tamper = directory.vault("frame-version-tamper");
    assert!(fs::copy(&base, &frame_version_tamper).is_ok());
    let connection = match Connection::open(&frame_version_tamper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    let mut frame = raw_frame(&frame_version_tamper, record.id);
    frame[9] = 2;
    assert_eq!(
        connection.execute(
            "UPDATE vault_records SET frame = ?1 WHERE record_id = ?2",
            rusqlite::params![frame, record.id.as_bytes().as_slice()],
        ),
        Ok(1)
    );
    drop(connection);
    let repository = match VaultRepository::open(&frame_version_tamper) {
        Ok(value) => value,
        Err(error) => panic!("structural open failed unexpectedly: {error}"),
    };
    let unlocked = match repository.unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("header unlock failed unexpectedly: {error}"),
    };
    assert!(matches!(
        unlocked.read_record(record.id),
        Err(VaultError::UnsupportedVersion)
    ));

    let version_tamper = directory.vault("version-tamper");
    assert!(fs::copy(&base, &version_tamper).is_ok());
    let connection = match Connection::open(&version_tamper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    assert_eq!(
        connection.execute("UPDATE vault_header SET container_version = 2", []),
        Ok(1)
    );
    drop(connection);
    assert!(matches!(
        VaultRepository::open(&version_tamper),
        Err(VaultError::UnsupportedVersion)
    ));

    let migration_tamper = directory.vault("migration-tamper");
    assert!(fs::copy(&base, &migration_tamper).is_ok());
    let connection = match Connection::open(&migration_tamper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    assert_eq!(
        connection.execute("UPDATE schema_migrations SET sha256 = zeroblob(32)", [],),
        Ok(1)
    );
    drop(connection);
    assert!(matches!(
        VaultRepository::open(&migration_tamper),
        Err(VaultError::Corrupt)
    ));

    let extra_table = directory.vault("extra-table");
    assert!(fs::copy(&base, &extra_table).is_ok());
    let connection = match Connection::open(&extra_table) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    assert!(
        connection
            .execute_batch("CREATE TABLE unexpected (value INTEGER) STRICT;")
            .is_ok()
    );
    drop(connection);
    assert!(matches!(
        VaultRepository::open(&extra_table),
        Err(VaultError::Corrupt)
    ));

    let nonce_ledger_tamper = directory.vault("nonce-ledger-tamper");
    assert!(fs::copy(&base, &nonce_ledger_tamper).is_ok());
    let connection = match Connection::open(&nonce_ledger_tamper) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    assert_eq!(
        connection.execute(
            "DELETE FROM nonce_reservations WHERE nonce = (SELECT header_auth_nonce FROM vault_header WHERE singleton = 1)",
            [],
        ),
        Ok(1)
    );
    drop(connection);
    assert!(matches!(
        VaultRepository::open(&nonce_ledger_tamper),
        Err(VaultError::Corrupt)
    ));
}

#[test]
fn concurrent_writers_use_compare_and_set_and_copied_vaults_draw_new_nonces() {
    let directory = TestDirectory::new("concurrency");
    let primary = directory.vault("primary");
    let copied = directory.vault("copied");
    let master_password = password(0x44);
    let bootstrap = match VaultRepository::initialize(&primary, &master_password, profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let unlocked = match bootstrap.repository().unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let initial = match unlocked.create_record(b"initial") {
        Ok(value) => value,
        Err(error) => panic!("record create failed: {error}"),
    };
    drop(unlocked);
    checkpoint(&primary);
    assert!(fs::copy(&primary, &copied).is_ok());

    let first =
        match VaultRepository::open(&primary).and_then(|value| value.unlock(&master_password)) {
            Ok(value) => value,
            Err(error) => panic!("first writer unlock failed: {error}"),
        };
    let second =
        match VaultRepository::open(&primary).and_then(|value| value.unlock(&master_password)) {
            Ok(value) => value,
            Err(error) => panic!("second writer unlock failed: {error}"),
        };
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_thread = thread::spawn(move || {
        first_barrier.wait();
        first.update_record(initial.id, 1, b"first")
    });
    let second_barrier = Arc::clone(&barrier);
    let second_thread = thread::spawn(move || {
        second_barrier.wait();
        second.update_record(initial.id, 1, b"second")
    });
    barrier.wait();
    let first_result = match first_thread.join() {
        Ok(value) => value,
        Err(_) => panic!("first writer panicked"),
    };
    let second_result = match second_thread.join() {
        Ok(value) => value,
        Err(_) => panic!("second writer panicked"),
    };
    assert!(matches!(
        (&first_result, &second_result),
        (Ok(_), Err(VaultError::Conflict)) | (Err(VaultError::Conflict), Ok(_))
    ));

    let primary_repository = match VaultRepository::open(&primary) {
        Ok(value) => value,
        Err(error) => panic!("primary reopen failed: {error}"),
    };
    let copied_repository = match VaultRepository::open(&copied) {
        Ok(value) => value,
        Err(error) => panic!("copy reopen failed: {error}"),
    };
    let primary_unlocked = match primary_repository.unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("primary unlock failed: {error}"),
    };
    let copied_unlocked = match copied_repository.unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("copy unlock failed: {error}"),
    };
    let primary_new = match primary_unlocked.create_record(b"primary copy branch") {
        Ok(value) => value,
        Err(error) => panic!("primary create failed: {error}"),
    };
    let copied_new = match copied_unlocked.create_record(b"copied branch") {
        Ok(value) => value,
        Err(error) => panic!("copy create failed: {error}"),
    };
    let primary_frame = raw_frame(&primary, primary_new.id);
    let copied_frame = raw_frame(&copied, copied_new.id);
    assert_ne!(&primary_frame[14..26], &copied_frame[14..26]);

    let mut readers = Vec::new();
    for _ in 0..4 {
        let reader = match VaultRepository::open(&primary)
            .and_then(|value| value.unlock(&master_password))
        {
            Ok(value) => value,
            Err(error) => panic!("parallel reader unlock failed: {error}"),
        };
        readers.push(thread::spawn(move || reader.read_record(initial.id)));
    }
    for reader in readers {
        assert!(matches!(reader.join(), Ok(Ok(value)) if value.generation == 2));
    }
}

#[test]
fn writer_lock_timeout_returns_fixed_busy_error() {
    let directory = TestDirectory::new("busy");
    let path = directory.vault("primary");
    let master_password = password(0x66);
    let bootstrap = match VaultRepository::initialize(&path, &master_password, profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let unlocked = match bootstrap.repository().unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let locker = match Connection::open(&path) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite lock connection failed: {error}"),
    };
    assert!(locker.execute_batch("BEGIN IMMEDIATE;").is_ok());
    let started = Instant::now();
    assert!(matches!(
        unlocked.create_record(b"blocked writer"),
        Err(VaultError::Busy)
    ));
    assert!(started.elapsed().as_secs() >= 4);
    assert!(locker.execute_batch("ROLLBACK;").is_ok());
}

#[test]
fn publication_is_no_replace_and_oversized_files_fail_before_sqlite() {
    let directory = TestDirectory::new("file-boundary");
    let path = directory.vault("primary");
    let master_password = password(0x77);
    let bootstrap = match VaultRepository::initialize(&path, &master_password, profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    assert!(matches!(
        VaultRepository::initialize(&path, &password(0x88), profile()),
        Err(VaultError::AlreadyExists)
    ));
    assert!(bootstrap.repository().unlock(&master_password).is_ok());

    let sidecar = PathBuf::from(format!("{}-journal", path.display()));
    let file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&sidecar)
    {
        Ok(value) => value,
        Err(error) => panic!("test sidecar create failed: {error}"),
    };
    assert!(file.set_len(1_073_741_825).is_ok());
    drop(file);
    assert!(matches!(
        VaultRepository::open(&path),
        Err(VaultError::InvalidFormat)
    ));
    assert!(fs::remove_file(&sidecar).is_ok());
    assert!(VaultRepository::open(&path).is_ok());

    let oversized = directory.vault("oversized");
    let file = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&oversized)
    {
        Ok(value) => value,
        Err(error) => panic!("test oversized file create failed: {error}"),
    };
    assert!(file.set_len(1_073_741_825).is_ok());
    drop(file);
    assert!(matches!(
        VaultRepository::open(&oversized),
        Err(VaultError::InvalidFormat)
    ));
}

#[cfg(unix)]
#[test]
fn symlink_targets_are_rejected() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new("symlink");
    let path = directory.vault("primary");
    let link = directory.vault("link");
    let master_password = password(0x78);
    assert!(VaultRepository::initialize(&path, &master_password, profile()).is_ok());
    assert!(symlink(&path, &link).is_ok());
    assert!(matches!(
        VaultRepository::open(&link),
        Err(VaultError::InvalidFormat)
    ));
}

#[test]
fn abrupt_writer_child() {
    let Ok(path) = std::env::var("AETERNA_I05_CRASH_WRITE_PATH") else {
        return;
    };
    let connection = match Connection::open(path) {
        Ok(value) => value,
        Err(_) => std::process::exit(84),
    };
    if connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             BEGIN IMMEDIATE;
             UPDATE vault_records SET generation = generation + 1;",
        )
        .is_err()
    {
        std::process::exit(85);
    }
    std::process::exit(83);
}

#[test]
fn interrupted_uncommitted_write_recovers_the_old_record() {
    let directory = TestDirectory::new("interruption");
    let path = directory.vault("primary");
    let master_password = password(0x79);
    let marker = b"i05-interrupted-record-8f834305f7d141be";
    let bootstrap = match VaultRepository::initialize(&path, &master_password, profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let unlocked = match bootstrap.repository().unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let record = match unlocked.create_record(marker) {
        Ok(value) => value,
        Err(error) => panic!("record create failed: {error}"),
    };
    drop(unlocked);

    let executable = match std::env::current_exe() {
        Ok(value) => value,
        Err(_) => panic!("test executable should resolve"),
    };
    let status = Command::new(executable)
        .arg("--exact")
        .arg("abrupt_writer_child")
        .arg("--nocapture")
        .env("AETERNA_I05_CRASH_WRITE_PATH", &path)
        .status();
    assert!(matches!(status, Ok(value) if value.code() == Some(83)));

    let repository = match VaultRepository::open(&path) {
        Ok(value) => value,
        Err(error) => panic!("post-crash vault open failed: {error}"),
    };
    let unlocked = match repository.unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("post-crash vault unlock failed: {error}"),
    };
    assert!(matches!(
        unlocked.read_record(record.id),
        Ok(value) if value.generation == 1 && value.plaintext() == marker
    ));
    scan_directory_for_marker(&directory.0, marker);
}

#[test]
fn rollback_journal_and_backup_contain_no_plaintext_marker() {
    let directory = TestDirectory::new("artifacts");
    let path = directory.vault("primary");
    let backup_path = directory.vault("migration-backup");
    let master_password = password(0x55);
    let marker = b"i05-disk-artifact-marker-ef6924b14678433f";
    let bootstrap = match VaultRepository::initialize(&path, &master_password, profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let unlocked = match bootstrap.repository().unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let record = match unlocked.create_record(marker) {
        Ok(value) => value,
        Err(error) => panic!("record create failed: {error}"),
    };
    let live_reader = match Connection::open(&path) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite reader failed: {error}"),
    };
    assert!(
        live_reader
            .execute_batch("BEGIN; SELECT COUNT(*) FROM vault_records;")
            .is_ok()
    );
    assert!(unlocked.create_record(marker).is_ok());
    let wal_path = PathBuf::from(format!("{}-wal", path.display()));
    let shm_path = PathBuf::from(format!("{}-shm", path.display()));
    assert!(wal_path.is_file());
    assert!(shm_path.is_file());
    scan_directory_for_marker(&directory.0, marker);
    assert!(live_reader.execute_batch("ROLLBACK;").is_ok());
    drop(live_reader);
    drop(unlocked);
    checkpoint(&path);

    let source = match Connection::open(&path) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite source failed: {error}"),
    };
    assert!(source.backup(rusqlite::MAIN_DB, &backup_path, None).is_ok());
    let mut frame = raw_frame(&path, record.id);
    frame[30] ^= 1;
    assert!(
        source
            .execute_batch("PRAGMA journal_mode=DELETE; BEGIN IMMEDIATE;")
            .is_ok()
    );
    assert_eq!(
        source.execute(
            "UPDATE vault_records SET frame = ?1 WHERE record_id = ?2",
            rusqlite::params![frame, record.id.as_bytes().as_slice()],
        ),
        Ok(1)
    );
    let journal_path = PathBuf::from(format!("{}-journal", path.display()));
    assert!(journal_path.is_file());
    scan_directory_for_marker(&directory.0, marker);
    assert!(source.execute_batch("ROLLBACK;").is_ok());
    drop(source);

    let restored = match VaultRepository::open(&backup_path) {
        Ok(value) => value,
        Err(error) => panic!("backup open failed: {error}"),
    };
    let restored = match restored.unlock(&master_password) {
        Ok(value) => value,
        Err(error) => panic!("backup unlock failed: {error}"),
    };
    assert!(matches!(
        restored.read_record(record.id),
        Ok(value) if value.plaintext() == marker
    ));
}
