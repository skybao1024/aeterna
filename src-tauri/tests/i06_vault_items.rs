use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use aeterna_lib::{
    crypto::{Argon2Profile, MasterPassword},
    vault::{
        ItemDraft, ItemKind, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_COUNT, VaultError,
        VaultRepository,
    },
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
        let path = root.join(format!("aeterna-i06-{label}-{encoded}"));
        assert!(fs::create_dir(&path).is_ok());
        Self(path)
    }

    fn vault(&self) -> PathBuf {
        self.0.join("vault.sqlite")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn password() -> MasterPassword {
    match MasterPassword::new(vec![0x61; 16]) {
        Ok(value) => value,
        Err(_) => panic!("synthetic password should be accepted"),
    }
}

fn profile() -> Argon2Profile {
    Argon2Profile::new(65_536, 1, 1)
}

fn note(title: &str, body: &str) -> ItemDraft {
    match ItemDraft::new(
        ItemKind::Note,
        title.to_owned(),
        "Synthetic category".to_owned(),
        String::new(),
        body.to_owned(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("synthetic note should be valid: {error}"),
    }
}

fn instruction(title: &str) -> ItemDraft {
    match ItemDraft::new(
        ItemKind::Instruction,
        title.to_owned(),
        "联系类别".to_owned(),
        "仅在无法自行解决时联系指定人员。".to_owned(),
        "先验证身份，再按照说明处理。".to_owned(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("synthetic instruction should be valid: {error}"),
    }
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
        if let Ok(text_marker) = core::str::from_utf8(marker) {
            assert!(
                !entry.file_name().to_string_lossy().contains(text_marker),
                "plaintext marker appeared in an app-created filename"
            );
        }
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
fn note_instruction_lifecycle_survives_restart_and_rejects_stale_writes() {
    let directory = TestDirectory::new("lifecycle");
    let path = directory.vault();
    let bootstrap = match VaultRepository::initialize(&path, &password(), profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let vault = match bootstrap.repository().unlock(&password()) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let note_item = match vault.create_item(note("First note", "Persistent body")) {
        Ok(value) => value,
        Err(error) => panic!("note creation failed: {error}"),
    };
    let instruction = match vault.create_item(instruction("联系说明")) {
        Ok(value) => value,
        Err(error) => panic!("instruction creation failed: {error}"),
    };
    let listed = match vault.list_items() {
        Ok(value) => value,
        Err(error) => panic!("item listing failed: {error}"),
    };
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|item| item.id == note_item.id));
    assert!(listed.iter().any(|item| item.id == instruction.id));
    drop(vault);
    drop(bootstrap);

    let reopened = match VaultRepository::open(&path).and_then(|value| value.unlock(&password())) {
        Ok(value) => value,
        Err(error) => panic!("restart unlock failed: {error}"),
    };
    let restored = match reopened.get_item(instruction.id) {
        Ok(value) => value,
        Err(error) => panic!("instruction read failed: {error}"),
    };
    assert_eq!(restored.kind, ItemKind::Instruction);
    assert_eq!(&*restored.title, "联系说明");
    assert_eq!(
        &*restored.contact_explanation,
        "仅在无法自行解决时联系指定人员。"
    );

    let updated = match reopened.update_item(
        note_item.id,
        note_item.revision,
        note("Edited note", "Edited body"),
    ) {
        Ok(value) => value,
        Err(error) => panic!("note update failed: {error}"),
    };
    assert_eq!(updated.revision, note_item.revision + 1);
    assert!(matches!(
        reopened.update_item(note_item.id, note_item.revision, note("Stale", "Stale")),
        Err(VaultError::Conflict)
    ));
    assert!(matches!(
        reopened.delete_item(note_item.id, note_item.revision),
        Err(VaultError::Conflict)
    ));
    assert!(reopened.delete_item(note_item.id, updated.revision).is_ok());
    assert!(matches!(
        reopened.get_item(note_item.id),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn attachment_edges_are_bounded_and_mutations_are_revisioned() {
    let directory = TestDirectory::new("attachments");
    let path = directory.vault();
    let bootstrap = match VaultRepository::initialize(&path, &password(), profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let vault = match bootstrap.repository().unlock(&password()) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let mut item = match vault.create_item(note("Attachment host", "Synthetic body")) {
        Ok(value) => value,
        Err(error) => panic!("item creation failed: {error}"),
    };

    for filename in ["重复.txt", "重复.txt"] {
        item = match vault.add_attachment(
            item.id,
            item.revision,
            filename.to_owned(),
            "text/plain".to_owned(),
            Vec::new(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("empty duplicate attachment failed: {error}"),
        };
    }
    item = match vault.add_attachment(
        item.id,
        item.revision,
        "photo.png".to_owned(),
        "image/png".to_owned(),
        b"not actually a png".to_vec(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("misleading metadata attachment failed: {error}"),
    };
    let misleading_id = item.attachments[2].id;
    let read = match vault.read_attachment(item.id, item.revision, misleading_id) {
        Ok(value) => value,
        Err(error) => panic!("attachment read failed: {error}"),
    };
    assert_eq!(&*read, b"not actually a png");

    item = match vault.replace_attachment(
        item.id,
        item.revision,
        misleading_id,
        "renamed.bin".to_owned(),
        "application/octet-stream".to_owned(),
        Vec::new(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("attachment replacement failed: {error}"),
    };
    item = match vault.add_attachment(
        item.id,
        item.revision,
        "boundary.bin".to_owned(),
        "application/octet-stream".to_owned(),
        vec![0xa5; MAX_ATTACHMENT_BYTES],
    ) {
        Ok(value) => value,
        Err(error) => panic!("exact attachment boundary failed: {error}"),
    };
    let stable_revision = item.revision;
    assert!(matches!(
        vault.add_attachment(
            item.id,
            item.revision,
            "one-too-many.bin".to_owned(),
            String::new(),
            vec![0],
        ),
        Err(VaultError::AttachmentTooLarge)
    ));
    assert!(matches!(
        vault.replace_attachment(
            item.id,
            item.revision,
            misleading_id,
            "oversized.bin".to_owned(),
            String::new(),
            vec![0; MAX_ATTACHMENT_BYTES + 1],
        ),
        Err(VaultError::AttachmentTooLarge)
    ));
    assert!(matches!(vault.get_item(item.id), Ok(value) if value.revision == stable_revision));

    item = match vault.remove_attachment(item.id, item.revision, misleading_id) {
        Ok(value) => value,
        Err(error) => panic!("attachment removal failed: {error}"),
    };
    while item.attachments.len() < MAX_ATTACHMENT_COUNT {
        item = match vault.add_attachment(
            item.id,
            item.revision,
            format!("empty-{}.bin", item.attachments.len()),
            String::new(),
            Vec::new(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("bounded empty attachment failed: {error}"),
        };
    }
    assert!(matches!(
        vault.add_attachment(
            item.id,
            item.revision,
            "ninth.bin".to_owned(),
            String::new(),
            Vec::new(),
        ),
        Err(VaultError::InvalidInput)
    ));
}

#[test]
fn concurrent_item_updates_have_one_winner() {
    let directory = TestDirectory::new("concurrency");
    let path = directory.vault();
    let bootstrap = match VaultRepository::initialize(&path, &password(), profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let initial_vault = match bootstrap.repository().unlock(&password()) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let item = match initial_vault.create_item(note("Initial", "Initial")) {
        Ok(value) => value,
        Err(error) => panic!("item creation failed: {error}"),
    };
    drop(initial_vault);

    let first = match VaultRepository::open(&path).and_then(|value| value.unlock(&password())) {
        Ok(value) => value,
        Err(error) => panic!("first writer unlock failed: {error}"),
    };
    let second = match VaultRepository::open(&path).and_then(|value| value.unlock(&password())) {
        Ok(value) => value,
        Err(error) => panic!("second writer unlock failed: {error}"),
    };
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_thread = thread::spawn(move || {
        first_barrier.wait();
        first.update_item(item.id, item.revision, note("First", "First"))
    });
    let second_barrier = Arc::clone(&barrier);
    let second_thread = thread::spawn(move || {
        second_barrier.wait();
        second.add_attachment(
            item.id,
            item.revision,
            "concurrent.bin".to_owned(),
            "application/octet-stream".to_owned(),
            b"concurrent attachment".to_vec(),
        )
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
}

#[test]
fn plaintext_item_and_attachment_markers_do_not_reach_sqlite_artifacts() {
    let directory = TestDirectory::new("privacy");
    let path = directory.vault();
    let title_marker = "i06-title-marker-89d383159f5e";
    let category_marker = "i06-category-marker-102fd3";
    let contact_marker = "i06-contact-marker-e7c2a4";
    let body_marker = "i06-body-marker-82654d69a7ac";
    let filename_marker = "附件-i06-filename-marker-31e0c574.bin";
    let media_type_marker = "i06marker/application";
    let content_marker = b"i06-attachment-marker-f13c535fdb7a";
    let bootstrap = match VaultRepository::initialize(&path, &password(), profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let vault = match bootstrap.repository().unlock(&password()) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let draft = match ItemDraft::new(
        ItemKind::Instruction,
        title_marker.to_owned(),
        category_marker.to_owned(),
        contact_marker.to_owned(),
        body_marker.to_owned(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("privacy-marker draft failed: {error}"),
    };
    let item = match vault.create_item(draft) {
        Ok(value) => value,
        Err(error) => panic!("item creation failed: {error}"),
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
    assert!(
        vault
            .add_attachment(
                item.id,
                item.revision,
                filename_marker.to_owned(),
                media_type_marker.to_owned(),
                content_marker.to_vec(),
            )
            .is_ok()
    );
    for marker in [
        title_marker.as_bytes(),
        category_marker.as_bytes(),
        contact_marker.as_bytes(),
        body_marker.as_bytes(),
        filename_marker.as_bytes(),
        media_type_marker.as_bytes(),
        content_marker.as_slice(),
    ] {
        scan_directory_for_marker(&directory.0, marker);
    }
    assert!(live_reader.execute_batch("ROLLBACK;").is_ok());
    drop(live_reader);
    drop(vault);
    let connection = match Connection::open(&path) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite connection failed: {error}"),
    };
    assert!(
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .is_ok()
    );
    drop(connection);
    for marker in [
        title_marker.as_bytes(),
        category_marker.as_bytes(),
        contact_marker.as_bytes(),
        body_marker.as_bytes(),
        filename_marker.as_bytes(),
        media_type_marker.as_bytes(),
        content_marker.as_slice(),
    ] {
        scan_directory_for_marker(&directory.0, marker);
    }

    let connection = match Connection::open(&path) {
        Ok(value) => value,
        Err(error) => panic!("test SQLite journal connection failed: {error}"),
    };
    let frame: Vec<u8> = match connection.query_row(
        "SELECT frame FROM vault_records WHERE record_id = ?1",
        [item.id.as_bytes().as_slice()],
        |row| row.get(0),
    ) {
        Ok(value) => value,
        Err(error) => panic!("test frame query failed: {error}"),
    };
    assert!(
        connection
            .execute_batch("PRAGMA journal_mode=DELETE; BEGIN IMMEDIATE;")
            .is_ok()
    );
    assert_eq!(
        connection.execute(
            "UPDATE vault_records SET frame = ?1 WHERE record_id = ?2",
            rusqlite::params![frame, item.id.as_bytes().as_slice()],
        ),
        Ok(1)
    );
    for marker in [
        title_marker.as_bytes(),
        category_marker.as_bytes(),
        contact_marker.as_bytes(),
        body_marker.as_bytes(),
        filename_marker.as_bytes(),
        media_type_marker.as_bytes(),
        content_marker.as_slice(),
    ] {
        scan_directory_for_marker(&directory.0, marker);
    }
    assert!(connection.execute_batch("ROLLBACK;").is_ok());
}

#[test]
fn non_item_and_unknown_item_payloads_fail_closed() {
    let directory = TestDirectory::new("payload-version");
    let path = directory.vault();
    let bootstrap = match VaultRepository::initialize(&path, &password(), profile()) {
        Ok(value) => value,
        Err(error) => panic!("vault initialization failed: {error}"),
    };
    let vault = match bootstrap.repository().unlock(&password()) {
        Ok(value) => value,
        Err(error) => panic!("vault unlock failed: {error}"),
    };
    let truncated = match vault.create_record(b"not-an-item") {
        Ok(value) => value,
        Err(error) => panic!("raw test record creation failed: {error}"),
    };
    assert!(matches!(
        vault.get_item(truncated.id),
        Err(VaultError::ItemInvalidFormat)
    ));

    let mut unknown = vec![0_u8; 30];
    unknown[0..8].copy_from_slice(b"AETRITM\0");
    unknown[8..10].copy_from_slice(&2_u16.to_be_bytes());
    unknown[10] = 1;
    let unsupported = match vault.create_record(&unknown) {
        Ok(value) => value,
        Err(error) => panic!("unknown-version record creation failed: {error}"),
    };
    assert!(matches!(
        vault.get_item(unsupported.id),
        Err(VaultError::ItemUnsupportedVersion)
    ));
    assert!(matches!(
        vault.list_items(),
        Err(VaultError::ItemInvalidFormat | VaultError::ItemUnsupportedVersion)
    ));
}
