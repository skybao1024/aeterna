use rusqlite::{Connection, OptionalExtension, params};
#[cfg(test)]
use sha2::{Digest, Sha256};

use super::{VaultError, VaultResult, format};

pub(super) const MIGRATION_NAME: &str = "create_vault_v1";
const MIGRATION_CHECKSUM: [u8; 32] = [
    0x04, 0xa2, 0xfa, 0x0e, 0x15, 0xc6, 0x2e, 0xfc, 0xcb, 0x3a, 0xcf, 0xad, 0x87, 0x1f, 0x96, 0xac,
    0x84, 0x8d, 0x69, 0xac, 0x21, 0xc9, 0xf1, 0x81, 0x96, 0xfc, 0x87, 0x67, 0xdc, 0x43, 0x99, 0x91,
];

const TABLE_STATEMENTS: [&str; 6] = [
    "CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY CHECK (version > 0),
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
        sha256 BLOB NOT NULL CHECK (typeof(sha256) = 'blob' AND length(sha256) = 32),
        applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
    ) STRICT",
    "CREATE TABLE vault_header (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        magic BLOB NOT NULL CHECK (typeof(magic) = 'blob' AND length(magic) = 12),
        container_version INTEGER NOT NULL CHECK (container_version BETWEEN 1 AND 65535),
        schema_version INTEGER NOT NULL CHECK (schema_version BETWEEN 1 AND 2147483647),
        crypto_version INTEGER NOT NULL CHECK (crypto_version BETWEEN 1 AND 65535),
        vault_id BLOB NOT NULL UNIQUE CHECK (typeof(vault_id) = 'blob' AND length(vault_id) = 16),
        device_id BLOB NOT NULL CHECK (typeof(device_id) = 'blob' AND length(device_id) = 16),
        header_auth_nonce BLOB NOT NULL CHECK (typeof(header_auth_nonce) = 'blob' AND length(header_auth_nonce) = 12),
        header_auth_tag BLOB NOT NULL CHECK (typeof(header_auth_tag) = 'blob' AND length(header_auth_tag) = 16),
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms)
    ) STRICT",
    "CREATE TABLE master_wrapper (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        revision INTEGER NOT NULL CHECK (revision > 0),
        format_version INTEGER NOT NULL CHECK (format_version BETWEEN 1 AND 65535),
        aead_algorithm INTEGER NOT NULL CHECK (aead_algorithm BETWEEN 1 AND 255),
        purpose INTEGER NOT NULL CHECK (purpose BETWEEN 1 AND 255),
        kdf_algorithm INTEGER NOT NULL CHECK (kdf_algorithm BETWEEN 1 AND 255),
        kdf_version INTEGER NOT NULL CHECK (kdf_version BETWEEN 1 AND 255),
        memory_kib INTEGER NOT NULL CHECK (memory_kib BETWEEN 65536 AND 262144),
        time_cost INTEGER NOT NULL CHECK (time_cost BETWEEN 1 AND 6),
        parallelism INTEGER NOT NULL CHECK (parallelism BETWEEN 1 AND 4),
        output_length INTEGER NOT NULL CHECK (output_length = 32),
        salt BLOB NOT NULL CHECK (typeof(salt) = 'blob' AND length(salt) = 16),
        nonce BLOB NOT NULL CHECK (typeof(nonce) = 'blob' AND length(nonce) = 12),
        ciphertext_and_tag BLOB NOT NULL CHECK (typeof(ciphertext_and_tag) = 'blob' AND length(ciphertext_and_tag) = 48),
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
        FOREIGN KEY (singleton) REFERENCES vault_header(singleton) ON DELETE RESTRICT
    ) STRICT",
    "CREATE TABLE recovery_wrapper (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        recovery_id BLOB NOT NULL UNIQUE CHECK (typeof(recovery_id) = 'blob' AND length(recovery_id) = 16),
        device_id BLOB NOT NULL CHECK (typeof(device_id) = 'blob' AND length(device_id) = 16),
        format_version INTEGER NOT NULL CHECK (format_version BETWEEN 1 AND 65535),
        aead_algorithm INTEGER NOT NULL CHECK (aead_algorithm BETWEEN 1 AND 255),
        purpose INTEGER NOT NULL CHECK (purpose BETWEEN 1 AND 255),
        nonce BLOB NOT NULL CHECK (typeof(nonce) = 'blob' AND length(nonce) = 12),
        ciphertext_and_tag BLOB NOT NULL CHECK (typeof(ciphertext_and_tag) = 'blob' AND length(ciphertext_and_tag) = 48),
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        FOREIGN KEY (singleton) REFERENCES vault_header(singleton) ON DELETE RESTRICT
    ) STRICT",
    "CREATE TABLE nonce_reservations (
        nonce BLOB PRIMARY KEY CHECK (typeof(nonce) = 'blob' AND length(nonce) = 12),
        purpose INTEGER NOT NULL CHECK (purpose BETWEEN 1 AND 255),
        reserved_at_ms INTEGER NOT NULL CHECK (reserved_at_ms >= 0)
    ) STRICT, WITHOUT ROWID",
    "CREATE TABLE vault_records (
        record_id BLOB PRIMARY KEY CHECK (typeof(record_id) = 'blob' AND length(record_id) = 16),
        singleton INTEGER NOT NULL CHECK (singleton = 1),
        generation INTEGER NOT NULL CHECK (generation > 0),
        frame BLOB NOT NULL CHECK (typeof(frame) = 'blob' AND length(frame) BETWEEN 46 AND 1048622),
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
        FOREIGN KEY (singleton) REFERENCES vault_header(singleton) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID",
];

pub(super) fn migration_sql() -> String {
    let mut sql = TABLE_STATEMENTS.join(";\n");
    sql.push(';');
    sql
}

pub(super) fn migration_checksum() -> [u8; 32] {
    MIGRATION_CHECKSUM
}

pub(super) fn apply_initial_schema(connection: &Connection, applied_at_ms: u64) -> VaultResult<()> {
    connection.execute_batch(&migration_sql())?;
    connection.execute(
        "INSERT INTO schema_migrations (version, name, sha256, applied_at_ms) VALUES (?1, ?2, ?3, ?4)",
        params![
            i64::from(format::SCHEMA_VERSION),
            MIGRATION_NAME,
            migration_checksum().as_slice(),
            to_sql_integer(applied_at_ms)?
        ],
    )?;
    connection.pragma_update(None, "application_id", format::APPLICATION_ID)?;
    connection.pragma_update(None, "user_version", format::SCHEMA_VERSION)?;
    Ok(())
}

pub(super) fn verify_schema(connection: &Connection) -> VaultResult<()> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id != i64::from(format::APPLICATION_ID) {
        return Err(if application_id == 0 {
            VaultError::InvalidFormat
        } else {
            VaultError::UnsupportedVersion
        });
    }
    let user_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if user_version != i64::from(format::SCHEMA_VERSION) {
        return Err(VaultError::UnsupportedVersion);
    }
    let integrity: String = connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    if integrity != "ok" {
        return Err(VaultError::Corrupt);
    }
    let foreign_key_failure: Option<i64> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()?;
    if foreign_key_failure.is_some() {
        return Err(VaultError::Corrupt);
    }

    verify_migration_ledger(connection)?;
    verify_schema_objects(connection)?;
    verify_table_options(connection)?;
    verify_foreign_keys(connection)?;
    Ok(())
}

fn verify_migration_ledger(connection: &Connection) -> VaultResult<()> {
    let row_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })?;
    if row_count != 1 {
        return Err(VaultError::Corrupt);
    }
    let (name, checksum): (String, Vec<u8>) = connection.query_row(
        "SELECT name, sha256 FROM schema_migrations WHERE version = ?1",
        [i64::from(format::SCHEMA_VERSION)],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if name != MIGRATION_NAME || checksum.as_slice() != migration_checksum() {
        return Err(VaultError::Corrupt);
    }
    Ok(())
}

fn verify_schema_objects(connection: &Connection) -> VaultResult<()> {
    let mut statement = connection.prepare(
        "SELECT name, type, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let mut actual = Vec::new();
    for row in rows {
        actual.push(row?);
    }
    let mut expected: Vec<(String, String)> = TABLE_STATEMENTS
        .iter()
        .map(|sql| {
            let name = sql
                .split_ascii_whitespace()
                .nth(2)
                .unwrap_or_default()
                .to_owned();
            (name, normalize_sql(sql))
        })
        .collect();
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    if actual.len() != expected.len() {
        return Err(VaultError::Corrupt);
    }
    for ((actual_name, object_type, sql), (expected_name, expected_sql)) in
        actual.into_iter().zip(expected)
    {
        if actual_name != expected_name
            || object_type != "table"
            || sql.as_deref().map(normalize_sql).as_deref() != Some(expected_sql.as_str())
        {
            return Err(VaultError::Corrupt);
        }
    }
    Ok(())
}

fn verify_table_options(connection: &Connection) -> VaultResult<()> {
    let mut statement = connection.prepare(
        "SELECT name, wr, strict FROM pragma_table_list WHERE schema = 'main' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut count = 0;
    for row in rows {
        let (name, without_rowid, strict) = row?;
        let expected_without_rowid =
            matches!(name.as_str(), "nonce_reservations" | "vault_records");
        if strict != 1 || (without_rowid == 1) != expected_without_rowid {
            return Err(VaultError::Corrupt);
        }
        count += 1;
    }
    if count != TABLE_STATEMENTS.len() {
        return Err(VaultError::Corrupt);
    }
    Ok(())
}

fn verify_foreign_keys(connection: &Connection) -> VaultResult<()> {
    for table in ["master_wrapper", "recovery_wrapper", "vault_records"] {
        let sql = format!(
            "SELECT \"table\", \"from\", \"to\", on_delete FROM pragma_foreign_key_list('{table}')"
        );
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query([])?;
        let Some(row) = rows.next()? else {
            return Err(VaultError::Corrupt);
        };
        let values = (
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        );
        if values
            != (
                "vault_header".to_owned(),
                "singleton".to_owned(),
                "singleton".to_owned(),
                "RESTRICT".to_owned(),
            )
            || rows.next()?.is_some()
        {
            return Err(VaultError::Corrupt);
        }
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    sql.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn to_sql_integer(value: u64) -> VaultResult<i64> {
    i64::try_from(value).map_err(|_| VaultError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use rusqlite::TransactionBehavior;

    use super::*;

    #[test]
    fn migration_checksum_and_exact_schema_are_stable() {
        let mut connection = match Connection::open_in_memory() {
            Ok(value) => value,
            Err(_) => panic!("in-memory SQLite should open"),
        };
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(value) => value,
            Err(_) => panic!("transaction should begin"),
        };
        assert!(apply_initial_schema(&transaction, 7).is_ok());
        assert!(transaction.commit().is_ok());
        assert!(verify_schema(&connection).is_ok());

        let computed: [u8; 32] = Sha256::digest(migration_sql().as_bytes()).into();
        assert_eq!(computed, MIGRATION_CHECKSUM);
    }

    #[test]
    fn a_failed_schema_transaction_leaves_no_partial_tables() {
        let mut connection = match Connection::open_in_memory() {
            Ok(value) => value,
            Err(_) => panic!("in-memory SQLite should open"),
        };
        {
            let transaction =
                match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
                    Ok(value) => value,
                    Err(_) => panic!("transaction should begin"),
                };
            assert!(apply_initial_schema(&transaction, 9).is_ok());
        }
        let count: rusqlite::Result<i64> = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        );
        assert!(matches!(count, Ok(0)));
    }
}
