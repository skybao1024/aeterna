# ADR 0007: Local vault container and SQLite schema v1

- Status: Accepted
- Date: 2026-09-21
- Decision owner: I05 format approval
- Approval: Explicit user approval recorded in the I05 task on 2026-09-21
- Governing ADRs: [ADR 0002](./0002-cryptographic-envelope-and-key-storage.md), [ADR 0005](./0005-vault-format-and-migration-ownership.md)
- Proposal: [`../research/I05-vault-format-and-dependency-proposal.md`](../research/I05-vault-format-and-dependency-proposal.md)

## Context

ADR 0005 assigns the exact local vault format and migration policy to I05. The
I02 JSON fixture is test interchange only. I05 needs an exact production local
format before it can persist the accepted ADR 0002 wrappers or encrypted
records.

## Decision

Local vault v1 uses a Rust-owned SQLite database accessed through
exactly pinned `rusqlite 0.40.2` with default features disabled and only
`bundled`, `limits`, and `backup` enabled. This resolves
`libsqlite3-sys 0.38.2` and bundled SQLite 3.53.2. No SQL API, key, file path,
or raw cryptographic operation is exposed to React or the WebView.

The database has these independent versions:

| Field                   |                                 v1 value | Meaning                                                  |
| ----------------------- | ---------------------------------------: | -------------------------------------------------------- |
| SQLite `application_id` |                    `0x41455452` (`AETR`) | Early file-family discriminator                          |
| Local magic             |                 12 bytes `AETERNA-VLT\0` | Aeterna local-vault discriminator                        |
| Container version       |                      unsigned 16-bit `1` | Header and database-level contract                       |
| Schema version          |                      unsigned 32-bit `1` | SQLite tables and migrations; mirrored in `user_version` |
| Crypto version          |                      unsigned 16-bit `1` | Accepted ADR 0002 primitive/wrapper family               |
| Header AAD version      |                       unsigned 8-bit `1` | Canonical authenticated header encoding                  |
| Wrapper-set encoding    | fixed ASCII domain `AETERNA-WRAPPERS-V1` | Canonical wrapper metadata digest                        |
| Record frame version    |                      unsigned 16-bit `1` | Encrypted-record BLOB framing                            |
| Record AAD version      |                       unsigned 8-bit `1` | Canonical record metadata encoding                       |

All canonical multibyte integers outside SQLite are unsigned big-endian. IDs
are raw 16-byte values. SQLite integers are accepted only after non-negative
range validation and exact conversion to their canonical widths. Timestamps are
non-negative UTC Unix milliseconds encoded as unsigned 64-bit big-endian in
AAD. User text never becomes a SQLite text column.

### Schema v1

Migration 1 creates only `STRICT` tables. Identifier, nonce, tag, wrapper, hash,
and frame lengths have `typeof(...)='blob'` and exact or bounded `length(...)`
checks. Foreign keys are explicit. The authoritative migration SQL and its
SHA-256 checksum are compiled into Rust and recorded in `schema_migrations`.
For the compiled canonical SQL corresponding to the schema below, that checksum is
`04a2fa0e15c62efccb3acfad871f96ac848d69ac21c9f18196fc8767dc439991`.

```sql
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    sha256 BLOB NOT NULL CHECK (typeof(sha256) = 'blob' AND length(sha256) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
) STRICT;

CREATE TABLE vault_header (
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
) STRICT;

CREATE TABLE master_wrapper (
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
) STRICT;

CREATE TABLE recovery_wrapper (
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
) STRICT;

CREATE TABLE nonce_reservations (
    nonce BLOB PRIMARY KEY CHECK (typeof(nonce) = 'blob' AND length(nonce) = 12),
    purpose INTEGER NOT NULL CHECK (purpose BETWEEN 1 AND 255),
    reserved_at_ms INTEGER NOT NULL CHECK (reserved_at_ms >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE vault_records (
    record_id BLOB PRIMARY KEY CHECK (typeof(record_id) = 'blob' AND length(record_id) = 16),
    singleton INTEGER NOT NULL CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation > 0),
    frame BLOB NOT NULL CHECK (typeof(frame) = 'blob' AND length(frame) BETWEEN 46 AND 1048622),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    FOREIGN KEY (singleton) REFERENCES vault_header(singleton) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
```

The repository verifies that the actual `sqlite_schema`, table options,
indices, foreign keys, `application_id`, `user_version`, and migration checksum
exactly match v1. Extra user tables, triggers, views, virtual tables, attached
databases, or a migration gap/checksum change fail closed.

### Wrapper representation and authenticated header

Master and recovery wrappers are stored as the exact fixed columns above. They
retain ADR 0002 version, algorithm, purpose, KDF, salt, nonce, ciphertext, and
tag semantics. The production database does not store JSON, ERC, SRS, KEK, or
VDK bytes.

The header authentication value is AES-256-GCM under the VDK with empty
plaintext and a full 16-byte tag. Its nonce is reserved through the v1 nonce
ledger. This is a storage-authentication use, not a VDK wrapper, and does not
change the accepted wrapper AAD.

Header AAD v1 is exactly 115 bytes:

```text
0..14    ASCII "AETERNA-HEADER"
14       header AAD version = 1
15..27   local magic = "AETERNA-VLT\0"
27..29   container version, u16 big-endian
29..33   schema version, u32 big-endian
33..35   crypto version, u16 big-endian
35..51   vault ID
51..67   device ID
67..75   created_at_ms, u64 big-endian
75..83   updated_at_ms, u64 big-endian
83..115  SHA-256 wrapper-set digest
```

The wrapper-set digest is SHA-256 over exactly 259 bytes:

```text
0..19    ASCII "AETERNA-WRAPPERS-V1"
19..35   vault ID
35..43   master revision, u64 big-endian
43..45   master format version, u16 big-endian
45       master AEAD algorithm
46       master purpose
47       master KDF algorithm
48       master KDF version
49..53   master memory_kib, u32 big-endian
53..57   master time_cost, u32 big-endian
57..61   master parallelism, u32 big-endian
61..63   master output length, u16 big-endian
63..79   master salt
79..91   master nonce
91..139  master ciphertext and tag
139..147 master created_at_ms, u64 big-endian
147..155 master updated_at_ms, u64 big-endian
155..171 recovery ID
171..187 recovery device ID
187..189 recovery format version, u16 big-endian
189      recovery AEAD algorithm
190      recovery purpose
191..203 recovery nonce
203..251 recovery ciphertext and tag
251..259 recovery created_at_ms, u64 big-endian
```

Exactly one master and one recovery row exist in v1. Rewrap updates the master
row, wrapper-set digest input, header timestamp, nonce, and tag in one
transaction. This binds all decryption-relevant header and wrapper metadata
without changing ADR 0002 AAD or HKDF bytes.

### Generic record frame and AAD

I05 record plaintext is an opaque byte string from 0 through 1,048,576 bytes.
The sole v1 record purpose is `1 = generic-local-record`. AES-256-GCM appends
its 16-byte tag to the ciphertext.

Each `frame` is exactly:

```text
0..8     record magic = 41 45 54 52 52 45 43 00 ("AETRREC\0")
8..10    frame version = 1, u16 big-endian
10..12   crypto version = 1, u16 big-endian
12       AEAD algorithm = 1 (AES-256-GCM)
13       record purpose = 1
14..26   nonce, 12 bytes
26..30   ciphertext-and-tag length, u32 big-endian
30..N    ciphertext followed by the 16-byte GCM tag
```

The length is 46 through 1,048,622 bytes and must equal the framing length
exactly. No trailing bytes are accepted.

Record AAD v1 is exactly 83 bytes:

```text
0..14    ASCII "AETERNA-RECORD"
14       record AAD version = 1
15..17   container version, u16 big-endian
17..19   frame version, u16 big-endian
19..21   crypto version, u16 big-endian
21       AEAD algorithm = 1
22       record purpose = 1
23..39   vault ID
39..55   record ID
55..63   generation, u64 big-endian
63..71   created_at_ms, u64 big-endian
71..79   updated_at_ms, u64 big-endian
79..83   plaintext length, u32 big-endian
```

Schema version is deliberately absent from record AAD so a schema-only
migration does not require record re-encryption. The authenticated header binds
the active schema version. A crypto, frame, or AAD change requires a reviewed
new version and explicit migration.

### VDK and nonce lifecycle

Initialization generates one 32-byte VDK with the existing OS CSPRNG. Only the
master and recovery wrappers persist it. An unlocked VDK is held by a
non-`Clone`, redacted, zeroize-on-drop Rust type and is never logged, serialized,
sent to the WebView, or placed in SQLite. Rewrap unwraps once, creates a fresh
salt and nonce, and atomically replaces only the master wrapper and header
authentication. Record frames remain byte-for-byte unchanged.

Every 12-byte AES-GCM nonce used by the vault container, wrappers, header, or
records is generated by the OS CSPRNG. Before encryption, the repository
inserts it into `nonce_reservations` in a separate durable `BEGIN IMMEDIATE`
transaction. A uniqueness collision causes a fresh random draw; after 16
collisions the operation fails closed. Reservation commits before encryption,
so failure, rollback, retry, interruption, or restart consumes rather than
reuses a nonce. Migrations that create new AEAD output use the same allocator;
migrations that merely move an existing frame preserve its nonce and bytes.

Initialization is the only exception to the separate reservation transaction:
all initial nonces are checked for in-memory uniqueness and inserted with the
new schema and wrappers in one atomic staging-database transaction. A failed or
interrupted initialization never becomes the target vault and is never resumed
as a valid database.

A quiescent copied database contains its reservation ledger. Independent writes
to live and copied databases draw independent 96-bit random nonces and enforce
local uniqueness. There is no cross-file coordination, so uniqueness between
independently writable copies is probabilistic at the 96-bit CSPRNG boundary,
not mathematically guaranteed. Direct live SQLite copying is unsupported; I07
owns the official export/import and restored-key policy.

### SQLite configuration and transactions

Initialization opens the staging path with exactly `READ_WRITE`, `CREATE`,
`NO_MUTEX`, `PRIVATE_CACHE`, `NOFOLLOW`, and `EXRESCODE`. An existing vault uses
the same flags without `CREATE`; inspection uses `READ_ONLY` instead of
`READ_WRITE`. URI filenames and shared cache are not enabled. The app, not the
WebView, chooses the path.

Before application reads, every connection enables defensive mode, disables
trusted schema, double-quoted strings, triggers, and views, sets foreign keys
on, disables ATTACH create/write, and verifies those settings through safe
`rusqlite` configuration APIs. `SQLITE_LIMIT_ATTACHED=0` independently disables
ATTACH entirely. The controls require no project-owned unsafe FFI call or extra
direct dependency feature. It also uses:

```text
page_size = 4096                 (new database, before schema creation)
journal_mode = WAL
foreign_keys = ON
cell_size_check = ON
trusted_schema = OFF
synchronous = FULL
temp_store = MEMORY
secure_delete = ON
auto_vacuum = FULL               (new database, before schema creation)
mmap_size = 0
max_page_count = 262144          (1 GiB at 4096 bytes/page)
wal_autocheckpoint = 256 pages
journal_size_limit = 16777216
busy_timeout = 5000 ms
```

The repository checks the main file and known sidecar sizes before expensive
work, caps a v1 vault at 1,073,741,824 bytes, sets `max_page_count` consistently,
and uses the `limits` API to cap a SQLite value/row at 1,100,000 bytes, SQL text
at 32,768 bytes, columns at 32, expression/parser depth at 20/100, compound
selects at 4, VDBE operations at 100,000, function arguments at 8, attached
databases at 0, variables at 32, trigger depth at 0, and worker threads at 0.

All write operations use `BEGIN IMMEDIATE`. SQLite serializes writers; readers
use independent connections and WAL snapshots. Record update is a compare-and-
set on `(record_id, generation)` and increments generation, so a stale writer
gets `vault_conflict`. Master rewrap similarly compares its wrapper revision.
Busy timeout exhaustion returns `vault_busy`; it is not silently retried after
an unknown commit result.

Initialization writes a same-directory random staging database, verifies it,
checkpoints and closes WAL, synchronizes the file, and atomically publishes it
without replacement by creating a hard link at the absent target. It then
synchronizes the parent directory, removes the staging name, and synchronizes
the directory again. A crash after link creation can leave two names for the
same valid inode; I05 does not automatically delete an unknown stale staging
file. A normal mutation reserves its nonce first, encrypts outside SQLite,
then changes all related rows in one transaction. A crash before commit leaves
the old logical state; a crash after commit is recovered through the hot WAL.
Checkpoint-on-close remains enabled.

SQLite and its WAL, SHM, rollback/statement journals, temp databases, transient
indices, staging files, and migration backups receive only ciphertext and
non-sensitive structural metadata. Plaintext is encrypted before any SQL bind.
`temp_store=MEMORY` reduces disk temp artifacts but is not treated as a secrecy
control. Side files are part of the vault state while live and must not be
copied separately.

### Validation and errors

On open, the repository configures the connection, runs `quick_check`, verifies
the exact application ID, versions, schema, migration checksums, and foreign
keys, then loads only fixed/bounded fields. It rejects hostile sizes and wrapper
parameters before Argon2 or variable allocation. Unlock validates the selected
ADR 0002 wrapper, unwraps the VDK, and verifies header authentication before
returning an unlocked handle or plaintext.

Unknown and zero application/container/schema/crypto/wrapper/frame/AAD,
algorithm, purpose, and KDF versions fail closed and never fall back. v1 does
not downgrade. Structural failures use fixed `vault_invalid_format`,
`vault_unsupported_version`, or `vault_corrupt` classifications. Wrong
credentials and any AEAD nonce/AAD/ciphertext/tag authentication failure use
the existing fixed `crypto_authentication_failed` classification. Errors and
logs contain no secret, ciphertext, nonce, identifier, or complete sensitive
path.

### Migrations, backup, and rollback

Production migrations are an append-only ordered Rust list with exact version,
name, SQL bytes, and SHA-256. Applied rows are never edited. A missing version,
checksum mismatch, duplicate, unknown future version, or downgrade request
fails closed.

Migration 1 is the new-vault schema above. There is no legacy production vault
to import. The migration engine is tested with synthetic additive fixtures and
failure injection, but test-only versions never become recognized production
formats.

Before any future existing-vault migration, the repository checkpoints and
closes writers, creates a same-directory ciphertext-only backup through the
SQLite online backup API, verifies and synchronizes it, then performs one
`BEGIN EXCLUSIVE` migration transaction. The transaction records the migration
and updates `user_version`, header schema version, header timestamp, and header
authentication last. It runs exact schema, `foreign_key_check`, and
`quick_check` verification before commit. Failure rolls back; committed schema
is never automatically reverse-migrated. Recovery after a committed but bad
migration closes the app and restores the verified pre-migration backup. A
destructive migration requires its own explicit approval and recovery plan.

## Consequences

- The format is deterministic, bounded, independently versioned, and rejects
  ambiguous or future data.
- Password rotation is cheap and does not touch encrypted records.
- WAL concurrency and committed nonce reservations favor safety over reclaiming
  unused nonce rows or minimizing writes.
- Bundled SQLite provides one reviewed version on supported targets but adds a
  large native C/FFI and build-script supply-chain surface.
- Field encryption prevents plaintext in SQLite artifacts, but filenames,
  sizes, row counts, timestamps, IDs, write timing, and access patterns remain
  observable structural metadata.
- `secure_delete` and FileVault may reduce forensic exposure but do not prove
  physical erasure from SSDs, snapshots, swap, backups, or crash dumps.
- Cross-copy nonce uniqueness rests on 96-bit OS randomness because two
  independently writable files cannot coordinate. I07 must not treat raw live
  database copying as the official backup protocol.
- I05 does not use Keychain/Credential Manager. ADR 0004 and the deferred
  I08/I09 metadata work remain unchanged.

## Alternatives rejected

- `sqlx`: a larger asynchronous runtime and macro surface without a benefit for
  this synchronous, local, narrowly controlled repository.
- Tauri SQL plugins or WebView SQLite: violate the Rust ownership and least-
  privilege boundary.
- Direct `libsqlite3-sys`: unnecessarily owns unsafe statement/bind/result
  handling already covered by maintained `rusqlite`.
- System SQLite: produces OS-dependent versions and compile options and weakens
  reproducibility and the tested security floor.
- SQLCipher: adds a different native crypto/OpenSSL dependency and whole-file
  key boundary while not removing the need for versioned application records,
  wrappers, and recovery semantics.
- JSON/CBOR wrapper blobs: make bounds and query-time validation less explicit
  and risk treating the I02 JSON fixture as production serialization.
- Deterministic counter-only nonces: cloned databases can reuse a counter under
  the same VDK. Full random nonces plus a durable local reservation ledger are
  safer for restore-like copies.
- Reclaiming rolled-back nonce reservations: can reuse a nonce whose ciphertext
  remains in a WAL, journal, backup, crash artifact, or external observation.

## Approval effect

Changing this ADR from Proposed to Accepted authorizes only the I05 local
implementation and tests described here. It does not authorize any later
format, destructive migration, network/server work, recovery release, import or
export, attachment, production signing, Windows work, publication, or
deployment.
