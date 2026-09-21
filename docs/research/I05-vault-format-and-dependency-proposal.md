# I05 vault format and dependency proposal

- Prepared: 2026-09-21
- State: **Approved for I05 implementation on 2026-09-21**
- Baseline: `5a4d92640ac9db4a803e212ce4381eb7cd845752`
- Proposed decision: [ADR 0007](../adr/0007-local-vault-format-v1.md)
- Iteration brief: [`../iterations/I05-versioned-vault-storage-core.md`](../iterations/I05-versioned-vault-storage-core.md)

## Approved decision

The user explicitly approved the complete proposal and ADR 0007 in the I05 task
on 2026-09-21 before any persistence code, manifest, lockfile, database, or
migration change.

The requested dependency approval is exactly:

```toml
rusqlite = { version = "=0.40.2", default-features = false, features = ["backup", "bundled", "limits"] }
```

For native desktop targets this selects `libsqlite3-sys 0.38.2` and its bundled
SQLite 3.53.2 amalgamation. No other new direct production or development
dependency is proposed. Cargo.lock will freeze all transitives. After approval,
the lockfile and `cargo tree -e features` diff must be inspected; an unexpected
native/runtime dependency or enabled feature stops implementation for renewed
approval.

Approval also covers the exact v1 container, schema, header authentication,
wrapper columns, record frame/AAD, limits, nonce allocator, transactions,
SQLite settings, migration/backup policy, validation, and residual risks below.

## Evidence and dependency review

Research used upstream material current on 2026-09-21:

- [`rusqlite` 0.40.2 manifest](https://raw.githubusercontent.com/rusqlite/rusqlite/v0.40.2/Cargo.toml)
  identifies the MIT license, active-maintenance badge, exact
  `libsqlite3-sys 0.38.2` requirement, and the feature graph. Its 0.40.2 release
  lowers MSRV to 1.88, below this repository's pinned Rust 1.98.1.
- [`rusqlite` feature documentation](https://docs.rs/crate/rusqlite/0.40.2/features)
  shows that `backup` and `limits` add no optional third-party package and that
  `bundled` selects the bundled SQLite bindings. Disabling defaults avoids the
  statement cache and wasm FFI dependency.
- [`libsqlite3-sys` bundled binding](https://docs.rs/crate/libsqlite3-sys/0.38.2/source/sqlite3/bindgen_bundled_version_ext.rs)
  records SQLite `3.53.2`, source ID
  `d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`.
- [`rusqlite` README](https://github.com/rusqlite/rusqlite) explains that the
  bundled feature compiles the embedded SQLite source instead of depending on
  an installed system version. The wrapper and sys crate are MIT; bundled
  SQLite is public domain.
- [SQLite's vulnerability record](https://www.sqlite.org/cves.html) states that
  SQLite 3.53.2 fixes the 2026 FTS5 issue affecting arbitrary SQL with defensive
  mode disabled. Aeterna additionally enables defensive mode and exposes no
  SQL input.
- [SQLite's hostile-input guidance](https://www.sqlite.org/security.html)
  recommends defensive mode, reduced runtime limits, untrusted-schema
  protection, integrity checking, cell-size checking, and disabling mmap for
  potentially altered database files. The proposal adopts those applicable
  controls.
- [SQLite WAL](https://www.sqlite.org/wal.html),
  [isolation](https://www.sqlite.org/isolation.html), and
  [temporary-file](https://www.sqlite.org/tempfiles.html) documentation define
  the concurrency, recovery, WAL/SHM, journal, and temp-file behavior used by
  the transaction and privacy test plan.
- [SQLite pragma documentation](https://www.sqlite.org/pragma.html) establishes
  the application/user version fields, foreign-key behavior, `secure_delete`,
  `temp_store`, `trusted_schema`, and `synchronous=FULL` durability behavior.

### Maintenance, license, unsafe/native, and network behavior

`rusqlite` is an actively maintained Rust wrapper with an August 2026 patch
release. The direct crate and `libsqlite3-sys` are MIT. The embedded SQLite
amalgamation is public domain. The enabled feature set does not select
SQLCipher, OpenSSL, chrono/time, JSON, UUID, virtual-table helpers, extension
loading, tracing, hooks, serialization, URLs, or a pool/runtime.

The material risk is native code: `libsqlite3-sys` exposes unsafe C FFI and its
build script compiles the embedded SQLite amalgamation with the Rust `cc` build
dependency. Aeterna will not add project `unsafe`; it relies on the wrapper's
FFI boundary and keeps all application SQL static and parameterized. Bundling
increases binary/build surface and requires a C toolchain, but gives one exact
SQLite security and behavior baseline across supported hosts. Cargo registry
fetch is build-time package acquisition only. Neither `rusqlite`, SQLite, nor
the proposed repository performs runtime networking, DNS, telemetry, or
updates. The upstream bundled C build includes SQLite's load-extension
capability, but Aeterna disables `rusqlite`'s `load_extension` feature and
exposes no API or SQL path that can invoke it; this remains part of the native
surface reviewed again at G1.

The expected newly resolved packages are `rusqlite 0.40.2`,
`libsqlite3-sys 0.38.2`, `fallible-iterator 0.3.0`,
`fallible-streaming-iterator 0.1.9`, and the `vcpkg 0.2.15` build helper.
`bitflags 2.13.2`, `smallvec 1.16.1`, `cc 1.4.7`, and `pkg-config 0.3.34`
already exist in the baseline lockfile and satisfy the declared ranges. The
bundled branch compiles embedded SQLite and does not use system discovery, but
the sys crate's default minimum-version feature still resolves the build-only
`pkg-config`/`vcpkg` helpers. OpenSSL, bindgen, SQLCipher, and wasm packages are
not selected. The post-approval lockfile diff is authoritative and must match
this set or trigger renewed review.

Supply-chain controls are the exact direct pin, Cargo.lock checksums, disabled
defaults, the three-feature allowlist, resolved-tree review, repository license
record, and the existing locked build/check commands. G1 must repeat
vulnerability, license, native-code, fuzzing, and independent security review
before release.

### Alternatives

| Alternative                        | Decision                                                                                                                                |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `sqlx` SQLite                      | Rejected for I05: it adds async executor/pool/macro surface that the synchronous local repository does not need.                        |
| Tauri SQL plugin / browser SQLite  | Rejected: it puts database capability too close to the WebView and conflicts with the controlled Rust boundary.                         |
| Direct `libsqlite3-sys`            | Rejected: it would require Aeterna-owned unsafe statement, bind, result, and lifetime handling.                                         |
| System SQLite                      | Rejected: runtime version and compile options vary by OS, weakening reproducibility and the security floor.                             |
| SQLCipher                          | Rejected: it adds a different crypto/native dependency and key boundary while application-level versioned encryption is still required. |
| Flat file / custom binary database | Rejected: Aeterna would own more crash, concurrency, indexing, and migration machinery.                                                 |

## Exact format decision

ADR 0007 is normative. This section gives the review rationale and operational
behavior that implementation and tests must preserve.

### SQLite identity, versions, and canonical values

- SQLite `application_id`: `0x41455452`, the bytes `AETR`.
- Local magic: exact 12 bytes `AETERNA-VLT\0`.
- Container version: unsigned 16-bit `1`.
- Schema version and `PRAGMA user_version`: unsigned 32-bit `1`, limited to the
  signed-positive SQLite range.
- Crypto version: unsigned 16-bit `1`, independent of container and schema.
- Header AAD version, record frame version, and record AAD version: `1` in
  their widths.
- IDs: exact 16-byte CSPRNG values stored as BLOBs, never text UUIDs.
- Canonical multibyte bytes: unsigned big-endian.
- Timestamps: non-negative UTC Unix milliseconds supplied through an injected
  Rust clock and encoded as u64 big-endian when authenticated.
- Generic record plaintext: 0 through 1,048,576 bytes; ciphertext/tag is 16
  bytes longer; record frame is 46 through 1,048,622 bytes.
- Vault main file and each known sidecar: at most 1,073,741,824 bytes in v1.

Unknown, zero, out-of-range, inconsistent, trailing, truncated, duplicated, or
noncanonical values are errors. SQLite integer affinity is never trusted as
canonical encoding; `typeof`, range, length, and Rust conversion are checked.

### Vault header representation

The one-row `vault_header` is the production header. It holds only magic,
independent versions, vault/device IDs, one header-auth nonce/tag, and
timestamps. `application_id` provides a pre-schema discriminator and
`user_version` mirrors schema version. All three representations must agree.

The header tag is AES-256-GCM under the VDK over empty plaintext and the exact
115-byte header AAD in ADR 0007. That AAD includes a SHA-256 digest of the fixed
canonical master and recovery wrapper rows. This authenticates the complete
decryption-relevant header/wrapper metadata after either wrapper yields a VDK,
without modifying the accepted 45-byte ADR 0002 wrapper AAD or 50-byte recovery
HKDF context.

The header is not a claim that every structural value is secret. An offline
observer can see SQLite structure, versions, counts, IDs, timestamps, lengths,
and write patterns. Authentication detects mutation before an unlocked handle
or plaintext is returned.

The wrapper digest input is exactly 259 bytes: the 19-byte
`AETERNA-WRAPPERS-V1` domain, 16-byte vault ID, then fixed-width master fields
(revision, format, AEAD, purpose, KDF identifiers/profile, salt, nonce,
ciphertext/tag, and timestamps), followed by fixed-width recovery fields
(recovery/device IDs, format, AEAD, purpose, nonce, ciphertext/tag, and
timestamp). ADR 0007 gives every offset and integer width. Exactly one master
and one recovery row exist in v1, so no variable count, sorting, or optional
encoding is involved.

### Master and recovery wrapper persistence

The master row stores the exact ADR 0002 fields: format, AEAD, purpose, KDF,
KDF version, memory/time/parallelism/output, 16-byte salt, 12-byte nonce, and
48-byte wrapped VDK/tag, plus revision and timestamps. All KDF parameters are
validated against ADR 0002 before Argon2 allocation. The I02 Apple Silicon
262,144 KiB/time-2/parallelism-1 profile may be passed and persisted as a named
provisional development profile; the API does not treat it as a universal
release default. Tests may use the accepted 65,536 KiB/time-1/parallelism-1
lower bound.

The recovery row stores one local device recovery ID, device ID, exact wrapper
version/AEAD/purpose, nonce, ciphertext/tag, and timestamp. It stores no ERC or
SRS. I05 may generate these secrets inside the Rust initializer and return them
only to a Rust-owned bootstrap result used by tests/future orchestration. It
adds no Tauri command, server call, release condition, or claim flow.

Wrong credentials and cryptographic tamper return only
`crypto_authentication_failed`. Structurally impossible or unknown fields fail
before derivation with a fixed format/version code. Neither path exposes VDK or
plaintext.

### Record framing and authenticated metadata

The `vault_records.frame` BLOB uses the exact 30-byte prefix and bounded
ciphertext/tag body in ADR 0007. The parser validates magic, versions,
algorithm, purpose, declared length, minimum tag, maximum size, and exact end
before decryption. The exact 83-byte AAD binds container/frame/crypto versions,
algorithm/purpose, vault and record IDs, generation, timestamps, and plaintext
length. Tampering with any bound field makes GCM authentication fail.

Titles, categories, contact explanations, and content are future record
plaintext, never columns or indices. I05 implements only opaque generic bytes;
it does not create the I06 business model.

### VDK lifecycle

1. Initialization obtains 32 random VDK bytes from the existing `getrandom`
   path and immediately owns them in the redacted zeroize-on-drop `Vdk` type.
2. The same VDK is independently wrapped with the accepted master and recovery
   semantics. Only wrappers persist.
3. Unlock loads and structurally validates bounded wrapper/header fields,
   derives the master KEK, unwraps the VDK, verifies header authentication, and
   only then returns a non-`Clone` unlocked Rust handle.
4. Record encryption/decryption is available only through that handle. The VDK
   never enters Serde, IPC, SQLite, logs, errors, or `Debug`.
5. Password change unwraps once, creates a fresh master salt and reserved nonce,
   compare-and-set replaces the master row, and retags the header in one
   transaction. It does not read or write record frames.
6. Lock/drop zeroizes owned VDK bytes on a best-effort basis under the existing
   ADR 0002 limitations.

### Nonce allocation and uniqueness

Every vault AES-GCM operation uses a fresh 12-byte OS-CSPRNG nonce. The
repository's allocator durably inserts each nonce into a unique
`nonce_reservations` ledger before encryption. It retries a database collision
with fresh randomness no more than 16 times. The ledger is append-only in v1;
failed operations and rolled-back record transactions leave harmless consumed
nonces.

This ordering addresses:

- retry and rollback: a nonce is committed before ciphertext exists and is not
  reclaimed;
- interruption: a crash leaves either an unused reservation or committed
  ciphertext, never an allocator rollback;
- restart: the uniqueness constraint retains all reservations;
- concurrency: `BEGIN IMMEDIATE` serializes reservation inserts and the unique
  key resolves a collision;
- migration: new AEAD output uses the same allocator, while moved frames retain
  existing bytes and reservations; and
- restore-like copies: quiescent copies inherit prior reservations, then each
  file draws independent 96-bit random values.

Two independently writable copies cannot coordinate after divergence.
Cross-copy uniqueness therefore has the accepted OS-CSPRNG 96-bit probability,
not a global deterministic guarantee. Counter-only schemes are rejected because
a copied `(prefix,counter)` state deterministically collides. I07 must define
official restore semantics and can choose a VDK rotation or import namespace if
its threat analysis requires a stronger post-copy guarantee.

Tests inject repeated candidate nonces to prove constraint/retry/fail-closed
behavior and use real CSPRNG samples, rollback, abrupt exit, restart,
concurrency, a synthetic migration hook, and two checkpointed database copies.

### Transactions, WAL, journals, temp files, and crash recovery

Connection configuration is exact in ADR 0007. The important durability and
privacy choices are WAL plus `synchronous=FULL`, foreign keys, defensive and
untrusted-schema settings, disabled mmap/attach/triggers/views, bounded SQLite
limits, `secure_delete=ON`, and `temp_store=MEMORY`.

SQLite documents that WAL commits append a commit record, supports concurrent
readers with one serialized writer, and recovers a hot WAL after an unclean
close. It also documents that WAL and rollback journals are transaction-control
files and can persist after interruption. They are treated as part of the vault,
not disposable caches. A live database is never copied without its WAL/SHM;
tests create restore-like copies only after checkpoint and clean close.

Transaction boundaries are:

- initialization: one transaction in a same-directory staging database,
  followed by validation, WAL checkpoint/close, file sync, no-replace atomic
  publication through `hard_link`, parent-directory sync, staging-name removal,
  and a second directory sync; a crash can leave a ciphertext-only staging link
  that I05 does not automatically delete as an unknown file;
- nonce allocation: its own committed `BEGIN IMMEDIATE` transaction;
- record create/update/delete: one `BEGIN IMMEDIATE` transaction after nonce
  reservation/encryption, with compare-and-set generation for updates;
- password rewrap: reserved nonces followed by one compare-and-set transaction
  for the master wrapper and header authentication;
- migration: verified backup first, then one `BEGIN EXCLUSIVE` transaction with
  migration ledger/version/header authentication updated last.

Failure before a mutation commit exposes the old logical state. Failure after a
successful commit recovers the new state. The repository never automatically
replays a high-level operation after an ambiguous I/O/commit error; the caller
must reopen and inspect the fixed outcome.

No plaintext is bound to SQLite. Consequently the main file, WAL, SHM,
rollback/statement journals, temp database/transient index, staging file, and
migration backup can contain only ciphertext and non-sensitive structure.
`temp_store=MEMORY` reduces but cannot define all SQLite temporary behavior, so
privacy does not rely on it.

### Concurrent access

`rusqlite::Connection` is not shared concurrently. Each worker/test thread uses
its own fully configured connection. WAL supplies reader snapshots; SQLite
allows one writer at a time. `busy_timeout=5000 ms` provides bounded contention.
Record and master-wrapper revisions make logical updates compare-and-set, so a
stale writer receives `vault_conflict` instead of overwriting a newer value.
No unconditional read-then-write transition is permitted.

The database is local-filesystem only. Network filesystems and shared cache are
unsupported. A second process may open the file through SQLite locking, but I05
does not introduce a multi-process coordinator; busy/conflict outcomes fail
safely.

### Hostile-size rejection

Before opening, the repository rejects non-regular/symlink targets and main or
known side files above the 1 GiB v1 cap. On every connection it configures
SQLite runtime limits before reading application rows, enables cell-size
checking and no mmap, and runs `quick_check`. It queries and validates fixed
metadata before any KDF. The record query checks SQLite `length(frame)` against
1,048,622 before materializing the BLOB. Frame declared lengths are checked
with non-overflowing arithmetic before allocating plaintext.

Master password input retains the existing 1–1,024-byte bound. KDF profile,
salt, nonce, ciphertext/tag, IDs, hashes, and versions have exact constraints
and Rust-side checks. Unknown or oversized KDF values fail before Argon2's
memory vector is allocated.

### Corruption, downgrade, and unknown versions

- SQLite `quick_check`, exact schema/migration checksum checks, foreign keys,
  strict types, and size constraints catch storage corruption before unlock.
- Wrong application ID or magic is `vault_invalid_format`.
- Unknown higher or zero container/schema/crypto/wrapper/frame/AAD/algorithm/
  purpose/KDF is `vault_unsupported_version` or `crypto_invalid_format` before
  decryption/KDF as appropriate.
- A recognized version with inconsistent schema, checksum, duplicate singleton,
  or invalid bounds is `vault_corrupt`.
- Wrong password and all AEAD authentication failures remain exactly
  `crypto_authentication_failed`; no oracle distinguishes bad password from
  authenticated-field/tag/ciphertext tamper.
- No plaintext, partial plaintext, fallback parser, legacy default, downgrade,
  repair-in-place, or "open anyway" mode exists.

### Migration, backup, and rollback policy

Migration source is an append-only Rust list. Each entry has an exact positive
version, stable ASCII name, SQL bytes, and SHA-256. The database ledger must be
a contiguous prefix with matching checksums. An applied migration is never
edited or silently rerun.

Schema v1 is new-vault creation; there is no legacy production vault. Tests use
synthetic fixtures to exercise the migration engine, rollback, interruption,
checksum mismatch, nonce allocation, and idempotent reopen without recognizing
a test fixture as a production format.

Before a future migration of an existing vault, the repository takes a
checkpointed, verified, same-directory backup through SQLite's online backup
API. The backup contains the same ciphertext and structural metadata, is
synchronized before migration, and is retained for explicit recovery. The
migration runs exclusively and atomically. Pre-commit failure rolls back; a
committed migration is forward-only. Restoring the verified backup requires all
connections closed and does not run an automatic downgrade. Any destructive
migration needs a new proposal, compatibility window, user approval, and tested
recovery plan.

I07 remains the only owner of user-facing export/import. Internal migration
backup is not advertised as a portable backup and direct copying of a live
database remains unsupported.

### Privacy inspection

Integration tests create conspicuous synthetic plaintext markers containing
ASCII, non-ASCII, and NUL-adjacent data, write/update/delete them, and scan
every observable artifact byte-for-byte for UTF-8 and UTF-16LE forms while the
relevant file is live.

Required artifacts are:

1. main database after checkpoint and after delete;
2. live `-wal` and `-shm` during open connections;
3. a live rollback `-journal` from an isolated real-SQLite test that binds only
   ciphertext;
4. a controlled serial subprocess using a task-specific `SQLITE_TMPDIR` and
   disk-temp exercise, again with ciphertext-only SQL values;
5. initialization staging database and sidecars; and
6. online migration backup.

The forced journal/temp modes are evidence that ciphertext-only binding holds
even in artifacts the production WAL/`temp_store=MEMORY` configuration normally
avoids; they do not alter production settings. Because SQLite may unlink or
avoid some temp files, the test records which artifacts were observed and also
asserts structurally that no production SQL bind ever receives record
plaintext. Missing an artifact that the test promised to force is a failed or
explicitly unverified criterion, not an inferred pass.

The scan is useful evidence, not proof against every encoding/compression or OS
copy. The stronger invariant is the narrow repository API: encryption occurs
before the storage adapter receives bytes.

### Secure storage and network boundary

I05 has no reason to use the device signing key, Keychain, Credential Manager,
refresh token, or any new secure-storage entry. Master-password and recovery
wrappers are the intended local VDK persistence. Therefore missing/locked/
unavailable secure-storage behavior is not newly exercised by I05; the existing
ADR 0004 fail-closed adapters and their tests must remain unchanged. Wiring the
device key or activity sentinel into vault access would improperly broaden I05
into I08/I09.

The proposed dependency graph has no HTTP client and the implementation adds no
socket, URL, server, SRS-release, claim, telemetry, update, or remote-script
path. Static dependency and source scans are part of completion evidence.

## Security impact and residual risk

Positive impact:

- keys and plaintext remain outside persistence and WebView boundaries;
- exact formats, sizes, algorithms, and versions fail closed;
- header/wrapper/record metadata is authenticated before plaintext release;
- durable nonce consumption survives local rollback and crashes;
- SQLite ACID recovery, foreign keys, strict tables, checksums, and optimistic
  revisions replace ad hoc persistence behavior; and
- side-file privacy is tested on real artifacts.

Residual risk accepted only for I05 development:

- SQLite is a large native C/FFI surface and a malicious local database remains
  hostile input despite defensive configuration and upstream fuzzing.
- AES-GCM cross-copy uniqueness between independently diverging raw database
  copies is probabilistic at 96 bits; no local file can coordinate globally.
- Offline observers see structural metadata, sizes, timing, and access patterns.
- Zeroization and `secure_delete` do not prove erasure from registers, allocator
  copies, swap, SSD remapping, snapshots, backups, crash dumps, or framework
  copies.
- The Apple Silicon Argon2 profile is provisional until I08 floor/current
  qualification, and G1 still owns independent crypto/dependency/native review,
  fuzzing, and penetration testing.
- I05 does not make a support, signing, backup-recovery, recovery-release,
  Windows, or production-readiness claim.

## Planned implementation shape after approval

The cohesive change is expected to add a private Rust `vault` module with
format, migration, repository, and error submodules; focused integration tests
and a synthetic interruption helper; migration SQL/checksum constants; the
single Cargo dependency; and dependency/design/result documentation. Existing
crypto code may receive crate-private constructors or injected randomness
needed to reserve wrapper nonces, but its algorithms, bounds, public byte
layouts, AAD, HKDF, ERC, and errors remain unchanged.

No Tauri vault command or frontend change is required to prove I05. If a UI is
later needed, it must be a separate narrow typed operation and cannot expose
raw keys, SQL, paths, or crypto.

## Approval boundary

The user crossed this boundary by explicit approval on 2026-09-21. I05 may now
implement only the approved local format and tests. Any dependency, feature,
format, destructive-migration, cryptographic, secure-storage, network, or scope
change still requires renewed approval.
