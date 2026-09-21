# I05 — Versioned vault format and encrypted storage core

- Status: Accepted — implementation and verification completed 2026-09-21
- Baseline: `5a4d92640ac9db4a803e212ce4381eb7cd845752`
- Governing decisions: ADR 0002, ADR 0004, ADR 0005, and ADR 0007
- Proposal: [`../research/I05-vault-format-and-dependency-proposal.md`](../research/I05-vault-format-and-dependency-proposal.md)
- Results: [`../research/I05-vault-storage-results.md`](../research/I05-vault-storage-results.md)

## Objective

Implement the first production-shaped, local-only encrypted vault repository in
Rust. The iteration proves that versioned SQLite persistence can initialize,
close, reopen, unlock, rewrap, and store generic encrypted records without
placing plaintext or keys in SQLite or exposing database, file, key, or raw
cryptographic access to the WebView.

The exact format and dependency proposal must receive explicit user approval
before any persistence source, Cargo manifest, Cargo lockfile, database, or
migration is added or changed.

## In scope after approval

- A Rust-owned SQLite repository with a fixed application identifier, local
  container version, schema version, migrations, strict validation, and narrow
  typed operations.
- Vault initialization with a CSPRNG-generated 256-bit VDK and the accepted
  ADR 0002 master and recovery wrappers.
- Versioned master-password unlock and password rewrap that changes only the
  master wrapper and authenticated header metadata.
- Local recovery-wrapper persistence. I05 may generate synthetic or
  caller-owned ERC/SRS material in Rust tests, but it does not release, upload,
  or claim recovery material.
- Generic encrypted records bounded to the exact v1 limit in ADR 0007.
- Transactional migrations, durable nonce reservation, optimistic record
  revisions, crash recovery, concurrent-connection behavior, and fixed safe
  error classifications.
- Real-file SQLite privacy, tamper, interruption, and restore-like-copy tests.
- Documentation updates for the accepted format, schema, dependencies, and
  observed evidence.

## Explicit exclusions

- No I06 item model, title/category indexing, attachments, or attachment
  streaming.
- No I07 export/import package or direct-live-database backup feature.
- No I08 production activity agent, lifecycle integration, or macOS support
  claim.
- No I09 device registration, public protocol, or production device-key use.
- No server, SRS release, recovery claim, heartbeat, notification, sync,
  updater, telemetry, signing/notarization, or deployment work.
- No React/WebView database, key, file, ERC, SRS, VDK, or raw crypto API.
- No Windows implementation or qualification.
- No change to ADR 0002 algorithms, KDF bounds, key hierarchy, wrapper AAD,
  recovery HKDF context, ERC representation, or ADR 0004 secure-storage
  boundary.

## Dependencies and prerequisites

1. G0 is Accepted and the client starts exactly at
   `5a4d92640ac9db4a803e212ce4381eb7cd845752` with a clean worktree.
2. ADRs 0002, 0004, and 0005 remain authoritative for cryptography, the
   secure-storage boundary, and format ownership.
3. The user explicitly approves the exact I05 proposal and ADR 0007 before the
   implementation boundary is crossed.
4. The existing pinned Node, npm, and Rust toolchains and repository-native
   commands remain the verification entry points.

## Approval boundaries

### Required before implementation

Explicit approval must cover:

- `rusqlite = 0.40.2` with defaults disabled and only `bundled`, `limits`, and
  `backup` enabled;
- bundled `libsqlite3-sys 0.38.2` and SQLite 3.53.2;
- the exact container/header, schema, wrappers, record frame/AAD, limits,
  SQLite settings, nonce ledger, transactions, migrations, backup policy, and
  error behavior in ADR 0007; and
- the security consequences and accepted residual risks in the proposal.

Approval of I05 does not approve a future format version, destructive
migration, release KDF default, SQLCipher, import/export package, streaming
format, server interaction, or secure-storage expansion.

### Requires a separate later decision

- Any cryptographic algorithm, KDF bound, key hierarchy, wrapper AAD/HKDF,
  ERC, or secure-storage change.
- Any new production dependency or broader `rusqlite` feature.
- Any destructive production migration or supported downgrade.
- Any larger record bound, attachment format, export/import format, network
  behavior, or WebView capability.

## Acceptance criteria

I05 is eligible for acceptance only when all of the following are true:

1. A new vault initializes atomically, closes, reopens, and unlocks with the
   correct password on a real SQLite file.
2. Generic encrypted records survive restart and decrypt only after successful
   unlock.
3. A wrong password and corrupted master or recovery wrapper fail closed. No
   failed operation returns plaintext, a VDK, or secret-bearing diagnostics.
4. Password change writes a new master wrapper and authenticated header but
   leaves every encrypted record frame byte-for-byte unchanged.
5. The recovery wrapper survives restart and can be validated in Rust without
   adding SRS release, server, claim, or WebView behavior.
6. Corrupted container/header metadata, wrapper fields, record framing, AAD
   inputs, nonce, ciphertext, and tag are rejected.
7. Unknown or downgraded application, container, schema, crypto, wrapper,
   frame, algorithm, purpose, and KDF values are rejected before allocation or
   KDF work where applicable.
8. Hostile file, sidecar, field, BLOB, ciphertext, plaintext-length, password,
   and KDF parameter sizes fail at their earliest controlled boundary.
9. Nonces are unique in a large deterministic and real-CSPRNG sample; an
   allocated nonce remains consumed after retry, rollback, interruption, and
   restart; quiescent restore-like copies independently obtain new random
   nonces; migrations never synthesize or reuse a record nonce.
10. Injected failures and an abruptly terminated subprocess demonstrate atomic
    rollback or committed recovery at initialization, nonce reservation,
    record mutation, password rewrap, and migration boundaries.
11. Independent connections demonstrate WAL reader/writer behavior, serialized
    writes, bounded busy handling, foreign-key enforcement, and optimistic
    revision conflicts without lost updates.
12. The main database and observable WAL, shared-memory, rollback-journal,
    statement/temp, staging, and migration-backup artifacts are scanned for
    conspicuous synthetic UTF-8 and UTF-16 plaintext markers and contain none.
13. No password, ERC, SRS, VDK, KEK, record plaintext, nonce, ciphertext, or
    full sensitive path appears in `Debug`, errors, logs, snapshots, or test
    output.
14. I05 does not use a production secure-storage dependency. Existing
    secure-storage failure behavior remains unchanged and no plaintext fallback
    is introduced.
15. Static source and dependency inspection finds no network client, server
    dependency, runtime download, telemetry path, raw SQL command, or WebView
    storage capability.
16. Documentation, the migration checksum ledger, Cargo manifest, and lockfile
    agree with the approved proposal, and every required check passes.

## Test matrix

| Area | Required evidence |
| --- | --- |
| Initialization | New-path success; existing-file refusal; failure before commit; staging cleanup/recovery; exact magic and version values |
| Restart | Initialize, close all handles, reopen, unlock, read multiple records |
| Credentials | Correct password; wrong password; old password after rewrap; new password after rewrap |
| Wrappers | Master/recovery field truncation, extension, version, algorithm, purpose, KDF, salt, nonce, ciphertext, tag, ID, and authenticated-metadata tamper |
| Records | Empty, boundary-size, and oversize plaintext; create/read/update; stale revision; frame magic/version/length, nonce, ciphertext, tag, generation, and timestamp tamper |
| Versions | Unknown application/container/schema/crypto/wrapper/frame; zero/downgrade; migration gap/checksum mismatch |
| Nonces | CSPRNG sample; deterministic collision/retry; reserved-then-failed write; rollback; abrupt exit; reopen; concurrent writers; quiescent copied databases; migration fixture |
| Transactions | Failpoints before/after reservation, encryption, row mutation, wrapper replacement, migration ledger, and commit |
| Concurrency | Parallel readers; two writers; busy timeout; stale revision; concurrent rewrap conflict; no unconditional read-then-write |
| SQLite recovery | Hot WAL/subprocess termination; checkpoint/reopen; `quick_check`, `foreign_key_check`, and exact schema verification |
| Privacy | Live scans of main DB, WAL, SHM, forced rollback journal, controlled disk-temp exercise, staging database, and migration backup for synthetic markers |
| Boundaries | No Tauri command for raw vault material; no frontend import; no network dependency or socket/API use |
| Secret handling | Redacted `Debug`; zeroize-on-drop traits; fixed error codes; no secret-bearing assertion output |

Unit tests cover canonical encodings, validation, errors, crypto adapters, and
failure-injection state. Integration tests use real files and independent
connections. Native evidence is the built macOS host plus real SQLite/side-file
behavior; I05 does not claim signed-app, Keychain, lifecycle, minimum-macOS, or
Windows evidence.

## Verification sequence

After implementation approval:

1. Run the most focused Rust unit tests for format, framing, repository, and
   migration behavior.
2. Run the real-file SQLite integration, tamper, concurrency, side-file privacy,
   and interruption suites.
3. Inspect the resolved dependency/feature tree and source diff.
4. Run `npm run check`.
5. Run `npm run desktop:build`.
6. Compare observed results with every acceptance criterion and record exact
   commands, counts, limitations, and artifacts.

## Completion report contract

The final I05 report must state:

- changed behavior and the final format/schema versions;
- main source, migration, test, dependency, and documentation files;
- exact unit, integration, native build, privacy, tamper, concurrency, and
  interruption commands and results;
- any unverified scope or residual risk, including probabilistic cross-copy
  nonce uniqueness and the provisional KDF profile; and
- one exact recommendation: `Accepted`, `In Progress`, or `Blocked`.

Compilation alone is never sufficient for `Accepted`. The next iteration must
not start in this task.
