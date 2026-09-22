# ADR 0009: Portable encrypted export package and atomic restore v1

- Status: Accepted
- Date: 2026-09-22
- Decision owner: I07 export/import format and security approval
- Approval: Explicitly approved by the user on 2026-09-22, including the corrected 15-byte `create_vault_v1` migration identifier and resulting 98-byte schema payload
- Governing ADRs: [ADR 0002](./0002-cryptographic-envelope-and-key-storage.md), [ADR 0005](./0005-vault-format-and-migration-ownership.md), [ADR 0007](./0007-local-vault-format-v1.md), [ADR 0008](./0008-vault-item-payload-and-session-ipc.md)
- Proposal: [I07 export/import format and dependency proposal](../research/I07-export-import-format-and-dependency-proposal.md)

## Context

ADR 0005 assigns the exact authenticated export/import package, manifest,
staging, atomic-completion protocol, and restoration compatibility to I07. Raw
copying of a live SQLite database is unsupported because a live vault includes
WAL state and because restoration must preserve authenticated records and all
consumed nonce reservations without inheriting arbitrary database pages or SQL.

The accepted vault has no package-wide authentication purpose. I07 also runs
before account/device binding and recovery release. The decision must therefore
define a new, domain-separated package authentication use and state exactly
what can be restored without inventing SRS, signing credentials, or a new
device identity.

## Decision

Adopt portable export package v1 from the linked proposal. Its extension is
`.aeterna-vault`. It is a purpose-built bounded framed stream with a 96-byte
preamble, deterministic typed entries, a 128-byte manifest, and a 64-byte
completion/authentication trailer. All multibyte integers are unsigned
big-endian, IDs are raw 16-byte values, timestamps are non-negative UTC Unix
milliseconds in `u64`, all flags/reserved bytes are zero, and compression,
archive defaults, implicit serializers, and trailing bytes are forbidden.

Package v1 exports only:

- the exact authenticated local header;
- exact master and recovery wrapper bytes and metadata;
- the exact recognized schema/migration compatibility ledger, not SQL;
- every nonce reservation, including consumed-but-unused rows; and
- every record ID, generation, timestamp, and unchanged encrypted frame.

It never exports ERC, SRS, plaintext VDK/KEK/EAK, password, device signing
secret, session token, log, browser state, SQL, title, kind, category, contact
explanation, body, attachment filename/media type/content, or other plaintext.

The exact byte layouts, entry types/order, maximums, minimums, compatibility
table, and leakage in the proposal are normative. In particular, package size
is at most 1,073,741,824 bytes, records at most 65,536, nonce reservations at
most 131,072, and entries at most 196,612. A parser validates fixed framing,
counts, checked total arithmetic, and the opened file size before variable
allocation or KDF.

## Package authentication

### Derived key

Derive a unique 32-byte export authentication key per package with the accepted
HKDF-SHA-256 implementation:

```text
EAK = HKDF-SHA-256(
  IKM  = VDK,
  salt = 32-byte random package salt,
  info = export_key_info_v1
)
```

`export_key_info_v1` is exactly 56 bytes:

```text
0..18    "AETERNA-EXPORT-KEY"
18       derivation encoding version = 1
19..21   crypto version = 1, u16 big-endian
21       purpose = 1 (export package authentication)
22..38   vault ID
38..54   random package ID
54..56   output length = 32, u16 big-endian
```

Package salt, package ID, and package authentication nonce are independent OS
CSPRNG draws of 32, 16, and 12 bytes. The EAK is redacted, non-clone, and
zeroize-on-drop and is never persisted or exposed.

### Authentication value

Use AES-256-GCM under the EAK with the random 12-byte trailer nonce, empty
plaintext, a full 16-byte tag, and exactly 294 AAD bytes:

```text
0..19    "AETERNA-EXPORT-AUTH"
19       AAD encoding version = 1
20..22   crypto version = 1, u16 big-endian
22..118  exact 96-byte preamble
118..246 exact 128-byte manifest
246..284 exact trailer bytes 0..38
284..294 exact trailer bytes 54..64
```

The manifest contains SHA-256 of the exact entry body. Each entry prefix
contains SHA-256 of its payload for early streaming corruption detection. Those
digests are not MACs; no package is authentic until the AES-GCM tag verifies.

This purpose is separate from recovery HKDF, wrappers, header authentication,
and record encryption. It does not change ADR 0002 or ADR 0007 bytes. Because
the AES key is unique per random package salt and package ID, its random nonce
is not inserted into the local VDK nonce ledger. This keeps export read-only and
lets two exports of an unchanged snapshot preserve the same source ledger.
Key/nonce uniqueness remains probabilistic under the OS CSPRNG and is subject
to independent G1 review.

## Snapshot and export atomicity

Export requires an unlocked session and reads every row through one SQLite read
transaction after its first metadata read establishes a committed WAL snapshot.
Ordinary writers may continue. Each record is authenticated and its item
payload validated one bounded record at a time, but only the unchanged encrypted
frame is written. Export does not checkpoint or mutate the source.

Rust creates a mode-0600 same-directory random temp file relative to a retained
directory descriptor, writes and verifies the complete package, synchronizes
it, atomically creates an absent destination name with a hard link, synchronizes
the directory, unlinks the temp name, and synchronizes again. Any existing
regular, symlink, hard-link, directory, or special target is refusal, not an
overwrite. Permission, read-only, quota/`ENOSPC`, short-write, or sync failure
does not publish a partial target.

Explicit lock cancels and joins an active export before responding and before
the last VDK owner is dropped. Cancellation is checked between rows and bounded
chunks and is disabled once atomic publication starts. A crash may leave no
target, a complete target, or a strictly recognizable temp/hard link; it can
never leave a partial file under the selected target name.

Stale cleanup is limited to exact versioned random names older than 24 hours
whose current-user ownership, regular-file type, restrictive mode, bounded size,
link count, embedded package ID, and no-follow descriptor identity all match.
Unrecognized or ambiguous directory entries are untouched.

## Import validation and atomic restore

Import is permitted only in the uninitialized state when the fixed target and
known SQLite sidecars are absent. It never overwrites or merges.

Rust opens the selected regular single-link package no-follow, copies it with a
hard size limit into a mode-0600 app-controlled quarantine file, verifies the
source descriptor did not change, and parses the stable descriptor. Validation
order is:

1. file type/size, fixed magic/version/flag/count/length/total relations;
2. exact entry type/version/ordinal/order/count/length and entry/body digests;
3. exact manifest/trailer copies, completion marker, EOF, and compatibility;
4. bounded master-wrapper metadata, then one Argon2 master unlock;
5. package AES-GCM authentication and existing header authentication;
6. complete nonce-ledger uniqueness and active-purpose coverage; and
7. authentication and item-payload validation of every encrypted record.

Unknown, zero, older, newer, or mismatched package, manifest, authentication,
trailer, entry, container, schema, crypto, wrapper, KDF, header-AAD,
record-frame, record-AAD, item, or migration version/checksum fails closed.
Malformed input fails before KDF whenever its defect is structurally knowable.
Wrong credentials and cryptographic authentication failures use the fixed
`crypto_authentication_failed` classification.

Only after the complete first pass succeeds does import create a fresh
app-controlled SQLite stage. A second pass rebuilds it using the compiled
schema and fixed repository statements, never package SQL or raw SQLite pages.
The importer checkpoints/closes, synchronizes, reopens through the ordinary
repository, verifies schema/integrity/header/nonces/items/privacy, and then uses
the same no-replace hard-link and directory-sync protocol at the fixed target.
Success leaves the app locked. Failure/cancel/crash before publication leaves
no target; crash after publication leaves a complete target that restart opens
locked.

## Restoration and identity semantics

I07 restores the same `vault_id`, source `device_id`, recovery identity,
wrappers, encrypted record identities/frames, and historical nonce ledger. An
older authentic package is intentionally restorable only into an absent target
after a rollback warning. I07 has no freshness oracle and makes no rollback
prevention claim. It never silently replaces current data.

This same-lineage restore is not production new-device binding. No device
signing seed is exported, no new device is registered, and no SRS or recovery
wrapper is created. The source recovery wrapper is preserved rather than
discarded, but I06's ERC/SRS were intentionally discarded, so an I06 restore
has no usable emergency-recovery path. I09 and I13/I14 must later define and
approve new-device binding and recovery rewrap before that product claim is
available.

Subsequent writes use the restored complete reservation ledger. Cross-copy
nonce uniqueness between two independently writable descendants remains the
accepted ADR 0007 96-bit CSPRNG probability; I07 is not sync or merge.

## IPC, UI, and platform boundary

Rust alone owns selected paths, package bytes, parsing, authentication, staging,
repository construction, and publication. Native panels produce one-shot
five-minute selection IDs. IPC adds only six strict commands for export/import
choose/start and transfer status/cancel. Requests deny unknown fields; IDs are
canonical lowercase hex; progress uses canonical decimal strings. No path or
package byte crosses IPC, and no generic filesystem, SQL, key, crypto, shell,
or execution command exists.

The main capability gains only those six command permissions. No Tauri
filesystem/dialog/shell/network plugin, broad path permission, or CSP source is
added. User-visible warnings, progress, cancellation, overwrite refusal,
rollback disclosure, errors, and recovery limitations use English-default and
Simplified Chinese resources.

The public picker flow is macOS-only in I07. It uses the existing exact
`objc2-app-kit 0.3.2` dependency with the proposal's exact additional generated
features. Add exact macOS-only direct `libc 0.2.189`, already present in the
lockfile, for a narrow audited directory-relative syscall boundary. No npm
dependency, Tauri plugin, archive/serialization/compression crate, or new
cryptographic crate is added. Non-macOS picker commands fail with a fixed
unsupported code; Windows qualification remains behind GW.

## Security and privacy consequences

- The tag authenticates metadata and a digest of the exact body; existing
  header/record tags retain their independent substitution protection.
- Hostile files cannot select unbounded memory/KDF work or package-provided SQL.
- Same-directory descriptor-relative create-new/no-replace operations constrain
  final-component TOCTOU. A fully compromised same-user process or unlocked OS
  remains outside the threat model.
- Package metadata exposes format, IDs, KDF parameters, counts, sizes,
  timestamps, and generations. Item/attachment semantics and bytes remain
  encrypted. The UI treats copied packages as sensitive.
- Export/import temps contain ciphertext and structural metadata only. They are
  mode 0600 on Unix, but physical erasure from SSDs, snapshots, swap, or crash
  dumps is not guaranteed.
- Password/VDK/EAK/item plaintext is bounded and cleared best-effort. Framework,
  allocator, compiler, JavaScript engine, OS, swap, and crash copies cannot be
  guaranteed erased.
- Authentication proves possession of the VDK reached through the master
  wrapper, not freshness, rightful user identity, device registration, or
  emergency-recovery eligibility.

## Alternatives rejected

- ZIP/TAR or compression: implicit parsing, path, size, duplication and
  decompression surfaces with no need for file trees.
- Raw SQLite/online-backup export: couples portability to pages/WAL/schema and
  bypasses explicit record/nonce/compatibility validation.
- JSON/Serde/bincode production serialization: implicit canonicalization and
  dependency contracts rather than fixed bytes.
- Mutating the source ledger with a package-auth nonce: makes read-only export
  false and two otherwise equivalent backups restore different source state.
- HMAC or an outer backup-password format: adds another primitive or password/
  KDF/recovery contract without product need.
- Reusing VDK directly under a new fixed nonce/AAD: risks key/nonce domain
  confusion with accepted record/header uses.
- Browser file input/download or raw package IPC: exposes paths/large package
  bytes and buffering to the WebView.
- `tauri-plugin-dialog` or a generic filesystem plugin: broader plugin,
  frontend-command, path-type, and transitive surface than the macOS-first
  native binding already pinned.
- Import overwrite/merge: destructive rollback/conflict semantics outside I07.
- Rewriting source identity or recovery wrapper: would require device binding,
  SRS, recovery, re-encryption, and server decisions owned by later iterations.

## Approval effect

Explicit acceptance authorizes only the exact v1 format, cryptographic use,
dependencies/features, six-command boundary, macOS native picker, streaming
snapshot/export, two-pass restore, and test/documentation work described here
and in the proposal.

It does not authorize a changed byte, bound, key/AAD layout, future format,
schema migration, overwrite/merge, cloud/sync, device binding, recovery,
lifecycle/activity hardening, telemetry, updater, Windows qualification,
production signing, publication, or deployment. Any such need requires a new
decision and approval.
