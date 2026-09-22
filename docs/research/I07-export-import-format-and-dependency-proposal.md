# I07 export/import format and dependency proposal

- Prepared: 2026-09-22
- State: **Approved for implementation on 2026-09-22**
- Baseline: `98069e58e71c9ff728983197ced9d87dcb9dd5da`
- Proposed decision: [ADR 0009](../adr/0009-portable-export-package-and-atomic-restore-v1.md)
- Iteration brief: [I07 atomic encrypted export and import](../iterations/I07-atomic-encrypted-export-import.md)

## Baseline and approval gate

At the start of I07, the managed worktree was clean, detached `HEAD` resolved
exactly to `98069e58e71c9ff728983197ced9d87dcb9dd5da`, and the local `main` ref
resolved to the same accepted I06 checkpoint. I05, I06, ADR 0007, and ADR 0008
are Accepted. The current application has one fixed app-local SQLite vault,
master-password unlock, explicit/restart lock, encrypted item/attachment CRUD,
and no export, import, account, device binding, server, or usable recovery path.

ADR 0005 assigns the exact authenticated export package and atomic restore
protocol to I07. Neither the I02 fixture nor the SQLite database is an export
format. This document and proposed ADR 0009 therefore require explicit user
approval before changing source, manifests, lockfiles, capabilities, generated
permissions, persistence behavior, migrations, or existing product design.

The requested approval includes a new cryptographic use: a package-specific
HKDF-SHA-256 key derived from the VDK and AES-256-GCM authentication over exact
package metadata. It does not alter any accepted wrapper, wrapper AAD, KDF,
header AAD, record AAD, record frame, local nonce allocator, or item payload.

## Proposed user and restoration model

I07 provides encrypted local backup/restore for the existing development vault:

1. An unlocked user chooses a new export filename through a native save panel.
2. Rust exports one committed encrypted snapshot without exposing a path or
   package byte to the WebView.
3. An uninitialized installation may select a package, acknowledge that an old
   backup can roll data back, and supply the package's master password.
4. Rust fully validates the package, reconstructs and verifies a new SQLite
   vault at an app-controlled staging path, atomically publishes it only if the
   fixed target is absent, and leaves it locked.
5. The user explicitly unlocks the restored vault with the master password.

This is same-lineage restoration. The imported header retains the source
`vault_id` and `device_id`; master and recovery wrapper bytes remain exact, and
encrypted records retain their IDs, generations, timestamps, and frames. I07
does not call this a new bound device. It does not copy a device signing secret,
register a device, obtain or invent SRS, or create a new recovery wrapper.

DESIGN.md says that a production import onto a new device must register that
device and create its own SRS/recovery wrapper. That requires I09 account/device
binding and I13/I14 recovery protocols. Until those exist, an I07 package can
be restored under its master password on an empty installation, but the
resulting local identity remains the restored source lineage and is not a
production-bound new device. A later approved flow must perform binding and
recovery rewrapping without silently treating this identity as newly bound.

I06 discarded its generated ERC and SRS material. Its persisted recovery
wrapper is still authenticated and must be preserved, but it is not usable.
I07 therefore improves password-based local backup only. The UI continues to
warn that forgetting the master password loses access, imported I06 data has no
emergency recovery, and irreplaceable production data is unsupported.

## Portable package v1

### File identity, encoding, and limits

| Value                        | Exact v1 decision                                                           |
| ---------------------------- | --------------------------------------------------------------------------- |
| Extension                    | `.aeterna-vault`                                                            |
| Package magic                | 16 bytes `AETERNA-EXPORT\0\0`                                               |
| Package version              | unsigned big-endian `u16 = 1`                                               |
| Manifest version             | unsigned big-endian `u16 = 1`                                               |
| Authentication version       | unsigned big-endian `u16 = 1`                                               |
| Entry framing version        | unsigned big-endian `u16 = 1` per entry                                     |
| Trailer version              | unsigned big-endian `u16 = 1`                                               |
| IDs                          | raw 16-byte values                                                          |
| Timestamps                   | non-negative UTC Unix milliseconds, unsigned big-endian `u64`               |
| Lengths/counts               | unsigned big-endian fixed-width integers at the stated offsets              |
| Compression                  | forbidden; flags are zero                                                   |
| Minimum valid package        | 1,161 bytes for the current empty-vault minimum of three nonce reservations |
| Maximum package file         | 1,073,741,824 bytes, including every header/trailer byte                    |
| Body byte length             | 873 through 1,073,741,536 bytes                                             |
| Maximum records              | 65,536                                                                      |
| Maximum nonce reservations   | 131,072                                                                     |
| Maximum entries              | 196,612 (`4 + 65,536 + 131,072`)                                            |
| Maximum record frame         | 1,048,622 bytes, unchanged from ADR 0007                                    |
| Maximum record-entry payload | 1,048,666 bytes                                                             |
| Streaming chunk              | at most 65,536 bytes per file read/write buffer                             |

Package v1 is a purpose-built framed stream. It is not ZIP, TAR, another
archive default, JSON, CBOR, MessagePack, Serde/bincode output, compression, or
SQLite pages. Unknown flags, reserved nonzero fields, zero versions, unknown
versions, excessive counts, impossible relations, arithmetic overflow, an
impossible minimum/maximum size, or a declared total unequal to the opened file
size fail before allocating a declared payload or invoking Argon2.

The package is exactly:

```text
96-byte preamble
body_length bytes of ordered framed entries
128-byte manifest
64-byte completion/authentication trailer
```

No byte may precede the preamble or follow the trailer.

### Preamble: exactly 96 bytes

```text
0..16    magic = 41 45 54 45 52 4e 41 2d 45 58 50 4f 52 54 00 00
16..18   package version = 1, u16 big-endian
18..20   manifest version = 1, u16 big-endian
20..22   authentication version = 1, u16 big-endian
22..24   flags = 0, u16 big-endian
24..40   random package ID, 16 bytes
40..72   random package authentication salt, 32 bytes
72..76   total entry count, u32 big-endian
76..80   record entry count, u32 big-endian
80..84   nonce-reservation entry count, u32 big-endian
84..92   body byte length, u64 big-endian
92..96   manifest byte length = 128, u32 big-endian
```

Package ID and salt are generated independently with the existing OS CSPRNG.
They are public structural values and are not local-vault nonce reservations.

### Entry framing: exactly 56 bytes plus payload

Every body entry has this prefix:

```text
0..4     entry magic = 41 45 4e 54 ("AENT")
4..6     entry type, u16 big-endian
6..8     entry version = 1, u16 big-endian
8..12    zero-based ordinal, u32 big-endian
12..20   payload byte length, u64 big-endian
20..52   SHA-256 of the exact payload bytes
52..56   flags = 0, u32 big-endian
56..N    exact payload; no padding
```

The unkeyed entry digest is an early streaming corruption check, not an
authentication claim. Authentication comes from the package tag, whose
authenticated manifest contains the SHA-256 digest of the exact complete body,
including every entry prefix, per-entry digest, and payload.

### Deterministic entry order and types

Entries occur once in this order:

1. ordinal 0, type 1: vault header;
2. ordinal 1, type 2: master wrapper;
3. ordinal 2, type 3: recovery wrapper;
4. ordinal 3, type 4: schema/migration compatibility;
5. exactly `nonce_count` type-5 entries, strictly ascending by raw 12-byte
   nonce; then
6. exactly `record_count` type-6 entries, strictly ascending by raw 16-byte
   record ID.

Ordinals must be consecutive. A duplicate, omission, unknown type, wrong type
position, unordered key, or extra entry is invalid even if counts would fit.
`nonce_count` is at least three, and `entry_count` must equal exactly
`4 + nonce_count + record_count` under checked arithmetic.

### Type 1 header payload: exactly 96 bytes

```text
0..12    local magic
12..14   container version, u16
14..18   schema version, u32
18..20   crypto version, u16
20..36   vault ID
36..52   source device ID
52..64   header-authentication nonce
64..80   header-authentication tag
80..88   created_at_ms, u64
88..96   updated_at_ms, u64
```

### Type 2 master-wrapper payload: exactly 120 bytes

```text
0..8     wrapper revision, u64
8..10    wrapper format version, u16
10       AEAD algorithm ID
11       wrapper purpose
12       KDF algorithm ID
13       KDF version
14..18   Argon2 memory_kib, u32
18..22   Argon2 time cost, u32
22..26   Argon2 parallelism, u32
26..28   output length, u16
28..44   salt, 16 bytes
44..56   nonce, 12 bytes
56..104  wrapped VDK ciphertext and tag, 48 bytes
104..112 created_at_ms, u64
112..120 updated_at_ms, u64
```

### Type 3 recovery-wrapper payload: exactly 104 bytes

```text
0..16    recovery ID
16..32   source recovery device ID
32..34   wrapper format version, u16
34       AEAD algorithm ID
35       wrapper purpose
36..48   nonce, 12 bytes
48..96   wrapped VDK ciphertext and tag, 48 bytes
96..104  created_at_ms, u64
```

### Type 4 schema/migration payload: exactly 98 bytes for v1

```text
0..4     SQLite application_id, u32
4..8     SQLite user_version, u32
8..20    local magic, 12 bytes
20..22   container version, u16
22..26   schema version, u32
26..28   crypto version, u16
28       header AAD version
29       wrapper-set encoding version (= 1 for AETERNA-WRAPPERS-V1)
30..32   record-frame version, u16
32       record AAD version
33..35   item-payload version, u16
35..37   migration count = 1, u16
37..41   migration version = 1, u32
41..43   migration-name byte length = 15, u16
43..58   ASCII "create_vault_v1"
58..90   canonical migration SHA-256
90..98   migration applied_at_ms, u64
```

The migration SQL itself is not exported or executed from the package. Import
requires the exact compiled v1 application/schema identifiers, name, and
checksum, then creates schema v1 using the application's authoritative fixed
migration. This prevents a package from supplying SQL.

### Type 5 nonce-reservation payload: exactly 21 bytes

```text
0..12    nonce
12       purpose (1 master wrapper, 2 recovery wrapper, 3 header, 4 record)
13..21   reserved_at_ms, u64
```

Every row is exported, not only nonces referenced by active objects. This
preserves failed, interrupted, rolled-back, and otherwise consumed-but-unused
reservations. Unknown purpose values are unsupported in v1. Import verifies
that each active master/recovery/header/record nonce exists once with its exact
purpose; extra historical reservations with a known purpose are retained.

The export package authentication nonce is not a type-5 reservation because it
is used under a package-specific derived key, not under the VDK. The derivation
and collision analysis appear below.

### Type 6 encrypted-record payload: 90 through 1,048,666 bytes

```text
0..16    record ID
16..24   generation, u64
24..32   created_at_ms, u64
32..40   updated_at_ms, u64
40..44   frame byte length, u32
44..N    exact ADR 0007 encrypted record frame
```

The encrypted frame remains byte-for-byte unchanged. No title, kind, category,
contact explanation, body, attachment filename/media type/content, or other
item plaintext enters package framing or a filename.

### Manifest: exactly 128 bytes

```text
0..16    ASCII "AETERNA-MANIFEST"
16..18   manifest version = 1, u16
18..20   package version = 1, u16
20..22   authentication version = 1, u16
22..24   flags = 0, u16
24..40   package ID copied from preamble
40..56   vault ID copied from type-1 header
56..72   source device ID copied from type-1 header
72..76   total entry count copied from preamble, u32
76..80   record count copied from preamble, u32
80..84   nonce count copied from preamble, u32
84..92   body byte length copied from preamble, u64
92..124  SHA-256 of the exact complete body
124..128 reserved zero bytes
```

### Completion/authentication trailer: exactly 64 bytes

```text
0..16    ASCII "AETERNA-COMPLETE"
16..18   trailer version = 1, u16
18       authentication algorithm = 1 (AES-256-GCM)
19       authentication purpose = 1 (export package v1)
20..22   flags = 0, u16
22..26   reserved zero bytes
26..38   package-authentication nonce, 12 bytes
38..54   AES-256-GCM authentication tag, 16 bytes
54..62   total package byte length, u64
62..64   reserved zero bytes
```

The target filename is published only after this complete trailer has been
written and the staging file synchronized. The marker alone is not trusted;
all structure, digests, and the tag must verify.

## New package authentication use

### Package authentication key derivation

Derive one 32-byte export authentication key (`EAK`) per package:

```text
EAK = HKDF-SHA-256(
  IKM  = VDK,
  salt = preamble.package_authentication_salt,
  info = export_key_info_v1
)
```

`export_key_info_v1` is exactly 56 bytes:

```text
0..18    ASCII "AETERNA-EXPORT-KEY"
18       key-derivation encoding version = 1
19..21   crypto version = 1, u16 big-endian
21       purpose = 1 (export package authentication)
22..38   vault ID
38..54   package ID
54..56   output length = 32, u16 big-endian
```

The EAK is a non-clone, redacted, zeroize-on-drop value. It is never persisted,
logged, returned over IPC, or used for local records/wrappers. The 32-byte salt,
16-byte package ID, and 12-byte AES-GCM nonce are independent OS-CSPRNG draws.

### AES-GCM authentication and exact AAD

Use the approved `aes-gcm 0.10.3` AES-256-GCM implementation with the derived
EAK, the trailer nonce, empty plaintext, and one 294-byte AAD value:

```text
0..19    ASCII "AETERNA-EXPORT-AUTH"
19       AAD encoding version = 1
20..22   crypto version = 1, u16 big-endian
22..118  exact 96-byte preamble
118..246 exact 128-byte manifest
246..284 exact trailer bytes 0..38 (including marker, versions, purpose, flags,
          reserved bytes, and authentication nonce)
284..294 exact trailer bytes 54..64 (total length and final reserved bytes)
```

Trailer bytes 38..54 are the tag itself and are necessarily excluded. The
authenticated manifest's body digest binds every entry byte. The wrapper and
record tags then independently authenticate their existing domains.

### Key separation, nonce, and substitution analysis

- Recovery KEK derivation uses SRS as salt and `AETERNA-RKEK` context. Export
  authentication uses a fresh 32-byte public package salt and a disjoint
  `AETERNA-EXPORT-KEY` context containing the vault/package IDs and purpose.
- The EAK is distinct from the VDK's direct AES record/header use and from both
  wrapper KEKs. No accepted key or AAD layout is reinterpreted.
- AES-GCM nonce uniqueness is scoped to one EAK. Each package uses a newly
  derived EAK from a fresh 256-bit salt and 128-bit package ID plus an
  independent 96-bit nonce. A package-salt/package-ID collision would still
  require a nonce collision for key/nonce reuse. This remains probabilistic
  under the OS CSPRNG; no cross-package coordinator is claimed.
- Reserving the package nonce in the local ledger was rejected. It would make
  export mutate the source and make two backups of an otherwise unchanged
  snapshot restore different historical ledgers. Deriving a per-package key
  keeps export read-only and preserves the exact source nonce state.
- Preamble/manifest/trailer substitution changes either HKDF inputs, AAD, or
  both. Body or entry substitution changes authenticated digests. A package
  authenticated under another VDK cannot validate after the selected master
  wrapper is unlocked.
- SHA-256 entry/body digests are not treated as MACs. A parser must not report a
  package authentic or construct a vault based only on digest success.

This is a new cryptographic use and is not authorized until the user explicitly
approves proposed ADR 0009. G1 still owns independent cryptographic review.

## Metadata and confidentiality

The package contains no ERC, SRS, plaintext VDK/KEK/EAK, password, device
signing seed, session token, log, browser state, SQL, or plaintext item data.
It contains the exact master/recovery wrapper ciphertext, header tag, record
ciphertext, and the structural state required to restore them.

An observer of a copied package can learn:

- that the file is an Aeterna export and its format versions;
- package/vault/source-device/recovery/record IDs;
- Argon2 parameters and wrapper/record nonces;
- record and nonce-reservation counts;
- exact ciphertext/frame/package sizes;
- vault, wrapper, record, migration, and reservation timestamps;
- record generations and update patterns represented by the snapshot; and
- whether two packages have the same body digest, even though random package
  metadata and tags differ.

These fields are already structural inputs to existing authenticated formats
or are necessary to parse and restore safely. I07 does not add an outer
password-encryption layer because doing so would introduce another password/KDF
format, password lifecycle, and recovery claim. The UI warns users that copied
packages remain sensitive, should be stored on protected media, and are only as
safe as the master password, endpoint, and accepted Argon2 profile. Titles,
kinds, categories, contact explanations, attachment names/media types/content,
and bodies remain encrypted.

## Export snapshot and streaming protocol

1. Require the Rust session to be unlocked, no other transfer active, and a
   valid one-shot export selection token.
2. Open and retain the selected parent directory handle; validate one leaf
   component ending in `.aeterna-vault`; reject existing/symlink/hard-link/
   special targets without following them.
3. Generate package ID, salt, and authentication nonce. Use the random 16-byte
   package ID as the temp suffix and create
   `.aeterna-export-v1-<32-lowercase-hex>.tmp` relative to the retained
   directory with create-new, no-follow, close-on-exec, and mode 0600. A name
   collision causes a fresh package ID/salt/nonce draw, bounded to 16 attempts.
4. Open one configured SQLite connection and begin one read transaction. The
   first metadata query establishes a WAL snapshot. Validate schema, header,
   wrappers, counts, bounds, and nonce relationships inside that transaction.
5. Stream entries in deterministic order. Hash prefixes/payloads while writing.
   Decrypt and validate each item one at a time from the same snapshot, then
   immediately clear its bounded plaintext; write only its unchanged ciphertext
   frame. Check cancellation between rows and every 65,536-byte chunk.
6. Write the manifest and trailer authentication, flush, synchronize the file,
   re-read and structurally verify the completed staging file, and confirm its
   descriptor identity, mode, link count, and exact length.
7. Atomically create the absent destination name with a directory-relative
   hard link. A competing target causes refusal, never replacement. Synchronize
   the directory, unlink the temp name, and synchronize the directory again.
8. Return only operation status. Never return or persist the selected path.

All rows come from one SQLite read transaction. Concurrent writers may commit
to the live WAL before or after the snapshot boundary; the package sees the
complete state on exactly one side. Export does not checkpoint, block normal
writes for the whole operation, or mutate the source nonce ledger.

An active export holds shared Rust ownership of the unlocked vault solely for
the worker lifetime. `vault_lock` marks the session fail-closed, requests
cancellation, waits for the worker to stop and drop the EAK/VDK owner, clears
file selections, then responds `locked`. No content command may begin during
that transition. Cancellation before publication removes the owned temp when
possible. Once no-replace publication begins, cancellation is disabled and the
operation finishes the bounded directory-sync/cleanup sequence.

## Export filesystem atomicity and stale files

On macOS, a narrow audited module uses directory-relative `openat`, `fstatat`,
`linkat`, `unlinkat`, `fstat`, `fchmod`, and `fsync` through `libc`. Paths are
split once; all security decisions and mutations use the retained directory
descriptor plus validated leaf names. The module rejects a symlink final
directory, final target of any type, temp identity change, unexpected owner,
group/other permission, or unexpected link count. Temporary and final names
are on the same filesystem by construction.

Crash boundaries have these outcomes:

- before `linkat`: no target; at most one recognizable temp remains;
- after `linkat` but before directory sync: after power loss the target may be
  absent or present, but any present target names the fully synchronized file;
- after directory sync but before temp unlink: the complete target and an
  extra temp hard link may remain;
- after temp unlink but before final directory sync: the complete target
  remains; the temp link may or may not reappear after power loss.

The app never deletes a target. On a later export to the same selected
directory it may remove only an exact `.aeterna-export-v1-<32hex>.tmp` entry
that is older than 24 hours, is owned by the current user, is a regular
mode-0600 file, has one or two links, is no larger than the package maximum,
and contains a preamble package ID matching the filename plus either an
incomplete package or a valid completed package. Every candidate is opened
no-follow relative to the retained directory and rechecked before unlink. An
unrecognized, young, multi-link, mismatched, inaccessible, symlink, directory,
or special entry is untouched. App-controlled import stages use analogous
strict names/checks and the same 24-hour live-process guard.

Permission denial, a read-only destination, `ENOSPC`, quota failure, short
write, failed file sync, failed directory sync, and existing-target races
return fixed safe errors and do not publish an incomplete target. A failed
directory sync after a complete link is reported as an uncertain durability
result; the app reopens and verifies the target, reports complete only if it is
present and authentic, and never retries by replacing it.

## Import validation and reconstruction protocol

Import is allowed only when the fixed app-owned target and known sidecars are
absent and the in-memory session is `Uninitialized` with no other transfer.
The selected source path remains behind a one-shot Rust token.

### Stable input and cheap preflight

1. Open the selected parent once and the leaf relative to it with no-follow and
   read-only flags. Require extension `.aeterna-vault`, a regular file, link
   count one, and exact size within 1,161 through 1,073,741,824 bytes. Capture
   descriptor identity, size, and timestamps.
2. Stream-copy at most the maximum size into a create-new mode-0600 quarantine
   file under the app-owned vault directory. Recheck the source descriptor
   metadata after EOF. Any change, short/extra byte, cancellation, read/write/
   sync error, symlink, hard link, or special source rejects the operation.
3. Parse the stable quarantine descriptor. Read only fixed preamble/trailer
   sizes first. Validate magic, all independent versions, flags/reserved bytes,
   counts, count relations, manifest length, checked body/total arithmetic, and
   exact descriptor size before allocating a variable payload or running KDF.

The quarantine copy is encrypted package data, not a SQLite copy. It prevents
later pathname replacement and supplies a stable private input. It is removed
after success/failure when possible and is eligible for exact stale cleanup
after interruption.

### Full pass 1: structure, compatibility, and authentication

4. Stream every entry in order. Enforce exact type/version/ordinal/length,
   bounded payload, strict nonce/record sort order, per-entry digest, exact
   counts, and exact body digest. Buffer only fixed header/wrapper/schema
   metadata, a bounded nonce set, and one bounded record payload/plaintext.
5. Validate the exact compatibility table before KDF. Validate master-wrapper
   KDF parameters and lengths before Argon2. Check manifest copies, trailer
   fields, completion marker, total length, EOF, and absence of trailing data.
6. Derive the VDK once with the supplied master password and accepted master
   wrapper. Wrong credentials and wrapper authentication map to the fixed
   `crypto_authentication_failed` classification.
7. Derive the EAK and verify the package authentication tag. Then verify the
   existing authenticated header, which binds the exact master and recovery
   wrappers. The recovery wrapper is not unwrapped because I07 has no ERC/SRS.
8. Verify every active master/recovery/header/record nonce against the complete
   reservation set and exact purpose. Reject duplicates, omissions, unknown
   purposes, or reservation tampering.
9. Decrypt and authenticate every record with its existing ADR 0007 AAD,
   validate exact plaintext length and I06 item payload v1, and clear each
   bounded plaintext before continuing. No partial item is returned to UI.

No app-owned SQLite stage exists until all nine steps succeed.

### Full pass 2: repository construction and publication

10. Rewind the same quarantine descriptor and revalidate entry/body digests
    while streaming into a fresh app-controlled
    `.aeterna-import-vault-v1-<32hex>.stage` SQLite file. Apply only the
    compiled canonical schema v1. Insert the exact header/wrappers/migration
    applied time/nonce rows/record rows through fixed repository statements;
    never execute package SQL or copy SQLite pages.
11. Checkpoint and close SQLite sidecars; synchronize the staging database;
    reopen it through the normal repository; verify exact schema, migration,
    quick/foreign-key checks, header authentication, nonce relationships, and
    all item records under the already validated password/VDK path. Scan all
    observable staging artifacts for synthetic plaintext markers in tests.
12. Recheck that the fixed target and known sidecars are absent. Publish with a
    same-directory no-replace hard link, synchronize the app-owned directory,
    remove the staging name/sidecars, and synchronize again.
13. Transition application state to `Locked(VaultRepository)`. Clear password,
    VDK/EAK/plaintext/quarantine state. The user must explicitly unlock.

If the process terminates before publication, restart sees no target and may
clean only recognized old staging files. If it terminates after publication,
restart opens the complete target locked; a leftover staging link is cleanup
only. A construction or verification failure removes the recognized stage and
quarantine when possible and never accepts a target. Retrying always starts
from the package beginning; partial stages are never resumed.

## Compatibility and rollback table

| Input                                                                                                             | I07 behavior                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Package/manifest/auth/trailer/entry v1 with exact local v1/schema v1/crypto v1/wrapper v1/frame v1/AAD v1/item v1 | Validate and restore as the same lineage into an absent target                                                    |
| Any zero, older, unknown newer, or mismatched package-layer version                                               | Reject `vault_import_unsupported_version`; no fallback/downgrade                                                  |
| Unknown container/schema/crypto/wrapper/KDF/frame/header-AAD/record-AAD/item version or migration name/checksum   | Reject before stage construction; no reinterpretation or migration                                                |
| Authentic older snapshot of supported v1                                                                          | Permit only into an absent target after rollback warning; no freshness guarantee                                  |
| Existing app-owned target or sidecar of any kind                                                                  | Refuse; no overwrite, delete, rename, merge, or replacement                                                       |
| Source identity from another physical machine                                                                     | Restore bytes as an unbound same-lineage local vault; do not claim new-device registration or production recovery |

I07 has no trusted monotonic counter, server, transparency log, or external
freshness record. It cannot detect that one authentic package predates another.
The UI discloses that restore may remove later changes. Because existing targets
are never overwritten, rollback cannot silently replace current data.

After restore, the complete historical nonce ledger remains authoritative.
Subsequent writes reserve fresh OS-random 96-bit nonces and reject local
duplicates. If the source and a restored copy are both writable, no coordinator
exists between them; ADR 0007's accepted cross-copy uniqueness remains
probabilistic. I07 is backup/restore, not sync or branching.

## File selection, IPC, session, progress, and cancellation

### Native selection and path ownership

macOS uses `NSOpenPanel`/`NSSavePanel` directly from the Rust main-thread
command through `objc2-app-kit`. The panel uses native OS-localized controls,
selects one file only, does not select directories, does not resolve a selected
file into a WebView-visible path, and suggests/filters `.aeterna-vault`.

Rust stores at most one selected path in a redacted, one-shot descriptor for
five minutes and returns only a random lowercase 32-hex selection ID. A later
start command consumes it. Path values never appear in IPC, frontend state,
browser persistence, diagnostics, logs, errors, or operation status. Package
bytes are streamed directly in Rust and never use JSON, base64, raw IPC, a
browser `File`, or a download URL. Existing raw IPC remains limited to I06
bounded attachment operations.

The public picker/transfer UI is macOS-only in I07. Non-macOS commands return a
fixed `vault_platform_unsupported` result. Core format/repository code remains
portable, but Windows behavior/support remains behind GW and Linux is not a
declared product target.

### Exact new commands

The main window gains only these commands:

| Command                 | Strict request              | Response/behavior                                                                                      |
| ----------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------ |
| `vault_export_choose`   | `{}`                        | Native save panel; `{ outcome: "selected", selectionId }` or `{ outcome: "cancelled" }`; unlocked only |
| `vault_export_start`    | `{ selectionId }`           | Consumes token; `{ operationId }`; unlocked only                                                       |
| `vault_import_choose`   | `{}`                        | Native open panel; selected/cancelled union; uninitialized only                                        |
| `vault_import_start`    | `{ selectionId, password }` | Consumes token; `{ operationId }`; uninitialized only                                                  |
| `vault_transfer_status` | `{ operationId }`           | Kind/state/phase plus canonical decimal byte/entry progress and terminal fixed error code              |
| `vault_transfer_cancel` | `{ operationId }`           | Requests cancellation only while cancellable; returns `{ state: "cancelling" }`                        |

All JSON request types deny unknown fields. IDs are canonical lowercase 32-hex.
Passwords retain ADR 0002's 1-1,024-byte backend bound. Operation progress uses
decimal strings, is monotonic, and reveals no path, ID, item count beyond the
already disclosed package entry totals, content, or ciphertext. One transfer
may exist at a time. Selection and operation IDs are random, process-local,
one-purpose, one-shot, and expire after five minutes when inactive/terminal.

Expired, reused, wrong-kind, stale, cancelled, or unknown IDs fail with a fixed
machine code. Export requires current unlocked session epoch. Import blocks
initialization while active. Content writes may continue during an export
snapshot; another transfer may not. Explicit lock follows the cancel/join rule
above. A cancelled/failed import leaves the session uninitialized; successful
import leaves it locked.

Proposed phase values are fixed English machine values:

```text
choosing, preparing, snapshotting, writing, copying, validating,
authenticating, reconstructing, verifying, publishing, cancelling,
completed, cancelled, failed
```

Errors remain fixed English codes, including `vault_operation_in_progress`,
`vault_operation_not_found`, `vault_operation_not_cancellable`,
`vault_selection_not_found`, `vault_export_target_exists`,
`vault_export_limit_exceeded`, `vault_import_target_exists`,
`vault_import_invalid_package`, `vault_import_unsupported_version`,
`vault_import_limit_exceeded`, `vault_path_rejected`,
`vault_platform_unsupported`, `vault_io_error`, and the existing
`crypto_authentication_failed`. No code contains a path or secret.

## UI and accessibility

- The unlocked view adds an **Export encrypted vault** action. Before selection
  it explains metadata leakage, password dependence, protected-storage advice,
  no overwrite, and that this does not add emergency recovery.
- The uninitialized screen adds **Import encrypted vault**. It warns that an
  authentic older package can roll back data, import requires an empty target,
  the master password is required, and the result preserves the source lineage
  without registering a new device or creating recovery material.
- Native panels handle path choice. The WebView never displays an absolute path.
  Existing-target refusal tells the user to choose a new filename.
- A modal confirmation precedes each start. The primary button names the
  action, focus enters the modal, Escape cancels only before transfer, and focus
  returns to the invoking control.
- Progress has a visible label and `aria-live="polite"` phase/percentage. It
  never estimates completion from untrusted package fields before validation.
- Cancel is keyboard reachable while the backend reports cancellable, changes
  to cancelling once, and is disabled during atomic publication.
- Completion/failure/cancellation and every fixed error code have English
  source/default and Simplified Chinese resources. No user-visible Rust string
  is introduced; native panel controls use OS localization.
- After success the UI may show the locale-formatted completion time for the
  current host process. I07 does not persist or authenticate a "last export"
  timestamp and does not use it as freshness evidence; durable backup history
  requires a later explicit local-metadata decision.
- Password fields use the existing no-persistence/no-log rules and clear after
  start settles. No package status or path is written to localStorage,
  sessionStorage, IndexedDB, URLs, clipboard, caches, service workers, or logs.

## Dependency, native, capability, and supply-chain proposal

### Exact manifest changes after approval

No npm package, Tauri plugin, runtime network library, serializer, compression
library, archive library, async runtime, or new cryptographic crate is proposed.
The existing `hkdf`, `sha2`, `aes-gcm`, `getrandom`, `zeroize`, `rusqlite`,
Tauri, Serde, and React pins are sufficient.

The proposed Rust manifest changes are:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
libc = { version = "=0.2.189", default-features = false }
objc2-app-kit = { version = "=0.3.2", default-features = false, features = [
  "std",
  "NSApplication",
  "NSOpenPanel",
  "NSPanel",
  "NSResponder",
  "NSSavePanel",
  "NSWindow",
  "NSWorkspace",
] }
```

`libc 0.2.189` is already resolved transitively in `Cargo.lock`, so making it a
direct macOS-only dependency should add no package or checksum. It is maintained
by the Rust project, licensed MIT OR Apache-2.0, contains raw OS declarations
and platform cfg/build code, and adds no runtime network, service, entitlement,
permission prompt, or WebView API. Aeterna will own a small unsafe wrapper whose
safety comments cover C strings, descriptor ownership, checked conversions,
and syscall return handling. Fault and real-filesystem tests cover it.

`objc2-app-kit 0.3.2` is already an exact macOS-only direct dependency from the
active `madsmtm/objc2` binding family, licensed Zlib OR Apache-2.0 OR MIT. I07
adds generated AppKit panel/window features but no new crate version. The
bindings expose `NSOpenPanel`/`NSSavePanel` with `MainThreadMarker`; synchronous
Tauri commands run on the main thread, and heavy transfer work moves to a Rust
worker. This adds native file-panel and filesystem access selected by the user,
but no entitlement, background service, remote code, or network behavior.

No `tauri-plugin-dialog` is proposed. Although official and cross-platform, its
current native stack would also add plugin initialization, a frontend command
surface, filesystem-path types, `tauri-plugin-fs`, `rfd`, and platform backend
dependencies. The macOS-first direct AppKit binding is narrower for I07. Raw
handwritten Objective-C declarations, shelling out to `osascript`, browser file
inputs/downloads, broad filesystem plugins, and platform-agnostic dialog crates
are rejected for larger unsafe, IPC, process, dependency, or WebView surfaces.

Capabilities add only the six exact command permissions above. No filesystem,
dialog-plugin, shell, opener, HTTP, clipboard, process, or generic command
permission and no CSP source is added. Generated permission schemas may change
only as the normal consequence of registering those exact commands.

## Verification proposal

### Golden and parser tests

- Golden bytes for preamble, all six entry payloads, entry prefix, manifest,
  export-key info, authentication AAD, and trailer, with every offset asserted.
- Minimum package and exact maximum counts/length arithmetic; count/size limit
  plus one; `u32`/`u64` overflow; huge declared payload; short read; appended
  byte; duplicate/omitted/out-of-order entry; unknown type/version/flag.
- Tamper each header, wrapper, schema, nonce, record, digest, body digest,
  manifest copy, salt/ID, auth nonce/tag, marker, and total-length field.
- A fixed-seed deterministic mutation harness over a bounded valid corpus,
  including bit flips, splice/delete/duplicate/reorder, hostile lengths and
  truncation. It proves reproducible exercised cases only, not exhaustive
  coverage, sanitizer behavior, or independent fuzz review.

### Restore and nonce evidence

- Real vault with notes/instructions, composed/decomposed Unicode, empty
  attachment, and exact 786,432-byte attachment.
- Import into an empty controlled destination, restart locked, unlock, and
  compare every logical item/attachment plus exact record IDs, generations,
  timestamps, frames, header/wrappers, migration metadata, and nonce ledger.
- Two independently generated valid packages from one unchanged snapshot;
  random package metadata differs, body digest agrees, and both restores are
  equivalent.
- Consumed-unused nonce reservations survive. Ledger omission/purpose change/
  duplication fails. Later writes after restart use a new reservation and do
  not reuse historical nonces.
- Wrong password and corrupt master/header/recovery wrappers fail without a
  target. Recovery-wrapper authenticity is established through header binding;
  no unavailable SRS/ERC path is claimed.

### Snapshot, filesystem, and crash evidence

- Coordinate writers before/after the snapshot's first read and during every
  entry class; restored output matches exactly one committed state.
- Inject failures and subprocess exits before/after temp creation, every write
  class, flush, file sync, verification, no-replace link, each directory sync,
  temp unlink, quarantine copy, stage creation, SQLite insert/checkpoint/close,
  stage verification, and import publication.
- Real existing regular target, symlink, hard link, FIFO/special file, parent/
  leaf swap, source mutation, permission denial, read-only directory, and
  competing no-replace link. Deterministic short-write and `ENOSPC` adapters
  cover disk exhaustion without filling the user's real disk.
- Verify exact stale cleanup accepts only old recognized files and leaves young,
  unrelated, malformed, multi-link, wrong-owner/mode, symlink, directory, and
  special entries untouched.

### Privacy, IPC, UI, and boundary evidence

- Scan the package, export temp, quarantine, SQLite stage/main/WAL/SHM/journal,
  errors, captured logs, browser stores, IPC bodies/responses, and generated
  filenames for conspicuous synthetic title/body/contact/filename/media/content,
  password, ERC, SRS, VDK, and EAK markers.
- Strict request/response tests for all six commands; wrong body/field/type;
  raw or oversized package-body attempts and the absence of a package chunk
  endpoint; noncanonical/expired/reused/wrong-kind selection and operation IDs;
  progress monotonicity; cancel races; explicit-lock join; locked/
  uninitialized/initialized denial; no path or byte exposure.
- React flow tests for both locales, warnings, confirmations, progress/cancel,
  failure/completion, overwrite/rollback/recovery limitation, keyboard/focus/
  live-region behavior, and no browser persistence.
- Native macOS test with synthetic data exercises save/open panels, completed
  export/import/unlock, panel cancel, transfer cancel, and overwrite refusal;
  cleanup verifies no persistent synthetic vault/package remains unexpectedly.
- Static inspection confirms exact dependencies/features/commands/capabilities,
  no runtime network/server/telemetry/remote asset, no secret export, no broad
  filesystem/plugin permission, and no I08/I09/I13/I14 work.

After focused checks, run exact pinned-toolchain `npm run check` and
`npm run desktop:build`. I07 is not acceptable if interruption, tamper,
restore-equivalence, two-copy, privacy, nonce, canonical checks, build, or
native macOS evidence is missing.

## Approval requested

Explicit approval is requested for all of the following as one narrow I07
checkpoint:

1. portable package v1, its `.aeterna-vault` extension, exact byte layouts,
   limits, deterministic order, compatibility table, leakage, and no archive or
   raw-SQLite behavior;
2. the byte-exact domain-separated HKDF/AES-GCM package-authentication use and
   its probabilistic per-package key/nonce analysis;
3. read-only snapshot export and two-pass authenticated import/repository
   reconstruction with no-replace publication and exact crash/stale rules;
4. same-lineage, master-password-only restoration that preserves but cannot use
   I06 recovery state and defers production new-device binding/rewrap;
5. macOS-only native file panels, six typed commands, Rust-only paths/bytes,
   progress/cancellation/session behavior, and bilingual UI contract; and
6. the exact direct `libc 0.2.189` pin, exact `objc2-app-kit 0.3.2` feature
   expansion, and no plugin/npm/new-crypto/archive dependency.

Approval does not authorize a later format version, changed bounds or crypto,
overwrite/merge, recovery/device binding, cloud/sync, lifecycle hardening,
Windows qualification, signing, publishing, or deployment.

## Approval record

The user explicitly approved the proposal on 2026-09-22. Before implementation,
inspection found that the accepted I05 migration identifier is the 15-byte
`create_vault_v1`, not the proposed 16-byte `initial_vault_v1`. The user then
explicitly approved the byte-level correction recorded above: the schema payload
is 98 bytes, the minimum body is 873 bytes, and the minimum package is 1,161
bytes. All other approved bytes, bounds, cryptographic uses, dependencies, and
scope remain unchanged.
