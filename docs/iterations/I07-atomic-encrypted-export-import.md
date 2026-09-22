# I07 — Atomic encrypted export and import

- Status: Accepted
- Baseline: `98069e58e71c9ff728983197ced9d87dcb9dd5da`
- Governing decisions: ADR 0002, ADR 0005, ADR 0007, and ADR 0008
- Accepted decision: [ADR 0009](../adr/0009-portable-export-package-and-atomic-restore-v1.md)
- Proposal: [I07 export/import format and dependency proposal](../research/I07-export-import-format-and-dependency-proposal.md)
- Evidence: [I07 export/import results](../research/I07-export-import-results.md)

## Objective

Add a bounded, authenticated, versioned, encrypted export package and a
crash-safe import path for the accepted local vault. Export reads one committed
SQLite snapshot and streams only authenticated ciphertext and required
structural metadata to a same-directory temporary file before no-replace
publication. Import copies a selected package into an app-controlled quarantine
file, validates the complete package and every encrypted record, constructs a
fresh SQLite vault through the Rust repository, verifies it, and publishes it
only at the fixed app-owned path when no vault already exists.

I07 restores the same local vault lineage under its master password. It does
not register a new device, create a new SRS or recovery wrapper, transfer a
device signing secret, merge vaults, or claim production cross-device or
emergency recovery.

## In scope after approval

- Portable package v1 with extension `.aeterna-vault`, exact byte encodings,
  explicit package/manifest/authentication versions, deterministic entries,
  fixed limits, per-entry digests, a package digest, and an authenticated
  completion trailer.
- A new domain-separated export-authentication key derived from the VDK with
  HKDF-SHA-256, and AES-256-GCM authentication of the exact package metadata.
  The byte layout and key/nonce analysis are in ADR 0009 and require explicit
  security approval.
- Export of the exact authenticated header, master wrapper, recovery wrapper,
  migration compatibility data, encrypted record identities/frames, and every
  nonce reservation, including consumed-but-unused reservations.
- A single SQLite read transaction for one committed export snapshot while
  ordinary writers may continue through WAL. Explicit lock cancels and joins
  an active export before the lock response drops the last VDK owner.
- Streaming Rust I/O in bounded chunks. Package bytes and filesystem paths do
  not enter the WebView or IPC.
- macOS native open/save panels through the already pinned `objc2` binding
  family, plus directory-handle-relative filesystem operations through an
  exact direct pin of the already locked `libc` crate.
- Same-directory mode-0600 export staging, file and directory synchronization,
  no-replace hard-link publication, and narrowly recognized stale-stage
  cleanup.
- Import into app-controlled mode-0600 quarantine and SQLite staging files,
  full validation before staging construction, repository-owned reconstruction,
  final integrity/privacy verification, and no-replace publication.
- One-shot Rust-held file-selection tokens, typed start/status/cancel commands,
  bounded progress polling, cancellation before publication, and fixed English
  machine error codes with localized UI explanations.
- English-default and Simplified Chinese warnings, progress, cancellation,
  overwrite refusal, rollback disclosure, and development-recovery limitations.
- Parser mutation/property tests with deterministic bounded generators, real
  filesystem fault/interruption tests, restore-equivalence tests, privacy scans,
  IPC tests, frontend tests, and native macOS dialog evidence.

## Explicit exclusions

- No ZIP, TAR, compression, serde-defined production format, raw SQLite copy,
  live database copy, sidecar copy, archive extraction, or package resume.
- No overwrite or merge of an existing app-owned vault and no arbitrary import
  destination. An older authentic package may be restored only when the fixed
  target is absent.
- No ERC/SRS entry, claim, password reset, recovery release, recovery-wrapper
  rotation, post-release rekey, new device registration, account/device
  binding, signing-key transfer, server, cloud backup, sync, or upload.
- No I08 lifecycle/activity hardening, autostart, tray, notification, or support
  floor work; no I09 protocol work; no I13/I14 recovery work; no I15 release
  operations.
- No change to ADR 0002 wrapper algorithms/AAD, ADR 0007 header/record AAD,
  record frames, KDF bounds, local schema, item payload, attachment limit, or
  nonce allocation policy.
- No arbitrary filesystem command, path-bearing IPC, raw key/SQL/crypto API,
  shell, generic execution, frontend file plugin, browser download, telemetry,
  remote asset, runtime network path, updater, signing, publication, or deploy.
- No Windows qualification or production support claim. Core format tests stay
  platform-independent; the approved I07 native picker/publication evidence is
  macOS-only.

## Prerequisites

1. The managed worktree and local `main` both resolve to the clean accepted I06
   checkpoint `98069e58e71c9ff728983197ced9d87dcb9dd5da`.
2. I05, I06, ADR 0007, and ADR 0008 remain Accepted.
3. ADR 0002 and ADR 0005 remain authoritative for cryptography and I07 format
   ownership.
4. The user explicitly approves the complete proposal and proposed ADR 0009,
   including the new export-key derivation/authentication use, native feature
   expansion, direct `libc` pin, restoration limitation, and exact IPC surface.
5. The pinned Node, npm, Rust, Cargo, Tauri, SQLite, crypto, and test toolchains
   remain the repository-native verification environment.

## Approval boundary

Before approval, only this brief, the linked research proposal, and proposed
ADR 0009 may change. No source, manifest, lockfile, generated permission,
capability, persistence behavior, migration, or existing product-design text
may change.

Approval authorizes only the exact I07 v1 format and implementation. Any change
to package bytes, limits, key derivation, AES-GCM AAD, dependency version or
feature, IPC command, destination policy, identity semantics, overwrite policy,
or compatibility table stops implementation for renewed approval.

## Threat model

| Threat | Required behavior |
| --- | --- |
| Malicious or truncated package | Reject hostile lengths/counts before allocation or KDF; reject bad framing, order, digest, marker, authentication, record AEAD, or trailing bytes before target publication. |
| Manifest or record substitution | The export authentication tag binds the preamble and manifest; the authenticated manifest binds the exact body digest; ADR 0007 independently binds each record identity and frame. |
| Copied package disclosure | Content and attachment metadata remain encrypted; structural IDs, counts, sizes, timestamps, and KDF parameters leak as documented. Password strength and endpoint security remain material. |
| Local path replacement or TOCTOU | Keep selected paths only in Rust; open the selected directory/file once; use no-follow, directory-relative, create-new, identity/link-count checks and no-replace publication. |
| Existing/symlink/hard-link/special target | Refuse every existing target kind. Import also rejects symlink, multi-link, non-regular, oversized, or changing input files. |
| Partial write, low disk, permission failure, crash, or power loss | Leave only a recognized staging file or a complete published file. Never expose a partial target; synchronize file then directory around publication. |
| Concurrent source mutation | One SQLite read transaction supplies every exported row from one committed snapshot; no mixed view is possible. |
| Explicit lock during export | Set cancellation, stop at a bounded checkpoint, join the worker, drop the VDK owner, then report locked. No export continues with stale session authority. |
| Replay or rollback | Authentic old packages may be restored only into an absent target after an explicit warning. I07 has no global freshness oracle and makes no rollback-prevention claim. |
| Nonce reuse after restore | Restore the complete source reservation ledger and exact record frames. New writes reserve fresh random nonces against that ledger. Cross-copy uniqueness retains ADR 0007's probabilistic limitation. |
| Recovery/device shortcut | Preserve the valid source recovery wrapper and source identity as opaque authenticated state; do not invent SRS, signing credentials, or new-device binding. |
| Compromised unlocked OS | Outside the stated threat model. Bounded zeroization reduces lifetime but cannot guarantee removal from framework, allocator, swap, snapshot, or crash copies. |

## Acceptance criteria

1. Package v1 matches ADR 0009 byte-for-byte, is bounded before allocation,
   uses deterministic entry order, and accepts no unknown or downgraded version.
2. Exporting notes, instructions, Unicode, an empty attachment, and an exact
   786,432-byte attachment then importing into an empty fixed target produces
   the same logical items, attachment bytes, record IDs, generations,
   timestamps, encrypted record frames, wrappers, and historical nonce ledger.
3. Two independently produced packages from an unchanged committed source both
   restore equivalent vaults. Their random package IDs/salts/nonces/tags differ,
   while their encrypted source body and restored logical state agree.
4. Concurrent committed mutations produce exactly one documented source
   snapshot, never a mixture of row versions or nonce state.
5. Exact count, entry, payload, and package byte boundaries succeed. Limit plus
   one, overflow, huge declared sizes, excessive counts, and allocation/KDF
   amplification fail before expensive work.
6. Wrong password, malformed KDF metadata, corrupt master wrapper, header tag,
   recovery wrapper, package authentication, nonce ledger, or record frame
   fails closed and never publishes a target.
7. Tamper tests cover preamble, every entry type/version/order/count/length/
   digest/payload, manifest, body digest, package salt/ID, authentication nonce/
   tag, completion marker, total length, truncation, extension, duplication,
   omission, substitution, and appended bytes.
8. Unknown package, manifest, authentication, trailer, entry, container,
   schema, crypto, wrapper, KDF, header/record AAD, frame, or item versions are
   rejected according to the approved compatibility table.
9. Import fully validates/authenticates the package and all item plaintext one
   bounded record at a time before creating a SQLite stage. It then reconstructs
   through fixed repository statements, verifies the completed vault, and
   publishes only without replacement.
10. Cancellation/interruption at every copy, parse, write, checkpoint, fsync,
    verification, link, directory-sync, and cleanup boundary leaves no partial
    accepted vault or export target. Recognized stale files are handled safely;
    unrelated files remain unchanged.
11. Existing targets, symlinks, hard links, special files, path swaps,
    permission denial, a read-only destination, simulated `ENOSPC`, and
    no-replace races follow ADR 0009.
12. Restart and subsequent record writes from a restored vault cannot reuse any
    historical local nonce. Tampering, omitting, duplicating, or changing a
    reservation or active-purpose mapping is rejected.
13. Packages, export/import temp files, SQLite staging artifacts, logs, errors,
    browser storage, IPC bodies, and app-created filenames contain none of the
    synthetic plaintext/password/ERC/SRS/VDK markers.
14. IPC rejects wrong body types, unknown fields, noncanonical or stale
    selection/operation IDs, locked export, initialized import, expired tokens,
    stale/cancelled operations, unapproved paths, and raw or oversized
    package-body attempts. No package byte or path is returned to the WebView,
    and no package chunk endpoint exists.
15. UI tests cover choose/start/progress/cancel/completion/failure, overwrite
    refusal, rollback and development-recovery warnings, keyboard/focus/live
    region behavior, and English/Simplified Chinese resources.
16. Static/runtime inspection finds no network, server, telemetry, remote
    asset, broad filesystem permission, exported secret, raw SQL/key/crypto
    command, or I08/I09/I13/I14 behavior.
17. Focused tests, bounded mutation/property evidence, `npm run check`,
    `npm run desktop:build`, privacy scans, and meaningful native macOS dialog
    evidence all pass before I07 can be recommended Accepted.

## Test matrix

| Area | Required evidence |
| --- | --- |
| Golden format | Exact preamble, entry, header/wrapper/schema/nonce/record payloads, manifest, HKDF info, AES-GCM AAD, trailer, offsets, total size, and two-copy fixtures |
| Parser bounds | Minimum/maximum file, record and nonce counts, maximum frame/package size, limit+1, checked-add/multiply overflow, huge length, short read, trailing byte, and no pre-KDF allocation amplification |
| Authentication | Wrong password; master/header/recovery/package tag tamper; package ID/salt/nonce substitution; entry/body digest tamper; fixed safe error mapping |
| Record validation | Every frame version/nonce/AAD/tag; item payload v1; notes/instructions; Unicode; zero/boundary attachments; duplicate/missing/substituted records |
| Nonce safety | Full historical ledger round trip, consumed-unused reservations, active-purpose checks, tamper/omission/duplication, restart, later writes, and independent restored copies |
| Snapshot | Writers before/after the first snapshot read, concurrent updates/deletes/nonce reservations, explicit lock/cancel, and no mixed committed view |
| Atomic export | Create/write/flush/fsync/link/directory-fsync/unlink failure and subprocess crash; existing/symlink/hard-link/special targets; destination swap; permissions/read-only/`ENOSPC`; stale cleanup |
| Atomic import | Source copy/change/truncation, quarantine and SQLite-stage failures, full pre-stage validation, repository reconstruction, checkpoint/verify/fsync/link crashes, absent/existing target, and startup recovery |
| Equivalence | Logical item/attachment equality, exact record identity/frame equality, wrapper/header equality, migration compatibility, two independently produced packages, unlock after restart |
| Privacy | Marker scans of package, every staging/SQLite side artifact, errors/logs, WebView storage, IPC, and generated filenames |
| IPC/session | Strict JSON, raw/oversized package-body rejection, absence of a chunk endpoint, token expiry/one-shot use, stale IDs, operation concurrency, progress monotonicity, cancellation, lock join, uninitialized/locked/initialized denial, no paths or bytes |
| UI/native | Both locales, warnings, focus/keyboard/live status, choose/cancel/error states, native macOS open/save panels, overwrite refusal, and a synthetic end-to-end restore |
| Boundaries | Manifest/feature/capability/CSP diff; no plugin, generic fs permission, network, telemetry, remote asset, server, sync, recovery, lifecycle, or Windows claim |

The parser mutation/property suite must use a fixed seed and bounded corpus so
the run is reproducible. It supplements but does not replace coverage-guided
fuzzing, sanitizers, independent cryptographic review, or penetration testing,
which remain later gates.

## Verification sequence after approval

1. Run focused golden/parser/authentication/record/nonce unit tests.
2. Run real-file export/import equivalence, two-copy, concurrency, interruption,
   atomicity, path-race, low-disk, and privacy integration tests.
3. Run strict IPC/session and frontend bilingual/accessibility tests.
4. Run the bounded deterministic parser mutation/property target and report its
   seed, cases, limits, and what it does not prove.
5. Inspect exact dependency features, lockfile, capabilities, CSP, command
   allowlist, and static network/secret/path surfaces.
6. Run `npm run check` and `npm run desktop:build` with the pinned toolchains.
7. Exercise native macOS choose/export/import/progress/cancel/overwrite-refusal
   behavior with conspicuously synthetic data and verify cleanup afterward.
8. Reconcile documentation and every acceptance criterion before recommending
   `Accepted`, `In Progress`, or `Blocked`.

## Completion report contract

The final report must state changed behavior; exact format/authentication and
restoration semantics; main source, test, dependency, capability, localization,
ADR, design, and operating-document files; exact commands and real results;
native macOS evidence; unverified scope; residual privacy/rollback/cross-copy
nonce/device-recovery risks; and one exact recommended I07 status.

I07 cannot be Accepted on compilation or mocked UI alone. Interruption, tamper,
restore equivalence, independent two-copy, privacy, nonce, canonical checks,
desktop build, and native dialog evidence must all pass. I08 must not start in
this task.
