# I06 — Vault item and bounded-attachment MVP

- Status: Accepted on 2026-09-22
- Baseline: `8a6e03e33a7e2fdf43143a4c5f0a321366d7cac3`
- Governing decisions: ADR 0002, ADR 0005, ADR 0007, and ADR 0008
- Proposal: [`../research/I06-item-attachment-ipc-proposal.md`](../research/I06-item-attachment-ipc-proposal.md)
- Results: [`../research/I06-vault-item-results.md`](../research/I06-vault-item-results.md)

## Objective

Add the smallest truthful desktop workflow that lets a user initialize or
unlock an app-owned local vault with a master password and create, list, open,
edit, and delete encrypted notes and instructions with bounded attachments.
All item fields and attachment metadata/content remain inside an authenticated
I05 record. Rust owns validation, serialization, session authority, optimistic
revisions, encryption, persistence, and filesystem decisions. React owns only
localized presentation and interaction.

The exact item payload, attachment bound, unlocked-session model, onboarding
limitation, IPC surface, and capability changes in ADR 0008 required
explicit user approval before any source, manifest, lockfile, Tauri
configuration/capability, or persistence behavior is changed.

## In scope after approval

- A versioned Rust item domain for `note` and `instruction` records with exact
  field, collection, encoding, identifier, timestamp, and size rules.
- One atomic encrypted I05 record per item, including its bounded attachment
  metadata and bytes; no schema migration or side attachment file.
- An aggregate attachment-content limit of exactly 786,432 bytes per item,
  with at most eight attachments and a separately enforced 1,048,576-byte
  encoded-item ceiling.
- An app-owned vault at a fixed Rust-resolved application-local-data path.
- A Rust-managed state machine for uninitialized, locked, and unlocked states;
  restart begins locked and explicit lock immediately drops the unlocked
  handle and any pending attachment-import metadata.
- A clearly labeled development-local initialization path that uses only the
  master-password wrapper and discards the generated recovery material. It
  must state that recovery, export, and backup are unavailable and that the
  user must not store irreplaceable data.
- Typed, purpose-specific Tauri commands for status, initialization, unlock,
  lock, item CRUD, and attachment prepare/commit/read/remove/cancel.
- A standard HTML file input for user-selected attachment bytes, optimized raw
  Tauri IPC for attachment upload/download, and no WebView filesystem path.
- An English-default and Simplified Chinese UI with accessible forms, keyboard
  save behavior, unsaved-change handling, destructive-delete confirmation,
  safe fixed error-code localization, and best-effort plaintext clearing.
- Focused Rust domain/repository/IPC tests, React user-flow tests, and real-file
  privacy, tamper, restart, conflict, and exact-boundary tests.
- Documentation updates that record the accepted behavior and evidence.

## Explicit exclusions

- No I07 export/import, save-to-disk attachment command, streaming encryption,
  official backup, live-database copy workflow, or file-system migration.
- No I08 automatic inactivity, sleep, window, session, or lifecycle lock;
  production activity agent; autostart; tray; support-floor qualification; or
  notification work.
- No I09 networking, account/device binding, device registration, protocol,
  signed request, server, sync, or remote storage behavior.
- No I13 recovery claim/SRS acquisition/ERC entry or display, and no I14 owner
  recovery, password-reset, recovery rotation, or post-release rekey flow.
- No updater, telemetry, remote asset, runtime download, production signing,
  deployment, Windows qualification, or control-plane work.
- No schema, migration, crypto algorithm, KDF, key hierarchy, wrapper, record
  frame/AAD, nonce policy, or 1,048,576-byte I05 record-limit change.
- No raw SQL, arbitrary path, raw key/VDK, generic encrypt/decrypt, generic file
  read/write, shell, clipboard, HTML rendering, or generic execution IPC.
- No attachment execution, external opening, media decoding, or authoritative
  trust in a filename extension or media-type hint.

## Dependencies and prerequisites

1. The task starts from exact clean baseline
   `8a6e03e33a7e2fdf43143a4c5f0a321366d7cac3`.
2. I05 and ADR 0007 remain Accepted and authoritative for the SQLite schema,
   record ceiling, encryption/framing, nonce reservations, transactions,
   migrations, and persistence failure behavior.
3. ADRs 0002 and 0005 remain authoritative for cryptographic wrappers and I06
   ownership of the initial bounded-attachment policy.
4. The user explicitly approves the complete I06 proposal and proposed ADR
   0008 before implementation begins.
5. The pinned Node, npm, Rust, Cargo, Tauri, React, and test toolchains remain
   the repository-native verification environment.

## Approval boundaries

### Required before implementation

Explicit approval must cover:

- the exact payload v1 fields, binary encoding, bounds, lack of Unicode
  normalization, unknown-version behavior, and migration ownership;
- the single-record atomicity model and 786,432-byte aggregate attachment cap;
- the master-password-only development-local onboarding limitation and
  disposal of inaccessible recovery material;
- the Rust session state, fixed app-local path, command schemas, raw binary
  attachment transfer, optimistic revision behavior, and fixed error codes;
- the exact main-window command allowlist and removal of the I00 smoke command;
  and
- the decision to add no new crate, npm package, Tauri plugin, filesystem
  permission, dialog permission, shell permission, or CSP source.

Approval authorizes only this I06 implementation. It does not approve a future
payload version, larger attachment, streaming format, schema migration,
export/import package, recovery flow, lifecycle lock, network capability, or
production-readiness claim.

### Requires a separate later decision

- Any new production dependency or Tauri plugin.
- Any new SQLite table/column/migration or side-file attachment format.
- Any change to accepted cryptography, wrappers, AAD, KDFs, nonce allocation,
  or the I05 record ceiling.
- Any automatic lifecycle lock, file export, external open, recovery, network,
  telemetry, sync, updater, or server behavior.

## Acceptance criteria

I06 is eligible for acceptance only when all of the following are true:

1. A user can initialize the explicitly labeled development-local vault,
   explicitly lock it, restart the host, unlock it with the correct master
   password, and receive only fixed safe errors for wrong or invalid input.
2. A user can create, list, open, edit, and delete both notes and instructions;
   every mutation uses an expected revision and stale update/delete attempts
   fail without lost data.
3. Lists are produced only by decrypting and validating every returned item.
   Titles, kinds/categories, contact explanations, bodies, attachment names,
   media types, and attachment bytes do not appear in SQLite columns, WAL,
   SHM, journals, temp files, logs, browser storage, URLs, or app-created
   filenames.
4. Payload v1 is byte-exact, bounded, and fail-closed for unknown version/kind,
   truncation, trailing bytes, invalid UTF-8, impossible lengths, invalid
   collection counts, duplicate attachment IDs, and item/record mismatch.
5. Attachment add, read, replace, remove, and enclosing-item delete work. One
   786,432-byte attachment succeeds when other fields are within bounds;
   786,433 bytes and aggregate limit violations fail before persistence.
6. Empty files, duplicate names/content, Unicode names/text, invalid metadata,
   misleading extension/media type, malformed raw upload, expired/cancelled or
   replayed upload identifier, and hostile-size cases follow ADR 0008 exactly.
7. An item and all attachments are one encrypted record. Every successful
   mutation is one compare-and-set replacement or delete, and injected failure
   leaves the prior complete record readable with no partial attachment state.
8. Item payload version/AAD/ciphertext tamper, truncation, invalid UTF-8 or
   lengths, wrong-vault access, and record substitution all fail closed without
   returning partial plaintext.
9. Locked and uninitialized states deny every content command. Explicit lock
   immediately drops Rust session authority, invalidates pending uploads, and
   causes later item/attachment commands to return `vault_locked`.
10. Every JSON request is manually deserialized inside the command from the
    Tauri request body with unknown fields denied. Missing, extra, wrong-type,
    noncanonical identifier/revision, and oversized values return a fixed
    machine-readable error. Raw attachment commands reject wrong body form,
    missing/invalid headers, size mismatch, and over-limit bodies.
11. The UI has associated labels, logical focus, keyboard-operable controls,
    Command/Ctrl+S save, accessible status/errors/dialogs, localized unsaved-
    change handling, and an explicit destructive-delete confirmation in both
    English and Simplified Chinese.
12. Vault plaintext exists in the WebView only while required for the active
    view/edit/selected attachment. It is never written to localStorage,
    sessionStorage, IndexedDB, URLs, query strings, clipboard, logs, telemetry,
    snapshots, or files; password and attachment buffers are cleared
    best-effort after use.
13. Static and runtime inspection finds no remote asset, runtime networking,
    server dependency, telemetry, export/import, broad filesystem/database/key
    access, or new dependency/plugin/capability beyond the exact command
    allowlist.
14. Documentation and tests agree with the accepted ADR, and all focused and
    canonical checks pass.

## Threat cases

| Threat | Required behavior |
| --- | --- |
| Offline database/side-file copy | User fields and attachment metadata/content remain authenticated ciphertext; only approved I05 structural metadata leaks. |
| Locked or restarted app | Rust has no unlocked VDK handle; all content commands fail with `vault_locked`. |
| Malicious WebView request | Exact command schema, field bounds, canonical IDs/revisions, session state, and Rust domain validation apply before persistence. |
| Oversized attachment or item | Frontend preflight is convenience only; Rust independently rejects the declared and actual raw-body size and the final encoded record. |
| Filename or media-type spoofing | Metadata is display-only, never a path or execution decision; content is not actively rendered or executed. |
| Stale or concurrent edit | I05 generation compare-and-set returns `vault_conflict`; the prior committed item remains intact. |
| Partial attachment mutation | The whole item is re-encrypted and replaced in one record transaction; no side file or partial child row exists. |
| Payload/frame/AAD substitution | Record ID, vault ID, generation, timestamps, and length remain authenticated by ADR 0007; payload parser additionally rejects malformed semantics. |
| WebView persistence/exfiltration | No content storage API, URL, clipboard, network, remote script, log, export, or arbitrary file capability is added. |
| Process or OS compromise while unlocked | Explicitly outside the threat model; best-effort clearing does not claim guaranteed memory erasure. |

## Test matrix

| Area | Required evidence |
| --- | --- |
| Item codec | Golden bytes; every offset/length; note/instruction fields; empty/max fields; Unicode round trip; no normalization; invalid UTF-8; truncation; extension; unknown version/kind/flags; count and arithmetic overflow |
| Domain CRUD | Create/list/open/edit/delete for both kinds; restart/unlock; empty body; maximum fields; invalid title/category/explanation/body; list requires successful decryption |
| Attachments | Add/read/replace/remove/delete; 0 and 786,432 bytes; 786,433 rejection; aggregate limit; eight/nine count; duplicate name/content; Unicode name; invalid filename/media type; misleading metadata; duplicate ID; malformed upload |
| Atomicity | Injected failure before encryption, before compare-and-set, and before commit leaves the exact prior record; no partial attachment state exists |
| Tamper/privacy | Payload version/length/UTF-8 tamper; record frame/AAD/ciphertext substitution; wrong vault; main/WAL/SHM/journal/temp/log/storage/filename marker scans |
| Revisions/concurrency | Stale update/delete/add/replace/remove/read; concurrent text and attachment mutations; exactly one stale-race winner; no lost update |
| Session | Uninitialized and locked denial; correct/wrong unlock; restart locked; explicit lock clears authority and pending upload; late UI response cannot repopulate locked state |
| IPC | Extra/missing/wrong-type/oversized JSON fields; canonical lowercase IDs; zero/unsafe revisions; JSON-vs-raw body confusion; missing/invalid/replayed upload header; raw-size mismatch |
| UI | Initialize/unlock/lock; note/instruction CRUD; list/open; attachment selection/read/remove; unsaved navigation/lock; delete confirmation; keyboard save; focus/labels/live regions; English and Simplified Chinese |
| Boundaries | Exact capability allowlist; no fs/dialog/shell/SQL/key/crypto command; no browser content storage; no URL/clipboard/log/telemetry/export/network path |

Focused tests use conspicuous synthetic data and never print or snapshot secret
or content values. Real-file tests inspect SQLite and every observable side
artifact. Frontend tests with mocked IPC are component/user-flow evidence, not
end-to-end native evidence.

## Verification sequence

After explicit approval and implementation:

1. Run focused Rust item-codec, service, state, IPC-schema, attachment-boundary,
   revision, atomicity, tamper, and real-file privacy tests.
2. Run focused React component and user-flow tests, including accessibility,
   unsaved-change, destructive-delete, locale, and no-browser-storage cases.
3. Inspect the source, manifest/lockfile, capability, CSP, and resolved feature
   diffs for unapproved surface expansion.
4. Run `npm run check` with the exact pinned toolchains.
5. Run `npm run desktop:build`.
6. If a meaningful native run can use only the approved development-local
   initialization path, exercise it and label its exact scope. Do not describe
   mocked UI tests or this recovery-less preview as production end-to-end
   evidence.
7. Compare the observed results with every acceptance criterion and record all
   gaps before recommending a status.

## Completion report contract

The final I06 report must state:

- changed behavior, final payload version, exact attachment bound, onboarding
  limitation, and session/IPC boundary;
- main source, test, capability, localization, ADR, and design files;
- exact focused and canonical commands with real results;
- native runtime scope, unverified behavior, residual risks, and deferred work;
  and
- one exact recommendation: `Accepted`, `In Progress`, or `Blocked`.

I06 cannot be Accepted if any required security/privacy, exact-boundary,
real-file, IPC-schema, bilingual UI, canonical check, or desktop build evidence
is missing. I07 must not start in this task.
