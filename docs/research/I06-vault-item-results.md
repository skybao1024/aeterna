# I06 vault item and bounded-attachment results

- Date: 2026-09-22
- Baseline: `8a6e03e33a7e2fdf43143a4c5f0a321366d7cac3`
- Decision: [ADR 0008](../adr/0008-vault-item-payload-and-session-ipc.md)
- Proposal: [I06 item and attachment IPC proposal](./I06-item-attachment-ipc-proposal.md)
- Recommendation: **Accepted**

## Delivered behavior

I06 adds the first useful local desktop workflow on top of the accepted I05
repository. A user can initialize the explicitly development-only vault,
create and edit encrypted notes and instructions, list and reopen them, delete
them, manage bounded attachments, explicitly lock, and unlock after restart.
The UI keeps the no-recovery, no-backup, no-export, and no-server warning
visible while unlocked. It does not claim production onboarding or recovery.

Rust owns the fixed
`app_local_data_dir()/vault/aeterna-vault.sqlite3` path, validation, item
serialization, encryption, persistence, revision checks, and the
uninitialized/locked/unlocked state machine. React owns localized interaction
only. Explicit lock drops the unlocked Rust handle and pending upload before
responding, clears the WebView view and draft immediately, advances a session
epoch, and prevents late responses from restoring plaintext UI state. Restart
loads an existing vault locked.

Payload v1 uses the accepted byte-exact `AETRITM\0` binary format. Each item
and every attachment's metadata and bytes occupy one authenticated I05 record,
so text and attachment mutations use the same atomic compare-and-set revision.
It permits at most eight attachments and exactly 786,432 aggregate content
bytes. The maximum valid encoded item is 929,358 bytes, below the unchanged
1,048,576-byte I05 plaintext ceiling. No schema, migration, crypto, record
frame, AAD, KDF, nonce, or storage-transaction format changed.

The main window has exactly fourteen purpose-specific commands for status,
development initialization, unlock/lock, item CRUD, and attachment
prepare/commit/cancel/read/remove. JSON bodies use explicit
`deny_unknown_fields` schemas and canonical lowercase IDs/revision strings.
Attachment commits and reads use raw bytes; one five-minute pending upload
descriptor is consumed on every terminal commit result and cannot be replayed.
The WebView never receives a filesystem path. The previous smoke permission
was removed, and no dialog, filesystem, shell, SQL, HTTP, clipboard, generic
crypto, generic file, or generic execution capability was added.

## Verification evidence

The host was Apple Silicon macOS 26.3. Verification used pinned Node 24.21.0,
npm 11.19.0, Rust 1.98.1, and Cargo 1.98.1.

| Command                                                                                          | Result                                                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cargo test --manifest-path src-tauri/Cargo.toml vault::item:: --lib --locked -- --nocapture`    | Passed 7 focused codec/domain unit tests.                                                                                                                                                                     |
| `cargo test --manifest-path src-tauri/Cargo.toml ipc::tests:: --lib --locked -- --nocapture`     | Passed 4 focused boundary tests, including state transitions, strict JSON, raw transfer, descriptor consumption, replay denial, and restart unlock.                                                           |
| `cargo test --manifest-path src-tauri/Cargo.toml --test i06_vault_items --locked -- --nocapture` | Passed 5 real-file integration tests.                                                                                                                                                                         |
| `npm test`                                                                                       | Passed 14 tests in 3 frontend test files.                                                                                                                                                                     |
| `npm run check`                                                                                  | Passed Prettier, ESLint, TypeScript, 14 frontend tests, frontend build/asset inspection, Rust formatting, Clippy, 72 Rust unit tests, 9 I05 integration tests, 5 I06 integration tests, and all-target check. |
| `npm run desktop:build`                                                                          | Passed and produced `src-tauri/target/release/aeterna-desktop`; the known non-fatal `rust-objcopy`/missing `libLLVM.dylib` stripping warning remained.                                                        |
| `git diff --check`                                                                               | Passed after the final documentation update.                                                                                                                                                                  |

### Behavior and failure matrix

| Area                      | Observed evidence                                                                                                                                                                                                                                                                                                                                                |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Item codec                | Exact minimal golden bytes, note/instruction and Unicode round trips, maximum 929,358-byte payload, exact attachment boundary, invalid field rules, unknown/truncated/extended/invalid-UTF-8 payloads, duplicate IDs, and redacted debug output passed.                                                                                                          |
| Item lifecycle            | Note and instruction create/list/open/update/delete, restart/unlock, wrong password, stale update/delete, and list decryption/validation passed against the real repository.                                                                                                                                                                                     |
| Attachments               | Add/read/replace/remove, empty content, duplicate name/content, Unicode name, misleading type metadata, eight attachments, ninth rejection, 786,432-byte success, 786,433-byte rejection, aggregate enforcement, stale revisions, raw body mismatch, cancellation semantics, and replay denial passed.                                                           |
| Atomicity and concurrency | Whole-item compare-and-set tests produced one concurrent mutation winner and one conflict with no lost update or partial attachment state. Existing I05 injected transaction/interruption evidence remains unchanged and applies to the reused record replacement boundary.                                                                                      |
| Tamper and privacy        | Non-item and unknown payload versions failed closed. Synthetic title, body, contact, filename, media type, and attachment markers were absent from the real SQLite main file and observable WAL, SHM, and journal artifacts. No plaintext side file or app-created content filename exists.                                                                      |
| Session and IPC           | Uninitialized and locked content access failed with fixed codes; explicit lock invalidated content authority; restart was locked; wrong/correct unlock behaved as specified. Strict schemas, canonical IDs/decimals, JSON/raw confusion, size mismatch, and one-shot upload replay were exercised through the same internal handlers used by the Tauri commands. |
| UI and storage            | Component tests cover setup, item workflow, instruction contact fields, raw attachment interaction, explicit lock, stale-response suppression, unsaved-change dialog paths, delete confirmation, keyboard save, focus return, both locales, and fixed error localization. Browser storage remains limited to locale preference.                                  |
| Boundaries                | Source/config inspection found the exact fourteen-command handler and capability allowlist, no new CSP source, no runtime network path, and no new dependency, Tauri feature/plugin, lockfile entry, migration, or schema change.                                                                                                                                |

## Native runtime scope

An unsigned macOS application bundle built from the I06 source was launched as
a real native process. Its first Rust `vault_status` call showed the
uninitialized setup screen, and accessibility inspection confirmed the
Simplified Chinese form, warning, password labels, and standard HTML file
input. Switching locale showed the corresponding English labels and the exact
development/no-recovery warning.

The actual development App ID data directory was deliberately not initialized:
doing so would create unrecoverable test data in the user's persistent
application storage. The expected
`~/Library/Application Support/dev.aeterna.desktop.foundation/vault/aeterna-vault.sqlite3`
file was confirmed absent afterward, and the app was quit. Native item CRUD is
therefore not claimed; the real repository/file tests, IPC-handler tests, and
frontend tests cover those layers independently.

## Residual risk and deferred scope

- Initialization intentionally discards inaccessible recovery material.
  Forgetting the master password permanently loses access; this preview must
  not contain irreplaceable data.
- I06 implements explicit and restart locking only. Sleep, inactivity,
  window/session events, production activity integration, and autostart remain
  I08 work.
- Whole-item encryption temporarily holds bounded plaintext in the Rust process
  and active plaintext in the WebView. Best-effort zeroization cannot guarantee
  removal from allocator copies, swap, snapshots, or a compromised process.
- I06 trusts neither filename nor media type and does not actively render,
  execute, externally open, save, export, or scan attachments.
- Windows behavior, the macOS 15 support floor, production signing/notarization,
  fuzzing, sanitizers, independent security review, and penetration testing
  remain deferred to their existing gates.
- The known non-fatal `rust-objcopy` warning caused by the unavailable local
  `libLLVM.dylib` may remain during the unsigned desktop build; it does not
  prevent the host executable from being produced.
- I07 export/import, I08 lifecycle hardening, I09 networking/device binding,
  and I13-I14 recovery remain unimplemented and unauthorized by this work.

The exact I06 recommendation is **Accepted**. I07 becomes eligible, but was not
started in this task.
