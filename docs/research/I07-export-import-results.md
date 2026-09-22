# I07 atomic encrypted export/import results

- Date: 2026-09-22
- Baseline: `98069e58e71c9ff728983197ced9d87dcb9dd5da`
- Decision: [ADR 0009](../adr/0009-portable-export-package-and-atomic-restore-v1.md)
- Proposal: [I07 export/import format and dependency proposal](./I07-export-import-format-and-dependency-proposal.md)
- Recommendation: **Accepted**

## Delivered behavior

I07 adds a macOS-native encrypted export and same-lineage restore workflow for
the accepted local vault. Rust owns paths, package bytes, snapshotting,
authentication, validation, staging, and no-replace publication. The WebView
receives only strict one-shot selection IDs, operation IDs, bounded progress,
and fixed error codes. The capability surface adds exactly six commands and no
filesystem, dialog, shell, network, archive, or generic execution plugin.

Portable package v1 follows the approved 96-byte preamble, ordered framed body,
128-byte manifest, and 64-byte authenticated completion trailer. The corrected
15-byte `create_vault_v1` migration identifier produces a 98-byte schema
payload, 873-byte minimum body, and 1,161-byte minimum package. Export derives
one package-specific EAK with the approved 56-byte HKDF-SHA-256 info and uses
AES-256-GCM over empty plaintext with the exact 294-byte AAD. It preserves the
authenticated header, exact wrappers, every historical nonce reservation, and
unchanged encrypted record frames; it never writes plaintext item or attachment
content into the package framing.

Export holds one deferred SQLite read transaction, validates decrypted items
one record at a time, writes a same-directory mode-0600 temp, synchronizes it,
and publishes by no-replace hard link. Ordinary WAL writers can continue, and
an explicit lock marks the session locked, cancels and joins export, and only
then responds. Import retains a no-follow source descriptor, copies into a
private quarantine descriptor, rechecks source identity, authenticates and
validates all records before creating a database stage, reconstructs only with
the compiled schema and fixed statements, reopens through the repository, and
publishes only to an absent fixed target. Restart performs age-gated cleanup of
strictly recognized old import artifacts; an unlocked export additionally
authenticates a completed old export candidate before deletion.

The UI provides English-default and Simplified Chinese warnings for metadata
leakage, rollback, no overwrite, unavailable development recovery, progress,
cancellation, completion, and failure. Native AppKit panels select one
`.aeterna-vault` file. The exact selected path and all package bytes remain in
Rust.

## Verification evidence

The host was Apple Silicon macOS. Verification used pinned Node 24.21.0, Rust
1.98.1, and Cargo 1.98.1.

| Command                                                                                                                                                                                            | Result                                                                                                                                                                                                                                                                                         |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cargo test --manifest-path src-tauri/Cargo.toml --locked real_vault_round_trip_two_copy_and_tamper_boundaries -- --nocapture`                                                                     | Passed the real-file I07 round trip, two-copy, attachment-boundary, fixed-seed mutation, cancellation-phase, concurrent-snapshot, source-change, no-replace-race, path-kind, privacy, restart, and later-write nonce checks.                                                                   |
| `cargo test --manifest-path src-tauri/Cargo.toml --locked ipc::tests:: -- --nocapture`                                                                                                             | Passed 5 IPC/session boundary tests, including strict new request shapes, one-shot/expired IDs, monotonic progress, raw body rejection, and lock cancellation/join.                                                                                                                            |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked vault::transfer::acceptance_tests::deterministic_io_failures_and_short_writes_preserve_atomicity -- --exact --nocapture`           | Passed deterministic short-write, `EIO`, `ENOSPC`, and `EDQUOT` injection across export and import write, flush, file-sync, SQLite, link, unlink, and directory-sync boundaries in 57.02 seconds.                                                                                              |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked vault::transfer::acceptance_tests::subprocess_crashes_leave_only_absent_or_complete_targets -- --exact --nocapture`                | Passed independent-process exits across 18 export and 23 import states in 57.30 seconds. Every final target was absent before publication or complete and independently verifiable afterward.                                                                                                  |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked vault::transfer::acceptance_tests::stale_cleanup_is_authenticated_exact_and_age_gated -- --exact --nocapture`                      | Passed the real 24-hour threshold and exact-name, ownership, mode, type, link-count, package-ID, and completed-package-authentication cleanup rules while retaining unrelated or unrecognized files.                                                                                           |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked vault::transfer::acceptance_tests::permissions_read_only_directories_and_special_files_fail_closed -- --exact --nocapture`         | Passed real permission denial, mode-0500 destination, FIFO target, directory source, and absent-target checks.                                                                                                                                                                                 |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked vault::transfer::acceptance_tests::destination_parent_swaps_are_detected_before_publication -- --exact --nocapture`                | Passed real export and import destination-parent replacement races. Retained descriptors were not redirected, replacement directories remained untouched, and publication failed before a target appeared.                                                                                     |
| `cargo test --manifest-path src-tauri/Cargo.toml --lib --locked vault::transfer::acceptance_tests::exact_maximum_package_is_valid_and_limit_plus_one_is_rejected -- --exact --ignored --nocapture` | Materialized an exact 1,073,741,824-byte package with 1,156 valid encrypted item records, then passed full package authentication and bounded record-by-record decryption in 568.33 seconds. The same package plus one byte failed at the size gate.                                           |
| `npm test`                                                                                                                                                                                         | Passed 20 tests in 3 frontend test files, including export, import, cancellation, failure, focus, live status, strict response parsing, both locale resources, and capability inspection.                                                                                                      |
| `npm run check`                                                                                                                                                                                    | Passed Prettier, ESLint, TypeScript, 20 frontend tests, frontend build/asset inspection, Rust formatting, Clippy, 85 Rust unit tests with the separately executed 1-GiB test reported as the sole ignored manual test, 9 I05 integration tests, 5 I06 integration tests, and all-target check. |
| `npm run desktop:build`                                                                                                                                                                            | Passed and produced `src-tauri/target/release/aeterna-desktop`. The known non-fatal local `rust-objcopy`/missing `libLLVM.dylib` stripping warning remained.                                                                                                                                   |
| `./node_modules/.bin/tauri build --bundles app`                                                                                                                                                    | Passed and produced the local unsigned `Aeterna.app` used only for native verification, with the same known non-fatal stripping warning.                                                                                                                                                       |

### Security and behavior matrix

| Area                       | Observed evidence                                                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Format and authentication  | Exact approved constants, minimum arithmetic, schema bytes, entry prefix, HKDF info, trailer, and 294-byte AAD have focused checks. EAK authentication round trip and info/AAD/tag tamper rejection pass. Unknown versions, flags, counts, hostile lengths, KDF bounds, and compatibility fields fail closed.                                                                                                                               |
| Equivalence and privacy    | A note/instruction with Unicode, an empty attachment, and an exact 786,432-byte attachment restored with logical content, IDs, revisions, timestamps, exact encrypted record rows, exact wrappers/header, and the complete nonce ledger. Package and SQLite artifacts were scanned for synthetic password, title, body, contact, and attachment-name markers.                                                                               |
| Two-copy and nonce safety  | Two exports of one unchanged snapshot had different package ID/salt/authentication material, identical encrypted bodies, and equivalent restores. Restart followed by a later write retained every historical reservation/record and added one fresh reservation and record.                                                                                                                                                                |
| Snapshot and interruption  | A writer committed after the export snapshot was established while export was paused; the package restored exactly the earlier snapshot. Cancellation at preparing, snapshotting, writing, verifying, copying, validating, authenticating, reconstructing, and verifying phases left no target or staging artifact. A changing import source and export/import no-replace races failed without replacing the competing file.                |
| Atomic filesystem behavior | Deterministic short-write, `EIO`, `ENOSPC`, and quota injection covered every write, flush, sync, SQLite reconstruction, link, unlink, and cleanup class. Forty-one independently terminated child operations proved crash states expose only an absent target or a complete verifiable target. Real permission, read-only-directory, FIFO, and directory-source cases failed closed.                                                       |
| Stale recovery             | A real 25-hour timestamp fixture removed only exact private recognized import artifacts, incomplete export artifacts, and cryptographically authenticated completed export artifacts. Young, unrelated, malformed, invalid-authentication, wrong-mode, three-link, symlink, directory, and special candidates remained untouched.                                                                                                           |
| Maximum boundary           | The manual heavy fixture streamed an exact 1-GiB package containing 1,156 valid encrypted item records, authenticated the complete package, decrypted and validated every record with bounded memory, and rejected the same package after a one-byte extension. Maximum count arithmetic and limit-plus-one fields are covered separately without allocation amplification.                                                                 |
| Tamper and hostile paths   | A fixed seed `0x7a6d3c19842155e3` generated 64 bounded body mutations. Explicit package ID, salt, entry version, manifest, trailer version/algorithm/purpose/flags/nonce/tag/length/reserved, truncation, appended byte, KDF metadata, and migration compatibility mutations failed. Existing targets, symlink targets/sources, hard-link targets/sources, destination-parent swaps, wrong password, and invalid record data failed closed. |
| IPC and session            | Native selection returned only a canonical ID after a real serialization-shape regression was found and fixed. Requests deny unknown fields and path/package-body injection. Selection IDs expire and are one-shot; progress is monotonic; terminal operations are retained briefly; completed import reconciles to locked even after expiry; explicit lock cancels and joins export.                                                       |
| Boundary inspection        | The lockfile adds only the direct already-resolved `libc` edge. AppKit uses exactly the approved feature expansion. Static inspection found no runtime network, remote asset, telemetry, archive, shell, raw SQL/key/crypto command, broad filesystem capability, or package chunk endpoint.                                                                                                                                                |

## Native macOS evidence

The exact locally built unsigned `Aeterna.app` was launched by path so an older
development app with the same bundle identifier could not be mistaken for the
I07 build. Accessibility inspection confirmed the I07 English and Simplified
Chinese setup warnings and labels.

The public AppKit import panel showed one-file selection and cancellation. A
disposable synthetic vault was then initialized, and the AppKit save panel
showed the `.aeterna-vault` default. Export completed as a 1,161-byte,
mode-0600, seven-entry package. After moving the synthetic source vault aside,
the AppKit open panel selected that package; the rollback/recovery warning was
confirmed; import completed into the absent fixed target; the UI returned
locked; and the same synthetic password unlocked the restored vault.

Selecting the same export name displayed the native replacement warning, but
Aeterna's Rust no-replace publication still failed with the localized safe
error. The package SHA-256 remained
`fb3538b7a2821b1ceb07d4d65bec12815c4352a81ab0d56b4c333321b2b6c04d`.
The synthetic source vault, restored vault, and package were then deleted and
their absence verified. No user vault or pre-existing package was modified.

Native verification exposed one real IPC response mismatch that mocks had not
caught: the tagged Rust enum initially serialized `selection_id` while the
approved frontend contract requires `selectionId`. The field annotation was
corrected, a Rust serialization regression assertion was added, the bundle was
rebuilt, and the complete native export/import sequence then passed.

## Acceptance reconciliation

All seventeen I07 acceptance criteria now have implementation and direct
evidence. Normal, hostile-input, cancellation, race, deterministic filesystem
failure, subprocess interruption, stale recovery, exact maximum package, full
verification, desktop build, and native macOS workflows pass. No format,
cryptographic, permission, destination, or overwrite rule was weakened to make
the evidence pass.

The fixed-seed mutation suite remains bounded and reproducible rather than
exhaustive. Coverage-guided fuzzing, sanitizers, independent cryptographic
review, and penetration testing remain the later security gates explicitly
identified by the approved brief. Rollback freshness, cross-copy probabilistic
nonce uniqueness, production new-device binding, and operational recovery also
remain assigned to their later decisions.

The exact I07 recommendation is **Accepted**. I08 is eligible but was not
started as part of this work.
