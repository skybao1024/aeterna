# I05 versioned vault storage results

- Date: 2026-09-21
- Task: `01a0c37c-83e4-7b70-a0e2-7d5a760b77e7`
- Baseline: `5a4d92640ac9db4a803e212ce4381eb7cd845752`
- Decision: [ADR 0007](../adr/0007-local-vault-format-v1.md)
- Recommendation: **Accepted**

## Delivered behavior

I05 adds a Rust-owned, local-only encrypted vault repository with no Tauri
command or WebView database/key/filesystem capability. The implemented format
uses SQLite application ID `0x41455452`, container version 1, schema version 1,
crypto version 1, header/record AAD version 1, and record frame version 1.
Migration 1 has the fixed checksum
`04a2fa0e15c62efccb3acfad871f96ac848d69ac21c9f18196fc8767dc439991`.

The repository initializes through a same-directory mode-0600 staging file,
verifies and synchronizes it, and publishes without replacement through a hard
link. Every connection applies the approved defensive SQLite settings and
limits before application-row reads. It rejects symlinks, non-regular files,
oversized main/side files, unexpected schema objects, checksum changes,
foreign-key failures, unknown versions, and inconsistent nonce reservations.

Initialization creates one non-clone, zeroize-on-drop VDK and persists only its
accepted master/recovery wrappers. Password and recovery unlock both verify the
authenticated header before returning an unlocked Rust handle. Password change
uses fresh reserved nonces and salt, compare-and-set replaces the master
wrapper/header, and leaves every encrypted record frame byte-for-byte unchanged.

Opaque records support 0 through 1,048,576 plaintext bytes. Create, update,
read, and delete use exact frame/AAD encodings, fixed safe errors, authenticated
generation/timestamps/IDs/length, and compare-and-set revisions. Plaintext is
encrypted before every SQL bind. Decrypted buffers, VDKs, passwords, ERC
entropy, and recovery salt use existing redacted/zeroizing secret ownership.

Every wrapper, header, or record encryption nonce is first inserted into the
unique reservation ledger. Normal operations commit reservation in an
independent `BEGIN IMMEDIATE` transaction before encryption. Initialization
checks initial nonce uniqueness and writes all initial state atomically in the
unpublished staging database.

## Dependency result

The manifest contains exactly the approved direct dependency:

```toml
rusqlite = { version = "=0.40.2", default-features = false, features = ["backup", "bundled", "limits"] }
```

The lockfile added exactly `rusqlite 0.40.2`, `libsqlite3-sys 0.38.2`,
`fallible-iterator 0.3.0`, `fallible-streaming-iterator 0.1.9`, and
`vcpkg 0.2.15`. The `bundled` feature selects SQLite 3.53.2 and internally
activates rusqlite's bundled modern bindings; no additional direct feature was
declared. Feature-tree inspection found no SQLCipher, OpenSSL, bindgen, async
runtime, pool, URL, hook, virtual-table, serialization, or extension-loading
feature. No project-owned SQLite `unsafe` block was added.

## Verification evidence

The host was Apple Silicon macOS 26.3. Verification used the pinned Node
24.21.0, npm 11.19.0, Rust 1.98.1, and Cargo 1.98.1.

| Command                                                                                                  | Result                                                                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm ci --ignore-scripts`                                                                                | Passed; 260 locked packages installed, audit reported zero vulnerabilities.                                                                                                                         |
| `cargo test --manifest-path src-tauri/Cargo.toml vault:: -- --nocapture`                                 | Passed 11 selected vault unit tests, including a subprocess abrupt-exit reservation test.                                                                                                           |
| `cargo test --manifest-path src-tauri/Cargo.toml --test i05_vault -- --nocapture`                        | Passed 9 real-file integration tests, including an abrupt-writer subprocess.                                                                                                                        |
| `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features --locked -- -D warnings` | Passed with no warning.                                                                                                                                                                             |
| `cargo tree --manifest-path src-tauri/Cargo.toml -e features -i rusqlite` and `-p rusqlite`              | Passed; resolved direct features and transitive packages matched the approval.                                                                                                                      |
| `npm run check`                                                                                          | Passed Prettier, ESLint, TypeScript, 7 frontend tests, frontend build/asset check, Rust formatting, Clippy, 65 Rust unit tests, 9 I05 integration tests, and all-target check.                      |
| `npm run desktop:build`                                                                                  | Passed and produced the unsigned 5.8 MiB `aeterna-desktop` host. The previously known non-fatal `rust-objcopy`/missing `libLLVM.dylib` stripping warning remained.                                  |
| `git diff --check`                                                                                       | Passed.                                                                                                                                                                                             |
| Static vault-source scan for `unsafe`, socket/network APIs, extension loading, and dynamic SQL surfaces  | No project `unsafe`, runtime network path, extension-loading call, or WebView/IPC exposure found. ATTACH occurrences are limited to the fixed disabling configuration/limit and its rejection test. |

### Behavior and failure matrix

| Area                  | Observed evidence                                                                                                                                                                                                                            |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Lifecycle             | Initialize, close, reopen, password unlock, recovery unlock after reopen, and multiple-record reads passed. Existing targets were not replaced.                                                                                              |
| Records               | Empty and exact 1 MiB boundary records passed; oversize input failed; create/read/update/delete passed; stale revisions returned `vault_conflict`.                                                                                           |
| Rewrap                | Wrong password failed, old password failed after rewrap, new/recovery unlock passed, and the preexisting record frame remained exactly unchanged.                                                                                            |
| Tamper/version        | Master and recovery ciphertext, authenticated header metadata, record ciphertext, frame version, wrapper length constraint, migration checksum, unexpected table, container version, and live nonce-ledger deletion all failed closed.       |
| Nonces                | Initial uniqueness, durable reservations, deterministic collision/retry, abrupt exit after reservation, restart, concurrent writers, and independently writable checkpointed copies passed.                                                  |
| Concurrency           | Four parallel readers passed; two writers produced exactly one generation-2 result and one conflict; a held writer lock returned `vault_busy` after the bounded timeout.                                                                     |
| Interruption/recovery | A subprocess exited with an uncommitted WAL mutation. Reopen/quick-check recovered the prior generation and plaintext. A dropped schema transaction left no partial tables.                                                                  |
| Files and sizes       | Symlink targets, a sparse over-1-GiB main file, and an over-1-GiB known sidecar failed before SQLite application reads.                                                                                                                      |
| Privacy artifacts     | Synthetic markers were absent from the main database, live WAL/SHM, forced rollback journal, staging database/sidecars, and online-backup file. A controlled temp-table exercise verified the configured temp database had no disk filename. |
| Boundaries            | No vault Tauri command, frontend import, Serde secret type, raw SQL API, raw key API, runtime network dependency, or secure-storage use was introduced.                                                                                      |

## Residual risk and deferred scope

- Nonce uniqueness across independently writable database copies remains the
  explicitly accepted 96-bit OS-CSPRNG probability; there is no cross-file
  coordinator. I07 owns official restore/import semantics.
- The test KDF uses the accepted 65,536 KiB/time-1/parallelism-1 lower bound.
  The I02 256 MiB profile remains a provisional Apple Silicon development
  profile, not a universal release default.
- Field encryption hides payloads and secrets, not filenames, file sizes, row
  counts, IDs, timestamps, write timing, or access patterns. `secure_delete`,
  in-memory SQLite temp storage, and OS full-disk encryption are not physical
  erasure guarantees for SSDs, swap, snapshots, backups, or crash dumps.
- Bundled SQLite retains native C/FFI and build-script supply-chain surface.
  Its compiled load-extension capability is unreachable through the disabled
  rusqlite feature and narrow repository API, but remains part of G1 review.
- No legacy production schema exists, so no production upgrade was executed.
  Transactional schema rollback and the ciphertext-only online backup path were
  exercised; the first future migration still requires its own reviewed entry
  and failure evidence. Destructive migration remains separately approval-gated.
- This run does not claim Windows behavior, macOS 15 minimum-floor behavior,
  production signing, packaging/notarization, fuzzing, sanitizer coverage,
  independent cryptographic review, or penetration testing. Those remain with
  I08, GW, G1, and the release gates.

The exact I05 recommendation is **Accepted**. I06 becomes eligible, but was not
started in this task.
