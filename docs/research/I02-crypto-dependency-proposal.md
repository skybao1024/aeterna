# I02 cryptography and secure-storage dependency proposal

Status: **Awaiting explicit approval**  
Prepared: 2026-09-20  
Scope: I02 risk prototype only; this proposal does not freeze a production vault
format and is not an independent cryptographic review.

## Approval boundary

No dependency manifest, lockfile, cryptographic implementation, ERC encoding,
AAD format, or Keychain behavior may change until the user explicitly approves
this proposal. Approval authorizes only the I02 prototype described here. G0
still owns acceptance of the eventual cryptographic ADR and production choices.

The decision requested at the end covers one combined set:

1. exact dependencies and features;
2. ERC representation and checksum;
3. master/recovery AAD and recovery-HKDF context encodings;
4. macOS Keychain class, attributes, identity, and mutation semantics; and
5. the Argon2 benchmark grid and recommendation policy.

## Baseline evidence before proposal work

The repository pins Node.js 24.21.0, npm 11.19.0, and Rust/Cargo 1.98.1. When
this proposal was drafted, the current shell instead resolved Node.js 23.6.1,
npm 10.9.2, and Homebrew Rust/Cargo 1.97.1, and the pinned installations had not
yet been located. Therefore the required pinned I00 verification could not be
run before the proposal text was written. The exact tools were subsequently
found under explicit Homebrew and rustup paths; the implementation may begin
only after both pinned baseline commands pass. No engine or `rust-version`
constraint was weakened, and no unpinned check will be used as acceptance
evidence.

## Primary references

- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), including the
  Argon2id version 19 vector in section 5.3 and the parameter-selection process
  in section 4.
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), including SHA-256
  test case 1.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), including Ed25519
  test 1.
- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) and the
  [NIST CAVP GCM vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES).
- [BIP 173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) and
  [BIP 350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) for
  Bech32/Bech32m encoding and error-detection behavior.
- Apple [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains),
  [`kSecUseDataProtectionKeychain`](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain),
  [`kSecClassGenericPassword`](https://developer.apple.com/documentation/security/ksecclassgenericpassword),
  [`kSecAttrSynchronizable`](https://developer.apple.com/documentation/security/ksecattrsynchronizable),
  and [`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly).

## Proposed direct dependencies

All versions will be exact `=` pins. Cargo.lock will freeze the complete
transitive graph. Default features are disabled unless explicitly listed.
Crate publication dates and repository activity were checked on 2026-09-20
using crates.io metadata and the upstream repositories.

| Crate and features                                                                                                     | Classification and purpose                                                                                                                                                                         | Ownership, maintenance, and release recency                                                                                                                                                                                                                  | License, transitive impact, unsafe footprint, and platform behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `argon2 = 0.5.3`, features `zeroize`                                                                                   | Runtime; exact Argon2id v=0x13 primitive. Aeterna allocates the memory matrix itself in a `Zeroizing<Vec<Block>>`, calls `hash_password_into_with_memory`, and never uses PHC strings or defaults. | RustCrypto/password-hashes; repository active 2026-09-14; release 2024-01-20. The newer 0.6.0 line was reviewed but is not proposed because it is much newer and adds a broader unsafe allocation/parallel-memory implementation without an I02 requirement. | MIT OR Apache-2.0. Brings Blake2, digest, and CPU-feature support; the disabled `alloc`, `password-hash`, and random features avoid unused PHC/Base64/random APIs. The crate has a narrow x86/x86_64 AVX2 intrinsic boundary; Apple Silicon uses safe portable code. No storage, permission, entitlement, or network behavior. No crate-specific independent audit was located; RFC vectors and later independent review remain required.                                                                                                                                                                                                                                                                                         |
| `aes-gcm = 0.10.3`, features `aes`, `alloc`, `zeroize`                                                                 | Runtime; only AES-256-GCM with a 96-bit nonce and 128-bit tag.                                                                                                                                     | RustCrypto/AEADs; repository active 2026-09-14; release 2023-09-21. Version 0.10.3 is the patched floor for RUSTSEC-2023-0096/GHSA-423w-p2w9-r7vq.                                                                                                           | Apache-2.0 OR MIT. Brings `aead`, `aes`, `cipher`, `ctr`, `ghash`, and `subtle`. The direct crate denies unsafe code; architecture-specific transitive AES/SHA acceleration contains reviewed intrinsic boundaries. No I/O or network behavior. Decrypt uses the allocating API so authentication failure never exposes a caller-owned partially decrypted buffer. No claim of FIPS validation or an independent crate audit.                                                                                                                                                                                                                                                                                                     |
| `hkdf = 0.12.4`, no features; `sha2 = 0.10.9`, no features                                                             | Runtime; fixed HKDF-SHA-256 extract-and-expand. SHA-256 is not selectable by callers.                                                                                                              | RustCrypto/KDFs and RustCrypto/hashes; repositories active 2026-08-31 and 2026-09-15; releases 2023-12-13 and 2025-04-30.                                                                                                                                    | Both MIT OR Apache-2.0. Adds HMAC/digest traits and SHA-2 implementation. `hkdf` forbids unsafe code; `sha2` uses target-specific intrinsic/assembly boundaries, including AArch64 SHA acceleration. No storage, permission, entitlement, or network behavior. RFC 5869 vectors provide interoperability evidence; no independent crate audit is claimed.                                                                                                                                                                                                                                                                                                                                                                         |
| `getrandom = 0.3.4`, no features                                                                                       | Runtime; the sole production randomness source for VDK, ERC entropy, SRS, salts, nonces, and Ed25519 seeds.                                                                                        | rust-random/getrandom; repository active 2026-08-31; release 2025-10-14; published security policy.                                                                                                                                                          | MIT OR Apache-2.0. Adds platform `libc`/WASI shims as selected by target. Unsafe code is restricted to OS/syscall and initialization boundaries. On Apple targets it uses the operating-system source and performs no storage or network access. Failure is returned; there is no deterministic fallback. The newer 0.4 line was rejected for this prototype because I02 does not need its newer API or `rand_core` integration.                                                                                                                                                                                                                                                                                                  |
| `ed25519-dalek = 2.2.0`, features `fast`, `zeroize`                                                                    | Runtime; Ed25519 key derivation, signing, and strict verification. `rand_core`, batch, digest, hazmat, PKCS#8, PEM, serde, and legacy compatibility stay disabled.                                 | dalek-cryptography/curve25519-dalek; repository active 2026-08-29; release 2025-07-09.                                                                                                                                                                       | BSD-3-Clause. Brings `curve25519-dalek`, `ed25519`, SHA-512, `signature`, and `subtle`; the lock must resolve `curve25519-dalek >= 4.1.3`, the patched floor for RUSTSEC-2024-0344. `ed25519-dalek` forbids unsafe code outside tests; the curve backend has reviewed constant-time/intrinsic boundaries. Version 2 is also the patched API line for RUSTSEC-2022-0093. No I/O, permissions, or network behavior. The 3.0 line was rejected as unnecessarily new for I02.                                                                                                                                                                                                                                                         |
| `zeroize = 1.9.0`, feature `alloc`                                                                                     | Runtime; zeroize-on-drop wrappers and explicit clearing of temporary vectors and Argon2 memory.                                                                                                    | RustCrypto/utils; repository active 2026-09-18; release 2026-06-12.                                                                                                                                                                                          | MIT OR Apache-2.0. Optional derive and serde features stay disabled. The crate uses volatile writes and compiler fences in a narrow unsafe implementation. It allocates nothing on its own and has no I/O or network behavior. It cannot guarantee removal of compiler-created copies, registers, swap, crash dumps, OS/framework copies, or previously copied buffers. `secrecy` was considered but rejected because small Aeterna-owned fixed-size wrappers plus `zeroize` provide a narrower API and dependency graph.                                                                                                                                                                                                         |
| `bech32 = 0.12.0`, feature `alloc`                                                                                     | Runtime; Bech32m encoding and checksum for the manual ERC representation.                                                                                                                          | rust-bitcoin/rust-bech32; repository active 2026-09-19; release 2026-06-12.                                                                                                                                                                                  | MIT. No transitive runtime dependencies and no unsafe code, storage, permissions, or network behavior. BIP 173/350 specify the interoperable checksum. Crockford Base32 plus a project-defined CRC was rejected because it would create a new composite format; Base58Check was rejected for mixed/manual transcription limitations and weaker error-localization rationale.                                                                                                                                                                                                                                                                                                                                                      |
| macOS only: `security-framework-sys = 2.17.0`, feature `OSX_10_15`; `core-foundation = 0.10.1`, default `link` feature | macOS runtime only; raw SecItem constants/functions and owned Core Foundation dictionaries/data for the narrow adapter.                                                                            | kornelski/rust-security-framework (active 2026-08-14; release 2026-02-20) and servo/core-foundation-rs (active 2026-09-14; release 2025-05-26).                                                                                                              | Both MIT OR Apache-2.0. Adds `core-foundation-sys` and `libc`; links only Apple system Security/CoreFoundation frameworks. Unsafe code is limited to FFI declarations, Core Foundation ownership wrappers, and one Aeterna adapter module with documented create/get ownership rules. No runtime network behavior. The APIs can access the current user’s Keychain; the adapter uses only its exact service/account and never enumerates unrelated items. The high-level `security-framework` and cross-platform `keyring` crates were rejected because their convenient password APIs do not make all required create-vs-replace, accessibility, synchronization, and returned-metadata checks explicit in one narrow interface. |
| Dev only: `serde_json = 1.0.151`, default features                                                                     | Test-only; parse documented synthetic JSON fixtures. It is already locked transitively by Tauri, but will become an explicit dev dependency.                                                       | serde-rs/json; repository active 2026-08-08; release 2026-07-20.                                                                                                                                                                                             | MIT OR Apache-2.0. No new resolved crate is expected in the current graph. It is not used in runtime crypto or production serialization; fixture JSON is explicitly not a vault format.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

No dependency above requires a Tauri capability, new entitlement, remote service,
runtime download, telemetry path, or WebView API. The macOS bindings are placed
under `cfg(target_os = "macos")`; other targets compile an explicit unsupported
adapter.

## Dependency and implementation alternatives

- `ring` was considered for AES-GCM, HKDF, and Ed25519, but rejected because it
  would combine a larger C/assembly-backed surface with less direct control over
  the selected standalone primitive adapters while still requiring separate
  Argon2, ERC, and Keychain dependencies.
- OpenSSL/CommonCrypto wrappers were rejected because they add native build or
  platform divergence without improving this cross-platform prototype.
- `rand`/`OsRng` was rejected in favor of the smaller direct `getrandom` OS
  interface. Production constructors will not accept injected randomness.
- `keyring` was rejected because I02 must prove exact SecItem data-protection,
  accessibility, non-synchronization, and metadata behavior, not merely store a
  generic secret through a cross-platform abstraction.
- Apple `SecKey` was considered for the signing key but rejected for this
  prototype because the required Ed25519 implementation and portable standard
  vectors use Dalek seed material. The raw 32-byte seed will instead be stored
  as one generic-password value protected by the Keychain. Hardware-backed or
  non-exportable device keys remain a G0/independent-review question.

## Proposed prototype model and validation bounds

The implementation will expose typed Rust values only. VDK, KEK, ERC entropy,
SRS, KDF salt, AEAD nonce, and device signing secret wrappers use redacted
formatting, do not implement `Copy`, minimize cloning, and zeroize on drop.
Wrapped ciphertext types also redact ciphertext, tag, and nonce in formatting.

The prototype constants are:

| Field                        | Proposed value or accepted range                            |
| ---------------------------- | ----------------------------------------------------------- |
| Crypto format version        | `1` only                                                    |
| KDF algorithm/version        | Argon2id, version `0x13` only                               |
| Master KEK output            | exactly 32 bytes                                            |
| Master salt                  | exactly 16 random bytes                                     |
| Password input               | 1 through 1,024 bytes; byte-preserving at the Rust boundary |
| Argon2 memory                | 65,536 through 262,144 KiB, validated before allocation     |
| Argon2 time cost             | 1 through 6                                                 |
| Argon2 parallelism           | 1 through 4                                                 |
| Recovery KEK                 | HKDF-SHA-256 output of exactly 32 bytes                     |
| ERC entropy                  | exactly 16 random bytes (128 bits)                          |
| SRS                          | exactly 32 random bytes                                     |
| AEAD                         | AES-256-GCM only                                            |
| AEAD nonce/tag               | exactly 12 random bytes / full 16-byte tag                  |
| Wrapped plaintext/ciphertext | exactly 32-byte VDK / 32-byte ciphertext plus tag           |
| IDs                          | opaque canonical 16-byte vault ID and 16-byte device ID     |
| Wrap purposes                | `master-vdk = 1`, `recovery-vdk = 2` only                   |

Unknown versions, algorithms, purposes, lengths, or parameters outside these
bounds are rejected before allocation, Argon2 derivation, or decryption. The
public production wrapping functions always call `getrandom`; deterministic
randomness exists only in private `cfg(test)` helpers.

## Proposed ERC representation

The ERC v1 payload is exactly 17 bytes: one version byte `0x01` followed by 16
bytes of CSPRNG entropy. It is encoded with Bech32m using the lowercase
human-readable part `aerc`.

- Canonical machine form: lowercase, ungrouped Bech32m, for example shaped as
  `aerc1...`; this is not a real recovery code.
- Canonical manual display: the same value in uppercase with the data/checksum
  portion grouped in four-character chunks separated by single ASCII spaces.
- Accepted input is either the exact lowercase machine form or the exact
  uppercase grouped display form. Mixed case, arbitrary grouping, hyphens,
  non-ASCII whitespace, visually ambiguous characters outside the Bech32
  alphabet, unknown HRP/version, truncation, extra data, and non-Bech32m
  checksums are rejected.
- Parsing validates structure, total decoded length, HRP, Bech32m checksum, and
  version before constructing `ErcEntropy`.

The six Bech32m checksum characters provide a standardized 30-bit polymod
checksum. Tests will cover every single-character mutation of one synthetic
code and selected adjacent/non-adjacent transpositions; passing those tests is
error-detection evidence, not a promise to detect every possible multi-error.
No clipboard, QR, word-list, translation, printing, or WebView path is added.

## Proposed canonical AAD and HKDF context

No general serializer is used. All integers are unsigned big-endian and all IDs
are fixed 16-byte values. The 45-byte AAD v1 layout is:

| Offset | Size | Value                                 |
| -----: | ---: | ------------------------------------- |
|      0 |    8 | ASCII `AETRNAAD`                      |
|      8 |    1 | AAD encoding version `1`              |
|      9 |    2 | crypto format version `1`             |
|     11 |    1 | AEAD algorithm ID `1` (AES-256-GCM)   |
|     12 |    1 | purpose ID (`1` master, `2` recovery) |
|     13 |   16 | vault ID                              |
|     29 |   16 | device ID                             |

Both master and recovery wrappers bind all fields. The envelope stores typed
metadata, a 12-byte nonce, 32-byte ciphertext, and a 16-byte tag; the JSON test
fixture is not a proposed persistence encoding.

Recovery HKDF `info` is a separate 50-byte canonical value:

| Offset | Size | Value                           |
| -----: | ---: | ------------------------------- |
|      0 |   12 | ASCII `AETERNA-RKEK`            |
|     12 |    1 | context encoding version `1`    |
|     13 |    2 | crypto format version `1`       |
|     15 |    1 | purpose ID `2` (`recovery-vdk`) |
|     16 |   16 | vault ID                        |
|     32 |   16 | device ID                       |
|     48 |    2 | output length `32`              |

HKDF input keying material is the 16-byte ERC entropy; salt is the independent
32-byte SRS. The context is independent of ERC and SRS. A different version,
purpose, vault ID, or device ID necessarily changes the derived KEK and/or AAD
and therefore fails authentication.

## Proposed macOS Keychain policy

The adapter uses Apple SecItem calls and the data-protection Keychain only:

- item class: `kSecClassGenericPassword`;
- `kSecUseDataProtectionKeychain = true` on every add, query, update, delete,
  and metadata operation;
- `kSecAttrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly`;
- `kSecAttrSynchronizable = false` explicitly on every operation;
- service: `dev.aeterna.desktop.i02.device-signing`;
- account: `v1:` plus the canonical lowercase 32-hex-character device ID;
- no explicit access group; the host process’s default signed application
  context applies, and the prototype records whether this prevents unsigned
  debug or release access;
- stored value: exactly the 32-byte Ed25519 signing seed; public key and
  signatures are the only material allowed outside the adapter/signing core;
- `store` uses `SecItemAdd` and classifies duplicates without overwriting;
- `replace` uses `SecItemUpdate` and requires an existing exact identity;
- `retrieve` uses `SecItemCopyMatching` with `kSecMatchLimitOne` and
  `kSecReturnData`, validates an exact 32-byte result, and immediately moves it
  into a zeroizing signing-secret wrapper;
- `delete` uses `SecItemDelete`; missing and repeated deletion are explicit,
  non-fatal classifications;
- metadata inspection requests attributes for only the exact service/account
  and validates accessibility and synchronizability without requesting secret
  data; and
- no error path falls back to a file, environment variable, SQLite, browser
  storage, or another Keychain implementation.

The FFI module will contain the only new Aeterna `unsafe` blocks. Each block
will document that input dictionaries own their values for the call, output
pointers start null, successful Copy-rule results are wrapped exactly once, and
unexpected Core Foundation types are rejected and released. Raw OSStatus values
are mapped to fixed internal classifications and are not combined with secret
data.

K01-K10 will determine the actual prompt, entitlement, lock-state, restart, and
unsigned-build behavior. Apple documents that the data-protection Keychain is
available only in a user context and derives access groups from code signing;
therefore an unsigned-build failure is possible and will block I02 rather than
trigger a plaintext or legacy-Keychain fallback.

## Proposed Argon2 benchmark and recommendation policy

The benchmark is an opt-in release binary with an internally compiled synthetic
password and salt. It accepts only a named numeric parameter profile, never
secret input, and prints only parameters, sample counts, durations, and memory
measurements.

Candidate profiles:

| ID  |  Memory | Time | Parallelism |
| --- | ------: | ---: | ----------: |
| A   |  64 MiB |    3 |           1 |
| B   |  64 MiB |    3 |           4 |
| C   | 128 MiB |    3 |           1 |
| D   | 128 MiB |    3 |           4 |
| E   | 256 MiB |    2 |           1 |
| F   | 256 MiB |    2 |           4 |

Each profile receives 3 unrecorded warmups and 20 measured samples in a release
build on AC power where practical. The report records macOS version,
architecture, non-identifying CPU model category, median, p95, maximum, sample
count, configured memory, and per-process peak resident memory from
`/usr/bin/time -l` where available. Thermal/power state is a caveat, not a
hidden correction.

The recommendation selects the strongest measured profile whose median is
250-500 ms and whose p95 is no more than 750 ms on the current Apple Silicon
host, preferring greater memory before greater time cost when latency is
comparable. If none meets the window, the nearest safe profile is reported with
the miss instead of changing bounds silently. The recommendation is named
`i02-apple-silicon-recommendation-v1`; it remains G0 input and is not a
production default or compatibility promise.

## Planned evidence after approval

- RFC 9106 Argon2id v=0x13 section 5.3 known-answer test.
- RFC 5869 SHA-256 test case 1 extract-and-expand test.
- NIST AES-256-GCM known-answer encrypt/decrypt, AAD, and reject tests.
- RFC 8032 Ed25519 test 1 public-key/signature test and strict verification.
- Deterministic synthetic dual-wrapper JSON fixture plus every required
  wrong-input, tamper, version, purpose, length, and KDF-bound test.
- ERC round-trip, canonicalization, checksum, mutation, transposition, and
  malformed-input tests.
- Device signing separation and modified message/signature/public-key tests.
- Secret redaction, fixed-error, zeroization-support, bounded uniqueness, fake
  secure-storage, macOS Keychain, and non-macOS unsupported tests.
- Release Argon2 benchmark results, K01-K10 real-machine results, source/privacy
  scans, pinned repository checks/build, results report, dependency review, and
  Proposed ADR 0002.

## Approval request

Please explicitly approve or reject this combined dependency and design
proposal. Approval must be recorded here before any protected implementation
change begins.

Approval record: **Approved by the user on 2026-09-20.** The user confirmed that
I01 was complete enough for work to continue and explicitly authorized I02
after receiving this combined proposal. The approval covers only the I02
prototype scope and does not accept the eventual production cryptographic ADR.
