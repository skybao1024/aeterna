# I02 cryptography and secure-storage prototype results

Status: **Accepted**  
Date: 2026-09-21  
Decision input: [`I02-crypto-dependency-proposal.md`](./I02-crypto-dependency-proposal.md)  
Proposed ADR: [`ADR 0002`](../adr/0002-cryptographic-envelope-and-key-storage.md)

## Executive result

The cryptographic part of I02 succeeded. Published Argon2id, HKDF-SHA-256,
AES-256-GCM, and Ed25519 known-answer tests pass; the deterministic Aeterna
dual-wrapper fixture matches exact bytes; negative authentication, metadata,
resource-bound, ERC, signing, storage-fake, redaction, and zeroization-support
tests pass. The release Argon2 grid also produced a suitable Apple Silicon
recommendation.

I02 is Accepted because the required real-machine Keychain matrix now passes in
an explicitly approved development-signed context. The user configured Xcode
26.6 with a Personal Team, created an Apple Development identity, approved the
development App ID and profile registration, and performed the required
lock/unlock actions. Apple's verified public WWDR G3 intermediate completed the
certificate chain. Xcode then generated a time-limited Mac development profile
for a private prototype application identifier.

The signed debug probe passed create, restart/retrieve/sign, wrong-identity,
replace, delete/not-found, locked denial, unlock recovery, metadata, and final
cleanup checks. An independently built and signed release probe retrieved the
same public key. The ad-hoc release probe could not create an item and returned
the fixed `secure_storage_missing_entitlement` classification. No probe prompt,
secret output, plaintext fallback, or residual development item was observed.
The Personal Team identity and profile are development evidence only; they do
not select the production signing, distribution, or upgrade-continuity policy.

## Approval and baseline

The combined dependency, ERC, AAD, recovery-HKDF, Keychain, and benchmark
proposal was prepared before any manifest or cryptographic implementation
change. On 2026-09-20 the user stated that I01 was complete enough to continue
I02; that response is recorded as explicit approval in the proposal. I02
depends only on accepted I00, so the separate I01 Blocked evidence was preserved
and was not used as an implementation contract.

On 2026-09-21 the user explicitly approved registration of the development App
ID and provisioning profile after the unsigned and entitlement-only probe
failures were reported. The signing identity and its private key remained in the
user's login Keychain; no certificate private key or account credential was
written to the repository or retained test artifacts.

The initially active shell pointed at older tools. The exact installed tools
were selected with an explicit `PATH`, without changing shell configuration:

- Node.js 24.21.0;
- npm 11.19.0;
- rustc 1.98.1; and
- cargo 1.98.1.

Before implementation, `npm run check` passed 7 frontend tests and 27 Rust
tests, and `npm run desktop:build` produced the host executable without a
developer signing identity. The
release build emitted a non-fatal environment warning because the rustup
toolchain's `rust-objcopy` could not load `libLLVM.dylib`; Cargo still completed
the optimized build successfully. No version constraint or check was weakened.

## Implemented boundaries

- Fixed-size redacted, zeroize-on-drop wrappers cover VDK, KEK, ERC entropy,
  SRS, master salt, and signing secret. Master passwords use a bounded
  zeroizing vector.
- Production VDK, ERC, SRS, salt, nonce, and signing-secret generation calls
  the operating-system CSPRNG. Production wrapping APIs do not accept a nonce.
- The Argon2id adapter fixes version 0x13 and a 32-byte output, and rejects
  memory, time, parallelism, or output sizes outside approved bounds before
  allocating the memory matrix.
- AES-256-GCM uses a 12-byte nonce, 16-byte tag, typed KEK, and canonical AAD.
  Authentication failures return one fixed error. Temporary decrypt buffers
  are zeroized before release.
- HKDF-SHA-256 uses ERC entropy as input keying material, a separate 32-byte SRS
  as salt, and the canonical 50-byte recovery context.
- Ed25519 exposes only public keys and signatures outside the signing-secret
  boundary. The private 32-byte seed is the only Keychain payload.
- ERC uses Bech32m with HRP `aerc`, a one-byte format version, and 16 bytes of
  entropy. Machine input is exact lowercase ungrouped form; the separate manual
  display form is uppercase and grouped every four characters.
- The storage port provides create, retrieve, replace, delete, and metadata
  operations. A zeroizing in-memory fake covers platform-independent behavior.
  The macOS adapter is the only new native unsafe boundary; other platforms
  return an explicit unsupported classification.
- No cryptographic or Keychain function is exposed as a Tauri command, event,
  or WebView API. No capability or entitlement was added to the production
  Tauri configuration. The real-machine matrix used a temporary
  development-signed app wrapper with only its private application identifier,
  team identifier, and private default Keychain group.

## Versioned encodings and bounds

The prototype crypto format version is 1. The canonical AAD is exactly 45
bytes:

| Offset | Length | Field                            |
| -----: | -----: | -------------------------------- |
|      0 |      8 | ASCII `AETRNAAD`                 |
|      8 |      1 | AAD encoding version 1           |
|      9 |      2 | big-endian crypto format version |
|     11 |      1 | AES-256-GCM algorithm ID 1       |
|     12 |      1 | purpose: master 1 or recovery 2  |
|     13 |     16 | canonical vault ID bytes         |
|     29 |     16 | canonical device ID bytes        |

The recovery HKDF info is exactly 50 bytes: ASCII `AETERNA-RKEK` (12), context
version 1 (1), big-endian crypto version (2), recovery purpose 2 (1), vault ID
(16), device ID (16), and big-endian output length 32 (2).

Project Argon2 inputs accept 65,536-262,144 KiB memory, 1-6 iterations, 1-4
lanes, a non-empty password of at most 1,024 bytes, a 16-byte salt, and an exact
32-byte output. The published RFC 9106 vector uses its standard 32 KiB test
setting through a test-only primitive path and does not weaken project bounds.

## Published known-answer tests

| Primitive    | Source and case                           | Result                                                    |
| ------------ | ----------------------------------------- | --------------------------------------------------------- |
| Argon2id     | RFC 9106 section 5.3, version 0x13        | Pass; exact 32-byte tag                                   |
| HKDF-SHA-256 | RFC 5869 test case 1                      | Pass; exact 42-byte OKM                                   |
| AES-256-GCM  | NIST zero-key/96-bit-IV, one-block vector | Pass; exact ciphertext/tag, decrypt, AAD/tamper rejection |
| Ed25519      | RFC 8032 test 1                           | Pass; exact public key and empty-message signature        |

The standards vectors are independent of the project fixture. A vector mismatch
cannot regenerate or update the expected bytes.

## Aeterna fixture and negative behavior

[`i02-dual-wrapper-v1.json`](../../src-tauri/tests/fixtures/i02-dual-wrapper-v1.json)
contains conspicuously synthetic hexadecimal inputs and fixed master/recovery
ciphertext-plus-tag outputs. It is a test interchange fixture, not a vault file
format. The exact fixture test proves both wrappers recover the same VDK.

Automated tests also prove:

- a password change replaces only the master wrapper while the recovery wrapper
  still recovers the same VDK;
- ERC without the correct SRS and SRS without the correct ERC cannot recover;
- wrong password, ERC, SRS, vault ID, device ID, purpose, version, algorithm,
  KDF version, nonce, ciphertext, tag, AAD context, or ciphertext length fails
  closed;
- hostile Argon2 values are rejected before memory allocation;
- bounded generated ERC, salt, and nonce samples contain no duplicate;
- ERC checksum mutations, a selected transposition, upper/mixed display input,
  whitespace, truncation, extension, wrong HRP, and unknown version are rejected;
- modified message, signature, or public key is rejected; and
- storage fake create/read/duplicate/replace/delete/repeated-delete/not-found and
  metadata behavior is deterministic.

The final local Rust suite result is recorded with the repository verification
below. Test assertions compare secret bytes through booleans and do not include
secret buffers in failure formatting.

## Argon2 Apple Silicon benchmark

Environment: macOS 26.3, `arm64` Apple Silicon category, AC power. The sandbox
did not permit a more specific CPU brand query; no serial number, hardware UUID,
or machine identifier was collected. Each release profile used three unrecorded
warmups and 20 recorded samples. A privileged read-only rerun of
`/usr/bin/time -l` supplied peak RSS; all profiles reported zero swaps. No
thermal sensor was sampled, so ambient and thermal state remain caveats.

| Profile | Memory KiB | Time | Lanes |  p50 ms |  p95 ms |  Max ms | Peak RSS bytes (MiB) |
| ------- | ---------: | ---: | ----: | ------: | ------: | ------: | -------------------: |
| A       |     65,536 |    3 |     1 |  89.453 |  91.760 |  95.817 |   75,710,464 (72.20) |
| B       |     65,536 |    3 |     4 |  88.119 |  89.464 |  89.675 |   75,710,464 (72.20) |
| C       |    131,072 |    3 |     1 | 186.536 | 188.794 | 189.032 | 142,819,328 (136.20) |
| D       |    131,072 |    3 |     4 | 185.960 | 188.589 | 189.068 | 142,819,328 (136.20) |
| E       |    262,144 |    2 |     1 | 279.970 | 293.894 | 298.826 | 277,037,056 (264.20) |
| F       |    262,144 |    2 |     4 | 279.941 | 285.705 | 293.112 | 277,037,056 (264.20) |

Recommendation `i02-apple-silicon-recommendation-v1`: profile E,
Argon2id-v0x13 with 262,144 KiB, time cost 2, parallelism 1, and 32-byte output.
It is the highest-memory candidate inside the 250-500 ms median and at-most-750
ms p95 policy. Profile F has similar measurements, but the approved crate
feature set deliberately excludes its optional parallel execution feature;
choosing one lane avoids implying a multicore speedup or silently changing
future latency. This is G0 evidence, not a production default.

## macOS Keychain matrix

The approved adapter queried only generic-password items with service
`dev.aeterna.desktop.i02.device-signing` and an account of `v1:` plus the
lowercase device-ID hex. Every query set the data-protection Keychain flag.
Create/update requested `WhenUnlockedThisDeviceOnly` and explicit
non-synchronization. No access group was provided.

| ID  | Observed result                                                                                                                                                                                                                                                                                                                                              |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| K01 | **Pass.** After strict signature/profile verification, debug create succeeded and printed only `created=true` plus a public key. No private seed or prompt appeared.                                                                                                                                                                                         |
| K02 | **Pass.** A separate debug process retrieved the item and verified a new signature with the same K01 public key; no key was regenerated.                                                                                                                                                                                                                     |
| K03 | **Pass.** The wrong device identity returned not found with `fallback=false`.                                                                                                                                                                                                                                                                                |
| K04 | **Pass.** Replace updated the exact existing item. The public key changed, the old signature was rejected, and a new signature verified.                                                                                                                                                                                                                     |
| K05 | **Pass.** The first delete returned deleted, the repeated delete returned not found, and a subsequent sign attempt returned `secure_storage_not_found`. A new item was then created for the remaining matrix.                                                                                                                                                |
| K06 | **Pass.** While the user held the macOS session at the lock screen, retrieval returned the approved locked/access-denied classification and the probe printed `locked_access_denied=true`.                                                                                                                                                                   |
| K07 | **Pass.** After the user unlocked normally, retrieval recovered without regeneration and the same pre-lock public key was confirmed.                                                                                                                                                                                                                         |
| K08 | **Pass.** The direct ad-hoc release probe could not create an item and returned `secure_storage_missing_entitlement`, with no fallback. A separately bundled Apple Development-signed release probe passed strict signature verification and retrieved the same item created by debug. The known `rust-objcopy` warning did not prevent the optimized build. |
| K09 | **Pass.** Adapter metadata reported data-protection Keychain true, `WhenUnlockedThisDeviceOnly` true, and synchronizable false. No unrelated item was queried.                                                                                                                                                                                               |
| K10 | **Pass.** Final delete returned deleted, repeated delete returned not found, and a subsequent sign attempt returned `secure_storage_not_found`. No development test item remains.                                                                                                                                                                            |

The original restricted context returned unavailable. A direct unsigned host
create then returned missing entitlement. A minimally signed executable without
a profile was rejected by AMFI with `No matching profile found`. These failures
established each authorization boundary before the approved profile-signed run.
The first lock-cycle run also exposed a probe-only polling defect: after the
first locked result it treated a repeated locked result as fatal. The harness
was corrected to continue polling identical locked/access-denied results until
unlock or timeout; the complete rerun then passed K06 and K07. No OS password
was requested, typed, stored, or recorded by the probe.

## Privacy and memory review

Repository scans found no I02 clipboard API, WebView event/command, local or
session storage use, database path, filesystem fallback, environment-secret
input, network code, or secret logging. Existing matches are the I00 locale
preference in browser local storage, the bounded foundation Tauri command, and
I01 redacted diagnostics. The I02 binaries accept only a benchmark profile ID
or fixed action name; all passwords, salts, key material, and probe messages are
compiled synthetic values or generated internally. Output is limited to timing,
memory, fixed status codes, booleans, and an Ed25519 public key.

`Zeroizing` clears owned secret wrappers and the Argon2 matrix on drop, and the
prototype explicitly clears invalid password input, decrypted temporary
vectors, and ERC payload/string temporaries. This cannot guarantee removal of
compiler-created copies, registers, stack remnants, swap, crash dumps,
allocator history, Bech32 internals, HKDF/HMAC internal state, Core Foundation
copies, Security.framework copies, or previously copied buffers. The project
does not claim secure-memory locking or a completed side-channel audit.

## Verification and remaining review

Checks completed during implementation include focused formatting, Clippy with
warnings denied, all-target/all-feature Rust tests, release binary builds, both
benchmark runs, debug Keychain probes, and the unsigned release probe. After the
lock-cycle harness correction and documentation formatting, the canonical
`npm run check` passed 7 frontend and 48 Rust tests, and
`npm run desktop:build` produced the optimized `aeterna-desktop` executable.
The known non-fatal `rust-objcopy`/`libLLVM.dylib` warning remained; the build
completed with exit code 0.

G0 and independent security review still own:

- acceptance or replacement of every algorithm, crate, parameter bound, and
  versioned encoding;
- production serialization and migration rules;
- the final Argon2 profile across the supported hardware floor;
- side-channel, memory, crash-dump, swap, and secret-copy analysis;
- production signing identity, distribution entitlements, and continuity beyond
  the time-limited Personal Team profile;
- password handling and ERC presentation UX; and
- an independent implementation/code audit and broader platform testing.
