# ADR 0002: Cryptographic primitives and versioned key wrappers

- Status: Accepted by G0 for implementation scope
- Date: 2026-09-21
- Decision owner: G0 architecture and security review
- Approval: Explicit user approval recorded in G0 on 2026-09-21
- Evidence: [`../research/I02-crypto-results.md`](../research/I02-crypto-results.md)
- Dependency review: [`../research/I02-crypto-dependency-proposal.md`](../research/I02-crypto-dependency-proposal.md)

## Context

Aeterna needs one random vault data key that can be recovered independently by
a master-password path and a delayed-recovery path. It also needs a per-device
request-signing key whose private material remains outside the WebView and
ordinary application persistence. Untrusted future headers must not select
unbounded KDF work or generic algorithms, and cryptographic evolution must not
silently reinterpret old data.

I02 is a risk prototype, not a production vault format or cryptographic audit.
Its primitive, envelope, benchmark, and macOS Keychain feasibility evidence now
passes. The Keychain investigation first observed `errSecNotAvailable` in
restricted execution, then `errSecMissingEntitlement` from an unsigned host
process, and finally an AMFI `No matching profile found` rejection from a signed
process without a profile. After explicit approval, a Personal Team Apple
Development identity and time-limited profile authorized only the prototype's
private application/default Keychain group. That context passed K01-K10,
including locked denial, unlock recovery, debug-to-signed-release continuity,
attributes, and cleanup. G0 owns whether these primitives and wrapper semantics
are a suitable basis for I05 implementation. Production application identity
and Keychain continuity are split into
[ADR 0004](./0004-macos-keychain-identity-continuity.md), while container and
migration ownership are split into
[ADR 0005](./0005-vault-format-and-migration-ownership.md). Independent review
remains a G1 release gate and is not a prerequisite circularly imposed on I05.

## Decision

Generate one 256-bit VDK from the operating-system CSPRNG. Never derive the VDK
from a password or ERC. Wrap the same VDK independently:

1. derive a 256-bit master KEK with Argon2id version 0x13 from the bounded
   master password and a fresh 128-bit salt; and
2. derive a 256-bit recovery KEK with HKDF-SHA-256 from a 128-bit random ERC as
   input keying material, an independent 256-bit SRS as salt, and the canonical
   versioned recovery context.

Use AES-256-GCM for each wrap with an independently generated 96-bit nonce and
full 128-bit tag. Authenticate a canonical purpose-specific AAD so master and
recovery wrappers cannot be substituted. A password change unwraps and
rewraps only the VDK; it does not re-encrypt vault records. Authentication
failure exposes one fixed error classification and no plaintext.

Generate each device Ed25519 signing seed independently with the OS CSPRNG.
Store only the 32-byte private seed through the secure-storage port. Public keys
and signatures may leave that boundary; I09/I10, not this ADR, own the signed
request protocol.

## Algorithms, sizes, and bounds

| Value                 | Proposed prototype rule                                      |
| --------------------- | ------------------------------------------------------------ |
| Crypto format         | version 1                                                    |
| VDK and KEKs          | 32 bytes                                                     |
| Master KDF            | Argon2id, version 0x13, exact 32-byte output                 |
| Project Argon2 bounds | 65,536-262,144 KiB; time 1-6; lanes 1-4                      |
| Master password input | 1-1,024 bytes at the backend boundary                        |
| Master salt           | fresh 16 bytes                                               |
| Recovery KDF          | HKDF-SHA-256                                                 |
| ERC entropy           | fresh 16 bytes, format version 1                             |
| SRS                   | independent fresh 32 bytes per device recovery record        |
| AEAD                  | AES-256-GCM, 12-byte nonce, 16-byte tag                      |
| Identifiers           | canonical 16-byte vault ID and 16-byte device ID             |
| Signing               | Ed25519, 32-byte seed, 32-byte public key, 64-byte signature |

Reject unknown versions, algorithms, KDF versions, purposes, lengths, or KDF
values outside these bounds before expensive allocation or derivation.

The I02 Apple Silicon recommendation is Argon2id-v0x13 with 262,144 KiB, time
cost 2, parallelism 1, and 32-byte output. It is an input to G0 and is not a
production default until the supported hardware floor and independent review
accept it.

## Canonical encodings

AAD version 1 is exactly 45 bytes:

```text
0..8    "AETRNAAD"
8       AAD encoding version (1)
9..11   crypto format version, big-endian u16
11      AEAD algorithm ID (1 = AES-256-GCM)
12      wrap purpose (1 = master-vdk, 2 = recovery-vdk)
13..29  vault ID
29..45  device ID
```

Recovery HKDF context version 1 is exactly 50 bytes:

```text
0..12   "AETERNA-RKEK"
12      context encoding version (1)
13..15  crypto format version, big-endian u16
15      recovery-vdk purpose (2)
16..32  vault ID
32..48  device ID
48..50  output length (32), big-endian u16
```

ERC manual transport uses Bech32m, HRP `aerc`, payload byte 1 for the ERC
format version followed by 16 entropy bytes. Canonical machine form is lowercase
and ungrouped. A separate display form is uppercase and grouped every four
characters with spaces. Decoding accepts only the exact machine form; UI
normalization or assisted entry remains a later, separately reviewed concern.

The deterministic JSON fixture is test interchange only. This ADR does not
choose a production vault/container serialization.

## Secure-storage split

This ADR retains only the cryptographic rule that an Ed25519 private seed is a
32-byte secret outside the WebView and ordinary application persistence. The
macOS SecItem policy, item identity, metadata validation, application/signing
identity continuity, and release rehearsal belong to ADR 0004. No final
Keychain namespace or production signing identity is selected here.

## Dependency decision

Use exact approved releases and restricted features of RustCrypto Argon2,
AES-GCM, HKDF/SHA-2, Ed25519 Dalek, `getrandom`, `zeroize`, and Rust Bech32.
Cargo.lock freezes the transitive graph; notably
`curve25519-dalek` resolves to the 4.1.3 patched floor. The full maintenance,
license, unsafe, audit, network, platform, and alternatives review is in the
dependency proposal and `docs/DEPENDENCIES.md`.

The Core Foundation and Security.framework pins remain reviewed prototype
dependencies, but their production policy is governed by ADR 0004 rather than
this primitive/wrapper decision.

## Alternatives rejected for the prototype

- Deriving the VDK directly from a password: prevents cheap password rotation
  and couples vault data to password availability.
- Using ERC as a password/PIN or omitting SRS: reduces entropy or removes the
  independent recovery factor.
- AES-CBC, unauthenticated encryption, variable nonce/tag sizes, caller-supplied
  production nonces, or generic algorithm selection: enlarge misuse and
  substitution risk.
- PHC strings or crate defaults as the persisted contract: hide parameters and
  do not define the wrapper/AAD version boundary.
- Base58Check, a project-defined CRC, word lists, QR codes, or localized ERC
  encodings: add unreviewed format/UX decisions beyond I02.
- Keychain convenience crates: do not expose every required data-protection,
  accessibility, synchronization, duplicate/update, and metadata decision in
  one narrow boundary.
- Legacy Keychain or plaintext fallback after a data-protection failure:
  violates the approved local-only policy.
- Secure Enclave key generation: Ed25519 is not provided by the required native
  Secure Enclave API and would change the evaluated algorithm/protocol.

## Security and privacy consequences

No crypto, raw encrypt/decrypt, ERC, signing-secret, or Keychain API is exposed
to React. Production constructors own randomness and nonce generation. Secret
types redact `Debug`, minimize cloning, and use zeroize-on-drop storage.
Decrypted and ERC temporary buffers under project control are cleared.

Zeroization is best-effort. It does not prove erasure of compiler copies,
registers, stack history, swap, crash dumps, allocator remnants, framework
copies, crate-internal state, or previously copied data. Core Foundation and
Security.framework can copy Keychain value data outside Rust's clearing
control. Production review must consider crash handling, memory locking where
appropriate, side channels, and OS behavior without claiming impossible
guarantees.

The benchmark and Keychain probes accept only fixed action/profile names on the
command line. They generate or compile their conspicuously synthetic inputs
internally and print no password, ERC, VDK, KEK, SRS, private seed, nonce, or
plaintext operation.

## Wrapper versioning expectations

Every stored wrapper must carry explicit format, algorithm, KDF, purpose,
length, and parameter values that are validated before use. A new algorithm,
parameter range, AAD layout, HKDF context, or ERC representation requires a new
reviewed version. Implementations must never reinterpret version 1 bytes under
new defaults.

The wrapper bytes do not define a database row, file, SQLite schema, export
package, or migration. ADR 0005 assigns those choices to I05 and I07 and
requires their independent version fields and recovery rules.

## G0 disposition and deferred decisions

Primitive interoperability, project wrappers, negative behavior, the Apple
Silicon benchmark, and the real-machine Keychain gate succeeded. K01-K10 passed
in the approved profile-signed development context. The unsigned release
prototype failed closed with `secure_storage_missing_entitlement`; it did not
fall back to another store. The Personal Team profile is time-limited prototype
evidence, not a production signing or distribution decision.

G0 accepts the algorithms, exact primitive pins, size and resource bounds,
wrapper-purpose separation, AAD/HKDF encodings, fail-closed errors, and
version-rejection rules as the implementation basis for I05. The Apple Silicon
profile E remains a provisional development recommendation whose parameters
must be persisted explicitly; it is not a universal release default.

Acceptance at G0 does not claim an external audit or production freeze. The
following owners remain explicit:

1. ADR 0004 and I09 own production device-key storage use; I15 owns final
   signing identity, entitlements, namespace continuity, and release rehearsal.
2. ADR 0005 and I05 own the local database/container representation and its
   migrations; I07 separately owns export/import packaging.
3. I08 validates the Argon2 recommendation on the Apple Silicon macOS 15 floor
   and current macOS under realistic application memory pressure.
4. I13 and I14 own password/ERC entry, display, print/export, recovery,
   rotation, and post-release UX.
5. G1 owns independent cryptographic, dependency, native-storage,
   side-channel, fuzzing, and penetration review before release.

The approved client baseline is preserved at
`54a213c5e17f5e1e3eae183f17f1f2370aa7a61d`. No I05 implementation is included
in this decision record.
