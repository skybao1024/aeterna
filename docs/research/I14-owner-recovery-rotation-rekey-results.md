# I14 Owner recovery, rotation, and rekey results

- Date: 2026-09-27
- Client baseline: `d27b9ab063f817043d76492516de81edced39887`
- Server baseline: `2ea0570be5e6f833e5e03e8506920518d3444e9e`
- Result: Accepted for the fail-closed engineering boundary
- Decision: [ADR 0015](../adr/0015-owner-recovery-rotation-and-post-compromise-rekey.md)
- Public protocol: prepared `protocol-v1.3.0`, digest
  `b7b0f41af9023ae7e30b4f21f5fae47976ec9b8cf490b50c8d61d81137abb75f`
- Production cloud activity: none

## Implemented boundary

Owner recovery now requires a signed request from the same bound device whose
sealed recovery record is requested, a valid heartbeat from the previous 15
minutes, and mailbox OTP verification. Before release, it has a 24-hour
cancellable cooldown and a bounded 24-hour same-device redelivery window. A
policy release during that cooldown cancels the old request and requires the
explicit successor-epoch flow instead of silently returning an old SRS.

Pre-release ERC rotation uses a monotonic recovery generation. The initiating
device first confirms a fresh wrapper before activation revokes the old live
generation and its grants. Each remaining device provisions a distinct SRS and
recovery record, confirms only its own wrapper digest, and remains visibly
`pending` or `not_enrolled` until completion or explicit exclusion. Concurrent
second batches, stale generations, substituted Owner authorizations, and
conflicting duplicate confirmations fail closed.

Post-release or post-claim recovery retains the released policy epoch and its
old grants, claims, audit, and ciphertext authority. The first successful local
rekey confirmation creates a new active successor epoch; unrekeyed devices can
only submit presence evidence for the historical epoch and cannot extend the
new inactivity deadline. Rotation status reports exact device identifiers,
safe labels, timestamps, and partial states.

The Rust core never exposes ERC, SRS, KEKs, VDKs, or decrypted records to React.
Normal Owner recovery atomically replaces both access wrappers around the
unchanged VDK. Post-compromise recovery generates a fresh VDK and ERC, validates
and re-encrypts every bounded item including embedded attachments, increments
record generations, replaces both wrappers and the complete nonce ledger, and
commits header authentication in one SQLite immediate transaction. Plaintext
buffers are zeroized after re-encryption. Injected failures before commit leave
the complete old Vault.

The desktop recovery status surface distinguishes not configured, cooling
down, rekey required, partial multi-device migration, and fully protected
states with localized device-state labels.

## Verification evidence

Pinned-toolchain `npm run check` passed 22 frontend tests, the exact 88-file
protocol package, 112 non-ignored Rust library tests with one intentional 1 GiB
boundary test ignored, nine I05 integration tests, six I06 integration tests,
Rust formatting, Clippy with warnings denied, Rust check, and the frontend
production build. The unsigned desktop build succeeded; the known non-fatal
`rust-objcopy` `libLLVM.dylib` warning remains.

The private service passed 103 Dockerized tests. Eleven real-PostgreSQL recovery
tests cover Owner cooldown, cancellation/release serialization, redelivery,
release-during-cooldown escalation, wrapper completion, generation revocation,
distinct per-device SRS records, exact partial completion, immutable successor
epochs, preserved released grants, conflicting confirmation, and concurrent
batch denial. Six heartbeat tests include historical released-presence behavior.

Migration head `b28a413c96d2` passed `alembic current` and `alembic check` with no
model drift. All 21 changed Python files passed focused Black and
Black-compatible isort; repository critical Flake8 and focused Bandit passed.
The destructive downgrade path was not executed because it intentionally
refuses to discard live I14 epoch or per-device rotation evidence.

## Remaining launch work

No test contacted KMS, SES, or another production service, and no real email,
deployment, resource provisioning, or protocol tag publication occurred. G1
still requires independent cryptographic review, penetration testing, fuzzing,
clean-device installation, restore drills, and a complete release/claim drill.
I15 retains production cloud configuration, monitoring, retention, backup,
disaster recovery, and launch authorization.
