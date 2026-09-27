# I13 delayed recovery material and claim results

- Date: 2026-09-27
- Client baseline: `ed6a4eb94c3261587787cd123415ccb79036f3a3`
- Server baseline: `6c7d4ebb35d62ac4b0ce029ea718a5b7b0abcf82`
- Result: Accepted for the fail-closed engineering boundary
- Decision: [ADR 0014](../adr/0014-delayed-recovery-kms-and-claim-protocol.md)
- Public protocol: prepared `protocol-v1.2.0`, digest
  `456335ec6baf6f7161aa715263943427402ff675606fc68db79cb381572ed2e1`
- Production AWS activity: none

## Implemented boundary

The public protocol now has closed schemas, stable errors, generated valid and
invalid fixtures, and Ed25519/JCS signature vectors for recovery-record
provisioning, confirmation, claim start, OTP verification, and one scoped SRS
read. Secret-bearing responses are marked `Cache-Control: no-store` by the
private service.

The desktop Rust core can explicitly replace a discarded development recovery
wrapper while the Vault is unlocked, persist the replacement atomically, bind
the wrapper digest to the exact local recovery row, validate every server
response binding, and use ERC plus SRS only inside the Rust recovery path. SRS,
the recovery KEK, VDK, and decrypted records are not exposed to React. Existing
I06 Vaults are not silently made recoverable.

The private service stores one KMS-encrypted SRS per device and Vault recovery
record. Provisioning returns plaintext SRS exactly once; a lost response must be
abandoned or expire before reprovisioning. Confirmation seals the record with
the local wrapper digest. Only authoritative `RELEASED`, a sealed record, and an
accepted, verified, non-deleted Recovery Contact can materialize an independent
one-time grant.

Claim links last 24 hours and are fragment-carried bearer secrets whose digests
alone are stored. Expired valid links can request a mailbox-only replacement,
limited to three issuances in a rolling 24 hours and one per 60 seconds. A live
link creates or, before the resend boundary, reuses a 10-minute eight-digit OTP;
resend invalidates the older challenge. Verification consumes the link and
returns a five-minute digest-only token bound to account, contact, record,
device, Vault, wrapper, grant, and the single `recovery.srs.read` operation.

SRS release re-locks and rechecks every authoritative row before KMS decrypt.
Only a successful decrypt and database commit consume the token and that
contact's grant. The same transaction writes redacted audit and queues Owner
and other-contact security notices. KMS or transaction failure returns no SRS
and leaves the authority retryable.

## AWS and cost boundary

The production adapter is constrained to one AWS KMS customer-managed,
symmetric, single-Region key in `ap-southeast-1`. It uses
`GenerateDataKey(AES_256)` for provisioning and `Decrypt` with the same key ARN
and exact non-secret encryption context for claims. No Multi-Region replica,
CloudHSM/custom key store, automatic Region failover, automatic rotation, or
recovery-specific cross-Region backup is included in the personal-project MVP.

AWS SES is approved as the notification channel for the 24-hour recovery link
and 10-minute OTP to an accepted and verified Recovery Contact. Rendering is
late, outbox-authorized, and covered with a capturing adapter. No AWS request,
real email, resource provisioning, deployment, production enablement, or
protocol tag publication occurred.

## Verification evidence

Pinned-toolchain `npm run check` passed 20 frontend tests, protocol generation
and the exact 65-file release digest, 106 non-ignored Rust library tests, nine
I05 integration tests, five I06 integration tests, Rust formatting, Clippy with
warnings denied, and Rust check. The unsigned desktop build succeeded; the
known non-fatal `rust-objcopy` `libLLVM.dylib` warning remains.

The private service passed 96 Dockerized tests. Six real-PostgreSQL I13 tests
cover pre-release denial, unverified-contact denial, provision replay,
expired-record deletion and reprovisioning, post-release recovery, exact
binding, single use, KMS rollback, concurrent claim release, SES link and OTP
rendering, OTP resend invalidation, and bounded expired-link replacement.
Migration `350391c65e38` passed current/check,
downgrade to `b1e89ccdb30a`, re-upgrade, and a second current/check. Focused
Black, Black-compatible isort, repository critical Flake8, and focused Bandit
checks passed.

## Remaining launch work

The AWS key, alias, IAM roles, SES sender and Region, and monitoring are not
provisioned. Production remains disabled and fail closed. I15 owns live cloud
configuration, backup/restore and outage drills, retention, monitoring, and
launch authorization. I14 still owns Owner self-recovery, ERC/SRS rotation,
post-claim VDK replacement, and re-encryption.
