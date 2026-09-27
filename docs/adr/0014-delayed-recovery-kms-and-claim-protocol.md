# ADR 0014: Delayed recovery KMS and claim protocol

- Status: Accepted for implementation scope
- Date: 2026-09-27
- Decision owner: I13 recovery material and claim security boundary
- Approval: Explicit user approval on 2026-09-27 for the cost-controlled
  single-Region KMS design
- Email approval: AWS SES may carry the 24-hour recovery link and 10-minute OTP
  to an accepted and verified Recovery Contact; live sending remains a separate
  launch action
- Proposal: [I13 delayed recovery KMS and claim proposal](../research/I13-delayed-recovery-kms-claim-proposal.md)
- Governing decisions: [ADR 0002](./0002-cryptographic-envelope-and-key-storage.md),
  [ADR 0010](./0010-v1-email-notification-and-contact-disclosure.md), and
  [ADR 0012](./0012-public-protocol-v1-account-device-binding.md)

## Context

The accepted client cryptography already defines a per-device 256-bit SRS as
the independent salt in the ERC plus SRS recovery path. The service has not yet
chosen a production KMS, a key hierarchy, a Region strategy, a release
authorization protocol, or the exact short-lived claim credentials. I13 cannot
persist or release recovery material until those decisions receive explicit
approval.

The server already owns irreversible account `RELEASED` state, accepted and
verified Recovery Contacts, transactional Outbox behavior, and a production
fail-closed key-provider boundary. The public client repository owns protocol
schemas and fixtures. I06 development Vaults contain recovery wrappers whose
ERC and SRS were deliberately discarded and therefore have no usable recovery
path.

## Proposed decision

Adopt the complete design in the linked proposal.

Use one AWS KMS customer-managed symmetric single-Region key with AWS-generated
material in `ap-southeast-1`. Do not create a replica, CloudHSM/custom key
store, automatic Region failover, or recovery-specific cross-Region backup.
Automatic rotation remains disabled for the personal-project MVP. The SRS key
is separate from PII, lookup, OTP, signing, database, backup, and email keys.
Production roles separate provisioning
(`GenerateDataKey` only), claims (`Decrypt` only), audited rewrap, and key
administration. Production provisioning, external KMS calls, deployment, and
Region failover remain separately authorized operational actions.

Generate each per-device 32-byte SRS with KMS
`GenerateDataKey(KeySpec=AES_256)`. Persist only the KMS ciphertext and exact
non-secret binding metadata. The encryption context binds environment, purpose,
context version, and a SHA-256 digest over protocol, account, device, Vault, and
recovery identifiers. It contains no direct personal identifier or secret.

An active bound device receives the SRS once while creating a pending recovery
record, creates the accepted local version 1 recovery wrapper, and confirms its
digest. A sealed record cannot be decrypted before authoritative `RELEASED`.
A lost provisioning response is abandoned and reprovisioned rather than
recovered through a pre-release decrypt path.

After `RELEASED`, each accepted and verified contact receives an independent
grant. A private Notification Target must first accept and verify the neutral
release invitation while the account remains `RELEASED`. Claim links are
24-hour random bearer secrets carried in a URL fragment and persisted only as
digests. A valid link starts a 10-minute, five-attempt email OTP. Successful
verification returns a five-minute opaque token scoped only to one SRS read and
bound to account, contact, recovery, device, Vault, wrapper, and grant.

Secret retrieval rechecks and locks every authoritative row, calls KMS with the
exact key and encryption context, and only then consumes the token and the
contact's grant in the same transaction as immutable redacted audit and Owner
plus other-contact security-notification intents. A KMS or transaction failure
returns no SRS and consumes nothing. Each contact grant can succeed once; other
contacts have independent grants.

The desktop validates all response and local-wrapper bindings and uses ERC plus
SRS only inside the Rust recovery path to open the existing local Vault. It
does not upload Vault data, VDK, ERC, master password, messages, images, or
attachments, and it never exposes SRS, recovery KEK, or VDK to React.

I06-era Vaults remain visibly recovery-unavailable. While unlocked with the
master password, an Owner may explicitly enroll by generating a new ERC,
provisioning a new SRS/recovery ID, atomically replacing the unusable wrapper,
and confirming it to the service. There is no automatic migration and no claim
that a Vault whose master password is already lost can be recovered.

## Security and operational consequences

- Database disclosure does not reveal SRS plaintext, while KMS/database
  compromise together remains a critical threat controlled by IAM, application
  authorization, audit, and operational separation.
- A selected-Region outage delays provisioning and claims. There is no
  alternate-Region or application-key fallback.
- Automatic KMS rotation is disabled for the MVP because it adds retained-key
  cost and does not re-encrypt existing ciphertext. Logical-key replacement
  uses audited KMS `ReEncrypt` and keeps the old key until inventory and restore
  evidence are complete.
- KMS outage delays recovery and never authorizes a bypass. Destruction of every
  usable KMS key copy makes affected SRS permanently unrecoverable.
- CloudTrail sees the non-secret encryption context. Application logs, audit,
  email, metrics, fixtures, and errors contain no recovery secret or bearer.
- The public contract becomes prepared protocol v1.2.0; no tag is published as
  part of I13 without separate authorization.
- I14 still owns Owner self-recovery, ERC rotation, and re-encryption after
  release or claim. I15 owns production infrastructure, backup replication,
  failover drills, and launch authorization.

## Alternatives rejected

CloudHSM/custom key stores, a multi-Region recovery key, a shared PII/SRS key,
application-generated SRS, plaintext provisioning retry storage, pre-release
sealed-record decrypt, query-string bearer links, JWT claim tokens, global
consumption after one contact claim, and silent reuse of I06 recovery rows are
rejected for the reasons recorded in the proposal.
