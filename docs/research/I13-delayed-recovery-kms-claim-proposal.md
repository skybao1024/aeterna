# I13 delayed recovery KMS and claim proposal

- Status: Approved for implementation scope
- Date prepared: 2026-09-27
- Client baseline: `ed6a4eb94c3261587787cd123415ccb79036f3a3`
- Server baseline: `6c7d4ebb35d62ac4b0ce029ea718a5b7b0abcf82`
- Proposed ADR: [ADR 0014](../adr/0014-delayed-recovery-kms-and-claim-protocol.md)
- Governing decisions: [ADR 0002](../adr/0002-cryptographic-envelope-and-key-storage.md),
  [ADR 0010](../adr/0010-v1-email-notification-and-contact-disclosure.md),
  and [ADR 0012](../adr/0012-public-protocol-v1-account-device-binding.md)

## Approval boundary

I13 changes a production cryptographic boundary and the conditions under which
the hosted service can release a factor that contributes to Vault decryption.
No persistence, protocol, KMS, claim, or recovery implementation described here
could begin until this proposal received explicit approval. The user approved
the cost-controlled single-Region KMS boundary on 2026-09-27.

Approval authorizes implementation and local engineering verification only. It
does not authorize provisioning AWS resources, making a production KMS call,
sending real email, deploying a service, enabling production, approving an SES
Region or recipient jurisdiction, or publishing a protocol tag.

The Owner separately approved AWS SES as the notification channel for the
24-hour recovery bearer link and the 10-minute, eight-digit OTP sent to an
accepted and verified Recovery Contact. This approves the payload category and
provider-adapter implementation, but it does not authorize a live send, AWS
resource provisioning, deployment, or production enablement.

## Reviewed baseline

The accepted local primitive boundary already fixes the relevant client
cryptography:

- each Vault has a random 256-bit VDK;
- the recovery KEK is HKDF-SHA-256 with the 128-bit ERC as input keying
  material, the independent 256-bit SRS as salt, and the exact version 1
  recovery context;
- AES-256-GCM wraps the VDK with the exact version 1 recovery AAD; and
- the recovery wrapper binds the Vault ID and device ID and fails under a wrong
  ERC, SRS, Vault ID, device ID, purpose, version, nonce, ciphertext, or tag.

The accepted server boundary already provides UUID accounts and bound devices,
signed requests, the irreversible `RELEASED` state, transactional Outbox
semantics, encrypted contacts, and the rule that only `ACCEPTED` plus a non-null
`verified_at` makes a record a Recovery Contact. A private Notification Target
has no recovery authority and receives only a neutral invitation after
`RELEASED`.

I06 created development Vaults by generating a recovery wrapper and then
discarding its ERC and SRS. Those Vaults are truthfully recovery-unavailable.
The existence of a local recovery-wrapper row must never be presented as a
usable delayed-recovery path unless a matching confirmed server recovery record
exists.

## AWS KMS capability review

The following AWS documentation was checked on 2026-09-27:

- [`GenerateDataKey`](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)
  returns a random plaintext data key and a copy encrypted under a symmetric
  KMS key. `AES_256` returns 32 bytes. AWS instructs callers to remove the
  plaintext from memory as soon as possible.
- [Encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html)
  is authenticated, must match exactly on decrypt, can constrain key policy,
  and is logged in plaintext in CloudTrail. It therefore cannot contain email,
  tokens, secrets, or direct personal identifiers.
- [KMS rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
  preserves older material for decrypt, but does not re-encrypt existing data
  keys or cure compromise of a plaintext data key. Rotation also adds retained
  key-material cost after the first and second rotations.
- [KMS internals](https://docs.aws.amazon.com/kms/latest/developerguide/kms-internals.html)
  states that AWS KMS cryptographic operations are protected by FIPS 140-3
  Security Level 3 validated HSMs.
- [Least-privilege guidance](https://docs.aws.amazon.com/kms/latest/developerguide/least-privilege.html)
  recommends specific principals and encryption-context conditions rather than
  broad `kms:*` permission.

The service already pins `boto3==1.43.103` for the accepted SES adapter, so the
proposed KMS adapter adds no production package. It uses the standard AWS SDK
credential chain, performs network calls only to the configured KMS Regional
endpoint, and has no static-credential configuration.

## Proposed KMS and key hierarchy

### Provider and Regions

Use one AWS KMS customer-managed, symmetric `ENCRYPT_DECRYPT`, single-Region
key with AWS-generated key material (`AWS_KMS` origin):

- Region: `ap-southeast-1` (Singapore);
- logical alias: `alias/aeterna-prod-recovery-srs-v1`; and
- automatic rotation: disabled for the personal-project MVP.

This is a cost-controlled single-Region decision. Approval permits the design
and code configuration, not resource creation, and does not itself enable SES.
There is no cross-Region KMS replica, CloudHSM cluster, automated Region
failover, or recovery-specific cross-Region backup.

Do not use AWS CloudHSM or a KMS custom key store for v1. They would add
customer-operated HSM availability, backup, quorum, and patching failure modes
without preventing the application from seeing plaintext SRS during
provisioning and an authorized claim. Do not use an AWS-managed key, asymmetric
key, imported key material, or the PII key for SRS.

The recovery SRS KMS key is a distinct root from every PII, lookup, OTP, JWT,
email, database, backup, and signing key. I13 does not silently convert the
existing environment-backed development PII key bundle into a production
provider; production remains fail closed until all required production key
providers are configured.

### Per-device SRS envelope

For a new recovery record, the provisioner calls `GenerateDataKey` with
`KeySpec=AES_256`. The 32 plaintext bytes are the SRS. The returned
`CiphertextBlob` is the only SRS representation persisted by Aeterna. The
service returns the plaintext SRS once, over the authenticated protocol
response, to the active bound device that requested provisioning. The device
creates the local recovery wrapper and clears the SRS from project-controlled
memory.

The exact KMS encryption context version 1 is:

```text
aeterna-purpose = recovery-srs
aeterna-environment = production
aeterna-context-version = 1
aeterna-binding = base64url_no_pad(SHA-256(
  "AETERNA-KMS-SRS-BINDING-v1\0" ||
  protocol_version_u16_be ||
  account_uuid_bytes ||
  device_uuid_bytes ||
  vault_uuid_bytes ||
  recovery_uuid_bytes
))
```

Only the four non-secret values above reach KMS and CloudTrail. Decrypt must
specify the exact configured key ARN and reconstructed context. The database
stores the ciphertext blob, provider, key ARN, KMS key-material identifier,
context version, account ID, device ID, Vault ID, recovery ID, wrapper digest,
state, and timestamps. It stores no plaintext SRS, ERC, VDK, master password,
Vault content, claim token, link token, or OTP.

The AWS SDK returns immutable byte buffers, so Python cannot prove complete
erasure of all SDK/runtime copies. The adapter copies plaintext into a bounded
mutable buffer, clears that buffer in `finally`, never logs it, and documents
this best-effort limit. No cache, queue, exception, audit row, test snapshot, or
email may contain SRS.

### Permissions and operational separation

Production uses separate workload and administration roles:

1. **Recovery provisioner**: only `kms:GenerateDataKey` on the exact primary
   recovery key, constrained to all four required encryption-context keys and
   exact purpose/environment/version values. It has no `kms:Decrypt`.
2. **Recovery claim broker**: only `kms:Decrypt` on the exact single-Region key
   ARN with the same context constraints. It has no
   `GenerateDataKey`, `Encrypt`, `ReEncrypt`, key administration, or grant
   permission.
3. **Recovery rewrap operator**: normally disabled; only narrowly scoped
   `kms:ReEncrypt*` between the explicitly approved old and new recovery keys,
   with two-person change approval and an audited runbook. It cannot retrieve
   plaintext.
4. **KMS administrator**: manages policy, alias, rotation, and deletion
   controls but receives an explicit deny for cryptographic use.
5. **General API, email workers, database roles, and support operators**: no
   KMS recovery-key permission.

The code exposes separate provision and claim provider interfaces so production
can deploy them under separate workload roles. Local engineering tests use an
explicit in-memory adapter; a single development process is not evidence of
production role separation.

CloudTrail event history or an explicitly budgeted trail records KMS activity
in the selected Region. Production alarms cover unexpected decrypt, policy
change, disable, and deletion scheduling. Application audit records only opaque
IDs, event types, outcomes, and timestamps. The encryption context remains
visible to AWS as documented, but contains only its digest binding.

### Rotation, backup, and failure recovery

- Automatic rotation is disabled for the MVP to avoid retained-key-material
  charges and because rotation does not re-encrypt existing SRS ciphertext. The
  application persists the returned key-material identifier for audit and
  never assumes it is a numeric application version.
- A logical-key replacement creates one new single-Region key. New records use
  the new key immediately. Existing ciphertext is moved with KMS `ReEncrypt`
  under the exact old and new contexts; plaintext never enters the application.
  Old keys remain decrypt-enabled until a complete inventory and restore drill
  prove that no live or retained backup references them.
- The database and any explicitly configured backup contain only KMS
  ciphertext. There is no plaintext or application-managed SRS backup. I13
  makes no cross-Region disaster-recovery promise.
- A selected-Region outage delays provisioning and claims. The application does
  not retry another Region or fall back to an application key.
- KMS timeout, throttling, disabled key, policy denial, bad context, wrong key,
  corrupt ciphertext, or unavailable Region returns one safe
  `recovery.material_unavailable` classification. It does not consume the
  claim token or grant and does not return partial material.
- Schedule-key-deletion is restricted to a break-glass two-person role, uses the
  maximum 30-day waiting period, and triggers an alarm. If all usable copies of
  a required key are nevertheless destroyed, recovery fails permanently; there
  is no plaintext fallback or support override.

## Recovery-record protocol

The public client repository remains authoritative. I13 extends protocol v1 as
a compatible `1.2.0` release and prepares, but does not create, the
`protocol-v1.2.0` tag. All new objects remain closed, every binary field uses
unpadded base64url, and all owner/device mutations use operation-specific JCS
and Ed25519 signed domains.

### Provision

`POST /api/v1/recovery/records/provision` uses domain
`aeterna.recovery-record.provision.v1`. The signed document binds request,
account, active device, Vault, client-generated recovery ID, crypto format, and
recovery-context version. The service requires an active account and active
non-dormant device, locks account then policy then device, and refuses
`RELEASED`, `DISABLED`, `DELETED`, lost, revoked, duplicate active, or rotation
states.

On success the server creates a `PENDING_CONFIRMATION` record with a 24-hour
expiry and returns exactly one 32-byte SRS. An exact request retry cannot replay
plaintext; it returns `recovery.provision_retry_required`. The client may
abandon the pending record with a separately signed operation and provision a
new recovery ID. Expired pending records are deleted without ever being
decryptable through a claim.

### Confirm

After atomically installing the recovery wrapper locally, the device submits
`aeterna.recovery-record.confirm.v1` with the exact recovery identifiers and:

```text
wrapper_digest = SHA-256(
  "AETERNA-RECOVERY-WRAPPER-DIGEST-v1\0" ||
  canonical_version_1_recovery_row_bytes
)
```

Confirmation is idempotent for the same digest and moves the record to
`SEALED`. A different digest or identifier fails. The application must show
the recovery path as unavailable until both local installation and server
confirmation succeed. I14, not I13, owns replacement of an already sealed
record.

## Release and claim protocol

### Release materialization

The I11 account/policy lock remains the authority. A deterministic worker
materializes one recovery grant per `(recovery_record, accepted_contact)` only
after it observes `RELEASED`, `SEALED`, an active non-deleted contact, exact
`ACCEPTED` consent, and non-null verification. It creates the grant, a 24-hour
claim-link verifier, redacted audit, and email Outbox event in one transaction.

For `PRIVATE_UNTIL_RELEASE`, the existing neutral invitation is still first.
Acceptance and verification must complete while the policy is still
`RELEASED`; only that transaction may materialize grants and a separate claim
email. An invitation, provider delivery state, contact ID, email possession,
or release Outbox event alone never authorizes a claim.

Claim-link secrets are random 32-byte values and only SHA-256 digests are
stored. They appear only in the URL fragment, never a path or query, so normal
HTTP access logs and referrers do not receive them. Production claim origin and
deep-link registration remain launch configuration and are not approved here.
An expired but otherwise valid link can only request that a replacement be sent
to the already verified mailbox. It cannot start OTP or return authority.
Issuance is limited to three links per contact/recovery record per rolling 24
hours with at least 60 seconds between sends.

### OTP and claim token

`POST /api/v1/recovery/claim/start` accepts a claim-link secret in the body. A
valid live link creates or reuses one 10-minute, eight-digit email OTP
challenge. The verifier is a keyed digest, attempts are limited to five, and a
resend after 60 seconds invalidates the older code. Responses to invalid,
expired, consumed, cross-contact, or unauthorized links do not reveal account
or contact existence.

`POST /api/v1/recovery/claim/verify` requires the same link, challenge ID, and
OTP. Success consumes the link and challenge and returns a random opaque claim
token valid for five minutes. PostgreSQL stores only its SHA-256 digest. The
token has exactly one operation, `recovery.srs.read`, and is bound to
`account_id`, `contact_id`, `recovery_id`, `device_id`, `vault_id`, wrapper
digest, grant ID, issuance time, and expiry.

`POST /api/v1/recovery/{recovery_id}/release-secret` requires the claim token
and repeats the recovery, device, Vault, and wrapper identifiers. The service
locks account, policy, record, grant, and token in that order, rechecks every
binding and expiry, requires authoritative `RELEASED`, and calls the claim KMS
provider with the exact key ARN and encryption context while the transaction is
open. Only after successful decrypt and exact 32-byte validation does it mark
the token consumed and that contact grant `CLAIMED`, append immutable redacted
audit, and queue Owner plus every other accepted/verified contact security
notification. The response is not emitted until commit succeeds.

Each contact grant can return the SRS at most once. Other accepted contacts have
independent grants and may claim once. A KMS failure or transaction failure
clears the plaintext buffer and rolls back token, grant, audit, and Outbox
changes. Notification delivery failure after a committed claim never restores
the consumed authority.

Every secret-bearing response uses `Cache-Control: no-store`; secrets and codes
are redacted from logs, tracing, exceptions, audit, metrics, fixtures, and
provider payload diagnostics.

## Client and local Vault boundary

The desktop recovery coordinator owns network/protocol validation, claim-token
handling, SRS lifetime, and local unwrap. React can invoke only a high-level
recovery operation and receives either a fixed safe error or an unlocked Vault
session; it never receives SRS, VDK, a recovery KEK, or decrypted record bytes.
The client verifies the response account/recovery/device/Vault bindings and the
local wrapper digest before constructing `RecoverySalt`, then calls the
accepted version 1 `unwrap_recovery` path and clears project-controlled ERC,
SRS, RKEK, and temporary VDK buffers.

Successful recovery opens the existing local Vault and displays its existing
items through the same session and bounded item APIs as master-password unlock.
No Vault row, VDK, ERC, master password, message, image, attachment, or decrypted
content is uploaded. A wrong local Vault, wrong device binding, or different
wrapper digest fails before or during authenticated unwrap.

I13 uses a replaceable Rust transport and a local deterministic test adapter;
it does not add a production HTTP dependency or claim live service acceptance.
The protocol fixtures and digest provide the cross-repository contract.

### I06 compatibility

An I06-era development Vault remains explicitly `recovery unavailable` even
though its database contains a discarded-material wrapper. It is never
auto-enrolled and its old recovery ID is never uploaded as if it were valid.
While the Vault is unlocked with its master password, the Owner may explicitly
choose **Enable delayed recovery**. The client provisions a new recovery ID and
SRS, generates and presents a new ERC, atomically replaces the unusable local
wrapper with one for the current VDK, confirms the new wrapper digest to the
service, and only then marks recovery enabled. Cancellation, crash, timeout, or
server failure leaves a truthful incomplete state and never claims protection.

New Vault onboarding after I13 must either complete the same confirmed recovery
enrollment or remain visibly recovery-unavailable. I13 does not recover a
legacy Vault whose master password is already lost. I14 remains responsible for
later ERC rotation, Owner self-recovery, and post-release VDK replacement and
re-encryption.

## Persistence and concurrency rules

The server migration is additive and uses checked string states and
`TIMESTAMPTZ`. It adds recovery records, per-contact grants, claim links, OTP
challenges, claim tokens, redacted audit, and the minimum Outbox references.
Database constraints enforce fixed lengths, state/timestamp consistency,
single live record per device/Vault, one grant per record/contact, token scope,
and stable idempotency keys.

All mutations use account-first lock ordering. Release materialization and
private-contact promotion lock account, policy, contact, then recovery rows.
Secret retrieval locks account, policy, record, grant, token. Compare-and-set,
row locks, uniqueness constraints, and one transaction prevent a heartbeat or
release race, two claim winners, replay, cross-contact/record substitution, and
partial audit/notification writes.

## Planned verification

### Public/client

- protocol `1.2.0` schemas, generated signatures, invalid fixtures, manifest,
  digest, strict duplicate/unknown-field/body-size validation, and Rust contract
  tests;
- provision/confirm/abandon state, response-loss behavior, wrapper-digest
  mismatch, expired provisioning, and explicit legacy enrollment;
- real local Vault recovery through the existing repository/session/item path;
- proof that ERC alone, SRS alone, wrong ERC, wrong SRS, another device's SRS,
  and SRS plus the wrong local Vault cannot recover the VDK;
- tampered metadata/ciphertext, wrong account/device/Vault/recovery binding,
  malformed base64url, oversized input, and secret-redaction tests; and
- `npm run check` plus `npm run desktop:build`.

### Server

- strict public schemas and exact vendored manifest digest;
- KMS adapter request shape, exact context/key ARN, size validation, timeout,
  throttling, wrong key/context, corrupt response, disabled provider, and no
  production call;
- every pre-release, unverified, deleted, declined, private-unaccepted,
  cross-contact, cross-account, cross-device, cross-Vault, expired, duplicate,
  and replay path fails closed;
- concurrent claim has exactly one winner per contact grant; injected failures
  after KMS and before commit return no SRS and roll back consumption, audit,
  and Outbox;
- KMS outage leaves authority retryable but unused; email failure after claim
  leaves the claim consumed; stable Outbox retries remain idempotent;
- private release acceptance cannot create a grant unless the policy remains
  `RELEASED`; and
- complete Docker/PostgreSQL tests, live Celery registration, migration
  upgrade/downgrade/re-upgrade/current/check, focused Black/isort/Flake8/Bandit,
  dependency consistency, and OpenAPI inspection.

No test will contact AWS, send real email, deploy, publish a tag, or claim
production readiness. Synthetic SRS, tokens, OTPs, addresses, Vaults, and
content are used throughout.

## Alternatives rejected

- **CloudHSM/custom key store:** adds operator-controlled HSM availability and
  cost without eliminating plaintext SRS at authorized application boundaries.
- **Multi-Region KMS key:** adds another billed key and operational scope that
  this personal-project notification channel does not presently need. A
  selected-Region outage therefore delays claims instead of invoking a replica.
- **One KMS key for SRS and PII:** makes database disclosure and operational
  permissions unnecessarily broad.
- **Application-generated SRS plus KMS `Encrypt`:** contradicts the product
  rule that the service generates SRS and adds a separate randomness boundary.
- **Persist plaintext SRS for response retries:** turns the database into a
  sufficient recovery factor and violates the trust model.
- **Decrypt a sealed SRS for an active Owner before release:** creates an
  alternate pre-release retrieval path. A lost provisioning response must be
  abandoned and reprovisioned instead.
- **Put link tokens in query strings:** exposes bearer material to access logs,
  histories, and referrers.
- **JWT claim tokens:** embeds durable authorization context in a replayable
  bearer and complicates single-use revocation. Opaque digest-backed tokens are
  narrower.
- **Treat one contact claim as globally consuming the SRS:** contradicts the
  accepted per-contact grant model and can deny another authorized contact.
- **Silently reuse I06 recovery rows:** those rows refer to discarded factors
  and provide no honest recovery path.

## Approval request

Approve or reject the complete decision above, including:

1. one AWS KMS customer-managed single-Region symmetric key with AWS-generated
   material in Singapore, no replica or automatic rotation, a separate SRS
   root, exact encryption context, and the stated role separation;
2. KMS `GenerateDataKey(AES_256)` as the per-device SRS generation and envelope
   mechanism, with one provisioning delivery and no sealed pre-release decrypt;
3. the exact release, link, OTP, opaque-token, per-contact single-claim,
   notification, transaction, and failure semantics;
4. public protocol v1.2.0 ownership and prepared-but-unpublished tag; and
5. explicit opt-in replacement of discarded-material I06 recovery wrappers,
   with no retroactive recovery claim.

Approval record: **Approved by the user on 2026-09-27.** The user selected the
cost-controlled single-Region KMS design after reviewing the SRS role and
current AWS KMS pricing. The approval excludes resource provisioning, live KMS
calls, live email, deployment, and protocol-tag publication.
