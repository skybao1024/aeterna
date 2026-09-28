# I14 owner recovery, rotation, and post-compromise rekey proposal

- Date: 2026-09-27
- Status: Accepted for implementation scope by ADR 0015 on 2026-09-27
- Proposed ADR: [ADR 0015](../adr/0015-owner-recovery-rotation-and-post-compromise-rekey.md)
- Governing decisions: [ADR 0002](../adr/0002-cryptographic-envelope-and-key-storage.md),
  [ADR 0007](../adr/0007-local-vault-format-v1.md),
  [ADR 0009](../adr/0009-portable-export-package-and-atomic-restore-v1.md),
  and [ADR 0014](../adr/0014-delayed-recovery-kms-and-claim-protocol.md)
- Product authority: `docs/DESIGN.md` sections 3, 7, 8.5-8.6, 10, 14,
  and 18.4-18.5

## Purpose and approval boundary

I14 must add three related security operations without turning email, support,
or an unbound device into Vault authority:

1. recovery by an Owner who forgot the master password but still has the ERC,
   a bound device, and mailbox control;
2. pre-release ERC rotation across independently stored device Vaults; and
3. a fresh VDK and complete local re-encryption after a release or claim has
   made the old recovery factors potentially copyable.

The accepted decisions do not authorize all of this work. ADR 0014 explicitly
defers Owner recovery, ERC/SRS rotation, and post-release rekey to I14. ADR 0007
does not define an atomic whole-Vault VDK replacement operation, and the
accepted server state machine makes `RELEASED` terminal. This proposal
therefore requires explicit approval before implementation changes the KMS
decrypt authorization, recovery protocol, policy lifecycle, recovery-record
states, or local rekey behavior.

Approval authorizes only code, migrations, protocol v1.3.0 fixtures,
tests, and documentation for this engineering boundary. It would not authorize
an AWS request, a real email, KMS or SES provisioning, deployment, protocol tag
publication, production credentials, a cryptographic algorithm change, or a
release claim. Those remain I15 and G1 work.

## Security invariants

- The service never receives a Vault record, attachment, VDK, ERC, master
  password, recovery KEK, plaintext message, or attachment metadata.
- Email OTP, support staff, a new device, or a server database alone never
  yields a usable Vault capability.
- An Owner SRS release is restricted to the same still-bound device whose
  Ed25519 key signed the request and whose current local recovery row is bound
  to that SRS.
- The server uses its own UTC receipt time. All boundaries are inclusive and
  all replayable operations have an exact request digest and idempotency rule.
- A pre-release ERC rotation makes the prior live SRS records unavailable at
  the service before the rotation can be reported as active.
- Partial multi-device rotation or rekey is always reported as partial. A
  device is complete only after its exact local wrapper digest is confirmed.
- `RELEASED` evidence and claimed grants are immutable historical facts. A new
  VDK protects only new ciphertext; it cannot revoke old ciphertext or any
  ERC/SRS copy that has already left its original boundary.
- Official clients fail closed on an unknown version, epoch, device, Vault,
  wrapper digest, signature, OTP, cooldown, or rekey requirement.

## Owner recovery authorization

### Eligible device and recent activity

An Owner recovery request is accepted only when all of these facts are locked
and rechecked:

- the account is not `DISABLED` or `DELETED`;
- the device is still bound and has status `active`;
- the device has a sealed, non-revoked recovery record for the exact local
  `vault_id`, `device_id`, recovery generation, and wrapper digest;
- the signed request uses the operation-specific
  `aeterna.owner-recovery.start.v1` domain; and
- the device's last accepted signed heartbeat was received no more than 15
  minutes before the request.

The 15-minute interval is a server constant in v1.3.0, not a client-selected
value. A heartbeat accepted while a policy is `ACTIVE`, `PRE_WARNING`, or
`GRACE_PERIOD` retains the existing state-machine semantics. A heartbeat from
a device in a historical `RELEASED` policy epoch may advance only that
device's replay-protected sequence and `last_seen_at`. It returns a
`released-presence-only` outcome and cannot reset the policy, cancel a grant,
or alter any release evidence. This narrow behavior supersedes only the I11
rule that a released policy rejects every heartbeat mutation; the released
policy itself remains terminal.

I08 is still stopped. Deterministic signed-heartbeat tests are engineering
evidence for this protocol condition and are not native activity acceptance.

### Mailbox challenge and cooldown

Starting a request creates one digest-bound eight-digit Owner mailbox OTP:

- lifetime: 10 minutes;
- resend delay: 60 seconds;
- maximum failed attempts: five; and
- a resend invalidates the older challenge.

Successful verification consumes the challenge and changes the request to
`cooling_down`. The service then queues security notifications to every
configured and verified Owner security channel. In v1 this means the verified
Owner mailbox plus a durable in-app security event visible to every active
bound device; it does not silently add SMS or another provider. The cooldown is
exactly 24 hours from the server verification timestamp. Notification provider
delay can delay awareness but never shorten the server cooldown.

Request states are closed:

```text
pending_email -> cooling_down -> ready -> material_released -> completed
       |               |          |
       +---------------+----------+-> cancelled
       +---------------+----------+-> expired
                                              |
                                              +-> expired
```

`ready_at` is the inclusive 24-hour boundary. A ready request expires 24 hours
after `ready_at` if no SRS has been released. Once the first SRS response is
committed, the same initiating device may repeat the exact signed release
operation until the earlier of completion or 24 hours after first release.
This bounded re-delivery is deliberate: one authorized SRS response is already
copyable, while repeatability lets a power loss before local wrapper rotation
recover without persisting SRS in ordinary storage or OS credential storage.
Every retry rechecks the device, heartbeat recency, request, policy epoch,
recovery record, Vault, and wrapper digest. The first release and any anomalous
retry burst queue security events. No response is cached.

### Verifiable cancellation and races

Any active bound device for the account may cancel a `pending_email`,
`cooling_down`, or `ready` request with its own operation-specific signed
request. Email alone cannot cancel or release material. Cancellation locks the
account, policy epoch, Owner request, initiating device, cancelling device, and
recovery record in the documented order. It records the cancelling device ID,
request ID, server timestamp, and redacted audit event and queues all Owner
security notifications.

Cancellation and release contend on the same Owner-request row. Exactly one
wins. Cancellation that commits first prevents KMS decrypt. A release that has
already passed its locked authorization and committed cannot be described as
revoked; a later cancellation returns the terminal released state.

### Device-scoped release and forced local follow-up

At or after `ready_at`, the initiating device submits
`aeterna.owner-recovery.release.v1`. The service rechecks every condition and
uses a dedicated Owner-recovery decrypt dependency that accepts only a mature
Owner request and its exact sealed SRS envelope. It returns only the initiating
device's SRS and exact non-secret bindings.

The Rust coordinator decodes the ERC and SRS, unwraps the existing VDK, and
does not expose ERC, SRS, KEK, VDK, or decrypted records to React. Before the
ordinary unlocked content surface is available, it requires a new master
password and a new SRS for that device. It atomically replaces the master and
recovery wrappers around the unchanged VDK, updates header authentication, and
then confirms the exact new recovery wrapper to the service. Confirmation
revokes the old live SRS authorization and completes the Owner request.

If the policy epoch was already `RELEASED`, any grant was `CLAIMED`, or the
server reports an unacknowledged compromise epoch, the coordinator must use the
post-compromise rekey path below instead of rewrapping the old VDK.

## ERC and SRS rotation

### Generations and activation

The service adds a monotonically increasing recovery generation and one active
rotation batch per account. Recovery records carry their exact generation.
The server never stores a digest or verifier of the ERC.

The initiating client generates a fresh version 1 ERC and a new SRS-backed
recovery record. Rotation has two phases:

1. `preparing`: the old generation remains authoritative while the initiating
   device atomically installs and confirms its target-generation wrapper;
2. `active`: confirmation of the initiating device atomically activates the
   target generation, makes every old current-generation SRS unavailable to
   all service release paths, and snapshots the remaining eligible devices as
   incomplete.

This sequence avoids declaring a rotation before any new wrapper works while
also giving the activation transaction one clear point at which the old live
generation stops authorizing release. Live SRS ciphertext for the superseded
pre-release generation is removed from current application rows and every
grant, link, OTP, and token for it is revoked. Database backups may retain old
KMS ciphertext until their retention expires, so this is service-authorization
revocation, not a false physical-erasure claim.

### Per-device completion

Every active bound device is represented in the batch with one closed status:

- `pending`: it had an old sealed wrapper and needs the new ERC plus a new SRS;
- `not-enrolled`: it had no confirmed delayed-recovery record at the snapshot;
- `complete`: its exact target-generation wrapper was confirmed; or
- `excluded`: it was explicitly removed, lost, or revoked after the snapshot.

The Owner enters the same new ERC on each device through a Rust-owned path,
unlocks that local Vault with its master password, provisions a distinct SRS,
and atomically replaces only that device's recovery wrapper around its existing
VDK. No ERC or VDK crosses the network. A batch becomes `complete` only when no
eligible device is `pending` or `not-enrolled`. The status API returns exact
device IDs, safe display labels, states, and server timestamps, not a synthetic
all-safe boolean.

Duplicate confirmations are idempotent for the same digest. A different
digest, stale generation, out-of-order provision, concurrent second rotation,
or confirmation after exclusion fails closed. Interrupted work leaves the
confirmed devices complete and the remaining devices visibly incomplete.

## Post-release or post-claim VDK replacement

### Immutable policy epochs

Directly changing one policy row from `RELEASED` back to `ACTIVE` would erase
the meaning of accepted I11 release evidence. Instead, one account has ordered
policy epochs:

- each epoch separately follows the accepted terminal state machine;
- a released epoch always remains `RELEASED` with its transition, grants,
  audit, and notifications intact;
- at most one non-retired current epoch exists; and
- a successor epoch can become current only after one device has atomically
  rekeyed locally and confirmed its new wrapper.

Recovery records, grants, claim credentials, policy events, and devices carry
the epoch they authorize. Claims for an old released epoch remain available
under their accepted rules and can recover only old ciphertext. A successor
epoch does not revoke them or pretend that copied material disappeared.

After a successor epoch is created, only devices that completed its rekey may
submit heartbeats that affect its inactivity deadline. Other still-bound
devices remain `migration-pending`: they may prove released-presence and run
the constrained migration protocol, but cannot indefinitely delay the new
epoch with a stale Vault lineage.

### Owner authorization and new factors

Rearming a successor epoch requires a signed bound-device request and an Owner
mailbox OTP. It does not have a second 24-hour cooldown because it never
releases an old SRS, cancels an old claim, or grants access to old ciphertext.
Old released grants remain valid. The new SRS is scoped only to the proposed
successor epoch and cannot unwrap the old VDK.

The official Owner path requires all of the following before local commit:

- authenticated access to the old VDK through MP or an authorized old recovery
  path;
- a new master password;
- a freshly generated ERC, not reuse of the potentially copied old ERC;
- a new per-device SRS for the successor epoch; and
- explicit disclosure that old ciphertext and copied old factors remain usable
  by anyone who already has them.

### Atomic local algorithm

The local Vault continues to use the accepted schema, crypto version, wrapper
encodings, record frame, and item format. I14 adds a whole-Vault operation but
does not reinterpret or silently migrate any version 1 byte.

The Rust operation consumes an unlocked session and performs this work in one
SQLite `BEGIN IMMEDIATE` transaction:

1. generate a fresh 256-bit VDK from the OS CSPRNG;
2. derive a new master KEK from the new password with the persisted approved
   Argon2 profile and create a fresh master wrapper;
3. derive a new recovery KEK from the fresh ERC and successor SRS and create a
   fresh recovery wrapper;
4. authenticate and decrypt each bounded record with the old VDK, validate its
   canonical item payload including embedded attachments, reserve a fresh
   record nonce, increment its generation, and encrypt it under the new VDK;
5. replace the VDK nonce ledger with fresh master-wrapper, recovery-wrapper,
   header, and record nonce reservations for the new VDK lineage;
6. recompute header authentication over the new wrappers and metadata; and
7. commit all record frames, wrappers, header authentication, timestamps, and
   nonce reservations together.

The transaction is the durable rekey marker. Before commit, an error, panic,
process termination, short write, `SQLITE_FULL`/`ENOSPC`, or power loss leaves
the complete old Vault. After commit, the complete new Vault opens with the new
password/ERC/SRS and the old factors cannot authenticate it. There is no state
in which a committed header points at a mixture of old- and new-VDK records.

If local commit succeeds but server confirmation fails, the new master path is
usable and the exact persisted recovery ID/wrapper digest makes confirmation
retryable. Recovery remains visibly pending until confirmation. If the process
loses an old SRS before local commit, a still-live mature Owner recovery request
can redeliver it under the bounded rules above. A one-time contact claim is not
silently made reusable; an Owner without the required bound device, mailbox,
and ERC remains unable to recover after losing the only delivered material.

Attachments require no separate plaintext or migration surface because ADR
0008 stores their metadata and bytes inside the authenticated item payload.
Each item is decrypted and re-encrypted as one bounded record.

### Multi-device successor status

The first confirmed rekey creates the successor current policy epoch and marks
that device complete. Every other active device from the released epoch is
listed as `migration-pending` until its own local Vault is rekeyed with a fresh
VDK and the shared new ERC plus a distinct new SRS. Removed/lost/revoked devices
are shown as excluded rather than silently counted as complete. The product may
say the account has a new protected epoch after the first device, but may say
all devices are protected only when every eligible device is complete.

## Public protocol and persistence

The public client repository remains authoritative. I14 prepares protocol
v1.3.0 with closed JSON Schemas, stable error codes, synthetic valid/invalid
fixtures, Ed25519/JCS vectors for every device mutation, and one exact manifest
digest consumed by both repositories. The release is prepared but not tagged.

The protocol adds narrowly scoped operations for:

- Owner recovery start, OTP verification, status, cancellation, and mature
  device-scoped SRS release;
- rotation start, per-device provision/confirm, status, and exclusion;
- post-compromise successor start, OTP verification, new-record provision, and
  local-rekey confirmation; and
- compromise status sufficient for the official client to require rekey.

Secret-bearing responses use `Cache-Control: no-store`. Closed schemas forbid
Vault data, VDK, ERC, passwords, messages, attachment metadata/content, paths,
and arbitrary user text. Binary material uses unpadded base64url with exact
lengths. UUIDs, timestamps, versions, generations, states, and purposes have
the same canonical rules as protocol v1.2.0.

The server migration is additive where possible and changes the existing
one-policy-per-account relationship into ordered immutable policy epochs. It
adds Owner requests/challenges, recovery rotations and device statuses, epoch
and generation bindings, and the minimum redacted audit/Outbox references.
Every time remains `TIMESTAMPTZ`; enum-like values remain checked strings.
Downgrade is refused by the migration if more than one policy epoch or any I14
row exists, because collapsing accepted release history would be destructive.

## Locking, idempotency, and rollback

The global order is account, current or referenced policy epoch, Owner request
or rotation, device rows in UUID order, recovery records in UUID order, then
grants/credentials and Outbox. KMS decrypt occurs only after all authorization
rows are locked and rechecked. An external KMS failure commits no release,
audit, request transition, or notification intent.

Owner start/verify/cancel/release, rotation activation/completion, and successor
confirmation use unique operation plus request-ID digest records. An exact
replay returns the persisted non-secret result, except a secret response is
recomputed only while its explicit bounded authorization window remains live.
A changed payload under the same request ID is an idempotency conflict.

Claim, Owner release, cancellation, rotation activation, and successor
confirmation are serialized under the same account and referenced policy rows.
No transaction may both revoke a pre-release SRS and return it. No successor
epoch may become current while its initiating local wrapper remains
unconfirmed.

## Verification plan

Client verification includes real temporary SQLite files and the ordinary item
and attachment APIs. It covers:

- correct and wrong MP/ERC/SRS/AAD/device/Vault/wrapper/epoch combinations;
- unchanged-VDK dual-wrapper replacement for Owner recovery;
- fresh-VDK re-encryption of empty, multi-record, and maximum bounded item
  Vaults with attachments;
- record generation and nonce-ledger replacement with no duplicate nonce;
- old factors failing against new data and new factors reading every record;
- transaction rollback before and during record replacement, short-write/error
  injection, SQLite full/`ENOSPC`, dropped transaction, and reopen after
  interruption;
- local commit followed by failed server confirmation and successful retry;
- unknown/malicious protocol data, hostile lengths, and privacy-log capture;
  and
- export of the new committed Vault plus rejection of mixed or tampered state.

Server verification uses Docker/PostgreSQL and covers:

- unbound, dormant, lost, revoked, stale, wrong-key, and modified-signature
  devices;
- OTP replay, resend invalidation, attempt exhaustion, and wrong purpose;
- exact cooldown boundaries, expiry, cancellation/release races, and repeat
  material reads outside the bounded window;
- release/claim/Owner recovery, rotation, and heartbeat concurrency;
- immediate old-generation revocation, cross-device substitution, partial
  rotation, duplicate/out-of-order requests, and exact completion status;
- immutable old released epochs, old grants remaining scoped to old records,
  successor activation, and stale-device heartbeat refusal;
- KMS and database rollback, Outbox idempotency, migration upgrade/downgrade
  guards, and captured logs/email intents containing no secrets.

Both repositories verify the exact same generated fixtures and digest. Full
repository checks and the unsigned desktop build are required. No test may
contact AWS, send real email, deploy, or treat I08 as native acceptance.

## Alternatives and security impact

### Reset the released policy row to ACTIVE

Rejected. It would contradict accepted I11 evidence, make old and new grants
ambiguous, and let later code accidentally interpret an irreversible release
as if it never happened.

### Keep the account terminal and rekey only locally

Rejected as the default. It can protect one local copy but cannot truthfully
restore delayed recovery or multi-device heartbeat protection for new data.

### Reuse the old VDK, ERC, or SRS after release

Rejected. Rewrapping the old VDK under copied factors or encrypting new data
under the old VDK would leave new versions within the old compromise boundary.

### Stage a new ERC while retaining old SRS until every device completes

Rejected. It improves availability but leaves the old ERC/SRS combination
authorized for an unbounded partial-rotation period. Activation instead waits
for one working new wrapper and then revokes the old live generation
atomically.

### Store an old SRS or VDK in ordinary local persistence for crash recovery

Rejected. It creates a new durable local secret target and contradicts the
accepted transient-SRS boundary. Bounded, same-device Owner re-delivery after
full authorization provides resumability without that storage.

### Let mailbox OTP, support, or a new device initiate SRS release

Rejected. Any of these choices would turn account recovery into Vault recovery
and collapse the independent device plus ERC factors.

### Physically erase every old ciphertext and factor copy

Impossible to promise. Local exports, SSD snapshots, recipient copies, server
backups, and an already returned SRS are outside reliable remote erasure. I14
uses explicit epochs, stops new data from using the old VDK, and tells the user
the exact limitation.

## Approval effect

Approval authorizes the exact v1.3.0 protocol, 15-minute recent-device rule,
24-hour Owner cooldown, bounded same-device redelivery, pre-release rotation
activation, immutable policy epochs, mandatory fresh VDK/ERC/SRS after
compromise, version 1 atomic local rekey semantics, additive server migration,
tests, UI status/disclosure, and documentation described here.

It does not authorize changing the accepted algorithms, KDF parameters,
wrapper/AAD/record bytes, export format, live cloud configuration, IAM roles,
provider resources, real notifications, deployment, production migration,
protocol publication, signing, or release. Any implementation discovery that
requires one of those changes returns for a separate decision.
