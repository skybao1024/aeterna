# ADR 0013: Signed heartbeat and device aggregation

- Status: Accepted
- Date: 2026-09-27
- Decision owner: I10 heartbeat protocol and device-activity boundary
- Approval: User authorized I10 development on 2026-09-27 after proposal review
- Governing decisions: [ADR 0004](./0004-macos-keychain-identity-continuity.md),
  [ADR 0006](./0006-public-protocol-ownership-and-versioning.md), and
  [ADR 0012](./0012-public-protocol-v1-account-device-binding.md)
- Proposal: [I10 signed heartbeat and multi-device proposal](../research/I10-signed-heartbeat-multi-device-proposal.md)

## Context

I09 established public protocol v1, bound Ed25519 device identities, strict
transport parsing, and cross-repository fixtures. It deliberately did not
authorize heartbeat sequencing, device dormancy, device status changes, or
account activity aggregation.

I10 must add those behaviors without trusting a device identifier, client wall
clock, process lifetime, or local activity observation. It must also make a
network retry safe without allowing an old accepted activity to be repackaged
as a later heartbeat. The I08 macOS lifecycle implementation is stopped and
unaccepted, so I10 cannot silently depend on or merge that checkpoint.

## Proposed decision

Adopt the complete I10 design in the linked proposal. The public repository
will extend protocol v1 with closed heartbeat and device-status schemas,
operation-specific Ed25519 domains, exact synthetic fixtures, stable errors,
and a new manifest digest. The private service will vendor that exact package
before implementing the endpoint and persistence changes.

The heartbeat signed document contains only protocol/signature metadata,
request, account and device UUIDs, and a positive monotonic sequence within the
I-JSON exact-integer range. It contains no timestamp, deadline, activity type,
activity observation, application, window, URL, input value, Vault data,
contact data, or recovery material. The domain is
`aeterna.heartbeat.submit.v1`; it is not shared with binding, device status,
recovery, or another operation.

The service locks the account and selected device in a consistent order,
verifies the bound public key and eligible device status, and accepts only a
sequence greater than the device's last accepted sequence. Server receipt time
is the sole `last_seen_at`. A fixed 30-minute per-device cooldown applies to
new heartbeats. Exact retries of the most recently accepted request return its
original acceptance data without changing sequence, receipt time, or account
activity. Reusing that request ID with different bytes fails. A same or lower
sequence under any other request ID fails.

The service stores only each device's latest sequence, accepted request digest,
server receipt time, and the account maximum. It does not retain a permanent
heartbeat history. The account aggregate is the maximum `last_seen_at` among
currently active devices and is recomputed transactionally when an eligible
heartbeat or device-status transition changes that set.

Device states are `active`, `dormant`, `lost`, and `revoked`. A device becomes
dormant when no heartbeat has been accepted for 90 days, measured from server
time; a never-seen device uses its latest authorization time. At the boundary,
the attempted heartbeat marks it dormant and fails with re-verification
required. `lost` and `revoked` are terminal for that device identity and never
accept heartbeats. An active device may sign a separate domain-separated
request to mark itself or another device on the same account lost or revoked.

A dormant device is re-verified through the existing I09 device-binding
approval boundary using the same device UUID and public key: it needs a fresh
mailbox-verified binding grant and then either another active device's signed
approval or the existing 24-hour delayed fresh-email path. Re-authorization
does not itself count as activity, does not reset the monotonic sequence, and
does not restore the old `last_seen_at` to the account aggregate. The first new
confirmed activity must submit a higher sequence. Lost or revoked identities
cannot use this path and require a new device identity and normal binding.

The desktop will implement an activity-candidate-to-heartbeat coordinator with
injected monotonic clock, durable sequence/pending-request store, signer, and
transport. It creates a heartbeat only from an explicit confirmed candidate,
persists one exact signed request before sending, and retries only those exact
bytes while the candidate remains fresh. A timeout never allocates a new
request ID or sequence for the same candidate. Startup, process lifetime,
online status, and a merely local candidate never become server-confirmed
activity.

I10 does not connect a real macOS activity source. That remains dependent on
I08 acceptance. I10 tests the boundary with deterministic candidates and
replaceable clocks and transports, and does not claim native lifecycle or
release readiness.

## Security impact

- Cross-operation replay fails because heartbeat and device-status signatures
  use domains not used by binding or recovery.
- A copied request cannot advance activity twice; an exact transport retry is
  a read-only replay of the prior acceptance result.
- Client clock changes cannot influence receipt time, cooldown, dormancy, or an
  account deadline.
- Revoked, lost, or dormant devices cannot extend account activity.
- Re-verification cannot manufacture activity or reset the replay counter.
- No new cryptographic primitive, production secret path, telemetry recipient,
  native permission, or third-party dependency is introduced.

## Consequences

- Public protocol v1 receives a new prepared package version and digest. No Git
  tag or publication occurs without a separate explicit request.
- The service needs an additive migration for heartbeat and aggregation fields
  plus a revised device-status constraint and repeatable dormant-device binding
  records.
- The client can prove sequence/retry behavior before I08 supplies a production
  activity source or an HTTP adapter.
- I11 remains responsible for policy deadlines, warning/grace transitions, and
  heartbeat-versus-release integration. I10 does not claim that state machine.
- Production KMS/HSM integration, macOS 15 qualification, native I08 acceptance,
  and the formal protocol tag remain release blockers.

## Alternatives rejected

- Client timestamps or deadlines: they make wall-clock manipulation affect the
  safety boundary.
- Device ID or bearer token as heartbeat authentication: neither proves control
  of the bound key.
- Allocating a new sequence after a timeout: it can turn one stale observation
  into repeated new heartbeats.
- Permanent heartbeat history: it is unnecessary for aggregation and expands
  behavioral data retention.
- Resetting sequence on dormancy: it permits old signed requests to become
  valid again.
- Treating re-verification as activity: mailbox or device approval is not a
  user-activity observation.
- Importing the stopped I08 branch: it would blur the unaccepted native
  lifecycle gate and I10's independently testable boundary.
