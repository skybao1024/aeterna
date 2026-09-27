# I10 signed heartbeat and multi-device proposal

- Status: **Implemented and accepted**
- Research date: 2026-09-27
- Approval date: 2026-09-27
- Client baseline: `e3ee9abdca3671824ae007dbe842cd25656136ba`
- Service baseline: `594873f48bec30745464d04099d26222dfa60664`
- Current public protocol digest:
  `a2d4fe59198267d3a246e278c6a0ab196c5f6660ed48b9f1dd276fb22af447fd`
- Proposed decision: [ADR 0013](../adr/0013-signed-heartbeat-and-device-aggregation.md)

## Approval boundary

Approval authorizes the exact public protocol, replay, cooldown, device-state,
re-verification, persistence, aggregation, and deterministic client boundary
below. Until approval, I10 may inspect the repositories and prepare these
documents, but it will not add endpoints, migrations, protocol fixtures, or
production behavior.

Approval does not authorize a protocol tag or publication, deployment,
production KMS/HSM access, a real macOS activity integration, merger or
acceptance of I08, I11 warning/grace behavior, notification delivery, recovery
material, or a release-readiness claim.

## Baseline and scope

The client `main` and `origin/main` are at the accepted I09 commit
`e3ee9ab`. The service default branch `dev` and `origin/dev` are at the accepted
I09 commit `594873f`. Both worktrees were clean at I10 start. I08 remains only
on `codex/i08-stopped-checkpoint` at `090912f` with status `Stopped`.

I09 already pins Ed25519, RFC 8785 JCS, strict I-JSON transport, public fixtures,
and a digest-verified private copy. I10 uses those dependencies and boundaries;
it adds no dependency and invents no cryptographic format.

I10 owns:

- a signed heartbeat request and response contract;
- monotonic per-device sequencing and exact-request retries;
- server-time cooldown and receipt timestamps;
- active, dormant, lost, and revoked heartbeat eligibility;
- a signed lost/revoke command;
- dormant-device re-verification through the approved binding boundary;
- account-level maximum aggregation; and
- a deterministic client coordinator driven by explicit activity candidates.

I10 does not own a platform activity source, UI, policy duration, warning/grace
state transitions, release behavior, contacts, recovery, telemetry, or native
release qualification.

## Public protocol additions

The existing `protocol/v1/` package remains authoritative. I10 prepares a new
minor package release and manifest digest containing these additional closed
schemas and fixtures:

```text
schemas/
├── heartbeat-request.schema.json
├── heartbeat-response.schema.json
├── device-status-change-request.schema.json
└── device-status-change-response.schema.json
fixtures/
├── valid/heartbeat-request.json
├── valid/heartbeat-response.json
├── valid/device-status-change-request.json
├── invalid/heartbeat-request-forbidden-data.json
└── signatures/
    ├── heartbeat-request.json
    ├── heartbeat-modified-payload.json
    ├── heartbeat-cross-domain-replay.json
    └── device-status-change.json
```

The request-body limit, response envelope, UUID encoding, unpadded base64url,
signature version, canonicalization, strict duplicate-member gate, and error
shape remain unchanged from I09.

### Heartbeat request

`POST /api/v1/heartbeats` accepts:

```json
{
  "protocol_version": 1,
  "signed": {
    "account_id": "00000000-0000-4000-8000-000000000010",
    "canonicalization": "jcs-rfc8785",
    "device_id": "00000000-0000-4000-8000-000000000011",
    "domain": "aeterna.heartbeat.submit.v1",
    "operation": "heartbeat.submit",
    "protocol_version": 1,
    "request_id": "00000000-0000-4000-8000-000000000012",
    "sequence": 1,
    "signature_version": 1
  },
  "signature": "<unpadded-base64url-64-byte-signature>"
}
```

`sequence` is an integer from 1 through `9007199254740991`, the largest exact
I-JSON integer. It is strictly increasing per device; gaps are valid and wrap
is forbidden. The document has no client timestamp, observed-at value,
deadline, candidate identifier, activity category, application, window, URL,
input value, encrypted-content field, or recovery field.

The success response contains only `account_id`, `device_id`,
`accepted_sequence`, `accepted_at`, and `next_heartbeat_not_before`. Both times
are UTC `Z` timestamps produced from the same injected server receipt instant.
There is no client-supplied or client-computed deadline.

### Device status change

`POST /api/v1/device-status-changes` uses the distinct domain
`aeterna.device-status.change.v1` and operation `device_status.change`. The
signed document contains the common signed header, `account_id`,
`authorizing_device_id`, `target_device_id`, and an action closed to `mark_lost`
or `revoke`.

The authorizing device must be active, not dormant at server receipt time, and
belong to the account. It signs the complete target and action. The target may
be the authorizing device. The transition and account re-aggregation are one
transaction. `lost` and `revoked` are terminal for that device identity;
repeated exact commands are idempotent, while contradictory terminal changes
fail closed.

This endpoint does not add generic device mutation, key replacement, arbitrary
state input, or administrator bypass.

### Stable I10 errors

| Code                                | HTTP | Meaning                                                        |
| ----------------------------------- | ---: | -------------------------------------------------------------- |
| `heartbeat.sequence_not_increasing` |  409 | Sequence is not greater than the last accepted sequence        |
| `heartbeat.cooldown`                |  429 | A new heartbeat arrived before the per-device cooldown elapsed |
| `device.not_active`                 |  403 | Selected signing device is not active or eligible              |
| `device.reverification_required`    |  403 | Device crossed the dormancy boundary and must re-verify        |
| `device.status_terminal`            |  409 | Lost/revoked identity cannot perform the requested transition  |
| `device.target_not_found`           |  404 | Authorized account has no visible target device                |

The existing `device.proof_invalid`, `request.idempotency_conflict`, transport,
and service-unavailable codes continue to apply. Error precedence verifies the
signature and account/device relationship before revealing a target state.

## Replay, retry, and cooldown semantics

The service processes a heartbeat in this order inside one transaction:

1. Parse the strict public envelope and verify the signature with the selected
   account/device public key.
2. Lock the account, then the device, using the same lock order in heartbeat,
   status, binding activation, and aggregation paths.
3. If `request_id` equals the device's most recently accepted heartbeat ID,
   compare the canonical request digest. A match returns the original
   `accepted_sequence`, `accepted_at`, and cooldown boundary without mutation;
   a mismatch returns `request.idempotency_conflict`.
4. Reject lost or revoked devices. If an active device has reached the 90-day
   dormancy boundary, mark it dormant, recompute the account maximum, commit,
   and return `device.reverification_required`.
5. Reject `sequence <= last_sequence`.
6. Reject a new request received before `last_seen_at + 30 minutes` with
   `heartbeat.cooldown` and bounded `retry_after_seconds`. Rejection does not
   consume the sequence or request ID.
7. Atomically store the sequence, request ID/digest, and receipt time; recompute
   `account.last_activity_at`; commit; then return the receipt and cooldown.

An exact retry is therefore transport idempotency, not a second accepted
heartbeat. A copied old request after a newer accepted request fails the
sequence check. A larger sequence with an old candidate is a client defect and
is prevented by the client coordinator; the service cannot infer activity
freshness from a privacy-minimized payload.

The 30-minute cooldown has no client-controlled bypass in I10. A future forced
refresh requires a separate signed operation and security review rather than a
boolean in this request.

## Device lifecycle and re-verification

The persisted heartbeat states are:

```text
active --90 days without accepted heartbeat--> dormant
active ---------------- signed mark_lost -----> lost (terminal identity)
active/dormant --------- signed revoke --------> revoked (terminal identity)
dormant -- approved I09 binding flow ----------> active
```

For dormancy, the server compares receipt time with `last_seen_at`, or with the
latest heartbeat authorization time for a device that has never submitted a
heartbeat. The boundary is inclusive: at 90 days the device becomes dormant
and the submitted heartbeat is not accepted.

A dormant device reuses the existing I09 binding request, existing-device
approval, and delayed confirmation schemas. The binding request must carry the
same device UUID and public key. The service permits one pending re-verification
record for that dormant identity. It still requires a fresh mailbox-verified
binding grant. Activation requires either another active device's signed
approval or the existing 24-hour delayed second mailbox verification and fresh
device signature.

Successful re-verification:

- sets status to `active` and a new server authorization time;
- preserves `last_sequence` so old signed heartbeats stay invalid;
- clears heartbeat receipt/request metadata so approval is not activity;
- leaves `account.last_activity_at` unchanged until a higher-sequence heartbeat
  from a confirmed candidate is accepted; and
- records a structural audit event without activity details.

Lost and revoked identities cannot re-verify. A replacement uses a fresh device
UUID/key and the normal I09 binding flow. I10 does not provide a hidden
administrator reactivation path.

## Persistence and aggregation

An additive service migration adds to `aeterna_devices`:

- `heartbeat_authorized_at TIMESTAMPTZ NOT NULL`;
- `last_sequence BIGINT NOT NULL DEFAULT 0` with an I-JSON-range check;
- nullable `last_seen_at TIMESTAMPTZ`;
- nullable `last_heartbeat_request_id UUID`;
- nullable 32-byte `last_heartbeat_request_digest`; and
- the closed status set `active`, `dormant`, `lost`, `revoked`.

It adds nullable `last_activity_at TIMESTAMPTZ` to `aeterna_accounts`, drops the
old one-binding-per-device uniqueness constraint, and replaces it with a
PostgreSQL partial unique index that permits at most one pending binding per
account/device. Existing active devices use `bound_at` as their initial
authorization time and retain status `active`.

No permanent heartbeat-event table is added. The service stores only the
latest per-device acceptance metadata and the account aggregate. Structural
security audit remains redacted and contains no input/activity reason.

After an accepted heartbeat or a transition that removes/adds an eligible
device, the service assigns:

```text
account.last_activity_at = MAX(last_seen_at for active devices)
```

Re-verification has `last_seen_at = NULL`, so it does not count. All timestamps
come from an injected UTC server clock. The same account lock serializes two
devices, duplicate deliveries, dormancy, status changes, and later I11 policy
integration. Concurrent valid heartbeats may commit in either order, but the
stored maximum equals the later server receipt time and never a client value.

## Deterministic desktop boundary

The Rust client adds protocol types plus a small heartbeat coordinator with
injected traits for:

- a monotonic clock used only for local candidate freshness;
- durable sequence and pending-request state;
- the existing Ed25519 signer; and
- a transport that returns success, a definitive protocol error, or an
  indeterminate timeout.

The coordinator accepts an explicit `ConfirmedActivityCandidate`; it never
constructs one from process start, online state, wake, or elapsed runtime. It
persists the next sequence, request ID, canonical document, signature, and
candidate freshness boundary before the first send. On timeout it keeps and
retries the exact envelope. It never increments the sequence or changes the
request ID/signature for that candidate. It discards the pending request after
the candidate freshness window, gate loss reported by the caller, or a
definitive rejection.

The deterministic test adapter uses the design's 15-minute retry-freshness
limit. It proves startup/no-candidate silence, one candidate/one allocation,
byte-exact timeout retry, expiry discard, no local-success promotion, sequence
monotonicity, response validation, and cross-domain/mutation failure. It is not
an HTTP client, background scheduler, macOS activity source, or I08 acceptance
substitute.

## Verification plan after approval

The public client will run:

- exact manifest/schema/fixture regeneration and validation;
- Rust canonical/signature, forbidden-field, sequence, and coordinator tests;
- timeout and retry tests proving byte identity and no sequence reallocation;
- `npm run check`; and
- `npm run desktop:build`.

The private service will run in Docker/PostgreSQL:

- public-package digest and runtime contract tests;
- duplicate, reordered, modified, wrong-key, and cross-domain requests;
- exact retry, request-ID conflict, cooldown boundary, and sequence-gap tests;
- concurrent same-device and different-device heartbeats;
- lost, revoked, 90-day dormancy, and both dormant re-verification paths;
- account maximum/recomputation and server-clock-only assertions;
- migration upgrade/downgrade/upgrade and schema-current checks;
- focused and full pytest; and
- Black, isort, and critical Flake8 checks.

The final I10 report will keep the iteration `In Progress` or `Blocked` if any
required contract, PostgreSQL concurrency, migration, complete repository
check, or build evidence is missing. It will explicitly state that native I08,
production KMS/HSM, macOS 15, and a formal protocol tag remain unverified.

## Decisions requested

One approval is requested for this cohesive boundary:

1. the exact heartbeat and device-status domains, fields, endpoints, stable
   errors, and prepared protocol-v1 minor release;
2. positive I-JSON monotonic sequences, latest-request exact retry, no sequence
   consumption on rejection, and no client-controlled cooldown bypass;
3. a fixed 30-minute server cooldown and inclusive 90-day dormancy boundary;
4. terminal lost/revoked identities and dormant re-verification through the
   existing binding approval or 24-hour delayed fresh-email path while
   preserving sequence;
5. latest-only heartbeat storage, transactional active-device maximum, and the
   stated additive migration; and
6. the deterministic candidate/clock/store/transport client boundary without
   merging I08 or claiming native activity acceptance.

## Approval record

After reviewing the proposal, the user authorized I10 development on
2026-09-27. This authorizes the six-part boundary above; it does not imply
separate commentary or additional decisions for each item.
