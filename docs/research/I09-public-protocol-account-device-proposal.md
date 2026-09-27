# I09 public protocol and account/device binding proposal

- Status: **Approved for implementation**
- Research date: 2026-09-27
- Approval date: 2026-09-27
- Client baseline: `98afa1a164806fbe3ebf3fda821d790f689f4d65`
- Service baseline: `9873e418909d52885ee4b4c61ae3a6d16f5beff6`
- Proposed decision: [ADR 0012](../adr/0012-public-protocol-v1-account-device-binding.md)

## Approval boundary

This document is the mandatory ADR 0006 checkpoint. Approval authorizes the
exact protocol, dependency, storage, account authorization, device binding, and
compatibility design below. Until it is approved, work may inventory existing
code, preserve the current design changes, prepare documentation, and improve
already-approved secure-storage metadata validation. It may not add a public
service endpoint, migration, protocol dependency, production key namespace, or
account/device state transition.

Approval does not authorize a protocol release, Git tag, deployment, production
KMS integration, credential-backed provider diagnostic, I10 heartbeat, I11
state machine, I12 contact delivery, I13 recovery path, or a change to the I08
checkpoint.

## Baseline and conflicts

The desktop worktree contains pre-existing changes to `docs/DESIGN.md`,
`docs/DEVELOPMENT_PLAN.md`, and proposed/accepted email-notification ADR 0010.
They establish the Notification Target/Recovery Contact distinction and record
I08 as stopped without acceptance. This proposal preserves those changes and
does not make I08 a prerequisite for I09.

ADR 0011 already exists on `codex/i08-stopped-checkpoint`, so this proposal uses
the next free identifier, 0012. The I08 implementation and result record remain
only at commit `090912f` and are not merged or treated as accepted evidence.

The service `dev` branch is one commit ahead of `origin/dev`; that commit is the
I03 concurrency checkpoint and remains intact. The service's generic client
authentication is transitional scaffolding, not a compatible I09 starting
point:

| Existing behavior                                               | I09 conflict                                                                    | Required disposition                                                                                       |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Sequential integer `users.id` exposed through generic auth      | Public account identity must not inherit a private template model               | Add UUID Aeterna accounts; do not migrate or expose the integer ID                                         |
| Plaintext `users.email`                                         | Design requires keyed lookup and field encryption                               | New encrypted email columns with an HMAC lookup index                                                      |
| Password/JWT signup and login                                   | Not selected by product design; broad reusable bearer authority                 | Unregister the legacy client auth router; use purpose-bound email challenges and short-lived opaque grants |
| Redis key includes the email and stores the OTP value           | Leaks PII into infrastructure keys and stores a low-entropy credential directly | Use opaque challenge IDs and keyed OTP verifiers                                                           |
| Different errors for absent, verified, and existing email       | Enables account enumeration                                                     | Uniform initiation response; stable non-enumerating verification errors                                    |
| Provider send inside a database transaction                     | A remote side effect cannot roll back with PostgreSQL                           | Commit challenge state first; send through an injected notifier and expose retryable delivery state        |
| Route schemas and `ApiResponse` define the wire shape privately | Conflicts with ADR 0006 public ownership                                        | Generate/implement runtime types from the public contract and run public fixtures                          |

## Proposed public package

The public repository adds this structure after approval:

```text
protocol/v1/
├── README.md
├── manifest.json
├── errors.json
├── schemas/
│   ├── common.schema.json
│   ├── error-response.schema.json
│   ├── account-challenge.schema.json
│   ├── account-challenge-verification.schema.json
│   ├── device-binding-request.schema.json
│   ├── device-binding-approval.schema.json
│   ├── delayed-device-confirmation.schema.json
│   └── device-binding-response.schema.json
└── fixtures/
    ├── valid/
    ├── invalid/
    └── signatures/
```

JSON Schema Draft 2020-12 describes request and response data. `$id` values use
stable `urn:aeterna:protocol:v1:*` identifiers and require no live schema host.
Objects are closed with `additionalProperties: false` unless the compatibility
table expressly marks a response extension object. Required and optional fields
are explicit. Regexes are ASCII and anchored.

HTTP uses exact `Content-Type: application/json`, UTF-8 JSON, and paths under
`/api/v1`. Every body includes `protocol_version: 1`. The service checks the
16,384-byte request-body limit before parsing. It rejects a BOM, invalid UTF-8,
duplicate member names, trailing bytes, non-I-JSON numbers, unsupported media
types, unknown versions, unknown signed fields, and schema violations before
business logic. It never relies on Pydantic's default 422 body as public
behavior.

### Common encodings and limits

| Value                          | v1 encoding or bound                                               |
| ------------------------------ | ------------------------------------------------------------------ |
| Protocol and signature version | JSON integer `1` only                                              |
| UUID                           | Lowercase RFC 4122 hyphenated string, exactly 36 ASCII bytes       |
| Binary                         | RFC 4648 base64url without `=` padding                             |
| Ed25519 public key             | 32 raw bytes / 43 base64url characters                             |
| Ed25519 signature              | 64 raw bytes / 86 base64url characters                             |
| Server challenge               | 32 random bytes / 43 base64url characters                          |
| Request ID                     | Client-generated UUID; idempotency scope is operation plus account |
| Email input                    | At most 254 UTF-8 bytes after validation and normalization         |
| Device label                   | Optional, 1-64 UTF-8 bytes, NFC, no control characters             |
| Error code                     | 3-64 lowercase ASCII characters in dot-separated segments          |
| Error details                  | Closed, error-specific object; never secrets or full email         |
| Request body                   | 16,384 bytes before JSON parsing                                   |
| Response body                  | 16,384 bytes for I09 endpoints                                     |

Device labels are display hints, not authenticators or hardware identifiers.
The client does not upload a serial number, OS account name, hostname, activity
type, application, window, URL, input observation, Vault field, attachment,
ERC, VDK, SRS, contact, or recovery instruction.

## Canonical signing contract

Signed operations use Ed25519 as already accepted and implemented by the
desktop crypto boundary. The value of the `signed` member is canonicalized with
RFC 8785 JCS; the resulting UTF-8 bytes are the exact Ed25519 message. The
transport wrapper is:

```json
{
  "protocol_version": 1,
  "signed": {
    "canonicalization": "jcs-rfc8785",
    "domain": "aeterna.device-binding.request.v1",
    "operation": "device_binding.request",
    "protocol_version": 1,
    "request_id": "00000000-0000-4000-8000-000000000001",
    "signature_version": 1
  },
  "signature": "<unpadded-base64url-64-byte-signature>"
}
```

Each operation schema adds its exact security fields to `signed`. The schema is
closed, so an implementation cannot ignore an unsigned extension with security
meaning. Signed payloads contain no JSON floating-point values. Future counters
or values outside the I-JSON exact-integer range use canonical decimal strings.
String bytes are preserved exactly as required by RFC 8785; fields that require
NFC state it in their schema and are rejected rather than silently rewritten.

The device-binding request signs:

- domain, operation, protocol/signature/canonicalization versions, and request
  ID;
- account binding grant ID;
- proposed device UUID;
- proposed Ed25519 public key; and
- optional normalized device label.

The existing-device approval signs:

- domain, operation, protocol/signature/canonicalization versions, and request
  ID;
- account UUID;
- pending binding UUID;
- approving device UUID;
- proposed device UUID and public key; and
- the server-issued single-use 32-byte challenge.

The delayed confirmation signs the same pending binding, proposed identity, and
a fresh server challenge under the proposed device key. A fresh email-verified
grant bound to that binding is also required after `not_before`.

The signature fixture set contains the canonical JCS bytes in base64url, a
synthetic seed/public key/signature, the parsed document, and mutations for each
domain, ID, key, challenge, version, and extra-field failure. Fixtures also
cover duplicate members, Unicode property order, string escaping, invalid
base64url padding, wrong key, modified signature, and cross-domain replay.

## Dependency review

### Desktop: `serde_jcs = 0.2.0`

- Purpose: serialize typed Serde values to RFC 8785 canonical JSON bytes.
- Source: <https://docs.rs/serde_jcs/0.2.0/serde_jcs/>
- License: MIT OR Apache-2.0.
- Surface: a small serializer over existing `serde`/`serde_json`; no network,
  filesystem, key storage, native permission, or cryptographic primitive.
- Pinning: exact production version in `Cargo.toml` and `Cargo.lock`.
- Control: only closed typed signed documents reach the serializer; hostile raw
  JSON is duplicate-checked and schema-validated before any server-side
  canonicalization.

### Service: `rfc8785 = 0.1.4`

- Purpose: produce RFC 8785 UTF-8 bytes in Python.
- Source: <https://pypi.org/project/rfc8785/>
- Publisher: Trail of Bits; latest listed release 0.1.4 on 2024-09-27.
- License: Apache-2.0.
- Surface: pure Python with no runtime dependency or network behavior.
- Pinning: exact version and hashes through the service's existing dependency
  process.
- Control: raw JSON duplicate detection precedes Pydantic and JCS; public
  cross-language vectors are mandatory.

RFC 8785 is an Informational RFC, not an IETF Standards Track document. It is
chosen because it specifies I-JSON constraints, primitive serialization, and
recursive property ordering and has independently available Rust and Python
implementations. A plain `sort_keys` serializer is not equivalent.

No new cryptographic algorithm, HTTP client, telemetry SDK, remote script, or
runtime code download is introduced. The existing Rust `ed25519-dalek` and
Python `cryptography` packages remain the signature and field-encryption
implementations.

## Account challenge flow

1. `POST /api/v1/account-challenges` accepts a normalized email and purpose.
   It always returns `202` with the same bounded shape. The public response does
   not reveal whether an account exists.
2. PostgreSQL stores an opaque challenge UUID, purpose, keyed email lookup,
   keyed OTP verifier, attempt count, expiry, cooldown, and delivery state.
   Neither the email nor OTP appears in a Redis key, log, metric, error, or
   audit payload.
3. The transaction commits before the injected mail service is called. Provider
   failures mark a retryable delivery result without rolling back or exposing
   the address.
4. `POST /api/v1/account-challenges/{challenge_id}/verify` permits at most five
   attempts during a ten-minute lifetime. Success consumes the challenge and
   returns a 10-minute opaque one-use binding grant. Only a SHA-256 digest of
   the 256-bit random grant is stored.
5. A new normalized email creates its account only after successful OTP
   verification. An existing account receives a grant for a later binding but
   no account-existence signal before proof of mailbox control.

Initiation is limited per IP and keyed email index, with a minimum resend
interval of 60 seconds. Exact operational rate values may tighten without a
schema change, but responses use the stable `auth.rate_limited` code and bounded
`retry_after_seconds` field.

The account email uses the `email-validator` normalization already present in
the service. The normalized representation is encrypted with AES-256-GCM using
random 96-bit nonces and AAD containing the account UUID, field purpose, format
version, and key version. A separate HMAC-SHA-256 key produces the lookup index.
Keys come from an injected provider. Test keys are synthetic; development may
read explicit key variables; production has no environment-key fallback and
must fail startup until a separately approved KMS/HSM provider exists.

## Device binding state machine

```text
EMAIL_VERIFIED_GRANT
        |
        | new-key possession proof
        v
     PENDING -------------------------> CANCELLED
        |                                  ^
        | active-device signed approval    |
        |                                  |
        +-------------> ACTIVE             |
        |                                  |
        | 24 h elapsed + fresh OTP grant   |
        | + fresh new-key proof             |
        +-------------> ACTIVE             |
        |
        +-------------> EXPIRED (7 days)
```

An account has a monotonic `first_device_bound_at` marker. Immediate activation
is allowed only while that marker is null and no device has ever been active.
Device deletion or revocation cannot clear it.

Creation locks the account row, consumes the binding grant, enforces a maximum
of three pending and ten active devices, stores the public key and single-use
challenge, and returns either `active` for the first device or `pending` with
`not_before` and `expires_at`. The protocol hard maximum is 32 devices so a
future operational increase does not change field encoding.

Existing-device approval locks the pending binding and approving device, checks
that the approver is active and belongs to the same account, verifies the
challenge and complete canonical signature, activates the new device, consumes
the challenge, and records a redacted audit event in one transaction.

Delayed confirmation is unavailable before 24 hours. At or after `not_before`,
it requires a fresh email challenge explicitly bound to the pending binding and
a fresh new-device signature. It locks and rechecks the binding before
activation. The initiating OTP or binding grant cannot be replayed after the
delay. Security notices go only to the verified Owner email and contain no Vault,
activity, contact, recovery, ERC, VDK, or SRS data.

Concurrent approvals, repeats with the same request ID, cancellation, expiry,
and delayed confirmation resolve through row locks and terminal-state checks.
An exact replay returns the original terminal result where safe; a reused
request ID with different canonical bytes returns `request.idempotency_conflict`.

## Stable response and error model

Successful responses contain `protocol_version`, `request_id`, and a closed
`data` object. Error responses contain `protocol_version`, `request_id` when it
was syntactically valid, and a closed `error` object with stable `code` and
bounded nonlocalized details. UI copy is selected by the client from the code.
No response includes a full email, token, OTP, signing seed, stack trace,
database identifier, SQL detail, or provider body.

Initial I09 codes are:

| Code                              | HTTP | Meaning                                                       |
| --------------------------------- | ---: | ------------------------------------------------------------- |
| `protocol.invalid_json`           |  400 | Invalid UTF-8/I-JSON, duplicate member, or trailing data      |
| `protocol.invalid_request`        |  400 | Schema or field validation failed                             |
| `protocol.unsupported_version`    |  400 | HTTP/body/signature/canonicalization version is unsupported   |
| `protocol.unsupported_media_type` |  415 | Content type is not exact JSON                                |
| `protocol.payload_too_large`      |  413 | Request exceeds the pre-parse body limit                      |
| `auth.challenge_invalid`          |  400 | Non-enumerating invalid or already-consumed challenge/code    |
| `auth.challenge_expired`          |  400 | Challenge expired                                             |
| `auth.attempts_exhausted`         |  429 | Challenge can no longer be attempted                          |
| `auth.rate_limited`               |  429 | Initiation or resend limit reached                            |
| `auth.binding_grant_invalid`      |  401 | Binding grant is invalid, expired, consumed, or wrong-purpose |
| `device.proof_invalid`            |  401 | New or existing device signature failed                       |
| `device.binding_not_found`        |  404 | No visible pending binding exists                             |
| `device.binding_not_ready`        |  409 | Delayed confirmation is too early                             |
| `device.binding_expired`          |  409 | Pending binding expired                                       |
| `device.binding_cancelled`        |  409 | Pending binding was cancelled                                 |
| `device.approver_not_active`      |  403 | Routing ID did not select an active eligible device           |
| `device.limit_reached`            |  409 | Pending or active device limit reached                        |
| `request.idempotency_conflict`    |  409 | Request ID was reused for different canonical bytes           |
| `service.temporarily_unavailable` |  503 | Required database, mail, or key service is unavailable        |

Error precedence prevents account enumeration. Malformed protocol is rejected
before lookup; authentication failures precede object visibility; terminal
binding errors appear only after authorization to observe that binding.

## Fixture publication and consumer checks

`manifest.json` contains package version, protocol version, creation metadata,
and path/SHA-256 pairs sorted by path. Its `release_digest` is SHA-256 over the
RFC 8785 canonical manifest with `release_digest` omitted. Tests recompute every
file hash and the release digest.

The public desktop tests load all fixtures directly from `protocol/v1`. The
private service vendors the exact released directory under a backend test-data
path, records `protocol-v1.X.Y` and `release_digest`, recomputes them in CI, and
runs every case through the service's strict parser, Pydantic models, JCS
implementation, Ed25519 verifier, and error mapper. A copied fixture edited in
the private repository fails the digest check.

A release is a signed Git commit/tag operation performed only on explicit user
request. Local I09 completion may prepare `1.0.0` artifacts and their digest but
does not publish or tag them.

## Compatibility rules

- The URL major and body `protocol_version` must agree.
- Signed objects are closed. Adding or removing a signed field, changing its
  normalization, or changing a domain requires a new operation/signature
  version and migration plan; security-semantic changes require a new major.
- Unsigned response additions are compatible only inside a schema extension
  object explicitly designated for that purpose. Existing required fields and
  meanings do not change within a major.
- Stable error codes are never reassigned. A new code may be added within v1;
  an unknown code maps to a generic safe client message.
- After v2 general availability, v1 remains accepted for at least 180 days and
  its sunset is announced at least 90 days ahead. Security retirement requires
  a separate recorded decision and migration path.
- The service never upgrades, downgrades, or reinterprets an unsupported
  request. It returns `protocol.unsupported_version` and supported-major
  metadata.

## Verification plan after approval

The desktop side will add:

- schema/manifest/fixture validation;
- typed protocol and canonicalization code;
- exact cross-language signature vectors and negative mutations;
- versioned secure-storage namespace and retrieve-time metadata validation;
- proof that protocol fixtures contain no forbidden field names or payloads;
- `npm run check` and `npm run desktop:build`.

The service side will add:

- additive migrations for accounts, challenges, grants, devices, pending
  bindings, idempotency, and redacted audit records;
- injected email, clock, randomness, and account-key providers;
- strict pre-Pydantic JSON boundary and stable response/error mapping;
- thin Aeterna account/device routes plus transactional services;
- vendored public fixtures pinned by exact release digest;
- Docker-run unit, integration, migration upgrade/downgrade, formatting, import,
  lint, and OpenAPI checks.

The matrices cover invalid/expired/exhausted OTPs, enumeration resistance,
delivery failure after commit, duplicate and concurrent requests, stolen device
ID, wrong key, modified challenge, cross-domain replay, first-device races,
revoked approver, all-devices-revoked behavior, too-early/expired/cancelled
delay, stale grants, request-ID conflict, malformed/oversized JSON, unknown
fields/versions, and transaction rollback.

No check will claim end-to-end provider delivery, production KMS readiness,
native I08 acceptance, I10 heartbeat security, or deployed compatibility.

## Approved boundary

The user approved this cohesive boundary on 2026-09-27:

1. JSON Schema 2020-12, strict UTF-8 JSON, RFC 8785 JCS, Ed25519, and the two
   exact binding domains;
2. exact pinned `serde_jcs 0.2.0` and `rfc8785 0.1.4` dependencies;
3. passwordless email OTP with opaque purpose-bound grants instead of the
   transitional password/JWT client signup contract;
4. immediate first-device binding, then existing-device signature or a 24-hour
   delayed path with fresh email OTP and new-key proof;
5. UUID Aeterna accounts, encrypted email plus keyed lookup, additive legacy
   coexistence, unregistration of the legacy client auth router, and production
   fail-closed until a KMS/HSM provider is approved;
6. `app.aeterna.device-signing.v1` with no implicit prototype-key migration;
7. digest-pinned public fixtures, `protocol-v1.X.Y` publication naming, and a
   180-day prior-major compatibility window with 90-day sunset notice; and
8. the stated limits, stable errors, privacy exclusions, and I09-only scope.
