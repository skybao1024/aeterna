# ADR 0012: Public protocol v1 and account/device binding

- Status: Accepted
- Date: 2026-09-27
- Decision owner: I09 public protocol and account/device security boundary
- Approval: Explicit user approval on 2026-09-27
- Governing decisions: [ADR 0004](./0004-macos-keychain-identity-continuity.md),
  [ADR 0006](./0006-public-protocol-ownership-and-versioning.md)
- Proposal: [I09 public protocol and account/device binding proposal](../research/I09-public-protocol-account-device-proposal.md)

## Context

ADR 0006 makes the public desktop repository authoritative for the network
contract while the hosted control plane remains private. It requires I09 to
choose the schema language, canonical bytes, signature layout, content type,
fixture distribution, and compatibility window before the private service adds
public endpoints. ADR 0004 also requires I09 to define the versioned device-key
namespace and to validate secure-storage metadata before a persisted signing
seed is used.

The private service currently contains transitional generic authentication
scaffolding. It stores plaintext email addresses against sequential integer user
IDs, uses password and JWT flows, stores low-entropy verification codes directly
in Redis, and returns account-enumerating errors. Its own `ARCHITECTURE.md`
states that this code is transitional. It is not an acceptable source for the
public Aeterna contract.

I09 must provision a verified Owner account and bind devices without allowing a
device identifier, email OTP, or bearer token alone to impersonate an already
bound device. The first device may be bound after initial email verification;
every later device requires either an active device's signature or a delayed
path with fresh email verification. I09 does not implement heartbeat sequencing,
the inactivity state machine, contacts, recovery claims, or notification
delivery beyond Owner email verification and security notices for binding.

## Proposed decision

Adopt the complete protocol and binding design in the linked proposal.
Normative v1 artifacts will live under `protocol/v1/` in the public repository
and use JSON Schema 2020-12 with closed objects, UTF-8 `application/json`, HTTP
paths under `/api/v1`, and an integer `protocol_version` in every request and
response body. Request bodies are limited to 16,384 bytes before parsing.
Unknown fields, duplicate JSON member names, unsupported versions or media
types, invalid encodings, and limit violations fail closed.

Signed documents use Ed25519 and RFC 8785 JSON Canonicalization Scheme bytes.
Every signed document contains a fixed operation-specific domain, protocol
version, signature version, canonicalization identifier, request ID, and every
security-relevant operation field. The signature is transported separately as
unpadded base64url. Signed schemas forbid floating-point values and unknown
fields. Binary values are unpadded base64url; UUIDs are canonical lowercase
hyphenated strings. The server rejects duplicate members before schema parsing
or canonicalization.

The initial signed domains are:

- `aeterna.device-binding.request.v1` for proof of possession by the proposed
  new device; and
- `aeterna.device-binding.approval.v1` for approval by an active existing
  device.

Neither domain is reused for heartbeat, revocation, recovery, or another
operation. I10 and later work must add distinct domains and fixtures.

The desktop will pin `serde_jcs = 0.2.0`. The service will pin
`rfc8785 = 0.1.4`. Both implementations must pass the same public canonical
byte and signature fixtures before use. These libraries perform no network I/O
or key management. A strict duplicate-member gate remains mandatory because a
generic JSON parser may otherwise collapse duplicates before canonicalization.

## Account and device authorization

I09 uses passwordless, single-purpose email authorization rather than making
the transitional password/JWT scaffolding part of the product protocol.
Successful email OTP verification returns a short-lived opaque binding grant.
Only a digest of a grant is stored. Low-entropy OTP verifiers use a keyed digest,
have bounded attempts, and are never logged.

The initial verified account may activate exactly one first device immediately
when the account has never had an active device. A subsequent device supplies a
client-generated UUID, a 32-byte Ed25519 public key, and a signature proving
possession of the matching private seed. It remains pending until either:

1. an active existing device signs the exact server-issued binding challenge;
   or
2. a 24-hour minimum delay elapses and the Owner completes a fresh email OTP
   challenge bound to that pending binding while the new device proves key
   possession again.

Revoking all devices never restores first-device eligibility. Pending bindings
expire after seven days, are single-use state machines, and can be cancelled.
Approval and delayed confirmation are transactional and idempotent. The server
validates the existing device's active status and public key; the supplied
device ID only selects that record.

The service adds UUID-based Aeterna account and device tables without rewriting
or exposing the legacy `users` table. New account emails are normalized once,
looked up through a keyed HMAC index, and encrypted at rest with AES-256-GCM
through a versioned injected key-provider boundary. Development and tests may
use explicit environment-backed synthetic keys. Production fails closed until
an approved KMS/HSM provider is configured; I09 does not introduce a production
KMS, a fallback key, or plaintext storage. The migration is additive and does
not delete or reinterpret legacy rows.

The entire legacy client authentication router will be unregistered so its
signup, login, reset, and token endpoints cannot be mistaken for alternate
Aeterna account operations. The corresponding template frontend login becomes
unavailable until it is deliberately replaced; the desktop protocol does not
depend on it. Existing template tables and code remain untouched unless their
removal is separately approved. Backoffice authentication is not changed by
I09.

On macOS the versioned signing-key service becomes
`app.aeterna.device-signing.v1`. Prototype I02 items are not imported or
silently migrated. Retrieval validates the exact Data Protection Keychain,
`WhenUnlockedThisDeviceOnly`, non-synchronizing metadata and the 32-byte seed
before use. I15 still owns the production application identity, entitlement,
upgrade, and distribution continuity matrix.

## Publication and compatibility

`protocol/v1/manifest.json` will list every normative schema and fixture with
its SHA-256 digest and one digest over the canonical manifest content. Fixtures
contain synthetic positive and negative cases, exact canonical bytes, public
keys, signatures, and expected stable error codes. They contain no real email,
token, device, activity, Vault, ERC, VDK, SRS, or contact data.

Protocol releases use Git tags named `protocol-v1.X.Y`. The private service
vendors the exact public fixture set and records both the tag and manifest
digest; CI verifies the digest and runs the fixtures through runtime schemas and
signature verification. No unpublished private schema may redefine the public
contract.

Compatible optional additions may be made only where an existing schema
explicitly permits them and where they do not affect authentication, signing,
authorization, idempotency, or security meaning. Signed objects remain closed.
A breaking schema, signature, canonicalization, authentication, identifier, or
state change requires a new HTTP/protocol major version.

After a successor major reaches general availability, the service supports the
previous major for at least 180 days and publishes its sunset date at least 90
days in advance. An urgent security retirement may be shorter only through an
explicit security decision and user-visible migration path; the server must
fail closed rather than silently reinterpret old requests.

## Privacy and scope limits

I09 request schemas permit only the Owner email needed for verification,
opaque authorization material, protocol/request identifiers, device routing
identifiers, Ed25519 public keys/signatures, and binding state. They have no
field for activity type, raw input, application, window, URL, hardware serial,
Vault data, attachment, ERC, VDK, SRS, contact, recovery instruction, or custom
notification content. The server rejects rather than stores unknown fields.

I09 does not authorize a heartbeat endpoint, monotonic sequence behavior,
device dormancy/revocation product flow, the I11 state machine, I12 contact
mail, I13 recovery material, telemetry, or a production secret-service
integration.

## Consequences

- The public repository defines an auditable and independently testable
  contract before the private endpoint implementation.
- Email possession can provision an account, but cannot immediately add a
  later heartbeat-capable device without an existing-device signature or a
  visible delay and second email verification.
- A stolen device ID is insufficient; an attacker needs the matching signing
  seed and a live one-time challenge.
- Canonicalization becomes a security dependency and therefore remains exact,
  pinned, fixture-tested, and independently reviewable.
- The 180-day overlap provides a bounded offline-client migration window but
  does not promise permanent support for vulnerable protocol versions.
- Production account onboarding remains intentionally unavailable until the
  approved production key provider is configured.

## Alternatives rejected

- Treating private Pydantic or Rust structs as the contract: it reverses the
  ownership established by ADR 0006.
- Reusing the legacy signup/password/JWT flow: it would canonize transitional
  enumeration, identity, OTP, and plaintext-PII behavior.
- JSON key sorting without RFC 8785: it leaves number and string encoding
  ambiguous across Rust and Python.
- Signing a device ID or HTTP path alone: it does not bind the new key, account,
  challenge, operation, or protocol version.
- Immediate new-device activation with email OTP: it turns mailbox compromise
  into immediate device authority and contradicts the product design.
- Making the delay configurable below 24 hours: it weakens the security notice
  and cancellation window in ways a client must not control.
- Storing plaintext email temporarily until KMS work: it violates the current
  design and creates a migration of live PII later.
- Implementing heartbeat, contact, recovery, or SRS fields early: those belong
  to I10-I13 and would bypass their security gates.
