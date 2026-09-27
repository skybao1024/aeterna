# Aeterna public protocol v1

This directory is the public, machine-readable source of truth for Aeterna I09
account/device binding, I10 signed heartbeat/device-status operations, and I13
delayed-recovery record and one-time claim operations.
Private database models, generated OpenAPI output, and desktop implementation
types are consumers, not protocol authority.

## Transport

- HTTP endpoints use `/api/v1` and exact `Content-Type: application/json`.
- Every body contains `protocol_version: 1`.
- Request and response bodies are at most 16,384 bytes.
- Input is UTF-8 I-JSON without a BOM, duplicate object members, trailing data,
  non-finite numbers, or unknown fields.
- UUIDs are lowercase canonical hyphenated strings. Binary fields use unpadded
  RFC 4648 base64url.
- Schema extension keywords beginning with `x-aeterna-` are normative runtime
  constraints not expressible by standard JSON Schema vocabulary.

## Signatures

The `signed` object is serialized to RFC 8785 JCS UTF-8 bytes and signed with
Ed25519. The outer `signature` is the unpadded base64url encoding of the raw
64-byte signature. Signed objects are closed and carry protocol, signature,
canonicalization, operation, request, and domain values.

The proposed new device uses `aeterna.device-binding.request.v1`. An existing
active device uses `aeterna.device-binding.approval.v1`. Operation names prevent
replay between initial request, delayed confirmation, cancellation, and
existing-device approval.

An active device submits heartbeats under `aeterna.heartbeat.submit.v1` and
changes device eligibility under `aeterna.device-status.change.v1`. These
domains are not interchangeable with each other or with device binding. A
heartbeat signs only account/device routing identifiers, a request identifier,
and a positive monotonic sequence. It contains no client time or deadline.

An active bound device provisions, confirms, or abandons one recovery record
under operation-specific signed domains. Provisioning returns a 32-byte SRS
once; confirmation binds the local wrapper digest. A released, accepted, and
verified contact then uses a fragment-carried claim-link token, an eight-digit
mailbox challenge, a five-minute opaque claim token, and one exact secret-read
operation. Secret-bearing responses require `Cache-Control: no-store`.

## Publication and compatibility

`manifest.json` hashes every normative file and contains a release digest over
the RFC 8785 canonical manifest without `release_digest`. The private control
plane vendors this exact package, pins the release tag and digest, and runs the
same fixtures.

The prepared release is `1.2.0` with tag name `protocol-v1.2.0`; preparing the
manifest does not create or publish a Git tag. Signed field changes and security
semantic changes require a new major/versioned operation as defined by ADR 0012. The prior major remains supported for at least 180 days after a successor
reaches general availability, with at least 90 days' sunset notice unless a
separate urgent security decision records a shorter migration.

## Privacy boundary

The package contains only Owner email verification, opaque authorization
material, request/account/device/binding identifiers, public keys, signatures,
challenges, device state, and the minimum monotonic heartbeat sequence and
server receipt response. Unknown fields are rejected. There is no activity
type or observation, client timestamp or deadline, application/window/URL data,
input value, local encrypted content, contact email, or custom notification
payload. The only recovery secret field is the purpose-limited 32-byte `srs`
in the provisioning and released-secret success responses; it is absent from
requests, logs, error bodies, audit fixtures, and all other operations.
