# ADR 0006: Public protocol ownership and versioning direction

- Status: Proposed — G0 decision digest pending
- Date: 2026-09-21
- Decision owner: G0 for ownership and versioning direction; I09 for protocol v1 details

## Context

The open desktop client must make its network behavior auditable while the
official control plane remains private. Neither private SQLAlchemy models nor
Rust implementation types may silently become the public contract. I03 is an
internal state-machine prototype and exposes no route, so it does not define a
heartbeat, device, recovery, or notification protocol.

## Proposed decision

The public client repository owns the protocol source of truth. I09 must add a
versioned public protocol package containing machine-readable request and
response schemas, stable error codes, bounds, signature canonicalization,
domain separation, and synthetic positive and negative fixtures.

The direction is:

- the HTTP major version and an explicit protocol version are both present;
- every signed payload carries an explicit signature/canonicalization version
  and domain separator;
- unknown versions, algorithms, fields that affect signatures, and oversized
  values fail closed;
- additive compatible changes remain within a major version only when old
  consumers can ignore them without changing security semantics;
- breaking schema, canonicalization, signature, authentication, sequence, or
  idempotency behavior requires a new major version and overlap/migration plan;
- client time never becomes the service deadline; server receipt time remains
  authoritative;
- device identifiers are routing identifiers, never authenticators; and
- payloads exclude activity type, raw activity observations, application or
  window metadata, vault content, ERC, VDK, SRS, and secrets.

The private server must consume a pinned protocol release or exact fixture
digest from the public repository and run the same fixtures in CI. The client
must do the same. A cross-repository contract change updates the public package
first, then each implementation; a private server migration or endpoint change
cannot redefine the contract by itself.

## Deferred I09 decisions

I09 must choose and review the exact schema language, canonical byte encoding,
signature input layout, content type, fixture packaging, compatibility window,
and publication/release mechanism before adding public endpoints. G0 does not
implement those artifacts or select an unreviewed canonicalization library.

## Consequences

- I05 remains local-only and does not need a network protocol.
- I03 transaction semantics may be accepted independently from an HTTP shape.
- I09 has a mandatory proposal checkpoint before client or server endpoint
  implementation.
- I10 and later protocol work must use the public fixtures and cannot copy
  private persistence models into a network schema.
