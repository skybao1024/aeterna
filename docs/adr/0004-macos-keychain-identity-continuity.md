# ADR 0004: macOS device-key storage and identity continuity

- Status: Accepted by G0 for the storage boundary
- Date: 2026-09-21
- Decision owner: G0 for the storage boundary; I09 and I15 for production use and release identity
- Approval: Explicit user approval recorded in G0 on 2026-09-21
- Evidence: [`../research/I02-crypto-results.md`](../research/I02-crypto-results.md)
- Dependency review: [`../research/I02-crypto-dependency-proposal.md`](../research/I02-crypto-dependency-proposal.md)

## Context

Aeterna needs one Ed25519 signing seed per bound device. The secret must remain
outside the WebView and ordinary application persistence, fail closed when the
macOS security context is unavailable, and survive legitimate application
upgrades without silently creating a new device identity. I02 demonstrated the
SecItem mechanics with a time-limited development profile, but it did not
select the production bundle identifier, signing identity, entitlement set, or
distribution channel.

Those release choices cannot be prerequisites for I05, which implements local
vault storage and does not register devices or send signed network requests.
They must nevertheless be fixed and tested before I09/I10 rely on a production
device identity and before I15 ships an artifact.

## Decision

Use one generic-password item in the macOS Data Protection Keychain with:

- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`;
- explicit `kSecAttrSynchronizable = false`;
- no plaintext, file, environment, SQLite, browser-storage, legacy-Keychain, or
  remote fallback;
- a versioned application service and device-specific account identity;
- exactly 32 Ed25519 private-seed bytes; and
- fixed non-sensitive error classifications.

Create must reject a duplicate. Replace must update an existing exact item and
must not emulate replacement with delete-and-add. Delete distinguishes deleted
from not found. Retrieve validates both the exact payload length and the stored
accessibility/synchronization metadata before returning a secret. Every
operation selects the Data Protection Keychain explicitly and suppresses
unexpected authentication UI.

The activity sentinel remains a separate fixed nonsecret item and must never
query the signing seed as an unlock gate. I08 must validate the sentinel value
and attributes on every production read. I09 must enforce the same metadata
validation before using a device signing seed.

## Identity and upgrade continuity

The current development service names, application identifier, Personal Team
profile, and default access group are prototype-only. They are not production
identities and must not be migrated implicitly.

Before any production device binding:

1. I09 defines the versioned device identity and storage namespace used by the
   public protocol.
2. I15 selects the production bundle/application identifier, signing and
   distribution identities, entitlements, and access-group policy.
3. I15 proves clean install, signed update, rollback/rejection behavior, and
   debug-to-production non-migration on representative clean devices.
4. A future identity or access-group change requires an explicit migration and
   rollback plan that never exports the private seed or falls back to plaintext.

If continuity cannot be proven, the release must require a deliberate device
rebind with explicit user-visible consequences rather than silently rotating a
key or losing the old identity.

## Current evidence and gap

K01-K10 passed on Apple Silicon macOS 26.3 in the approved development-signed
profile. The ad-hoc release probe failed closed with a missing-entitlement
classification. No test item remained after cleanup.

The prototype signing-key adapter exposes a metadata operation, but its normal
retrieve path currently validates only the returned byte length. The I01
activity sentinel likewise validates its value but not its stored security
attributes on each read. These are explicit I08/I09 productionization tasks;
neither adapter may be wired into production activity or network signing until
the gap is closed and the real Keychain matrix is rerun.

## Consequences

- G0 accepts the storage architecture without choosing a release identity.
- I05 may proceed without device registration or production Keychain identity.
- I09/I10 cannot use a persisted signing key until metadata validation and the
  versioned namespace are implemented and tested.
- I15 cannot ship until signing and upgrade continuity are proven.
- G1 independently reviews native storage and secret handling; G0 acceptance
  does not claim an external audit.
