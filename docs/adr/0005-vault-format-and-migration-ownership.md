# ADR 0005: Vault format and migration ownership

- Status: Accepted by G0 for ownership and invariants
- Date: 2026-09-21
- Decision owner: G0 for ownership and invariants; I05 and I07 for exact formats
- Approval: Explicit user approval recorded in G0 on 2026-09-21
- Inputs: [ADR 0002](./0002-cryptographic-envelope-and-key-storage.md), [`../DESIGN.md`](../DESIGN.md)

## Context

The I02 test fixture and its AAD/HKDF byte layouts prove primitive
interoperability. They do not define a SQLite schema, a vault header, a record
encoding, an attachment format, or an export package. Treating the prototype
fixture as a production container would skip migration, crash-safety, rollback,
and size-limit decisions. Requiring a final container before I05 would be
circular because I05 is the iteration that must design and test it.

## Decision

G0 fixes ownership and invariants, not the final serialization:

- I05 must propose and approve the local vault header, SQLite schema,
  transaction boundaries, schema and crypto version fields, record framing,
  authenticated metadata, bounds, nonce allocation, and forward/rollback
  migration rules before persistent vault implementation begins.
- I07 separately owns the authenticated export/import package, staging and
  atomic-completion protocol, manifest, and restoration compatibility.
- I06 owns the initial bounded attachment limit. A streaming encryption format
  is a separate later decision and must not be inferred from AES-GCM record
  wrapping.

All formats must reject unknown versions and hostile sizes before expensive
allocation or KDF work. SQLite databases, WAL files, journals, temporary files,
exports, and backups may contain only ciphertext and non-sensitive structural
metadata. Titles, categories, contact explanations, and content remain inside
authenticated ciphertext.

The cryptographic wrapper version and the database/schema/export versions are
independent fields. No migration may reinterpret old wrapper bytes under new
defaults. A destructive migration requires a backup, compatibility, and
recovery plan plus explicit approval.

## I05 decision checkpoint

Before I05 changes persistence code, its exact format proposal must state:

1. magic and version fields, canonical integer and identifier encodings, and
   maximum lengths;
2. how master and recovery wrappers are stored without treating the I02 JSON
   fixture as production serialization;
3. how per-record nonces are generated and how uniqueness is protected across
   interruption, retry, rollback, restore, and migration;
4. SQLite transaction, WAL, temporary-file, and crash-recovery behavior;
5. unknown-version, corruption, wrong-credential, tamper, partial-write, and
   downgrade behavior; and
6. how migrations are backed up, rolled back, and tested without plaintext
   leakage.

G0 acceptance of this ownership boundary authorizes I05 to make that proposal;
it does not pre-approve any particular schema or container bytes.
