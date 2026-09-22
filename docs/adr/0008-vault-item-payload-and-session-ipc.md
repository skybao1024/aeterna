# ADR 0008: Vault item payload, bounded attachments, and session IPC

- Status: Accepted
- Date: 2026-09-21
- Decision owner: I06 item, attachment, and IPC approval
- Approval: Explicit user approval recorded in the I06 task on 2026-09-22
- Governing ADRs: [ADR 0002](./0002-cryptographic-envelope-and-key-storage.md), [ADR 0005](./0005-vault-format-and-migration-ownership.md), [ADR 0007](./0007-local-vault-format-v1.md)
- Proposal: [`../research/I06-item-attachment-ipc-proposal.md`](../research/I06-item-attachment-ipc-proposal.md)

## Context

I05 provides a Rust-only encrypted repository whose opaque record plaintext is
bounded to 1,048,576 bytes. It deliberately defines no item semantics,
attachment representation, user workflow, app-owned path, unlocked application
session, or Tauri command. ADR 0005 assigns the first bounded attachment limit
to I06. I06 must define those contracts without changing ADR 0007 cryptography,
record framing/AAD, schema, nonce allocation, transactions, or migrations.

The full product setup and recovery flows require account/device binding, SRS
acquisition, ERC presentation/entry, claims, and owner recovery that belong to
I09 and I13-I14. I06 still needs a truthful way to exercise real encrypted item
CRUD through the desktop application without fabricating those deferred flows.

## Decision

### Payload and item semantics

I06 payload version 1 is the fixed canonical binary format specified in the
proposal. It uses magic `AETRITM\0`, big-endian integers, payload version 1,
kind `1 = note` or `2 = instruction`, zero flags, four ordered UTF-8 fields,
and zero through eight ordered attachment entries. Each attachment contains a
random 16-byte ID, bounded UTF-8 filename, bounded ASCII media-type hint, and
bounded opaque content bytes.

Notes contain title, category, and body; their contact explanation is exactly
empty. Instructions additionally permit a contact explanation. Exact limits
are title 256 bytes, category 128 bytes, contact explanation 8,192 bytes, body
131,072 bytes, filename 255 bytes, media type 127 bytes, and eight attachments.
The proposal's validation rules are normative.

Version 1 preserves accepted UTF-8 bytes exactly. It performs no Unicode case,
normalization, whitespace, or line-ending rewrite. Invalid UTF-8, NUL or
disallowed controls, invalid field semantics, checked-arithmetic failure,
unknown magic/version/kind/flags, duplicate attachment IDs, truncation, and
trailing bytes fail closed. Unknown versions are never interpreted as v1.

The item ID, revision, and timestamps are the existing authenticated ADR 0007
record ID, generation, and timestamps; they are not duplicated in payload.
Item/attachment IDs use exact lowercase 32-character hexadecimal IPC encoding.
Revision and timestamps use canonical decimal strings across IPC.

Future payload support is owned by the first iteration that needs it. It must
add an explicit decoder and migration, preserve old-version semantics, and
replace a validated old item under an unlocked optimistic revision. No future
implementation may reinterpret v1 bytes under changed defaults.

### Attachment bound and representation

An item and all of its attachment metadata/content are the plaintext of one
ADR 0007 encrypted record. There is no attachment table, side file, app-created
user filename, schema change, or migration in I06.

Attachment content is bounded to exactly 786,432 bytes per attachment and in
aggregate per item. One exact-boundary attachment succeeds and limit plus one
fails. At every maximum field/count, the canonical encoded payload is at most
929,358 bytes, leaving 119,218 bytes below the accepted 1,048,576-byte record
ceiling. Rust independently checks each length, aggregate content, and final
encoded payload.

Attachment content is unrestricted opaque bytes. Empty files, duplicate
filenames, and duplicate content are accepted. Filenames and media types are
untrusted display metadata, never paths or execution/rendering decisions.
Extension/type mismatch is accepted and visibly unverified. I06 provides only
an inert escaped-text or capped-hex inspector after an explicit read; it does
not execute, externally open, save, export, or actively render content.

Create writes one record. Text edit, attachment add/replace/remove, and any
other mutation reserialize and compare-and-set replace that complete record.
Delete removes it. Therefore a successful change is atomic and any failure
leaves the prior complete record; all mutation types share one generation and
cannot silently overwrite a stale peer.

### Session authority and truthful initialization

Rust alone owns the app-local vault path:

```text
app_local_data_dir()/vault/aeterna-vault.sqlite3
```

The WebView cannot choose or receive it. A Tauri-managed mutex owns exactly one
process-local `Uninitialized`, `Locked(VaultRepository)`, or
`Unlocked(UnlockedVault)` state plus at most one bounded pending attachment
descriptor. Startup and restart are never auto-unlocked.

I06 initialization is explicitly a development-local, master-password-only
preview. Rust initializes the real ADR 0007 vault, transitions to unlocked,
and immediately drops the generated recovery material. The UI must warn before
initialization and while using the vault that recovery, account binding,
backup/export, and server support are unavailable; losing the master password
loses access, and irreplaceable data must not be stored. No ERC, SRS, recovery,
claim, or password-reset UI/API is introduced.

Explicit lock immediately drops the unlocked handle and pending upload
descriptor before responding. Subsequent content commands fail with
`vault_locked`. Process exit drops the session and restart is locked. Automatic
sleep, window, OS-session, and inactivity locking remain I08 responsibilities
and are not claimed by I06.

### IPC and file-selection boundary

The main window receives exactly these purpose-specific commands:

```text
vault_status
vault_initialize
vault_unlock
vault_lock
vault_list_items
vault_get_item
vault_create_item
vault_update_item
vault_delete_item
vault_prepare_attachment
vault_commit_attachment
vault_cancel_attachment
vault_read_attachment
vault_remove_attachment
```

There are no I06 events. JSON commands manually deserialize the complete Tauri
request body into `deny_unknown_fields` schemas so application code maps shape
failure to `ipc_invalid_request`. Responses receive TypeScript runtime
validation. Errors cross IPC only as a fixed machine-readable English code.
The exact schemas and added codes in the proposal are normative.

Attachment add/replace uses one typed prepare command followed by one raw-byte
commit. Rust retains only one one-shot metadata descriptor for at most five
minutes; it validates declared/actual size, operation, item/attachment IDs, and
expected revision, and clears the descriptor on every terminal result, cancel,
lock, or exit. Read returns only explicitly selected attachment bytes as a raw
response and requires the exact current item revision.

File selection uses the standard local HTML file input and Tauri v2 raw IPC.
Rust resolves the fixed application path through existing Tauri core APIs and
uses `std::fs`. I06 adds no dialog/filesystem/shell/SQL/HTTP/clipboard plugin or
permission, no arbitrary path, no generic read/write or crypto command, and no
CSP source. The I00 smoke command/permission is replaced by the exact I06
allowlist.

The WebView may hold only the password being submitted, decrypted list/open
data, the active draft, and bytes of one explicitly inspected attachment. It
must not persist vault content in localStorage, sessionStorage, IndexedDB,
caches, service workers, URLs/history, clipboard, logs, diagnostics, snapshots,
telemetry, or files. Explicit lock advances a UI epoch, clears plaintext state,
best-effort overwrites mutable byte buffers, and ignores late prior-epoch
responses. The existing non-content locale preference may remain in
localStorage.

### Dependencies and configuration

I06 adds no Rust crate, npm package, Tauri plugin, feature, native library,
lockfile entry, SQLite schema/migration, or crypto/container version. It uses
the already pinned Tauri, Serde, React, frontend Tauri API, and accepted
vault/crypto dependencies. Any unexpected dependency, feature, lockfile,
schema, migration, cryptographic, CSP, or non-command capability change stops
implementation for renewed approval.

## Security and privacy consequences

- User content remains inside the existing authenticated record. Observable
  structural row IDs, counts, sizes, timestamps, and access/write patterns
  retain ADR 0007's accepted leakage and physical-deletion limits.
- Whole-item rewrite gives simple atomicity but costs memory and encryption
  proportional to the bounded item. The 768 KiB cap makes that cost explicit.
- The WebView necessarily sees actively edited/inspected plaintext. Strict CSP,
  no remote/network path, no persistence/capability, and best-effort clearing
  reduce but do not eliminate exposure from an unlocked compromised process.
- The master-only preview has intentionally unrecoverable data if its password
  is lost. Clear development-local warnings prevent it from masquerading as
  the deferred production recovery design.
- No automatic lifecycle lock is provided. This ADR authorizes explicit lock
  and restart-locked behavior only.

## Alternatives rejected

- Separate rows or side files: unnecessary schema, rollback, delete, naming,
  metadata-leakage, and migration surface for sub-1 MiB content.
- JSON or a new serialization crate for persisted payloads: avoidable
  canonicalization and dependency surface.
- Unicode normalization dependency: no I06 identity/search requirement
  justifies rewriting user text.
- Tauri dialog/filesystem plugins: HTML selection and raw IPC satisfy the
  bounded workflow without path/capability expansion.
- Base64 or JSON byte arrays: avoidable binary transfer overhead.
- Fake ERC/SRS, recovery, or account setup: violates the I13/I14 boundary and
  would misrepresent security.
- Automatic lifecycle lock in I06: lacks I08's platform evidence and policy.

## Approval effect

Acceptance of this ADR authorizes only the I06 implementation and evidence
described here and in the linked proposal. It does
not authorize I07 export/import, a larger or streaming attachment format, an
item/schema/crypto migration, I08 lifecycle/activity productionization, I09
network/device binding, I13/I14 recovery, server work, sync, updater,
telemetry, production signing, Windows qualification, publication, or
deployment.
