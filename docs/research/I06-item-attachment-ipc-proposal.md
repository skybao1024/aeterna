# I06 item, bounded-attachment, and IPC proposal

- Prepared: 2026-09-21
- State: **Approved for I06 implementation on 2026-09-22**
- Baseline: `8a6e03e33a7e2fdf43143a4c5f0a321366d7cac3`
- Proposed decision: [ADR 0008](../adr/0008-vault-item-payload-and-session-ipc.md)
- Iteration brief: [`../iterations/I06-vault-item-bounded-attachment-mvp.md`](../iterations/I06-vault-item-bounded-attachment-mvp.md)

## Baseline and decision boundary

The managed worktree was clean at the start of I06 and `HEAD` resolved exactly
to `8a6e03e33a7e2fdf43143a4c5f0a321366d7cac3`. I05 and ADR 0007 are Accepted.
The existing implementation exposes a Rust-only vault repository with opaque
records, a 1,048,576-byte plaintext ceiling, authenticated record IDs,
generations, timestamps, and lengths, durable nonce reservation, and
compare-and-set update/delete. It exposes no vault Tauri command, app-owned
vault path, item codec, attachment model, or user workflow.

The user explicitly approved this complete proposal and ADR 0008 in the I06
task on 2026-09-22 before any source, manifest, lockfile, Tauri
configuration/capability, schema, migration, or persistence behavior changed.

## Proposed scope summary

I06 should reuse the accepted I05 record unchanged and make each vault item,
including all of its attachments, the plaintext of exactly one encrypted
record. This gives item text and attachment changes the same atomic
compare-and-set boundary without a schema migration, side file, recovery
protocol, or new cryptographic format.

The proposed user workflow is a clearly labeled local development preview:

1. If the fixed app-owned vault is absent, the user creates it with a master
   password and confirmation.
2. Rust initializes the real ADR 0007 vault, keeps the returned unlocked
   handle, and immediately drops the generated ERC/SRS recovery material.
3. The UI explicitly warns that this preview has no recovery, backup, export,
   account, or server path and must not hold irreplaceable data.
4. After restart the vault is locked. The master password is the only usable
   I06 unlock path.
5. The user can create, list, open, edit, delete, and explicitly lock notes and
   instructions, and can add/read/replace/remove bounded attachments.

This is intentionally not a fake production onboarding or recovery flow. It
does not display or accept an ERC, acquire an SRS, claim recovery, reset a
password, register a device/account, or imply that discarded I06 recovery
material can be reconstructed. I13 and I14 retain those responsibilities.

## Exact item model

### Item kinds and fields

Payload version 1 recognizes exactly two kinds:

|  ID | Machine value | Fields                                                                       |
| --: | ------------- | ---------------------------------------------------------------------------- |
|   1 | `note`        | `title`, `category`, `body`, attachments; `contactExplanation` must be empty |
|   2 | `instruction` | `title`, `category`, `contactExplanation`, `body`, attachments               |

All item fields are user content inside authenticated ciphertext. Kind is also
inside ciphertext. The SQLite row exposes only ADR 0007 structural metadata:
the random record ID, generation, frame length, and timestamps.

| Value               | Exact v1 rule                                                                                                                    |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Title               | 1-256 UTF-8 bytes; not all Unicode whitespace; no NUL or control character                                                       |
| Category            | 0-128 UTF-8 bytes; no NUL or control character                                                                                   |
| Contact explanation | Note: exactly empty. Instruction: 0-8,192 UTF-8 bytes; NUL forbidden; tab, CR, and LF allowed; other control characters rejected |
| Body                | 0-131,072 UTF-8 bytes; NUL forbidden; tab, CR, and LF allowed; other control characters rejected                                 |
| Attachments         | 0-8 entries; IDs unique within the item                                                                                          |

Rust `String` decoding supplies valid UTF-8 at IPC. The persisted decoder
independently validates UTF-8 before constructing a string. Version 1 performs
no NFC, NFD, case, whitespace, or line-ending normalization. Accepted text is
preserved byte-for-byte, so canonically equivalent Unicode sequences remain
distinct. Validation may use Unicode whitespace/control classification, but it
does not rewrite accepted input. Future normalization would require a new
payload version or an explicit migration that owns the semantic change.

### Identifiers, revisions, and timestamps

- The item ID is the existing random 16-byte I05 `record_id`; it is not
  duplicated inside payload plaintext. ADR 0007 already authenticates it in
  record AAD.
- Each attachment has an independent random 16-byte ID stored only in the item
  ciphertext. ID generation uses the existing OS CSPRNG path and rejects a
  collision within the item after a bounded retry.
- IPC renders both IDs as exactly 32 lowercase hexadecimal ASCII characters.
  Uppercase, prefixes, separators, incorrect length, and non-hex input are
  rejected as noncanonical.
- The item revision is the I05 record generation. Create returns revision 1;
  every text or attachment mutation requires an exact positive expected
  revision and increments it through the repository compare-and-set operation.
- Created and updated timestamps are the authenticated I05 UTC Unix-millisecond
  record metadata. They are not duplicated in the payload. IPC returns them as
  non-negative decimal strings to avoid JavaScript integer precision loss.
  Revision is also a positive decimal string for the same reason.
- List order is `updatedAtMs` descending and then item ID ascending. The order
  uses visible structural metadata, but the list title, kind, category, and
  attachment count are available only after record decryption and payload
  validation.

## Canonical item payload v1

All multibyte integers are unsigned big-endian. Fields occur once in the fixed
order below. Lengths count bytes, not Unicode scalar values. No padding,
alignment, compression, map ordering, omitted field, duplicate field, or
trailing byte is permitted.

```text
0..8     item magic = 41 45 54 52 49 54 4d 00 ("AETRITM\0")
8..10    payload version = 1, u16 big-endian
10       item kind (1 = note, 2 = instruction)
11       flags = 0; every other value is unsupported
12..14   attachment count, u16 big-endian
14..18   title byte length, u32 big-endian
18..22   category byte length, u32 big-endian
22..26   contact-explanation byte length, u32 big-endian
26..30   body byte length, u32 big-endian
30..A    title UTF-8 bytes
A..B     category UTF-8 bytes
B..C     contact-explanation UTF-8 bytes
C..D     body UTF-8 bytes
D..N     exactly `attachment count` attachment entries
```

Each attachment entry is:

```text
0..16    attachment ID, 16 bytes
16..18   filename byte length, u16 big-endian
18..20   media-type byte length, u16 big-endian
20..24   content byte length, u32 big-endian
24..A    filename UTF-8 bytes
A..B     media-type ASCII bytes
B..C     content bytes
```

The decoder validates the fixed header and every declared length with checked
arithmetic before slicing or allocating a declared buffer. It rejects unknown
magic/version/kind/flags, truncation, extension, invalid UTF-8, impossible
lengths, invalid field semantics, over-limit counts/content, duplicate
attachment IDs, and any final offset not equal to the plaintext length. It
never attempts fallback interpretation. An unknown payload version returns
`vault_item_unsupported_version`; malformed recognized v1 returns
`vault_item_invalid_format`.

ADR 0007 record AAD continues to bind vault ID, record/item ID, generation,
timestamps, and plaintext length. Because payload v1 contains no independent
item ID or timestamp, there is no duplicated value that can disagree. Record
substitution across vaults or item IDs continues to fail GCM authentication.

Payload v1 is an I06 domain format, not a new encryption, record, SQLite, or
export format. Future payload decoders and forward migrations are owned by the
first iteration that needs them. The existing bytes must never be reinterpreted
under new defaults. That later iteration must decrypt the recognized old
payload, validate it fully, construct a new version under an unlocked session,
and replace it with an optimistic revision; unknown future versions always
fail closed.

## Attachment representation and bound

### Exact limit proof

Version 1 permits:

- at most eight attachments;
- each attachment content length from 0 through 786,432 bytes; and
- the sum of all attachment content lengths from 0 through exactly 786,432
  bytes per item.

`786,432` bytes is 768 KiB. A single attachment of exactly that size succeeds;
786,433 bytes fails. Multiple files may reach the same aggregate boundary but
may not exceed it.

The worst-case encoded non-content overhead is:

```text
item fixed header                         30 bytes
maximum title                            256 bytes
maximum category                         128 bytes
maximum contact explanation            8,192 bytes
maximum body                           131,072 bytes
8 attachment fixed headers          8 × 24 = 192 bytes
8 maximum filenames                8 × 255 = 2,040 bytes
8 maximum media types              8 × 127 = 1,016 bytes
                                        ---------
maximum metadata/text                    142,926 bytes
maximum attachment content               786,432 bytes
                                        ---------
maximum encoded payload                  929,358 bytes
I05 plaintext ceiling                  1,048,576 bytes
remaining safety margin                  119,218 bytes
```

Rust enforces every component bound, the aggregate attachment bound, and the
final encoded length no greater than `MAX_PLAINTEXT_LENGTH`. The cap therefore
fits ADR 0007 even when every metadata/text field and all eight per-entry
overheads are maximal. The unused margin is deliberate; version 1 does not
dynamically trade body or metadata capacity for attachment capacity.

### Filename, media type, duplicate, and empty-file rules

- Accepted content types are unrestricted opaque bytes. I06 does not parse,
  execute, decompress, scan, or actively render attachment content.
- Filename is display metadata only, 1-255 UTF-8 bytes after validation, not
  all whitespace, and contains no NUL, control character, `/`, or `\`. It is
  never used as a path or app-created filename and is preserved without Unicode
  normalization.
- Media type is an optional 0-127-byte lowercase ASCII hint. A nonempty value
  must contain exactly one `/`; each side must be nonempty and contain only
  lowercase ASCII letters, digits, `!`, `#`, `$`, `&`, `^`, `_`, `.`, `+`, or
  `-`. Parameters are not accepted. The hint is never trusted for execution or
  rendering.
- Filename extension/media-type mismatch is accepted because both are
  untrusted user-supplied labels. The UI states that Aeterna has not verified
  the type. Preview behavior never branches into active media rendering based
  on either label.
- Empty files are accepted and represented by content length zero.
- Duplicate filenames and duplicate content are accepted. Attachment identity
  is the random attachment ID, not the name or hash.

### Add, read, replace, remove, and delete behavior

- Add and replace are two-step command-specific IPC operations. A typed prepare
  command validates item/revision/metadata/declared size and stores one pending
  descriptor in Rust memory. A raw commit command consumes that descriptor and
  accepts only the exact declared byte count. The descriptor is one-shot,
  expires after five minutes, and is cleared on cancel, success, failure,
  explicit lock, or process exit.
- Add creates a fresh attachment ID. Replace preserves the selected attachment
  ID but replaces its filename, media type, and bytes.
- Commit reopens/decrypts the current item, checks the exact expected revision,
  checks the final count/aggregate/encoded length, creates a new canonical
  payload, and invokes one I05 compare-and-set record update. Conflict or any
  failure leaves the prior record unchanged and consumes the upload descriptor.
- Read requires item ID, attachment ID, and expected item revision. Rust
  decrypts and validates the item, rejects a stale revision, and returns only
  the selected bytes as a raw IPC response. Metadata is returned by item-open,
  not repeated in raw headers.
- The UI may present selected bytes only in an inert bounded inspector: strict
  UTF-8 can be shown as escaped React text and non-UTF-8 as a capped hexadecimal
  view. No HTML, script, image, media, archive, PDF, URL, external-open, save,
  or download behavior is part of I06.
- Remove and enclosing-item delete require the expected revision. Remove
  rewrites the complete item without the selected attachment; item delete
  removes the single encrypted record and therefore all attachments atomically.

No plaintext temporary file, attachment table, side file, export marker, or
streaming format is created. Re-encrypting the whole item is accepted because
the exact bound is small. I07 remains responsible for export/import; a future
large-attachment format requires a separate reviewed decision.

## Atomicity, rollback, deletion, and concurrency

An item and its attachments are one atomic encrypted record. The consequences
are intentional:

- create writes one record;
- text edit, add, replace, or remove serializes the complete next item and
  compare-and-set replaces one record;
- delete removes one record;
- failure before commit exposes the exact old record after reopen;
- there is no cross-record child state to orphan or roll back; and
- every mutation advances the same generation, so concurrent text and
  attachment edits cannot silently overwrite each other.

The service must not retry a `vault_busy` or an unknown commit outcome as a new
mutation. A stale expected revision returns `vault_conflict`. The UI preserves
the unsaved draft, explains the conflict through localized fixed-code mapping,
and lets the user reload or copy manually; it never silently overwrites.

SQLite physical deletion remains subject to ADR 0007: `secure_delete` and
full-disk encryption reduce exposure but do not prove SSD, snapshot, swap,
backup, or crash-dump erasure. I06 makes no stronger deletion claim.

## App-owned path and unlocked-session lifecycle

Rust resolves the vault path through Tauri's `AppHandle.path()` API:

```text
app_local_data_dir()/vault/aeterna-vault.sqlite3
```

The path is never supplied by or returned to the WebView. Rust creates only the
fixed `vault` directory, using mode `0700` on Unix when creating it; the
existing I05 repository creates/publishes the database as mode `0600` on Unix
and enforces its current file checks. Windows ACL behavior is not qualified by
I06. No directory picker, alternate path, arbitrary path, or raw filesystem
command exists.

A Tauri-managed `Mutex` owns exactly one process-local state:

```text
Uninitialized
Locked(VaultRepository)
Unlocked(UnlockedVault)
```

The same state also owns at most one pending attachment descriptor. Commands
serialize through this state lock, while the underlying I05 repository remains
responsible for cross-connection revision and transaction safety. Mutex poison
or unexpected internal state maps to a fixed safe error and never exposes the
path or content.

- Startup detects only whether the fixed vault exists and begins
  `Uninitialized` or `Locked`. It never auto-unlocks.
- Successful initialization transitions directly to `Unlocked`; its
  `RecoveryMaterial` is immediately dropped and never serialized, displayed,
  persisted outside the accepted wrapper, or sent to the WebView.
- Successful master-password unlock replaces `Locked` with `Unlocked`.
- Explicit lock consumes/drops `UnlockedVault`, clears pending attachment
  metadata, advances a frontend session epoch, and responds only after Rust has
  dropped the VDK owner.
- Process exit drops the state. Restart is locked. A WebView refresh within the
  same host process does not claim to be a lifecycle lock; I08 owns automatic
  window/session/sleep/inactivity behavior.
- Passwords enter Rust only through initialize/unlock requests, are converted
  immediately to the existing zeroizing `MasterPassword`, and are not retained
  in command state. The WebView clears its input after the call settles.

The I06 state deliberately does not store a password, ERC, SRS, raw VDK, item
plaintext cache, or attachment bytes between commands. Zeroization remains
best-effort under ADR 0002 and does not claim erasure of framework, allocator,
JavaScript-engine, OS, swap, or crash copies.

## Exact IPC surface

### Request and response rules

Every JSON command accepts `tauri::ipc::Request`, requires a JSON body, and
manually deserializes that complete body into a request type with
`#[serde(rename_all = "camelCase", deny_unknown_fields)]`. This keeps
missing/extra/wrong-type errors under application control and maps them to
`ipc_invalid_request` rather than exposing framework deserialization text.
Strings, identifiers, revisions, and sizes then receive domain bounds before
database access. Every response has a TypeScript runtime validator; a malformed
native response maps to `ipc_invalid_response`.

Errors are serialized only as:

```json
{ "code": "machine_readable_english_code" }
```

No error includes item content, attachment metadata/bytes, password, key,
nonce, ciphertext, ID, or sensitive path. The frontend maps known codes to
localized messages and maps every unknown rejection to a generic localized
failure without logging the original value.

The exact JSON commands are:

| Command                    | Request                                                                                   | Response                              | Allowed state                                      |
| -------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------- | -------------------------------------------------- |
| `vault_status`             | `{}`                                                                                      | `{ state: "uninitialized"             | "locked"                                           | "unlocked" }` | Any |
| `vault_initialize`         | `{ password: string }`                                                                    | `{ state: "unlocked" }`               | Uninitialized                                      |
| `vault_unlock`             | `{ password: string }`                                                                    | `{ state: "unlocked" }`               | Locked                                             |
| `vault_lock`               | `{}`                                                                                      | `{ state: "locked" }`                 | Locked or unlocked; idempotent when already locked |
| `vault_list_items`         | `{}`                                                                                      | `{ items: ItemSummary[] }`            | Unlocked                                           |
| `vault_get_item`           | `{ itemId: HexId }`                                                                       | `{ item: VaultItem }`                 | Unlocked                                           |
| `vault_create_item`        | `{ kind, title, category, contactExplanation, body }`                                     | `{ item: VaultItem }`                 | Unlocked                                           |
| `vault_update_item`        | `{ itemId, expectedRevision, kind, title, category, contactExplanation, body }`           | `{ item: VaultItem }`                 | Unlocked                                           |
| `vault_delete_item`        | `{ itemId, expectedRevision }`                                                            | `{ deleted: true }`                   | Unlocked                                           |
| `vault_prepare_attachment` | `{ itemId, expectedRevision, operation, attachmentId?, filename, mediaType, byteLength }` | `{ uploadId, expiresInSeconds: 300 }` | Unlocked                                           |
| `vault_commit_attachment`  | raw bytes plus `x-aeterna-upload-id` header                                               | `{ item: VaultItem }`                 | Unlocked with matching pending descriptor          |
| `vault_cancel_attachment`  | `{ uploadId }`                                                                            | `{ cancelled: true }`                 | Unlocked                                           |
| `vault_read_attachment`    | `{ itemId, attachmentId, expectedRevision }`                                              | raw bytes                             | Unlocked                                           |
| `vault_remove_attachment`  | `{ itemId, attachmentId, expectedRevision }`                                              | `{ item: VaultItem }`                 | Unlocked                                           |

`ItemSummary` contains item ID, revision, kind, title, category, attachment
count, and created/updated decimal timestamps. `VaultItem` adds body, contact
explanation, and attachment descriptors `{ attachmentId, filename, mediaType,
byteLength }`; it never embeds attachment content in JSON. `operation` is
exactly `add` or `replace`. `attachmentId` is forbidden for add and required
for replace. `byteLength` is a canonical non-negative decimal string and is
bounded before creating pending state.

The raw commit command accepts `InvokeBody::Raw` only. It requires one canonical
lowercase upload ID header, no metadata headers, and a body length exactly equal
to the prepared length. The raw read response uses Tauri `ipc::Response` and
contains only the selected content bytes. There are no Tauri events in I06;
command responses are sufficient and avoid a second unowned plaintext route.

### Error codes

Existing I05 codes remain unchanged. I06 adds only these fixed codes where an
existing classification is not exact:

| Code                             | Meaning                                                                                                |
| -------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `ipc_invalid_request`            | JSON/raw form, header, type, unknown field, identifier, revision, or command-specific shape is invalid |
| `ipc_invalid_response`           | Frontend runtime response validation failed; generated only in TypeScript                              |
| `vault_uninitialized`            | Operation requires an initialized app-owned vault                                                      |
| `vault_already_initialized`      | Initialize was requested for an existing vault                                                         |
| `vault_locked`                   | Content operation requires the Rust unlocked session                                                   |
| `vault_item_invalid_format`      | Recognized item payload is malformed or violates v1 semantics                                          |
| `vault_item_unsupported_version` | Item magic/version/kind/flags is unknown                                                               |
| `vault_attachment_too_large`     | Per-file, aggregate, or final item size bound would be exceeded                                        |
| `vault_attachment_not_found`     | Selected attachment ID is not present in the item                                                      |
| `vault_upload_pending`           | A pending upload already occupies the single bounded slot                                              |
| `vault_upload_not_found`         | Upload ID is absent, cancelled, expired, consumed, or nonmatching                                      |
| `vault_internal_error`           | Mutex poison or unreachable internal state; no diagnostic detail crosses IPC                           |

Field-semantic failures that are not attachment-size specific use the existing
`vault_invalid_input`. Repository authentication, conflict, busy, corrupt,
format, unsupported-version, I/O, randomness, and not-found codes retain their
ADR 0007 meanings. The UI does not distinguish wrong password from wrapper or
header authentication tamper beyond `crypto_authentication_failed`.

## File selection, capability, and CSP decision

Attachment selection uses a standard `<input type="file">` in the local React
document. The platform WebView presents the native chooser and yields a browser
`File` object without an arbitrary readable path. The UI validates `File.size`
for prompt feedback, reads only the selected file into an `ArrayBuffer`, and
sends its `Uint8Array` as a Tauri v2 raw invoke body. Rust treats frontend size
checks as untrusted and repeats every check.

I06 verifies this behavior on the current macOS host only. The HTML control is
cross-platform, but no Windows picker, path, accessibility, or filesystem
support claim is made before the separate GW qualification gate.

This approach intentionally avoids `@tauri-apps/plugin-dialog` and
`@tauri-apps/plugin-fs`. The alternative dialog-plus-Rust-path approach would
add a plugin, reveal a path across IPC, and require a narrowly scoped read
capability or a tokenized Rust dialog result. It adds no value for a sub-1 MiB
single-selection MVP. A JSON number array or base64 body is also rejected
because Tauri v2 supports raw payloads and the encoding would add memory and
size overhead. Tauri's official v2 documentation describes raw `Uint8Array`
invocation and `InvokeBody::Raw` handling in
[Calling Rust from the frontend](https://v2.tauri.app/develop/calling-rust/).

Rust app-local path resolution uses the existing Tauri core `Manager::path`
API and `std::fs`; it does not require a WebView filesystem plugin or
capability. The main capability changes from the I00 smoke permission to an
allowlist containing exactly the fourteen I06 commands above. It grants no
core/plugin filesystem, dialog, shell, process, clipboard, SQL, HTTP, asset
protocol, or global scope permission.

No CSP source changes are proposed. Attachment content is displayed only as
React-escaped text/hex, so `blob:`, `file:`, remote image/media, frame, object,
or script sources are unnecessary. Existing strict production CSP and local
development-only loopback allowances remain unchanged.

## Decrypted WebView data and frontend storage policy

The WebView may receive only:

- the password value typed by the user until initialize/unlock settles;
- decrypted item summaries after an explicit unlocked list command;
- one opened item's text and attachment descriptors; and
- one explicitly selected attachment's bytes while its inert inspector is
  open.

The WebView never receives the VDK, ERC, SRS, wrapper, nonce, ciphertext,
database path, arbitrary filesystem path, or SQL capability. It never
automatically reads attachment bytes for a list or item-open response.

Vault content and passwords remain ephemeral React/JavaScript memory only.
They are prohibited from localStorage, sessionStorage, IndexedDB, Cache API,
service workers, URL/query/hash/history state, clipboard, console, error text,
analytics, telemetry, test snapshots, file names created by Aeterna, or
temporary files. The only existing browser-persisted value remains the locale
key `aeterna.locale`, which contains no vault content. Tests enumerate storage
and assert that no other key is written.

Lock increments a frontend session epoch, clears item/draft/password/preview
state, overwrites mutable attachment `Uint8Array` buffers with zero, and ignores
late responses from the prior epoch. JavaScript strings cannot be reliably
zeroized; the UI drops references promptly and makes only the documented
best-effort claim.

## Accessibility, destructive actions, and unsaved changes

- Every input has a visible localized label and validation association. Status
  and safe errors use appropriate live regions without announcing content.
- Item list, editor, kind selection, attachment controls, locale switch, lock,
  and dialogs are keyboard operable with visible focus.
- Command/Ctrl+S saves the active draft. It never bypasses validation or a
  pending conflict.
- Changing item, creating another item, switching locale, locking, or closing
  with a dirty draft opens a localized accessible confirmation. Cancel keeps
  focus and content; discard clears the draft; save performs the same bounded
  command as the primary action. Host/window close also installs a
  `beforeunload` guard while dirty, without persisting the draft.
- Delete uses a localized modal `alertdialog`, clearly states that the item and
  every attachment will be deleted, and requires an explicit destructive
  button. Escape/cancel closes it; initial focus is non-destructive; focus
  returns to the invoker.
- Attachment replace/remove likewise identify the target in visible UI and
  require an explicit action, but only full item delete uses the destructive
  confirmation dialog.
- All user-visible copy, labels, warnings, errors, empty states, dates, sizes,
  and confirmation text use i18n keys with English source/default and complete
  Simplified Chinese resources. Dates and byte sizes use locale-aware APIs.

## Dependency and supply-chain review

### Proposed dependency delta

No new Rust crate, npm package, Tauri plugin, feature, native library, build
script, or lockfile entry is proposed.

The implementation uses already pinned direct dependencies:

- `tauri = 2.11.6` for managed state, app-local path resolution, commands,
  `ipc::Request`, raw `InvokeBody`, and raw `ipc::Response`;
- `serde = 1.0.228` for strict request/response schemas; and
- existing vault/crypto dependencies accepted by ADRs 0002 and 0007.

The frontend uses already pinned React 19.3.0 and `@tauri-apps/api` 2.11.1.
No lockfile or feature change is expected. Implementation must stop for renewed
approval if the manifest or lockfile needs any unexpected change.

Tauri/Serde are already part of the built application and governed by the
existing dependency ledger. I06 adds application usage but no new license,
maintenance, native, unsafe, network, or build-time package. Raw Tauri IPC is
process-local and adds no runtime network destination. App-local path access is
Rust `std::fs` against one fixed derived path. No project-owned `unsafe` is
proposed.

### Alternatives considered

| Alternative                              | Decision                                                                                                                                                                      |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Separate attachment rows/files           | Rejected for I06: adds schema/migration, multi-part rollback/delete, side-file naming, and more observable metadata without need under the bound.                             |
| JSON item payload                        | Rejected: canonical object ordering, duplicate/unknown fields, numeric representation, escaping, and production `serde_json` ownership add ambiguity to the persisted format. |
| CBOR/MessagePack/Protobuf                | Rejected: new dependency and canonicalization rules are unnecessary for a small fixed format.                                                                                 |
| Unicode NFC dependency                   | Rejected: normalization is not required for identity/search in I06; preserving exact valid UTF-8 avoids a dependency and lossy semantic rewrite.                              |
| Tauri dialog and filesystem plugins      | Rejected: broadens dependency/capability/path surface; HTML file input plus raw IPC is adequate.                                                                              |
| JSON byte array or base64 attachment IPC | Rejected: avoidable serialization and memory overhead; raw IPC is already available.                                                                                          |
| Automatic WebView or OS lifecycle lock   | Deferred to I08, which owns platform lifecycle evidence and policy. Explicit lock and restart-locked behavior are truthful I06 scope.                                         |
| Fake ERC/SRS or recovery screen          | Rejected: crosses I13/I14 and misrepresents security. The development-local master-only warning is explicit.                                                                  |

## Security and privacy consequences

- Single-record items leak no new plaintext columns or user-derived filenames.
  SQLite still exposes ADR 0007 row count, IDs, timestamps, sizes, and write
  timing.
- Attachment metadata/content is protected by the same AES-GCM record and AAD
  as item text. There is no independently replaceable attachment ciphertext;
  every attachment mutation re-encrypts the complete bounded item.
- The WebView necessarily handles content being edited or inspected. Strict
  CSP, no remote assets/network/capabilities, ephemeral state, and content-free
  diagnostics reduce exposure but do not protect an already compromised
  unlocked process or OS.
- The two-step raw upload stores only validated attachment metadata in Rust
  between prepare and commit. Bytes are never staged. The one-slot/five-minute
  rule bounds retained metadata and replay surface.
- Discarding initialization recovery material means I06-created data has no
  recovery path if the master password is lost. The UI warning and development
  identifier make this limitation explicit; I06 must not be presented as
  production-ready.
- No automatic lifecycle lock exists. Explicit lock and process restart are
  the only I06 lock transitions. I08 remains mandatory before a lifecycle or
  support claim.

## Required implementation evidence

The test requirements and exact acceptance matrix are normative in the I06
iteration brief. In addition, implementation review must show:

1. golden payload bytes and independent parser rejection for every header and
   attachment length boundary;
2. a mathematical/unit assertion for the 929,358-byte worst-case payload and
   a real encrypted-record test at 786,432 versus 786,433 attachment bytes;
3. real-file marker scans covering item title/category/contact/body, Unicode
   filename/media type/content, main DB, live WAL/SHM, forced journal, temp
   behavior, app-created path components, and captured logs;
4. injected item/attachment mutation failures proving old-record recovery;
5. IPC calls that bypass frontend checks and prove Rust rejection of malformed,
   extra, missing, wrong-type, oversized, JSON/raw-confused, and replayed input;
6. explicit lock followed by every content command, plus a late-response UI
   race, proving no post-lock content repopulation;
7. source/config scans proving no network, remote asset, file/dialog/shell/SQL,
   clipboard, export/import, telemetry, key, or generic crypto surface; and
8. exact pinned-toolchain `npm run check` and `npm run desktop:build` results.

## Approval

The user approved the complete ADR 0008 decision and implementation scope in
this document on 2026-09-22, including:

- payload v1 and its exact field/encoding/version/migration rules;
- one atomic I05 record per item and its attachments;
- the exact 786,432-byte aggregate attachment limit and type/name behavior;
- the development-local master-only initialization warning and discarded
  recovery material;
- the fixed app-local path and Rust session lifecycle;
- the fourteen-command JSON/raw IPC surface, fixed error codes, and exact main
  capability allowlist;
- HTML file selection, raw in-memory binary transfer, inert attachment
  inspection, and unchanged CSP; and
- no new dependency, plugin, lockfile entry, schema, migration, crypto, network,
  or filesystem capability.

Approval moved I06 beyond the documentation checkpoint into implementation.
