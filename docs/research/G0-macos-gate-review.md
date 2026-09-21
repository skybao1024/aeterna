# G0 macOS Phase 0 architecture and security gate review

- Review date: 2026-09-21
- Gate state: **Accepted by explicit user approval**
- Approval date: **2026-09-21**
- Client baseline: `54a213c5e17f5e1e3eae183f17f1f2370aa7a61d`
- Integrated server baseline: `9873e418909d52885ee4b4c61ae3a6d16f5beff6`
- Next eligible iteration: **I05 — Versioned vault format and encrypted storage core**
- Windows state: **I04 In Progress; ADR 0003 Proposed; GW Pending**

## Executive decision

The reviewed I01, I02, and I03 evidence is sufficient for a macOS-first I05
implementation path. The I04 shared contracts compile and pass the macOS
regression suite, but no Windows behavior is accepted or inferred. The user
approved the final digest, the reviewed client tree has a recoverable root
commit, and the accepted I03 implementation is integrated into authoritative
server `dev`.

G0 accepts the following implementation-scoped decisions:

- the I01 macOS activity policy, including two distinct HID-class epochs, an
  intervening successful Keychain gate read, cooldown, fail-closed lifecycle,
  and authenticated remote-login semantics;
- the I02 primitive set, exact pins, bounds, wrapper separation, and versioned
  AAD/HKDF encodings as an I05 implementation basis, without claiming an
  external audit or final container;
- the macOS Data Protection Keychain boundary and continuity requirements in
  ADR 0004, while deferring the production identity to I15;
- the I03 PostgreSQL row-lock, compare-and-set, server-time, outage-recovery,
  transactional-Outbox, and idempotency semantics;
- the vault/container and migration ownership boundary in ADR 0005; and
- the public protocol ownership and versioning direction in ADR 0006.

The initial product and test floor is Apple Silicon macOS 15.0. That
is a product target, not a completed support claim: real native evidence today
covers macOS 26.3 only. I08 must replay the native matrix on an updated macOS 15
host and the then-current macOS release. If the floor cannot pass, the minimum
must be raised rather than waived.

## Evidence map

| Gate concern                | Design requirement                                                                       | Exact evidence inspected                                                                                             | Evidence class                                                   | G0 disposition                                                                               |
| --------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Release scope               | `DESIGN.md` section 1.3 and G0 brief                                                     | I04 brief, proposal, result, ADR 0003, shared adapters and tests                                                     | Documentation, compilation, deterministic tests                  | macOS-only; I04/GW remain incomplete                                                         |
| Activity policy             | `DESIGN.md` sections 6.1-6.4 and 18.1                                                    | I01 brief, result ledger, ADR 0001, `activity/policy.rs`, macOS adapter, diagnostics, observer tests                 | Deterministic tests plus signed-host matrix                      | Accepted with M10/M13 waivers and I08 obligations                                            |
| Remote sessions             | Valid activity requires target unlocked session; local physical presence is not promised | I01 M14 Screen Sharing evidence and approved semantic                                                                | Real-machine observation plus explicit product decision          | Authenticated remote HID-class input is valid; Combined-only input is suppressed             |
| Cryptographic core          | `DESIGN.md` sections 8, 10.2, 14, 17.2, and 18.4                                         | I02 brief, dependency proposal, result ledger, ADR 0002, primitive and wrapper code, published-vector tests, fixture | Published KATs, deterministic fixture, negative tests, benchmark | Accepted for implementation scope; no external-audit claim                                   |
| macOS signing-key storage   | Secret remains outside WebView and ordinary persistence; no fallback                     | I02 K01-K10, secure-storage port and macOS adapter                                                                   | Signed-host matrix plus source review                            | Accept boundary in ADR 0004; metadata enforcement and production identity remain later gates |
| KDF profile                 | Explicit, bounded, versioned parameters                                                  | Apple Silicon release benchmark, profile E                                                                           | One-host benchmark                                               | Provisional development profile only; I08 validates the floor/current release                |
| Server winner semantics     | `DESIGN.md` sections 7.3-7.4 and 18.3                                                    | I03 result, server ADR 0001, model, service, migration, 12 race/rollback tests                                       | Real PostgreSQL transactions and deterministic concurrency hooks | Accepted and integrated at the recorded server commit                                        |
| Protocol ownership          | Development plan repository-ownership rule                                               | ADR 0006 and absence of public I03 routes                                                                            | Architecture decision; no protocol implementation                | Public client repo owns schemas/fixtures; I09 chooses exact encoding                         |
| Version/container ownership | `DESIGN.md` sections 9.2 and 10                                                          | ADRs 0002 and 0005; I02 fixture explicitly test-only                                                                 | Architecture decision                                            | I05 owns local format/migrations; I07 owns export/import package                             |
| Baseline integrity          | G0 brief baseline checkpoint                                                             | Client root checkpoint; server checkpoint branch and authoritative `dev` integration                                 | Source-control inspection, content manifests, exact commits      | Pass                                                                                         |

## Findings

### G0-01 — Resolved: reviewed baselines now have recoverable commit references

**Trigger:** the client repository has no commits and every non-ignored Phase 0
file is untracked. The I03 implementation is an uncommitted patch in a detached
worktree based on server commit
`d9dd7cb7e03e6b869d1068e24703d53a817b4b42`; the authoritative server `dev`
checkout is clean at the same commit and contains none of I03.

**Impact:** loss of either working tree would remove the only recoverable copy
of reviewed implementation evidence. A later task could also review a different
baseline while using the same iteration labels.

**Resolution:** after explicit authorization, client root commit
`54a213c5e17f5e1e3eae183f17f1f2370aa7a61d` preserved the Phase 0 checkpoint.
Server commit `9873e418909d52885ee4b4c61ae3a6d16f5beff6` preserved I03 on
`codex/i03-concurrency-checkpoint` and was fast-forwarded into clean
authoritative `dev`. Neither repository was pushed.

### G0-02 — High: Keychain reads do not yet enforce stored security metadata

**Trigger:** `src-tauri/src/activity/macos.rs:191-213` validates the sentinel
value but does not request its accessibility and synchronization attributes on
normal reads. `src-tauri/src/secure_storage/macos.rs:78-88` validates only the
32-byte signing-secret payload during retrieval, while the metadata validation
at lines 116-141 is a separate operation.

**Impact:** a stale, migrated, or incorrectly created item with weaker
attributes could be treated as a valid gate or signing-key record. That would
undermine locked-session activity suppression or the intended secret-storage
policy.

**Fix:** I08 must validate the sentinel value plus
`WhenUnlockedThisDeviceOnly` and non-synchronization on every production gate
read. I09 must perform equivalent metadata validation before returning a
signing seed. Unexpected metadata fails closed. Rerun the signed Keychain and
lock matrices afterward. This blocks production activity/signing use, not
local-only I05.

### G0-03 — High: the accepted product/test floor lacks native behavior evidence

**Trigger:** all real activity, Keychain, and Argon2 evidence was collected on
one Apple Silicon macOS 26.3 host. The repository declares a `macos-15` CI job,
but no CI job has run for the Phase 0 checkpoint and CI cannot replace the
interactive lock, user-switch, Screen Sharing, or Keychain matrix.

**Impact:** claiming macOS 15 support now would overstate compatibility and KDF
performance at the minimum floor.

**Fix:** use Apple Silicon macOS 15.0 as the product/test floor, set
the Tauri minimum system version before packaging, and make I08 replay the
native matrix on updated macOS 15 and current macOS. A failed floor raises the
minimum. I15 owns the final signed-package compatibility claim.

### G0-04 — Resolved: ADR 0002 created a planning circularity

**Trigger:** the original ADR required G0 to decide production signing,
container, migration, UX, supported-floor KDF performance, and independent
review before accepting the primitives that I05 needs. Several of those choices
belong to I05-I15, while G1 itself depends on I05-I14.

**Impact:** literal enforcement would either block I05 indefinitely or invite a
false claim that release work and independent review were complete.

**Resolution:** ADR 0002 now covers only primitives and wrapper semantics. ADR
0004 owns macOS Keychain/identity continuity, ADR 0005 owns container and
migration responsibility, and ADR 0006 owns protocol direction. I13-I14 own
recovery UX, I15 owns production signing, and G1 owns independent release
review. No acceptance criterion was weakened.

### G0-05 — Medium: I03 has no durable executable brief file

**Trigger:** neither repository contains an I03 iteration brief. The exact
scope survives in the initiating task, the development plan, the server result
ledger, the accepted server ADR, implementation, migration, and tests.

**Impact:** future reviewers cannot reconstruct the original pre-implementation
acceptance checklist from Git alone.

**Fix:** treat the server result ledger and ADR as the durable accepted scope
for this completed prototype and require every future iteration to add its brief
before source changes. Do not invent a retroactive brief and present it as the
original. This traceability gap does not invalidate the exact PostgreSQL
evidence inspected here.

### G0-06 — Release caveat: stripping is not verified

**Trigger:** `src-tauri/Cargo.toml:57-61` requires release stripping, and
`npm run desktop:build` exits successfully, but the pinned Rust toolchain's
`rust-objcopy` cannot load `libLLVM.dylib`, so debug stripping is skipped with a
warning.

**Impact:** the unsigned development executable is valid build evidence but not
proof of final artifact stripping, size, symbols, signing, or notarization.

**Fix:** I15 must repair the release toolchain and verify the signed packaged
artifact. The warning does not block local I05 development.

## Activity decision

G0 accepts these macOS semantics:

1. startup, wake, switch-in, unlock, or one input epoch never creates activity;
2. the first gate-accessible sample after uncertainty establishes fresh HID and
   Combined baselines;
3. a later HID-class epoch arms a candidate and a distinct later HID-class
   epoch confirms it only after the intervening successful gate read;
4. Combined-only input clears the pending confirmation;
5. post-unlock, 30-minute idle recovery, four-hour continuous refresh,
   two-minute confirmation, and 30-minute cooldown use monotonic time;
6. lock, sleep, switch-out, failed/malformed gate, invalid/stale sample,
   initialization failure, and shutdown fail closed; and
7. authenticated Screen Sharing that advances Quartz HID state is valid
   activity, but it is described as `hid_class`, never local physical presence.

M10 fast-user-switch and M13 manual wall-clock changes remain explicit Phase 0
waivers. I08 owns a real fast-user-switch run on the minimum floor. Automated
monotonic tests remain the primary wall-clock-independence evidence.

## Cryptography and secret boundary decision

G0 accepts for I05 implementation:

- OS-CSPRNG 256-bit VDKs and per-device 256-bit SRS values;
- Argon2id v0x13 master KEKs with explicit bounded parameters;
- HKDF-SHA-256 recovery KEKs with versioned vault/device context;
- AES-256-GCM VDK wrappers with 96-bit random nonces, 128-bit tags, and
  purpose-specific 45-byte AAD;
- 128-bit CSPRNG ERC entropy with versioned Bech32m transport;
- Ed25519 device signing with only the 32-byte seed treated as private;
- fixed non-sensitive errors, rejected unknown versions, and bounds checked
  before expensive work; and
- the exact dependency pins recorded in `Cargo.toml`, `Cargo.lock`, and
  `docs/DEPENDENCIES.md`.

The profile using 262,144 KiB, time cost 2, and parallelism 1 is a provisional
Apple Silicon development recommendation. I05 persists parameters explicitly
and must not hard-code it as an unversioned universal default. The JSON fixture
is test interchange only.

No external cryptographic audit, side-channel review, memory-lock guarantee,
crash-dump protection, final container, production signing identity, or final
password/ERC UX is claimed.

## Server transaction decision

The I03 implementation matches the product invariant and is accepted:

- one PostgreSQL `SELECT ... FOR UPDATE` row lock serializes a policy;
- a compare-and-set update on ID, state, and version prevents stale mutation;
- server receipt time recomputes heartbeat deadlines;
- the state mutation and structural Outbox event commit in one transaction;
- stable logical identifiers plus a unique database key make repeated mutations
  idempotent;
- one scheduler invocation advances at most one state;
- lock acquisition/commit order decides heartbeat versus release, and
  `RELEASED` is not reversed; and
- outage recovery clears warning proof and requires a new proven warning plus a
  complete grace interval.

A committed Outbox intent is not delivery proof. I11/I12 must authenticate and
persist the eventual warning/delivery evidence without weakening this rule.
I03 exposes no public endpoint, recovery material, or notification provider.

## Public protocol direction

ADR 0006 makes the public client repository the contract source of truth.
I09 must publish machine-readable schemas, stable errors, limits, explicit
protocol and signature-format versions, domain separation, canonicalization,
and shared synthetic fixtures before either side implements public endpoints.
The private server consumes a pinned release or exact fixture digest. Unknown or
security-changing versions fail closed. I03 database models do not become wire
schemas.

## Deferred decisions and owners

| Decision or evidence                                                                                                | Owner                    | Blocks                                      |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------ | ------------------------------------------- |
| Exact local vault header, SQLite schema, nonce allocation, and migrations                                           | I05 / ADR 0005           | I05 persistence implementation              |
| Bounded attachment limit and any later streaming format                                                             | I06                      | Attachment production use                   |
| Authenticated export/import package and restore compatibility                                                       | I07 / ADR 0005           | I07                                         |
| Production macOS activity agent, sentinel metadata enforcement, floor/current native matrices, and KDF floor replay | I08                      | Production activity and macOS support claim |
| Exact public schema/canonical encoding and device-key metadata enforcement                                          | I09 / ADRs 0004 and 0006 | Device binding and public API               |
| Signed heartbeat replay, sequence, revocation, and aggregation                                                      | I10                      | Heartbeat service                           |
| Warning proof source, Outbox dispatch, scheduler integration, and delivery attempts                                 | I11-I12                  | Notifications and release workflow          |
| Password/ERC entry, display, print/export, recovery, and rotation UX                                                | I13-I14                  | Recovery release                            |
| Independent crypto/dependency/native-storage review, fuzzing, and penetration test                                  | G1                       | Production release                          |
| Production bundle ID, signing/notarization, entitlements, update continuity, stripping, and packaging               | I15                      | Production release                          |
| Windows matrices, input provenance, Credential Manager race, floor, signing, lifecycle, and packaging               | I04 / GW                 | Any Windows production work or claim        |

## Source-control checkpoint record

The user explicitly approved the following local-only actions on 2026-09-21.
No repository was pushed.

### Client checkpoint

1. The non-ignored file list and fresh verification results were unchanged.
2. Root commit `54a213c5e17f5e1e3eae183f17f1f2370aa7a61d` on `main` contains the
   complete reviewed Phase 0 and proposed G0 record, with no ignored build
   output, traces, credentials, or generated local artifacts.
3. Its subject is `chore: checkpoint macOS Phase 0 gate baseline`.
4. This follow-up acceptance record changes only the approved documentation.

Reviewed client baseline: `54a213c5e17f5e1e3eae183f17f1f2370aa7a61d`.
Excluding this review file to avoid a self-referential hash, the pre-checkpoint
non-ignored snapshot contained 82 files with SHA-256 manifest digest
`fb7484fd6402d216b209ddc0e1d321f2d94b6b5479210fcc9d89d57cf02d342b`.

### Server checkpoint and integration

1. The detached worktree was reconfirmed at base
   `d9dd7cb7e03e6b869d1068e24703d53a817b4b42` and the authoritative `dev`
   checkout was clean at the same commit.
2. Server ADR 0001 records G0 acceptance.
3. Branch `codex/i03-concurrency-checkpoint` was created in the isolated
   worktree.
4. Exactly the ten reviewed I03/startup-fix/documentation files were committed
   as `9873e418909d52885ee4b4c61ae3a6d16f5beff6` with subject
   `feat: checkpoint account policy concurrency prototype`.
5. The authoritative `dev` branch was clean and unchanged, then fast-forwarded
   to that exact commit without rebase or conflict resolution.
6. `alembic current`, `alembic check`, focused and full PostgreSQL tests,
   focused Black/isort, and critical Flake8 passed against the authoritative
   integrated checkout.

Server reference: base
`d9dd7cb7e03e6b869d1068e24703d53a817b4b42`; I03 patch manifest digest
before approval-record editing
`a44be4efc0cbac8562276e4b415288a9816d78893c48f828b14c248e0f9b9883`.
The final ten-file patch, including accepted server ADR metadata, had digest
`3175c204cf1e7d641c15ec098862c1a97daa757f6ad7c915493cadc6cd8ba054`.
Integrated I03 commit: `9873e418909d52885ee4b4c61ae3a6d16f5beff6`.

## Verification performed for G0

Client host: Apple Silicon macOS 26.3.

- Pinned Node 24.21.0, npm 11.19.0, Rust/Cargo 1.98.1.
- `npm run check`: passed Prettier, ESLint, strict TypeScript, 7 frontend tests,
  production frontend build and remote-asset scan, Rustfmt, Clippy with warnings
  denied, 54 Rust tests, and all-target/all-feature Cargo check.
- `npm run desktop:build`: exited zero and produced the unsigned host executable;
  the known nonfatal `rust-objcopy`/`libLLVM.dylib` warning remained.

Server verification used the already healthy Docker Compose environment and
real PostgreSQL 16:

- focused I03 PostgreSQL suite: 12 passed with two existing deprecation warnings;
- complete backend suite: 35 passed with the same two warnings;
- `alembic current`: `3f9e0e028cab (head)`;
- `alembic check`: no new upgrade operations;
- focused Black: 7 files unchanged;
- focused Black-compatible isort: passed; and
- repository critical Flake8 `E9,F63,F7,F82`: passed.

After server integration, the same checks passed from one-off containers
mounted to the authoritative checkout at
`9873e418909d52885ee4b4c61ae3a6d16f5beff6`. The first one-off attempt used the
authoritative checkout's different ignored `.env`, recreated PostgreSQL and
Redis, and failed authentication before Alembic ran. No migration or schema
operation executed. The original worktree-configured stack was restored and is
healthy; subsequent authoritative checks explicitly reused its matching local
environment without exposing credentials.

The destructive migration downgrade was requested but not authorized because it
drops the prototype tables and their data. It was not bypassed. The accepted I03
evidence retains the prior real-PostgreSQL downgrade/upgrade result; G0 freshly
verified the current head and schema drift instead.

No external audit, penetration test, production signing, notarization, final
container, recovery UX, Windows behavior, or deployment was performed.

## Acceptance-criterion status

| G0 criterion                                                | Status                        | Reason                                                                                        |
| ----------------------------------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------- |
| I01-I03 evidence remains accepted                           | Pass                          | Exact artifacts and implementations inspected; fresh deterministic and PostgreSQL suites pass |
| I04 isolated; GW incomplete                                 | Pass                          | No Windows row is marked Pass; ADR 0003 remains Proposed                                      |
| No unresolved risk blocks local-only I05                    | Pass                          | Native production gaps are assigned to I08/I09/I15 and are outside I05                        |
| Every I05 decision approved or assigned without circularity | Pass                          | ADRs 0002 and 0004-0006 split the ownership                                                   |
| No premature production claims                              | Pass                          | Signing, container, UX, audit, and release remain explicit deferrals                          |
| Recoverable exact baselines                                 | Pass                          | Exact client and integrated server checkpoint commits are recorded                            |
| Relevant checks rerun                                       | Pass with recorded limitation | Client suite/build and live PostgreSQL tests pass; destructive downgrade not rerun            |
| Design, ADRs, implementation, and plan agree                | Pass                          | Documents and server ADR record the accepted G0 decisions                                     |
| Explicit user approval                                      | Pass                          | User approved the complete six-item digest on 2026-09-21                                      |

## Approved digest

The user explicitly approved this digest on 2026-09-21:

1. Revised client ADR 0001, revised ADR 0002, and new ADRs 0004-0006 are
   Accepted.
2. Server ADR 0001 is Accepted and records this G0 approval.
3. Windows ADR 0003 remains Proposed, I04 remains In Progress, and GW remains
   Pending with every real-Windows criterion unchanged.
4. Apple Silicon macOS 15.0 is the initial product/test target, subject to I08
   floor/current native validation before any support claim.
5. The exact local client checkpoint and server checkpoint/integration commits
   described above were created without pushing.
6. Both commit IDs are recorded, checks remain green, G0 is Accepted, and I05 is
   the next eligible iteration.

I05 is now authorized only to propose and implement the versioned local vault
header/schema/migrations, controlled SQLite repository, VDK lifecycle,
master-password unlock, recovery-wrapper persistence, and encrypted records,
with the required corruption, wrong-credential, unknown-version, nonce,
rollback, interruption, and plaintext-leak tests. It is not authorized to start
I08 activity productionization, I09 protocol/device binding, heartbeat,
notifications, recovery claims, updater, telemetry, production signing,
Windows work, publishing, or deployment.

G0 is **Accepted**. I05 is authorized to begin only within the scope above and
must first approve the exact ADR 0005 schema/container and migration proposal.
