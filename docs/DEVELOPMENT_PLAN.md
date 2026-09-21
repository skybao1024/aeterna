# Aeterna Development Plan

> Planning baseline: 2026-09-20  
> Product source of truth: [`DESIGN.md`](./DESIGN.md)  
> Repositories: public desktop client (`aeterna`) and private hosted control plane (`aeterna-control-plane`)

## 1. Purpose

This plan turns the product design into a sequence of small, independently
verifiable development iterations. It is intentionally separate from
`AGENTS.md`: this document may change as evidence is collected, while
`AGENTS.md` contains durable engineering rules.

The project uses one active implementation iteration at a time. A later
iteration may be prepared, but it must not start source changes until its
declared dependencies are accepted. Each iteration should normally run in a
fresh Codex task so that its scope, evidence, and completion boundary remain
clear.

## 2. Repository ownership

| Concern                             | Authoritative repository | Notes                                                             |
| ----------------------------------- | ------------------------ | ----------------------------------------------------------------- |
| Product and trust-boundary design   | `aeterna`                | `docs/DESIGN.md` remains authoritative.                           |
| Desktop application and local vault | `aeterna`                | Intended to be open source.                                       |
| Public device/recovery protocol     | `aeterna`                | Public documentation must make client network behavior auditable. |
| Hosted service implementation       | `aeterna-control-plane`  | Private repository; must never receive vault content.             |
| Backoffice operations UI            | `aeterna-control-plane`  | Added only when a concrete operational workflow requires it.      |

Cross-repository changes are contract changes. Define or update the public
protocol first, then implement both sides against the same versioned fixtures.
Do not silently let either repository become the protocol source of truth.

## 3. Iteration rules

Every implementation task must follow this lifecycle:

1. Read the relevant sections of `DESIGN.md`, the repository `AGENTS.md`, this
   plan, and the iteration brief.
2. Confirm that dependencies and required environments are available.
3. Record any product, security, persistence, or protocol decision in an ADR
   before relying on it as a stable contract.
4. Implement only the iteration scope and add tests for the stated failure
   modes.
5. Run repository-native formatting, linting, type checks, tests, and builds.
6. Compare the changed files and observed behavior with every acceptance
   criterion.
7. Update this plan with evidence and remaining risks. Do not mark an iteration
   complete when a required platform or integration check was skipped.

An implementation session must not weaken an acceptance criterion, delete a
failing test, or broaden a security boundary to make the iteration pass. A
failed risk prototype is valid evidence and must result in a design or ADR
review, not a disguised production implementation.

## 4. Milestones and iterations

Status values are `Pending`, `In Progress`, `Blocked`, and `Accepted`.

| ID  | Iteration                                            | Repository | Depends on                                          | Exit evidence                                                                        | Status  |
| --- | ---------------------------------------------------- | ---------- | --------------------------------------------------- | ------------------------------------------------------------------------------------ | ------- |
| I00 | Desktop engineering foundation                       | Client     | None                                                | Reproducible Tauri/React/Rust build and test baseline                                | Accepted |
| I01 | macOS activity-detection risk prototype              | Client     | I00                                                 | Event traces prove accepted and rejected activity cases without content capture      | Accepted    |
| I02 | Cryptography and secure-storage risk prototype       | Client     | I00                                                 | Versioned test vectors, KDF benchmark, dual unwrap paths, and Keychain evidence      | Accepted |
| I03 | Control-plane concurrency risk prototype             | Server     | Current cleanup baseline reviewed; Docker available | Deterministic state-machine and race tests pass in PostgreSQL                        | Accepted |
| I04 | Windows activity and secure-storage risk prototype   | Client     | I00; Windows test host                              | Windows session/input/Credential Manager matrix passes                               | In Progress |
| G0  | macOS Phase 0 architecture and security gate         | Both       | I01-I03; approved I04 implementation checkpoint     | macOS-scope ADRs approved; deferred decisions assigned to explicit later gates        | Accepted |
| I05 | Versioned vault format and encrypted storage core    | Client     | G0                                                  | Local encrypted records survive restart and tampering is rejected                    | Pending |
| I06 | Vault item and bounded-attachment MVP                | Client     | I05                                                 | User can create, edit, read, and delete encrypted local content                      | Pending |
| I07 | Atomic encrypted export and import                   | Client     | I05-I06                                             | Interruption and tampering tests pass; restored vault matches source                 | Pending |
| I08 | macOS lifecycle, activity agent, and hardening       | Client     | G0, I01, I05-I07                                    | macOS autostart, tray health, CSP, capabilities, and i18n acceptance pass            | Pending |
| GW  | Windows platform qualification gate                 | Client     | I04; application core available for Windows testing | Real-Windows matrices pass; ADR 0003 approved or redesigned; no unqualified release  | Pending |
| I09 | Public protocol v1 and account/device binding        | Both       | G0                                                  | Versioned schemas and fixtures drive client and server contract tests                | Pending |
| I10 | Signed heartbeat and multi-device aggregation        | Both       | I09                                                 | Replay, revocation, stale-device, and concurrent-device tests pass                   | Pending |
| I11 | Warning/grace state machine and transactional outbox | Server     | I03, I10                                            | Time, outage, concurrency, idempotency, and rollback tests pass                      | Pending |
| I12 | Contacts, consent, and email notification delivery   | Server     | I11                                                 | Verification, opt-out, retry, redaction, and provider-failure tests pass             | Pending |
| I13 | Delayed recovery material and claim protocol         | Both       | I02, I09, I11-I12; KMS design approved              | Pre-release denial and post-release recovery tests pass end to end                   | Pending |
| I14 | Owner recovery, ERC rotation, and post-release rekey | Both       | I13                                                 | Cooldown, cancellation, rotation, and re-encryption tests pass                       | Pending |
| G1  | macOS v1 security and recovery-readiness gate        | Both       | I05-I14                                             | Independent crypto review, macOS penetration test, and recovery drill pass           | Pending |
| I15 | macOS release operations and resilience              | Both       | G1                                                  | Signed artifacts, update path, backup restore, shutdown migration, and runbooks pass | Pending |
| I16 | Optional commercial extensions                       | Server     | Stable v1 core                                      | Billing and SMS cannot compromise base email or recovery guarantees                  | Pending |

## 5. Detailed iteration scope

### I00 — Desktop engineering foundation

Bootstrap the public desktop repository without implementing activity,
cryptography, recovery, or vault behavior. Establish a pinned Rust toolchain,
Tauri v2, React, strict TypeScript, Tailwind/Shadcn foundations, English-default
i18n with a Simplified Chinese resource, least-privilege Tauri configuration,
test runners, and repeatable local verification commands. Use a development-only
application identifier until release identity and signing are decided.

The executable brief is [`iterations/I00-desktop-foundation.md`](./iterations/I00-desktop-foundation.md).

### I01 — macOS activity-detection risk prototype

Create a narrow Rust platform interface and a macOS implementation that gates
activity with a noninteractive Data Protection Keychain sentinel, observes
sleep/wake and session transitions, and samples both HID and Combined elapsed
input ages without capturing content. Require two distinct HID epochs separated
by a successful gate check, and suppress Combined-only remote or synthetic input
by default. Use a local-only diagnostic harness with redacted, structured
events. Validate startup, locked background work, unlock with and without
subsequent input, idle recovery, continuous use, fast user switching, and remote
desktop behavior on supported macOS versions.

This prototype must not send a network heartbeat. Its output is evidence for an
activity ADR and the production activity-agent contract.

The executable brief is
[`iterations/I01-macos-activity-prototype.md`](./iterations/I01-macos-activity-prototype.md).

### I02 — Cryptography and secure-storage risk prototype

Evaluate maintained Rust crates and record maintenance, license, audit status,
serialization behavior, and alternatives. Prototype VDK generation, Argon2id
master wrapping, ERC generation and checksum, HKDF recovery derivation,
AES-256-GCM wrapping, versioned AAD, zeroization, Ed25519 device signing, and
macOS Keychain storage. Produce deterministic non-secret fixtures where
possible, negative tamper tests, and target-hardware Argon2 benchmark results.

G0 may accept the exact primitive pins and bounded wrapper semantics as an
implementation basis for I05 without claiming an independent audit. The local
container and migrations remain an I05 decision, the export package remains an
I07 decision, and G1 owns the independent review and production release freeze.

The executable brief is
[`iterations/I02-crypto-secure-storage-prototype.md`](./iterations/I02-crypto-secure-storage-prototype.md).

### I03 — Control-plane concurrency risk prototype

Work in the private service repository. Model the account policy states and
server-time transitions independently of notification providers. Use real
PostgreSQL transactions to test heartbeat-versus-release races,
compare-and-set transitions, at-least-once scheduler execution, outage recovery,
and outbox idempotency. Keep the prototype behind internal modules and tests;
do not expose recovery material or claim endpoints.

Before this iteration starts, review and checkpoint the existing cleanup diff
so product code is not mixed with an ambiguous framework-cleanup baseline.
The accepted implementation evidence must remain in a recoverable server
commit; a detached uncommitted worktree is not an integration baseline.

### I04 — Windows activity and secure-storage risk prototype

Implement the same platform contracts behind Windows-only adapters. The author
has deferred real-Windows validation until the complete application is
available; I04 remains In Progress until a supported interactive Windows host
tests login, lock/unlock, sleep/wake, idle recovery, fast user switching, Remote
Desktop, autostart, and Credential Manager behavior. Differences from macOS
must remain behind the platform interface and be captured in the activity and
secure-storage ADRs. macOS regression evidence does not accept Windows behavior.

### G0 — macOS Phase 0 architecture and security gate

No production vault or macOS release implementation starts before this gate.
Review the I01-I03 evidence and the I04 shared-interface/macOS-regression
checkpoint, then approve only the decisions required for the macOS-first path:

- the supported macOS version floor and observed limitations;
- the valid-activity algorithm and privacy boundary;
- device-key storage and signing protocol;
- cryptographic crates, parameters, formats, and versioning strategy;
- state-machine transaction and outage semantics;
- the public protocol/versioning approach and verification commands.

G0 accepts Apple Silicon macOS 15.0 as the initial product/test target. Real
native evidence currently covers macOS 26.3, so I08 must run the activity,
lifecycle, secure-storage, fast-user-switch, and KDF matrix on the floor and
current macOS before a support claim. G0 authorizes local-only I05 work because
I05 neither productionizes the activity agent nor binds a network device
identity.

G0 splits the former ADR 0002 scope into: cryptographic primitives and wrappers
in ADR 0002; macOS Keychain/signing-identity continuity in ADR 0004; vault
format and migration ownership in ADR 0005; and public protocol ownership and
versioning direction in ADR 0006. Production signing belongs to I15, recovery
UX to I13-I14, and independent review to G1.

Windows ADR 0003 remains Proposed and I04 remains In Progress. G0 must not turn
missing Windows evidence into a waiver, Pass, or support claim. If a macOS-scope
prototype fails a design requirement, update `DESIGN.md` and the relevant ADR
with an explicit trade-off before continuing.

The executable brief is
[`iterations/G0-macos-architecture-security-gate.md`](./iterations/G0-macos-architecture-security-gate.md).

### I05 — Versioned vault format and encrypted storage core

Implement migrations, a controlled SQLite repository, VDK lifecycle, master
password unlock, recovery wrapper persistence, and encrypted record storage.
SQLite, WAL, journals, and temporary files must only contain ciphertext and
non-sensitive structural metadata. Cover wrong credentials, corrupt headers,
unknown versions, nonce uniqueness, rollback, and interrupted writes.

I05 may start only after the user approves the G0 digest, ADRs 0001-0002 and
0004-0006 receive their approved G0 dispositions, the client Phase 0 tree has a
recoverable commit, and the exact I03 commit is integrated into the clean
authoritative server `dev` branch. Before persistence code changes, I05 must
approve the exact ADR 0005 schema/container and migration proposal. I05 may use
the I02 Apple Silicon KDF profile only as an explicitly versioned provisional
development profile; it must not advertise it as the release default.

I05 remains local-only. It must not implement the production activity agent,
device registration, signed heartbeat/public protocol, notification, recovery
claim, updater, telemetry, production signing, or Windows behavior.

### I06 — Vault item and bounded-attachment MVP

Add the smallest useful desktop workflow for encrypted notes, instructions,
and bounded attachments. Titles, categories, contact explanations, and content
remain inside encrypted payloads. Keep attachment size within the limit approved
at G0; streaming encryption is out of scope until separately reviewed.

### I07 — Atomic encrypted export and import

Define and implement an authenticated, versioned export package. Export through
a temporary file and atomic completion marker; import into a staging location,
verify the complete manifest and ciphertext, then commit. Test interruption,
truncation, duplication, tampering, unsupported versions, and restoration from
two independent copies.

### I08 — macOS lifecycle, activity agent, and hardening

Turn the accepted macOS prototypes into production components. Add autostart,
bounded heartbeat scheduling inputs, last-success health state, tray warning,
local notification, strict CSP, window-specific Tauri capabilities, and
English/Simplified Chinese user flows. The WebView must not receive raw input
events, database access, keys, or unrestricted filesystem access. Windows
production lifecycle behavior remains out of scope until GW passes.

### GW — Windows platform qualification gate

GW is outside the macOS-first critical path. It may run only when a supported
interactive Windows host and enough of the application core are available for
truthful end-to-end platform testing. Complete I04's unchanged real-Windows
activity, Credential Manager, autostart, local/remote-session, lifecycle,
build, cleanup, and negative-input matrices. Resolve synthetic-input provenance
and the Credential Manager create-only race explicitly. Approve or replace ADR
0003 before any Windows production hardening, packaging, support statement, or
release. macOS evidence, cross-compilation, mocks, CI compilation, and user
waivers cannot substitute for the required Windows evidence.

### I09 — Public protocol v1 and account/device binding

Publish machine-readable request/response schemas, signature canonicalization,
error codes, size limits, protocol versioning, and synthetic fixtures in the
public client repository. Implement verified email onboarding and delayed or
existing-device confirmation for new devices in the private server. The client
and server must consume the same fixtures; device ID alone is never an
authenticator.

### I10 — Signed heartbeat and multi-device aggregation

Implement signed heartbeats with monotonic sequences, server receipt time,
cooldown, revocation, lost-device state, dormant-device re-verification, and
account-level maximum aggregation. Test duplicate, reordered, modified,
concurrent, revoked, and stale-device requests. The payload must not contain an
activity type, application, URL, input value, or client-computed deadline.

### I11 — Warning/grace state machine and transactional outbox

Implement `ACTIVE`, `PRE_WARNING`, `GRACE_PERIOD`, `RELEASED`, `DISABLED`, and
`DELETED` transitions using transactional compare-and-set logic. State changes
and outbox writes share one transaction. Repeated Celery tasks and provider
attempts use stable idempotency keys. Service recovery must restart a complete
minimum grace period when prior owner warning cannot be proven.

### I12 — Contacts, consent, and email notification delivery

Add encrypted contact fields and constrained plaintext notification templates,
contact consent/verification, test delivery, opt-out, bounce visibility,
provider adapters, retry policy, and redacted delivery audit. Base email and
configured recovery notification must not depend on a paid entitlement.

### I13 — Delayed recovery material and claim protocol

After KMS and crypto review, add per-device SRS envelope encryption, release
authorization, short-lived claim links, contact OTP, scoped claim tokens,
single-purpose API operations, retrieval audit, and owner/other-contact alerts.
Prove that ERC without SRS and SRS without ERC plus a local vault are useless,
and that every pre-release retrieval path is rejected.

### I14 — Owner recovery, ERC rotation, and post-release rekey

Implement bound-device owner recovery with secondary authentication, security
notifications, cooldown, cancellation, and device-scoped release. Add complete
multi-device ERC rotation status and force a new VDK plus local re-encryption
after release or claim. Test interrupted rotation and partial-device states.

### G1 — macOS v1 security and recovery-readiness gate

Require independent cryptographic review, desktop penetration testing, dependency
and license review, fuzzing of containers/import/IPC, clean-device installation,
two-copy restoration, control-plane backup restoration, and a full release/claim
drill. Findings affecting data loss or premature release block v1.

### I15 — Release operations and resilience

Add signed installers, signed updates and configuration, production key-role
separation, monitoring without sensitive payloads, disaster recovery, retention
jobs, operator runbooks, and the service-shutdown migration that converts delayed
recovery into an owner-authorized offline recovery path.

### I16 — Optional commercial extensions

Only after the base system is stable, add SMS and billing behind isolated
adapters and verified webhooks. Expiration, quota exhaustion, or provider failure
must never silently disable base email warning or already configured recovery.

## 6. Verification ownership

The implementing task performs focused and repository-wide checks, but a
security-sensitive iteration should receive a separate review before acceptance.
For I01-I04, I10-I15, acceptance evidence must include observed failure cases,
not only successful compilation. G0 and G1 require human approval because they
freeze or validate security assumptions that automated tests cannot certify.

## 7. Known prerequisites and blockers

- A real Windows test environment is required for final I04 acceptance and GW.
  The author has deferred that matrix until enough of the complete application
  is available. I04 and GW are not prerequisites for the macOS G0/I05 path, but
  no Windows production hardening, packaging, support claim, or release may
  begin before they pass. A macOS build, cross-build, CI compilation, mock, or
  waiver is not Windows acceptance evidence.
- Docker must be running before server tests, migrations, or service diagnostics.
- I03 is preserved on `codex/i03-concurrency-checkpoint` and integrated by
  fast-forward into authoritative server `dev` at
  `9873e418909d52885ee4b4c61ae3a6d16f5beff6`.
- The complete reviewed client Phase 0 baseline is preserved at root commit
  `54a213c5e17f5e1e3eae183f17f1f2370aa7a61d`.
- The accepted Apple Silicon macOS 15.0 floor has build-runner coverage only in
  configuration, not executed native behavior evidence. I08 owns the
  minimum-floor and current-release matrices before any support claim.
- Production provider, region, retention, quota, and final default timing choices
  remain release parameters. They do not block Phase 0.
- KMS/recovery implementation must wait for crypto and KMS design approval.
- Installer signing identities and final bundle identifiers are release decisions;
  I00 may use explicitly development-only values.

## 8. Progress log

Add one dated line after each accepted or blocked iteration. Include the task
link or identifier, verification evidence, ADRs created or changed, and the next
eligible iteration. Do not use this log as a substitute for detailed review
evidence.

- 2026-09-20: Initial ordered plan created from `DESIGN.md` and current repository state. I00 is the next eligible iteration.
- 2026-09-20: I00 accepted in task `01a0be5b-4c6b-7c93-beb8-189457cbd704`. `npm run check` and `npm run desktop:build` passed with pinned Node 24.21.0 and Rust 1.98.1; the macOS native window was observed in English and Simplified Chinese, typed IPC succeeded, and the saved locale survived restart. CI defines unsigned checks for Ubuntu 24.04, macOS 15, and Windows 2025; those remote jobs were not executed from this uncommitted local baseline. No ADR was required. I01 and I02 are now eligible.
- 2026-09-20: I01 blocked in task `01a0be9f-a241-77c3-94fa-54c260f5d874`. Pinned-toolchain `npm run check` passed 7 frontend and 27 Rust tests, `npm run desktop:build` passed, the feature-gated macOS probe ran without sensitive permission prompts, idle process samples were 0.0%-0.7% CPU at a one-second interval, and two normal Quit/restart traces ended with `observer_stopped`. Supported Apple APIs provide elapsed input age and switch/power notifications but no verified lock/unlock signal, so the mandatory matrix cannot distinguish login-screen credential input from later in-session input. ADR 0001 remains Proposed; recovery requires a documented public signal or an explicit G0 product-rule redesign. I02 remains eligible but was not started.
- 2026-09-21: I02 accepted in task `01a0beb2-901e-7662-9a37-65e3c1e607ae`. The dependency and versioned-format proposal was approved before implementation, and the development App ID/profile was separately approved after unsigned and entitlement-only failures. Published vectors, the exact dual-wrapper fixture, negative behavior, ERC, signing, fake storage, redaction, and zeroization-support tests passed. The release Apple Silicon grid recommends the G0-only 256 MiB/time-2/parallelism-1 profile (p50 279.970 ms, p95 293.894 ms, peak RSS 277,037,056 bytes). With the Personal Team profile, K01-K10 passed create, restart/sign, wrong identity, replace, delete/not-found, locked denial, unlock recovery with the same key, debug-to-signed-release continuity, metadata, and cleanup; the ad-hoc release probe failed closed with `secure_storage_missing_entitlement` and no fallback. A repeated-locked-result harness defect found during the first lock cycle was corrected before the complete rerun. Final pinned-toolchain `npm run check` passed 7 frontend and 48 Rust tests, and `npm run desktop:build` produced `aeterna-desktop`; the known non-fatal `rust-objcopy`/`libLLVM.dylib` warning remained. No test Keychain item remains. ADR 0002 remains Proposed pending G0 and independent security review, including production signing and continuity. I03 was not started.
- 2026-09-21: I01 accepted after the approved Keychain-gated, dual-Quartz-source revision passed startup, lock, login-screen, unlock, sleep/wake, idle, continuous-use, cooldown, lifecycle, and real Screen Sharing scenarios on the signed target host. M10 and M13 received explicit user waivers. M14 confirmed that Screen Sharing-only input advances both HID-system and Combined-session ages and enters two-stage confirmation; the user explicitly clarified that authenticated remote login counts as activity, so the boundary is HID-class interaction rather than local physical presence. Diagnostics were renamed to `hid_class` and v3, the signed v3 startup established only a fresh baseline, final pinned-toolchain `npm run check` passed 7 frontend and 47 Rust tests, and `npm run desktop:build` succeeded with the known non-fatal `rust-objcopy`/`libLLVM.dylib` warning. ADR 0001 remains `Proposed` pending G0 architecture and security review.
- 2026-09-21: I03 started in task `01a0c260-89ad-7a71-8395-d7cd2c12dbeb` from an isolated worktree at the clean committed `aeterna-control-plane` `dev` baseline `d9dd7cb`. The task is limited to the internal PostgreSQL concurrency prototype and its transaction, race, outage-recovery, and transactional-Outbox evidence; later public APIs and recovery or notification features remain out of scope.
- 2026-09-21: I03 accepted in task `01a0c260-89ad-7a71-8395-d7cd2c12dbeb`. Docker Compose started the complete development environment against PostgreSQL 16; Alembic revision `3f9e0e028cab` passed downgrade and upgrade; 12 deterministic PostgreSQL state-machine, race, and Outbox tests and 35 total backend tests passed. Focused Black/isort and repository critical Flake8 checks passed. Server ADR 0001 remains Proposed for G0 human approval. I04 is next eligible only on a real Windows host; G0 remains pending I04 and ADR review.
- 2026-09-21: I04 started in task `01a0c2bc-9883-7d70-9e4b-4a64e5b25e50`. The task must first define the missing executable brief and obtain explicit approval for any Windows native dependencies, then collect activity and Credential Manager evidence on a real interactive Windows host. macOS, mocks, and cross-compilation cannot satisfy the acceptance gate.
- 2026-09-21: The author approved a macOS-first release sequence. G0 now governs only the macOS path and depends on I01-I03 plus the approved I04 implementation checkpoint. I04 remains In Progress with unchanged real-Windows criteria, and GW blocks every Windows production hardening, packaging, support claim, and release. Missing Windows evidence was not converted into a waiver or Pass.
- 2026-09-21: macOS G0 started in task `01a0c30a-8bf6-76a1-b994-9398e5adf229`. The gate reviews and reconciles I01-I03 evidence, the I04 shared-interface checkpoint, ADR scope, protocol ownership, and source-control baseline integrity. It cannot approve Windows behavior or start I05, and it requires a separate explicit user approval digest before acceptance.
- 2026-09-21: G0 review evidence and proposed ADR splits were prepared in task `01a0c30a-8bf6-76a1-b994-9398e5adf229`. Fresh pinned client checks passed 7 frontend and 54 Rust tests and the unsigned desktop build; fresh real-PostgreSQL I03 checks passed 12 focused and 35 total backend tests, Alembic current/check, focused Black/isort, and repository critical Flake8. The destructive migration downgrade was not repeated without separate approval; the accepted I03 run retains its prior downgrade/upgrade evidence. G0 remains In Progress pending explicit digest approval and recoverable client/server checkpoint commits. I04 and GW remain incomplete.
- 2026-09-21: G0 accepted by explicit user approval in task `01a0c30a-8bf6-76a1-b994-9398e5adf229`. Client root checkpoint `54a213c5e17f5e1e3eae183f17f1f2370aa7a61d` preserves the reviewed Phase 0 baseline. Server checkpoint `9873e418909d52885ee4b4c61ae3a6d16f5beff6` is on `codex/i03-concurrency-checkpoint` and was fast-forwarded into clean authoritative `dev`; post-integration Alembic current/check, 12 focused and 35 total PostgreSQL tests, focused Black/isort, and critical Flake8 passed. ADRs 0001, 0002, and 0004-0006 are Accepted; the server ADR is Accepted. Apple Silicon macOS 15.0 is the initial product/test target subject to I08 native qualification. I05 is next eligible. I04 and GW remain incomplete.
