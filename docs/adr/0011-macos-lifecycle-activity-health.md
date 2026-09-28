# ADR 0011: macOS lifecycle, activity agent, and local health boundary

- Status: Accepted
- Date: 2026-09-22
- Owners: Aeterna desktop
- Scope: I08 on macOS 15 and later

This decision was approved as proposed ADR 0010 and renumbered to 0011 on
2026-09-27 to avoid a collision with the v1 email notification ADR. Its decision
and approval scope did not change.

## Approval state

The user approved this ADR and its companion proposal on 2026-09-22. That
approval authorizes the described repository implementation. Native validation
steps that mutate login items, display permission prompts, change signing
state, or disrupt the host still require separate just-in-time approval.

## Context

Aeterna must remain available in the macOS menu bar, survive ordinary window
closure, optionally start at login, and convert the privacy-minimized I01
activity signal into a bounded future-heartbeat candidate. It must also tell the
user when its local activity agent, login item, notifications, or future server
delivery needs attention.

The boundary is security-sensitive:

- an activity observation is not physical-presence proof;
- Keychain availability is a gate, not user authentication;
- I09 and I10 define provisioning and delivery, while I08's native candidate
  source remains unbound until a separate production integration;
- window, vault, transfer, power, user-session, worker, and process lifecycle
  must stop in a defined order;
- login items and notifications are visible operating-system state and must not
  be enabled or prompted silently;
- a stale or replayed candidate could create an incorrect future heartbeat;
- a broad WebView/native bridge would let presentation code cross a trust
  boundary; and
- background status must be available while the encrypted vault is locked
  without retaining a vault key or storing user content.

ADR 0001 defines the macOS activity detector and its privacy limits. ADR 0002
and ADR 0004 define cryptographic/key-storage ownership and identity continuity.
ADR 0007 through ADR 0009 define vault and atomic-file boundaries. This ADR
does not supersede them.

## Decision

### 1. Use one in-process supervised agent

The Rust host will own one idempotent lifecycle coordinator and one in-process
activity worker thread. Native callbacks enqueue only small typed signals into
a capacity-32 nonblocking channel. The worker owns sampling, monotonic policy
time, the single candidate slot, cooldown, and health timers.

The agent will not use a helper process, daemon, shell command, WebView timer,
unbounded channel, callback I/O, or callback policy evaluation. Queue overflow,
disconnect, contradictory events, observer failure, worker panic, or shutdown
will clear policy and candidate state and publish `agent_error`.

Production release builds will use unwind panic semantics so the worker entry
point can contain a panic, clear state, and be joined. Panics remain defects and
will not be used for normal errors. Every Rust native callback will contain an
unwind before returning through Objective-C/C; no Rust panic may cross an FFI
boundary. An uncontained top-level host panic terminates nonzero after
best-effort safe shutdown rather than keeping an unknown process alive.

### 2. Make startup and shutdown transactional

Startup will validate health state, native configuration, Keychain gate,
observers, worker ownership, and fresh HID/Combined/lifecycle baselines before
publishing `ready`. Startup can never emit a candidate. Partial setup rolls
back registrations and joins any created worker.

Shutdown will, in order:

1. reject new mutations and IPC;
2. lock/drop the vault and cancel/join transfers;
3. unregister observers and stop signal intake;
4. stop, clear, and join the agent;
5. atomically persist validated non-sensitive health; and
6. tear down tray/window resources.

The operation is idempotent. Sleep, screen lock, user switch-out, gate failure,
and accepted window close invoke the relevant lock/drop and candidate-clear
portion. Wake/unlock starts new baselines and never restores a vault session or
candidate.

### 3. Keep the activity and delivery boundary private to Rust

The accepted I01 invariants remain in force: one HID/Combined sample, an
intervening successful Keychain read, two distinct HID epochs, Combined-only
invalidation, monotonic windows, and fail-closed ambiguity.

The fixed I08 policy is a 5-second sample, 2-minute post-unlock exclusion,
2-minute confirmation window, 30-minute idle threshold, 30-minute candidate
cooldown, 15-minute candidate lifetime, 4-hour continuous refresh, and 12-hour
hard ceiling for any future configurable refresh.

At most one opaque candidate exists in memory. A candidate is never persisted
and cannot survive lock, sleep, switch-out, gate/agent/channel error, expiry,
shutdown, or restart. A fresh process requires fresh baselines and two new
epochs.

An internal binding port distinguishes `unbound`, `not_configured`, and
`actively_bound`. I08 supplies no active binding. A future I10 worker may take
a fresh candidate only for an I09 active binding. Only an internal call made
after authenticated server acceptance may advance last-success time. There
will be no IPC for samples, candidate creation/take, cooldown reset,
last-success mutation, or server acknowledgement.

### 4. Harden the activity Keychain gate as an exact public item

The activity gate will be a Data Protection Keychain generic-password item
with this exact contract:

- service `aeterna.desktop.activity-gate.v1`;
- account `unlock-availability`;
- public ASCII value `AETERNA-ACTIVITY-GATE-V1`;
- `WhenUnlockedThisDeviceOnly` accessibility;
- synchronizable false; and
- the exact current application's `com.apple.application-identifier` access
  group, derived from the signed process.

Every read will request data plus attributes and require exactly one result.
The exact query fixes class and non-synchronizability; returned attributes
validate service, account, access group, accessibility, length, and value.
macOS can omit class from the returned dictionary and represent the default
false synchronizability inconsistently, so those two properties are enforced
by the query rather than inferred from returned attributes. Missing, duplicate,
malformed, locked,
unavailable, entitlement, or unexpected results fail closed. Runtime activity
code will never repair, update, or delete the item.

Create occurs only after an exact not-found result and is followed by a full
read. A test/maintenance update uses exact `SecItemUpdate` and revalidation.
Test deletion is exact and idempotent. No operation will broaden the query or
touch the separate I02 signing key. I15 owns uninstall cleanup.

### 5. Persist one fixed non-sensitive health record

The host will persist
`<app-local-data>/health/activity-health-v1.bin`, a 96-byte little-endian
versioned record containing only:

- magic/version/flags and zeroed reserved bytes;
- desired start-at-login flag and `en`/`zh-CN` locale;
- generation;
- future authenticated server-acceptance wall time;
- last successfully scheduled stale-notification wall time;
- save wall time; and
- SHA-256 over the first 64 bytes for corruption detection.

It will not contain a candidate, local activity time, attempt, raw activity,
reason/source, identifier, path, URL, message, vault/contact/item data, binding
material, credential, or secret. SHA-256 is not an authenticity claim.

The directory/file modes are `0700`/`0600`. Reads and writes use a retained
directory descriptor, no-follow and ownership/type/mode/link checks, exclusive
same-directory temporary creation, complete write, file sync, atomic rename,
and directory sync. Unknown version/flags/reserved bytes, corruption, symlink,
hard link, special file, parent replacement, bad permissions/owner, partial
data, low disk, or ambiguous time fails closed without silent overwrite.

Recovery is an explicit localized “Reset local health state” action. It deletes
only the validated health entry and does not touch the vault, Keychain,
login-item registration, or notification authorization.

Current-process policy uses monotonic time. Every start imposes a fresh
30-minute monotonic candidate guard, preventing restart cooldown bypass without
persisting local activity time. Persisted wall time never creates a candidate.
A materially future saved time or clock rollback produces `agent_error` until
correction and clean restart. A forward jump cannot invent activity or server
acceptance.

### 6. Use public macOS framework boundaries for tray, login item, and notification

The tray will use Tauri's built-in Rust tray support. Its native menu has only a
coarse localized status, Open Aeterna, Lock Vault, and Quit Aeterna. A manual
launch shows the main window; the documented login-item Apple Event property
keeps it hidden. Reopen/tray-open focuses the existing window. Window close
locks/drops sensitive state and hides the application after the presentation
layer resolves unsaved edits.

Start at login is opt-in through `SMAppService.mainAppService`. Register,
unregister, and opening Login Items settings require distinct visible user
actions. Desired preference and observed native status are separate. Denial,
external disable, approval required, unsuitable signature, or native failure is
shown truthfully and is never silently repaired.

Notification settings are read without prompting. Authorization is requested
only by an explicit action in a visible, focused settings window. The only
planned notification is a generic localized future stale-health message, at
most once per 24 hours while stale and only after active binding plus 24 hours
without authenticated server acceptance. I08 remains unbound/not configured,
so it cannot emit that notification.

No Accessibility, Input Monitoring, Screen Recording, Automation, Full Disk
Access, Contacts, privileged-helper, background-daemon, or new Keychain-sharing
entitlement is added. I08 sets the macOS build floor to 15.0 but leaves final
bundle identity, Team ID, signing, hardened runtime, notarization, packaging,
and uninstall behavior to I15.

### 7. Expose coarse health through a minimal WebView boundary

Health has separate facets:

- service: `unbound`, `not_configured`, `healthy`, `stale`;
- activity: `ready`, `gate_unavailable`, `agent_error`;
- start at login: `enabled`, `disabled`, `drifted`, `unavailable`;
- notifications: `not_requested`, `authorized`, `denied`, `unavailable`.

`stale` requires a future active binding and 24 hours without authenticated
server acceptance. While I08's native agent remains unbound, product copy will
not say that the service or a heartbeat failed.

Only five strict main-window commands are permitted: read status, set the
explicit login-item preference, request notification authorization, select
`en`/`zh-CN`, and explicitly reset invalid health state. Mutations require the
main window to be visible/focused. No generic native, filesystem, Keychain,
notification, URL/settings, shell, SQL, network, activity, or acknowledgement
command will be added.

The production CSP remains self-only with only the minimum Tauri IPC connection
origins and explicit denial of unused active-content surfaces. There is no
runtime remote content, telemetry, or network capability.

### 8. Treat localization, accessibility, energy, and floor evidence as release gates

All WebView/native tray/notification/status/error/confirmation strings use
English and Simplified Chinese resources. Health is textual as well as visual.
The UI must support keyboard-only use, VoiceOver, focus restoration, 200% zoom,
long translations, high contrast, and reduced motion.

A release-shaped hidden-window idle run must average at most 0.5% CPU, at most
30 activity-agent wakeups per minute, and at most 5 MiB RSS growth after
warmup. The accepted Argon2id profile is replayed under representative bounded
pressure without parameter changes.

The owner approved the 30/minute wakeup limit on 2026-09-28 after Instruments
measured approximately 27/minute on the named agent thread. A five-second
sample timer wakes the worker, and the required synchronous Keychain gate read
adds a securityd reply wake. The alternative of reading the gate less often
would delay gate-failure detection and was not chosen. The five-second sample,
exact gate validation on every read, and policy invariants remain unchanged.

Acceptance requires native evidence on the current host and on a separate,
updated Apple Silicon macOS 15 machine. Missing floor evidence leaves I08 in
progress. Every native step that changes system state or may prompt requires a
fresh just-in-time approval and cleanup proof.

## Dependency consequences

If accepted, implementation may:

- add Tauri's built-in `tray-icon` feature at the existing exact version;
- add exact macOS-only `objc2-service-management` 0.3.2 and direct
  `objc2-user-notifications` 0.3.2 dependencies with minimal features;
- add only the needed Apple Event features to the existing
  `objc2-foundation` dependency;
- reuse the existing exact `security-framework-sys`, `libc`, and `sha2`
  dependencies;
- add a narrow documented `SecTask` FFI declaration;
- change the release panic strategy from abort to unwind;
- set Tauri's macOS minimum system version to 15.0; and
- add only the five exact commands to the existing main capability.

No Tauri autostart, notification, or single-instance plugin, npm package,
network client, updater, remote script, helper executable, LaunchAgent writer,
or new privacy entitlement is accepted by this ADR. The companion proposal's
feature-graph, license, lockfile, and supply-chain checks are mandatory. An
unexpected transitive capability returns the decision to review.

## Consequences

### Positive

- Lifecycle, policy, health, and privileged native actions have explicit owners
  and failure semantics.
- The WebView cannot manufacture activity, server acceptance, arbitrary
  notifications, or login-item identifiers.
- Candidate memory and persisted health are bounded and privacy-minimized.
- Exact gate metadata closes the G0/I01 wrong-item and access-group gap.
- Public macOS APIs expose user control and truthful approval/drift state.
- Transactional stop ordering reduces stale candidates, lingering plaintext,
  transfer races, and orphaned observers/threads.
- The floor/energy/KDF gates prevent a newer development host from silently
  waiving macOS 15, resource, or cryptographic performance requirements.

### Negative

- Release unwind support increases binary metadata and requires careful panic
  boundary tests.
- One new direct ServiceManagement binding expands the Rust supply chain; the
  notification binding becomes a direct dependency even though it is already
  transitive.
- A separate fixed health format adds migration/recovery ownership.
- Close-to-tray and native menu localization add lifecycle/UI coordination.
- Accurate login-item and notification behavior cannot be fully tested in an
  unsigned unit-test process, so controlled signed native evidence is required.
- Wall time is unavoidable for future 24-hour health and notification rate
  limiting; the design must fail closed on rollback rather than promise perfect
  continuity.

## Rejected alternatives

- WebView-owned polling or lifecycle: presentation code is not a trusted
  scheduler and is suspended/destroyed independently.
- unbounded channels or one thread per callback: permit event-storm resource
  exhaustion and nondeterministic ordering.
- helper daemon/privileged helper: unnecessary authority and a larger install,
  signing, IPC, and cleanup surface.
- Tauri autostart/notification plugins: broader generic command/policy surface
  than this product boundary needs.
- application-written LaunchAgent or AppleScript login item: more filesystem or
  Automation authority and less truthful macOS 15 status handling.
- persistent activity/candidate journal: creates replay and privacy risk.
- vault-database health: unavailable while locked and risks extending vault-key
  lifetime.
- silent health-file/Keychain repair: destroys evidence and can bless attacker-
  or corruption-controlled state.
- a single healthy/unhealthy flag: conflates unbound service, agent failure,
  login-item drift, notification denial, and future server staleness.
- local send/attempt as last success: falsely reports delivery without
  authenticated server acceptance.
- hard-coded Team/access-group identity: conflicts with development profiles
  and future I15 identity continuity.
- treating Screen Sharing input as physical presence: exceeds what the native
  evidence proves.

## Compatibility and migration

The I01 prototype gate is not automatically migrated or deleted. I08 creates
the new exact gate if absent and ignores the prototype identity. The I02
signing-key item and ADR 0007/0009 persisted formats are unchanged.

Health version 1 is new and contains no secret. Future readers must either
support it exactly or fail closed with explicit recovery; they may not
reinterpret bytes. Future versions require a migration decision and tests.

The fixed 4-hour policy and private future ports preserve I09/I10 ownership.
No public protocol field or server behavior is established here.

## Verification

Acceptance requires all automated and native cases in
`docs/iterations/I08-macos-lifecycle-activity-hardening.md` and
`docs/research/I08-macos-lifecycle-dependency-and-permission-proposal.md`,
including:

- hostile policy/event, Keychain, health-file, IPC, panic, shutdown, and restart
  tests;
- login-item, notification, tray/window, session/power, fast-switch, Screen
  Sharing, clock-change, and cleanup matrices;
- English/Simplified Chinese and accessibility cases;
- capability/CSP/dependency/license/remote-origin inspection;
- current-host plus separate Apple Silicon macOS 15 evidence;
- release-shaped energy measurements; and
- exact Argon2id replay under representative bounded pressure.

Results must identify real commands, hosts, failures, waivers, and cleanup. A
missing floor run or failed cleanup keeps the iteration in progress.
