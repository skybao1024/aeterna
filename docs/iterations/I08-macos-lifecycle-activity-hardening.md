# I08 macOS lifecycle, activity, and hardening

## Status

**In progress, not accepted.** Implementation was approved on 2026-09-22. The
stopped checkpoint at `090912f` passed its repository checks, unsigned host
build, and one signed current-host startup/gate step. Work resumed on
2026-09-28 against the I09-I14 client baseline. Those earlier checks and native
observations do not verify the integrated revision. The fixed signed probe
subsequently deleted and independently verified the exact synthetic Keychain
gate on both native hosts. Later app launches can recreate the gate, so final
cleanup remains part of acceptance. The acceptance criteria below remain
unchanged.

The original checkpoint branched from `98afa1a164806fbe3ebf3fda821d790f689f4d65`.
The resumed integration began from clean client `main` at `0da6166` (I14). Its
newer protocol, recovery, UI, and vault work must be preserved.

## Validation order and stop rule

Finish implementation before extending the native matrix. The immediate
development gate is focused regression coverage for each changed behavior,
`npm run check`, `npm run desktop:build`, a signed startup smoke test on both
required macOS versions after the last native-code change, and review of the
security and lifecycle boundaries. A failure returns work to implementation;
do not continue to unrelated native cases merely to collect more evidence.

After the development gate is stable, complete the behavioral native cases in
the verification plan below: login launch and rollback, vault/window/quit,
notification, lock/sleep/switch, gate failure, remote-session classification,
and cleanup on both hosts. Then collect the prescribed 15-minute energy and
exact KDF evidence. These are still required for formal I08 acceptance, but
repeating a passed case after an unrelated change or running the entire matrix
while known implementation gaps remain adds no acceptance value.

Extra Instruments traces, custom Quartz probes, repeated pressure runs, and
additional timing or power-log captures are diagnostic tools. Run them only
when a required case has ambiguous evidence or fails. They do not replace a
required pass and are not separate acceptance criteria.

I08 deliberately leaves the native agent unbound. A real account/device
heartbeat, server acceptance, release, and recovery drill cannot be an I08
development or native-test prerequisite. Run those end-to-end cases only after
the later binding and delivery integration exists, within its own gate.

## Approval boundary

The exact documentation set and ADR 0011 received explicit implementation
approval on 2026-09-22. That approval covers repository changes only. Native
validation retains a separate, just-in-time approval boundary before every
step that changes system state or may display an operating-system permission
prompt.

## Sources of truth

I08 must remain consistent with:

- `docs/DESIGN.md`, especially the activity, lifecycle, trust-boundary,
  privacy, localization, accessibility, and acceptance sections;
- `docs/DEVELOPMENT_PLAN.md`, including the repository iteration rules and the
  I08 scope;
- accepted ADRs 0001, 0002, and 0004;
- the G0 macOS gate review and the I01 and I02 native result ledgers;
- the I05 through I07 iteration and result ledgers for vault, session,
  attachment, transfer, and atomic-file invariants; and
- the current manifests, Tauri configuration, capabilities, Rust activity and
  secure-storage modules, React shell, and localization resources.

The companion documents are:

- `docs/research/I08-macos-lifecycle-dependency-and-permission-proposal.md`;
- accepted `docs/adr/0011-macos-lifecycle-activity-health.md`.

## Goal

Deliver a production-shaped macOS 15 lifecycle and activity agent that:

- starts and stops predictably;
- can be explicitly registered as a login item without opening a window on a
  login-item launch;
- keeps a localized, accessible tray surface available while the main window
  is hidden;
- hardens the I01 activity policy, Keychain availability gate, and bounded
  scheduling path;
- exposes a coarse, honest local health model without claiming that the
  currently unconnected native agent has delivered a server heartbeat;
- persists only the minimum non-sensitive state needed for restart continuity;
- requests notification permission only in response to an explicit action in
  a visible window; and
- fails closed on malformed input, unavailable native services, worker failure,
  corrupted state, and contradictory lifecycle events.

## Non-goals

I08 does not:

- provision or bind a server account;
- sign or send a heartbeat;
- change the accepted I09-I14 protocol, recovery, or vault behavior, or make
  I15 production signing/release decisions;
- choose a final production bundle identifier, Team ID, distribution
  certificate, notarization profile, installer, or uninstall experience;
- alter cryptographic envelope formats, Argon2 parameters, key hierarchy,
  signing-key identity, vault schemas, or export/import formats;
- infer physical presence from HID input or Screen Sharing activity;
- add telemetry, analytics, a remote script, a generic filesystem or shell
  endpoint, a generic notification endpoint, or a network capability;
- store raw HID events, foreground applications, window titles, keystrokes,
  pointer coordinates, device identifiers, vault content, contact details, or
  heartbeat payloads; or
- silently repair login-item settings, Keychain metadata, or a corrupted health
  file.

## Required behavior

### Process and window lifecycle

The Rust host owns one `ActivityAgent` supervisor and at most one named worker
thread. Startup is idempotent. A manual cold launch shows the locked main
window. A launch reported by the documented macOS login-item Apple Event starts
the same application and agent but leaves the window hidden. Reopen, Dock, or
tray actions show, unminimize, and focus the existing main window.

Closing the window is not process termination. The close path must resolve
unsaved-edit handling in the existing presentation layer, lock the vault, drop
plaintext session state, cancel and join active transfers, clear WebView
content, and then hide the window. Opening it again presents the locked state.
The tray provides only bounded actions: open Aeterna, lock the vault, and quit.
Login-item and notification controls remain in the visible settings UI.

Sleep, screen lock, fast-user switch-out, loss of the Keychain gate, lifecycle
contradiction, worker failure, and controlled shutdown all clear the activity
candidate and lock/drop the vault. Wake, unlock, and switch-in re-establish
fresh gate and HID baselines; they never unlock a vault or replay a candidate.

Controlled shutdown follows one ordering:

1. reject new lifecycle mutations and IPC work;
2. lock/drop the vault and cancel/join transfers;
3. unregister native observers and stop accepting lifecycle signals;
4. signal and wake the activity worker;
5. let the worker clear policy state and its candidate, then join it;
6. durably flush only validated non-sensitive health state; and
7. remove tray/window resources and exit.

Repeated stop requests are harmless. A failure at any step is reported as
`agent_error`, keeps delivery disabled, and may not be hidden by continuing
with stale state.

### Activity gate and policy

The I01 policy invariants remain authoritative: successful gate access is an
availability signal, not authentication; HID and Combined readings must be
captured in one sample; a successful gate read must occur between the sample
and evaluation; two distinct HID epochs are required; Combined-only movement
invalidates the pending observation; all decision windows use monotonic time;
and ambiguous, missing, stale, contradictory, or overflowing input fails
closed.

Every runtime gate read validates the exact value and Keychain metadata defined
in the companion proposal. The activity gate remains distinct from the I02
device-signing key. Runtime code never automatically updates or deletes either
item.

The worker owns sampling, policy evaluation, candidate creation, cooldown, and
health timers. Native callbacks perform only bounded, non-blocking signal
enqueue operations. A full or disconnected queue sets a sticky error flag;
the worker clears the policy and candidate before any recovery attempt.

### Candidate and future delivery boundary

I08 creates an internal, in-memory candidate only. The queue capacity is one,
and a candidate expires after 15 minutes. It contains an opaque generation and
monotonic creation instant, not user content or raw input. A sleep, lock,
switch-out, gate failure, overflow, agent failure, shutdown, or expiry clears
it.

The private Rust boundary distinguishes `unbound`, `not_configured`, and
`actively_bound`. I08 supplies only the first two. A later native integration
may pass a fresh candidate to the existing I10 delivery coordinator only after
I09 reports an active binding. Only an authenticated, server-accepted response
may call the internal
`record_server_accepted_heartbeat` transition. App launch, candidate creation,
delivery attempt, local signing, tray interaction, or a successful HTTP status
without authenticated protocol acceptance must not advance last success.

The fixed I08 policy uses:

- 5-second sampling;
- a 2-minute post-unlock exclusion window;
- a 2-minute second-epoch confirmation window;
- a 30-minute idle threshold;
- a 30-minute candidate cooldown;
- a 15-minute candidate freshness limit;
- a 4-hour continuous-activity refresh interval; and
- a hard 12-hour ceiling for any future continuous-activity configuration.

I08 has no remote policy configuration. Invalid local constants or persisted
timing state prevent the agent from becoming ready. Wall-clock values are used
only for display, notification rate limiting, and future server-accepted
timestamps; they never substitute for monotonic policy time. Every process
start imposes a fresh 30-minute monotonic candidate guard, so a restart cannot
bypass cooldown and no local activity time must be persisted.

### Health model

The product exposes separate coarse facets rather than one misleading boolean:

| Facet | States |
| --- | --- |
| Service | `unbound`, `not_configured`, `healthy`, `stale` |
| Activity | `ready`, `gate_unavailable`, `agent_error` |
| Start at login | `enabled`, `disabled`, `drifted`, `unavailable` |
| Notifications | `not_requested`, `authorized`, `denied`, `unavailable` |

An overall presentation state uses the most actionable condition but never
hides the facets. While I08's native agent remains unbound, the service state is `unbound` or
`not_configured`; the UI must not say a heartbeat failed. `stale` means an
active future binding exists and no authenticated server acceptance has
occurred for at least 24 hours. “No server-confirmed heartbeat yet” is distinct
from failure.

Only the following non-sensitive restart state is persisted in the versioned
health record: the user's login-item preference, selected locale, a state
generation, future last server-accepted time, last stale-notification time, and
save time. The record contains no candidate, local activity time, delivery
attempt, reason/source, raw activity, vault/contact/item identifiers,
filesystem path, URL, token, secret, or message content.

### Start at login

Start at login is opt-in. A visible user action invokes
`SMAppService.mainAppService.register()` or `unregister()`. I08 never
automatically enables, repairs, or opens System Settings. The UI shows the
requested preference separately from the observed service status and offers a
localized, explicit “Open Login Items Settings” action when macOS reports that
approval is required.

The native `NotFound` status is treated as disabled before the main app's first
registration; macOS can return it when no Login Item record exists yet. A
registration failure is surfaced as a native error and never treated as success.
Explicit disable unregisters the service and updates the local preference only
after the native operation succeeds. Uninstall cleanup is owned by I15; I08
documents that an unregistered main-app service no longer launches at login.

### Notifications

Notification permission is requested only after the user selects “Enable
notifications” in a visible settings window. Startup, a login-item launch, the
tray, and background health evaluation never prompt. Denial or unavailability
leaves tray/UI health usable and is not treated as an activity failure.

A future 24-hour stale transition may schedule at most one generic notification
per 24 hours while stale. Successful server acceptance resets that transition.
The title and body are localized equivalents of “Aeterna needs attention” and
“Open Aeterna to review background status.” They contain no name, vault,
contact, activity source, timestamp, URL, or recovery detail. I08 cannot produce
this notification while the service is unbound/not configured.

### Security surface

The strict production CSP retains `connect-src 'self' ipc: http://ipc.localhost`
and adds explicit denial for unused object, frame, child, worker, media,
manifest, form, and base surfaces where supported. It does not permit remote
scripts, images, styles, or network origins.

Only the main window capability receives exact lifecycle commands. Commands
use strict, size-bounded schemas with unknown-field rejection. There is no raw
activity, arbitrary notification, Keychain, filesystem, URL, login-item,
system-settings, shell, SQL, or generic native-call endpoint. Candidate
creation and server-acceptance transitions remain private Rust calls.

The proposed narrow commands are:

- read coarse lifecycle status;
- set the explicit start-at-login preference;
- request notification authorization;
- set the locale to `en` or `zh-CN`; and
- explicitly reset a corrupted non-sensitive health record after localized
  confirmation.

## Verification plan

### Automated tests

Implementation is not complete until focused unit/integration tests cover:

- normal startup, login-item startup, repeated start, window close/reopen,
  controlled quit, and restart after an interrupted shutdown;
- worker start/stop, queue overflow/disconnect, panic containment, timer wakeup,
  observer-registration rollback, and idempotent joins;
- exact Keychain item creation, retrieval, value and metadata validation,
  duplicate/missing/wrong-class/wrong-service/wrong-account/wrong-accessibility/
  wrong-synchronizable/wrong-access-group cases, locked Keychain, update, and
  exact deletion in a synthetic test namespace;
- startup baseline, lock/unlock, sleep/wake, switch-out/in, Combined-only
  movement, two HID epochs, stale samples, impossible input ages, out-of-order
  and duplicate signals, rapid event bursts, cooldown, expiry, wall-clock
  rollback/advance, and restart with no candidate replay;
- malformed, truncated, oversized, checksum-invalid, unknown-version,
  wrong-owner/mode/type/link-count, symlink, parent-swap, low-disk, interrupted
  write, and concurrent-read health-file cases;
- strict IPC decoding, unknown fields, wrong types, oversized values,
  unauthorized window/capability, and absence of a raw candidate/acceptance
  command;
- autostart state mapping, explicit enable/disable, approval-required drift,
  unavailable signing context, login-item launch hiding, and no silent repair;
- notification first-use, authorized/denied/unavailable states, no background
  prompt, generic localized content, transition/rate limiting, and no send while
  unbound;
- CSP/capability snapshots, remote-origin scans, release-feature checks, log and
  trace redaction, and production absence of diagnostic persistence;
- English and Simplified Chinese rendering, long-string layouts, VoiceOver
  labels/order, keyboard-only operation, focus restoration, reduced motion,
  native menu localization, and notification localization; and
- existing vault lock, transfer cancellation/join, export/import, secure
  storage, and activity-policy regression suites.

### Native macOS matrices

Native evidence must use two distinct Apple Silicon environments:

1. the current development host; and
2. a separate, fully updated macOS 15 environment.

The second environment is an acceptance requirement. Its first unavailability
keeps an active I08 effort `In Progress`; it is not by itself a reason to mark
the iteration `Blocked`. A user-directed stop records `Stopped` without
acceptance.

The runbook records app hash, repository commit, OS/build, hardware, signing
context, capability/CSP snapshot, start/end state, synthetic Keychain namespace,
and artifact cleanup. It exercises manual/login launch, enable/disable and
approval-required login-item states, quit/relaunch, window/tray flows, user
switching, screen lock, sleep/wake, Keychain locked/unavailable/wrong-metadata
states, Screen Sharing, notification first-use/denial/settings changes,
wall-clock changes, rapid bursts, and restart recovery. Screen Sharing may
advance HID and Combined samples but is recorded only as authenticated remote
activity, never as physical presence.

Every login-item mutation, permission prompt, login/logout, user switch,
lock/unlock, sleep/wake, Screen Sharing session, clock change, signing/profile
change, or comparable system mutation requires a fresh just-in-time approval
before it is performed. The runbook includes exact preconditions, expected
side effects, rollback, and cleanup for that step.

### Energy and KDF evidence

A signed release-shaped build is measured after warmup for 15 idle minutes with
the window hidden. The acceptance targets are no more than 0.5% average CPU,
no more than 30 activity-agent wakeups per minute, no sustained polling leak,
and no more than 5 MiB RSS growth after warmup. Process RSS is reported
separately rather than disguised as agent memory.

The exact accepted Argon2id profile is replayed without changing the vault
format or parameters: version `0x13`, 262144 KiB memory, two iterations, one
lane, and 32-byte output. The benchmark uses fixed synthetic material, three
warmups, and at least 20 measured samples while the release-shaped app, agent,
tray, and representative synthetic vault are active and a bounded 512 MiB test
pressure fixture is resident. Targets are p50 250–500 ms, p95 no more than
750 ms, peak process RSS no more than 384 MiB, and no swap. A miss keeps I08 in
progress and requires a separate profile/version, migration, and security
decision; I08 may not silently lower persisted KDF parameters.

## Acceptance criteria

I08 is complete only when:

- the approved ADR and proposal are implemented without unapproved scope
  drift;
- all automated suites and repository canonical checks pass;
- a release-shaped macOS build has a strict CSP and minimal capabilities;
- lifecycle, activity, health, localization, accessibility, energy, and KDF
  evidence passes on both required Apple Silicon environments;
- login-item and notification flows are explicit, truthful, reversible, and
  cleaned up;
- production paths contain no persistent raw activity trace, secret-bearing
  diagnostic, or generic privileged endpoint;
- the exact Keychain gate metadata is validated on every read and its synthetic
  native-test item is removed;
- no stale candidate survives a lock, sleep, switch, error, expiry, quit, or
  restart;
- missing floor-platform evidence prevents acceptance rather than being waived;
  and
- result ledgers and relevant design/dependency documentation are synchronized.

## Implementation sequence after approval

1. Land the accepted ADR and dependency/permission decisions.
2. Add the versioned health store and hostile-file tests.
3. Harden the Keychain gate and activity policy tests.
4. Add the supervised agent and lifecycle ordering.
5. Add tray/window, start-at-login, notification, IPC, CSP, i18n, and
   accessibility work.
6. Run focused checks, then the complete repository check and release build.
7. Prepare the native runbook and request approval before each disruptive
   matrix step.
8. Record current-host and macOS 15 results, energy/KDF evidence, cleanup, and
   any remaining risk.
