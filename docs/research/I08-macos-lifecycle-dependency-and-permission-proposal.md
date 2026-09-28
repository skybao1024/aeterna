# I08 macOS lifecycle dependency and permission proposal

## Status and approval

Proposal for review. It is not an implementation record and grants no authority
to modify source code, manifests, lockfiles, Tauri capabilities or
configuration, entitlements, persisted formats, or operating-system state.

Baseline: clean `main` at
`98afa1a164806fbe3ebf3fda821d790f689f4d65`.

Approval of this proposal and proposed ADR 0011 authorizes only the described
repository implementation. It does not authorize native validation steps that
change login items, display permission prompts, lock or sleep a machine, switch
users, change the clock, start Screen Sharing, alter signing state, or perform
another disruptive system action. Each such step requires a separate,
just-in-time approval against the runbook.

## Decision summary

Use one in-process Rust supervisor and one bounded worker thread. Keep activity
observations and heartbeat candidates private to Rust. Use Apple's public
`SMAppService` main-app API for opt-in login launch, Tauri's built-in tray
support for the menu bar surface, and Apple's UserNotifications framework for
explicitly authorized generic health notifications. Harden the I01 Keychain
gate by validating its exact public value and all security-relevant metadata on
every read. Persist a single small, checksummed, atomic, non-sensitive health
record outside the vault database. Fail closed whenever native services,
ordering, file integrity, time continuity, or worker supervision is uncertain.

The approach deliberately avoids Tauri autostart, notification, and
single-instance plugins. Their generic command surfaces and broader
cross-platform policy are unnecessary for the narrow macOS-only boundary in
I08. The host exports only five typed lifecycle commands to the main window and
does not export candidate creation or server-acceptance transitions.

## Existing evidence and constraints

- The G0/I01 evidence established that HID plus Combined idle time can support
  an availability policy, including Screen Sharing as remote authenticated
  activity, but cannot prove physical presence.
- The I01 gate currently checks an exact value but not all Keychain attributes.
  G0 explicitly carried that as an I08 hardening item.
- The existing activity prototype already clears state for sleep, inactive
  sessions, gate failure, and Combined-only movement, and requires two HID
  epochs. The proposal preserves those invariants rather than replacing the
  detector.
- The I02 device-signing key uses a distinct Keychain service and is not an I08
  migration target.
- The I05-I07 vault and transfer layers already define lock/drop, transfer
  cancellation, bounded payload, and atomic-file invariants that lifecycle
  shutdown must call rather than duplicate.
- Production CSP and the current main-window capability are already narrow.
  I08 must not add network, filesystem, dialog, shell, or remote-content access.
- The current bundle identifier is a development identifier and production
  bundling is disabled. I08 may make a release-shaped signed test bundle but
  does not choose the I15 production identity.
- Native floor evidence is required on a separate updated Apple Silicon macOS
  15 environment in addition to the current host.

## Proposed process architecture

### Ownership

`LifecycleCoordinator` is Rust host state created during Tauri setup. It owns:

- an idempotent `ActivityAgent` supervisor;
- native observer registrations;
- the login-item and notification adapters;
- the versioned health repository;
- a coarse immutable health snapshot for IPC/tray rendering; and
- references to the existing vault/session and transfer shutdown boundaries.

`ActivityAgent` owns exactly one named worker thread in production. It does not
spawn a helper process, execute commands, or hold a WebView handle. The worker
owns the activity policy, sample timer, candidate slot, cooldown timer, stale
timer, and health-state transitions. Native callbacks do not run policy, touch
files, take a blocking lock, call Keychain, or invoke the WebView.

### Bounded signal channel

Native callbacks send a small enum through `std::sync::sync_channel` with
capacity 32 by `try_send`. Signals are limited to:

- display/session lock and unlock;
- workspace sleep and wake;
- session resign-active and become-active;
- window show/hide requests needed for lifecycle coordination; and
- shutdown.

Repeated equivalent state signals may be coalesced by an atomic bitset. A full
queue, disconnected receiver, observer-registration error, impossible state
transition, or poisoned coordinator lock sets a sticky atomic overflow/error
flag. The worker observes that flag before producing any candidate, clears all
policy and candidate state, and publishes `agent_error`. Recovery requires a
fresh lifecycle baseline and two new HID epochs; queued data is never replayed
as proof of activity.

The worker samples at a fixed 5-second interval using a monotonic wait deadline.
Callbacks wake the same wait object. This gives 12 scheduled samples per minute
at idle; the energy ceiling allows 18 activity-agent wakeups per minute so
native state transitions and timer jitter have bounded headroom. No timer or
callback performs busy waiting.

### Startup transaction

Startup is an ordered transaction:

1. create and validate the app-local health directory and read the health
   record without following links;
2. construct the localized tray in a disabled/not-ready state;
3. validate fixed timing bounds and derive the current signed application's
   Keychain access group;
4. retrieve or create, then fully re-read and validate, the activity gate;
5. register workspace, power, and session observers, rolling back already
   registered observers on any failure;
6. create the bounded channel and worker, then transfer observer ownership to
   the coordinator;
7. enqueue `ProcessStarted` and establish fresh HID, Combined, gate, session,
   and power baselines; and
8. publish `ready` only after all steps pass.

No startup state can produce a candidate. A partially started agent is stopped
and joined before setup returns an error. A second start request returns the
existing compatible handle or an explicit incompatible-state error; it never
starts a second observer set or worker.

### Shutdown transaction and panic containment

Controlled quit, application termination, setup rollback, and test teardown use
one idempotent stop operation:

1. atomically move to `stopping` and reject new lifecycle mutations/IPC;
2. invoke the existing vault lock/drop and transfer cancel/join boundary;
3. unregister all native observers and close the signal producer side;
4. set the stop flag and wake the worker;
5. clear policy/candidate state on the worker and join it;
6. serialize and atomically flush only a validated health snapshot; and
7. remove tray/window resources and finish termination.

The worker entry point is wrapped in `catch_unwind`. This requires changing the
release profile from `panic = "abort"` to `panic = "unwind"`; otherwise a worker
panic cannot be converted into `agent_error` or joined in a defined order. The
cost is unwind metadata and a potentially larger binary. Panics remain bugs,
but the boundary guarantees that a test-injected panic clears the candidate,
locks the vault through supervisor recovery, emits only a fixed non-sensitive
error code, and does not pretend the agent is healthy. Panics are never used as
normal control flow.

Every Rust closure invoked directly by Objective-C/C or a Tauri native callback
also catches a Rust unwind before it reaches the foreign ABI, sets the same
sticky error, and returns its documented fail-closed value. No Rust panic may
cross an FFI boundary. An uncontained panic in top-level host setup/dispatch
records only a fixed code, makes a best-effort coordinator stop when state is
still reachable, and terminates nonzero; the process is not kept alive in an
unknown state. Restart safety comes from non-persistence of candidates and
fresh baselines, not from claiming crash cleanup always runs.

An unexpected failure to unregister, wake, join, or flush is recorded as a
fixed health error. Shutdown continues only far enough to minimize retained
plaintext and avoid hanging; no stale state is reported as successfully saved.

### Window and tray behavior

The tray uses Tauri's Rust `TrayIconBuilder` and native menu implementation.
It contains:

- a disabled localized coarse-status item;
- Open Aeterna;
- Lock Vault, enabled only when an unlocked session exists; and
- Quit Aeterna.

There is no tray login-item toggle, notification-permission action, raw
activity view, or recovery action. Those decisions require the explanatory
context and focus management of the visible settings UI.

A manual launch shows the main window. The host inspects the initial
`kAEOpenApplication` event's documented `keyAELaunchedAsLogInItem` property; a
true property starts the process and tray with the main window hidden. It does
not infer login-item launch from an undocumented argument. Reopen and tray-open
show, unminimize, and focus the same window.

A window close request first permits the presentation layer to resolve its
existing unsaved-edit warning. Once accepted, the coordinator locks the vault,
cancels/joins transfers, destroys sensitive WebView state, and hides the
window. Reopen constructs or reloads only the locked view. Lock from the tray
uses the same boundary. Sleep, screen lock, and switch-out also lock/drop and
clear the view. Wake/unlock never restores the vault session.

## Activity policy and scheduling contract

### Monotonic inputs

All policy comparisons use one monotonic clock abstraction. A sample contains
HID idle age, Combined idle age, and the monotonic instant at which both were
captured. Ages greater than the capture instant, non-finite platform values,
conversion overflow, and an event instant that would precede the process
baseline are invalid. A successful gate read occurs after capture and before
evaluation.

The fixed bounds are:

| Input                                 |      Value | Purpose                                        |
| ------------------------------------- | ---------: | ---------------------------------------------- |
| Poll interval                         |  5 seconds | Bounded sampling/energy                        |
| Maximum sample staleness              |  2 seconds | Reject delayed policy evaluation               |
| Post-unlock exclusion                 |  2 minutes | Prevent unlock from counting as later activity |
| Confirmation window                   |  2 minutes | Require a second distinct HID epoch            |
| Idle threshold                        | 30 minutes | Clear active policy after sustained inactivity |
| Candidate cooldown                    | 30 minutes | Bound local candidate production               |
| Candidate freshness                   | 15 minutes | Prevent delayed future delivery                |
| Continuous refresh                    |    4 hours | Fixed current product refresh                  |
| Future configurable ceiling           |   12 hours | Reject excessive future intervals              |
| Clock skew tolerance for restart data |  2 minutes | Detect rollback/future state                   |

The fixed 4-hour refresh is intentionally below the documented 6–12-hour
upper-bound range; I08 adds no remote configuration. Any later configurable
value must remain no greater than 12 hours and requires a protocol/product
decision in its owning iteration.

### Candidate state machine

The candidate slot has capacity one. A candidate contains only an opaque
generation, monotonic creation instant, and monotonic expiry. It has no raw HID
value, activity source, username, vault/item/contact reference, wall timestamp,
or payload.

A candidate is created only after a valid gate read and a confirmed second HID
epoch within the monotonic window. Creation sets the in-process monotonic
30-minute cooldown. Lock, sleep, inactive session, Combined-only change, gate
failure, channel error, worker error, expiry, shutdown, and restart destroy the
candidate. A fresh process always begins from baseline and must observe two
new epochs.

Every process start seeds a fresh 30-minute monotonic candidate guard in
addition to establishing new baselines. This conservative delay prevents a
restart from bypassing cooldown without persisting a local activity or
candidate time. A forward or backward wall-clock jump cannot shorten that
guard, create a candidate, or restore a prior candidate.

### Future binding and acknowledgement boundary

The internal `BindingEligibilityPort` returns one of `unbound`,
`not_configured`, or `actively_bound`. I08 implements the first two. A future
I09 adapter may provide active binding; a future I10 delivery worker may take a
fresh candidate and construct/sign/send a heartbeat. Those integrations are
not exported to the WebView.

Only the private Rust call
`record_server_accepted_heartbeat(accepted_server_time)` may advance last
success. Its caller must already have validated the authenticated I10 protocol
response and binding identity. Candidate creation, an attempted send, local
signing, TCP/TLS success, an HTTP success code alone, app open/wake, and local
notification delivery do not advance success.

## Keychain activity-gate contract

### Exact identity and value

The I08 production gate is a Data Protection Keychain generic-password item:

| Attribute      | Required value                                                   |
| -------------- | ---------------------------------------------------------------- |
| Class          | `kSecClassGenericPassword`                                       |
| Service        | `aeterna.desktop.activity-gate.v1`                               |
| Account        | `unlock-availability`                                            |
| Value data     | ASCII `AETERNA-ACTIVITY-GATE-V1`                                 |
| Accessibility  | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`                   |
| Synchronizable | `false`                                                          |
| Access group   | exact current app `com.apple.application-identifier` entitlement |

The access group is derived at runtime from the code-signed process using
public Security `SecTaskCreateFromSelf` and
`SecTaskCopyValueForEntitlement` calls. A missing, non-string, empty, or
unexpected entitlement makes the gate unavailable; I08 does not guess a Team
ID, use a wildcard, or hard-code the development profile. A small documented
FFI declaration is proposed because the already pinned
`security-framework-sys` crate exposes the required Security types and
Keychain constants but not `SecTask` convenience bindings.

The new identity intentionally differs from the I01 prototype service. I08 does
not migrate or delete the prototype item automatically. Native-test cleanup
may delete only its exact synthetic namespace after explicit runbook approval.
The I02 device-signing service and key are never queried or modified by the
activity adapter.

### Retrieve and validate

Every gate operation uses the Data Protection Keychain, suppresses
authentication UI, matches the complete class/service/account/access-group
identity, requests both data and attributes, and requires exactly one result.
The adapter validates:

- result type and result count;
- service, account, access group, and accessibility in returned attributes;
- class and non-synchronizability through exact query constraints (the macOS
  return dictionary can omit class and does not consistently represent the
  default false synchronization value);
- exact value length and constant-time byte equality; and
- that no unexpected UI or cloud/synchronizable behavior was requested.

Missing, duplicate, malformed, inaccessible, interaction-not-allowed,
entitlement, decoding, or unexpected status results fail closed. The code does
not broaden the query, fall back to an unscoped item, update malformed
metadata, or log the returned dictionary/value.

### Create, update, and delete semantics

Normal startup creates the gate only when an exact query returns not found.
Creation uses the exact table above. A duplicate-item result is treated as a
race and followed by a complete read/validation; it is not overwritten.

Runtime activity code never updates or deletes the gate. A narrowly scoped
internal test/maintenance update operation, needed to prove semantics, uses an
exact identity query and `SecItemUpdate`, then fully re-reads the item. It may
change only the public value to the exact same contract value; delete-and-add
is forbidden because it weakens atomicity and metadata continuity.

The test/maintenance delete operation uses the exact class, service, account,
and access group. `success` and `item not found` are terminal idempotent
outcomes; every other status is an error. It never deletes by service prefix,
account alone, access group alone, or all generic passwords. Uninstall behavior
belongs to I15 because macOS does not run application code on ordinary bundle
deletion. The residual item is public non-secret data but is documented for
the future uninstaller/cleanup design.

## Persisted health record

### Location and permissions

The file is
`<app-local-data>/health/activity-health-v1.bin`. It is independent of the
encrypted SQLite vault, ADR 0007 schemas, exports, and the signing Keychain
item. The `health` directory is mode `0700`; the file is mode `0600` and owned
by the effective user.

The repository retains an opened parent-directory descriptor and uses
descriptor-relative operations with `O_NOFOLLOW`, `O_CLOEXEC`, and exclusive
temporary creation. Reads require a regular file, owner match, link count one,
exact mode, and exact length. A symlink, hard link, special file, owner/mode
mismatch, parent replacement, or inconsistent identity is an error. No path
from IPC or persisted input is accepted.

### Exact version 1 bytes

Version 1 is exactly 96 bytes, little-endian:

| Offset | Size | Field                                                                          |
| -----: | ---: | ------------------------------------------------------------------------------ |
|      0 |    8 | Magic bytes `AETRHST\0`                                                        |
|      8 |    2 | Version `1`                                                                    |
|     10 |    2 | Flags; bit 0 is desired start-at-login, all other bits zero                    |
|     12 |    1 | Locale: `0` = `en`, `1` = `zh-CN`                                              |
|     13 |    3 | Reserved, all zero                                                             |
|     16 |    8 | State generation                                                               |
|     24 |    8 | Last authenticated server acceptance, Unix milliseconds; zero = none           |
|     32 |    8 | Last successfully scheduled stale notification, Unix milliseconds; zero = none |
|     40 |    8 | Save time, Unix milliseconds                                                   |
|     48 |   16 | Reserved, all zero                                                             |
|     64 |   32 | SHA-256 of bytes 0 through 63                                                  |

SHA-256 detects accidental corruption and torn data; it is not an authenticity
claim. Local same-user tampering therefore fails closed where detected but is
not part of Aeterna's cryptographic trust model. Unknown flags, locale, version,
reserved data, impossible timestamp ordering, arithmetic overflow, a timestamp
more than two minutes in the future, or a checksum mismatch is invalid.

The record deliberately omits delivery attempts, candidate data, local activity
time, activity source/age, observer events, filenames, URLs, window state,
vault/item/contact identifiers, binding material, notification content, errors,
secrets, and credentials. The current I08 service remains unbound/not
configured even if a test fixture contains a nonzero future-owned acceptance
field; production code does not synthesize it.

### Atomic read/write and recovery

Writes serialize into memory first. The repository creates a random
same-directory temporary file with a fixed non-sensitive prefix, exclusive
mode `0600`, and no link following; writes all 96 bytes; syncs the file;
revalidates any existing destination without following links; atomically
renames by retained directory descriptor; and syncs the directory. A short
write, low-disk error, interruption, metadata mismatch, rename failure, or
directory-sync failure leaves the last known-good destination in place where
the platform permits and removes only the exact temporary name it created.

Concurrent writers are serialized inside the coordinator. Generation must
advance by exactly one. A read during replacement sees one complete generation,
never a partially written record. Shutdown does not overwrite a file that
became invalid or was externally replaced after startup.

Invalid state is not silently repaired, overwritten, renamed, or uploaded. The
agent publishes `agent_error`, disables candidate production and future
delivery, and leaves the original bytes for diagnosis. The visible UI may offer
“Reset local health state” with an explanation and localized confirmation.
That exact command deletes only the validated path entry by parent descriptor,
syncs the directory, creates a fresh default record, and re-establishes
baselines. It does not touch the vault, Keychain, login-item registration, or
notification authorization.

## Health, login-item, and notification semantics

### Coarse health facets

Rust exposes these enums:

- service: `unbound`, `not_configured`, `healthy`, `stale`;
- activity: `ready`, `gate_unavailable`, `agent_error`;
- login item: `enabled`, `disabled`, `drifted`, `unavailable`;
- notifications: `not_requested`, `authorized`, `denied`, `unavailable`.

The UI/tray may compute a prioritized summary but must render the individual
facets in settings. A configured future service becomes `stale` only when an
active binding exists and the last authenticated server acceptance is at least
24 hours old. Never-accepted service setup is described as “No
server-confirmed heartbeat yet,” not a failed heartbeat. With I09/I10 absent,
I08 renders `unbound` or `not_configured` and cannot emit a stale notification.

Wall time is for coarse display and the 24-hour future health threshold only.
Current-process elapsed time is monotonic. A backward clock step, impossible
saved time, or loss of the wall-time source makes time-based health unknown and
maps to `agent_error`; it never turns stale into healthy. A forward jump may
make a future bound service stale but cannot create an activity candidate or
server acceptance.

### Start at login

The adapter uses `SMAppService.mainAppService` on macOS 15. Its public status is
mapped as follows:

| Desired preference | Native status                                    | Product status |
| ------------------ | ------------------------------------------------ | -------------- |
| false              | not registered                                   | `disabled`     |
| true               | enabled/registered                               | `enabled`      |
| true               | requires approval or not registered              | `drifted`      |
| either             | not found, unsigned/invalid context, API failure | `unavailable`  |

The status is refreshed at startup, when settings becomes visible, after an
explicit mutation, and every 15 monotonic minutes while the process is alive.
I08 does not poll on the activity interval.

Enable and disable occur only from an explicit visible-window action. The
native result is re-read before the preference is committed. An enabled result
commits the explicit preference; a requires-approval result commits only the
user's desired preference and remains truthful drift, not native success. A
denial or other native failure does not commit a new preference and is not
automatically repaired. “Open Login Items Settings” calls Apple's public
settings helper only after a distinct second user click. No Automation,
Accessibility, Screen Recording, Full Disk Access, or background-daemon
entitlement is requested.

`SMAppService` requires an appropriately code-signed application bundle. Direct
development executable runs and unsuitable signatures report unavailable. I08
does not choose the production Team ID, identifier, distribution identity, or
notarization path. It proposes `bundle.macOS.minimumSystemVersion = "15.0"` to
make the intended build floor explicit; I15 still owns final packaging and
compatibility evidence.

I08 does not add an uninstaller. Before manually removing a development bundle,
the runbook explicitly disables start at login and verifies the service is not
registered. Ordinary bundle deletion cannot run cleanup code and may leave the
public Keychain gate or local health file; I15 must either provide an exact
signed cleanup path or document those residuals in the production uninstall
experience. No future cleanup may infer a wildcard access group or delete a
Keychain service prefix.

### Notifications

The adapter reads `UNUserNotificationCenter` settings without prompting.
Authorization is requested only by the typed command invoked from an enabled
button in a visible/focused settings window. The command cannot accept title,
body, category, attachment, URL, sound, or recipient input. Startup,
login-item launch, background timers, and tray callbacks cannot invoke the
request.

The only planned notification is a future 24-hour stale transition. It is
generic and localized:

- title: “Aeterna needs attention”;
- body: “Open Aeterna to review background status.”

The Simplified Chinese resource provides the product-reviewed equivalent.
There is no sound, badge, attachment, deep-link parameter, activity detail,
contact, vault, timestamp, recovery status, or user content.

The worker schedules only when authorization is currently granted, an active
binding is stale, and the health record shows no successful stale notification
within the preceding 24 hours. It stores the notification time only after the
native scheduling call succeeds. Denied, provisional, ephemeral, or unavailable
authorization sends nothing and leaves tray/UI status available. Server
acceptance clears the stale transition; repeated app launches do not bypass the
rate limit.

## IPC, capability, and CSP proposal

### Commands

The main-window capability adds only:

1. `lifecycle_status` with an exact empty body;
2. `lifecycle_set_autostart` with `{ "enabled": boolean }`;
3. `lifecycle_request_notification_permission` with an exact empty body;
4. `lifecycle_set_locale` with `{ "locale": "en" | "zh-CN" }`; and
5. `lifecycle_reset_health_state` with an exact empty body after presentation-
   layer confirmation.

All bodies reject unknown keys, wrong types, repeated/missing fields, and input
over the shared small IPC limit. Calls from any unlisted window/label are
denied. Mutating commands also require the main window to be visible and
focused and are serialized by the coordinator. Response errors are stable
English codes plus localized presentation-layer explanations; they contain no
native dictionary, Keychain status dump, file path, entitlement, signing
identity, or secret.

There is deliberately no IPC for activity samples, observer injection,
candidate creation/take, cooldown reset, wall-clock override, last-success
write, arbitrary notification, arbitrary locale string, arbitrary URL/System
Settings pane, login-item identifier, Keychain query, filesystem path, command
execution, or agent trace.

### CSP and remote surface

The production CSP retains self-only scripts/styles/images/fonts and the
minimum Tauri IPC connection origins. It explicitly denies objects, frames,
children, workers, media, manifests, forms, and base-URI changes where the
embedded WebKit version supports the directive. `unsafe-eval`, remote origins,
wildcards, `data:` scripts, runtime-loaded scripts, and CDN assets remain
forbidden. Development-only Vite origins remain confined to the development
CSP.

Automated release checks inspect the compiled configuration/capability and scan
source/build metadata for unexpected `http:`, `https:`, WebSocket, remote
asset, script injection, shell, generic filesystem, generic dialog, updater,
or network permission paths. Login-item and notification framework use is local
operating-system IPC and does not add a network recipient.

## Dependency and build impact

### Manifest changes proposed

Exact versions and minimal features are proposed:

| Package/configuration                           | Change                                                                                                                                                                                                     | Rationale and risk                                                                                                                                                                                                                                        |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tauri = 2.11.6`                                | Add built-in `tray-icon` feature                                                                                                                                                                           | Official Tauri native tray/menu; already pinned and its `tray-icon`/`muda` transitive packages are already locked. Adds native menu code, no network/permission/plugin command surface.                                                                   |
| `objc2-service-management = 0.3.2` (macOS only) | New direct dependency, defaults off, `std`, `objc2`, `objc2-foundation`, `SMAppService`                                                                                                                    | Generated bindings to Apple's ServiceManagement framework. No network or runtime download. Unsafe FFI is isolated in the adapter.                                                                                                                         |
| `objc2-user-notifications = 0.3.2` (macOS only) | New direct dependency, defaults off, minimal `std`, `block2`, `UNUserNotificationCenter`, `UNNotificationSettings`, `UNNotificationContent`, `UNNotificationRequest`, and `UNNotificationTrigger` features | Generated bindings to Apple's notification framework. `UNNotificationTrigger` is required by the immediate-request constructor even when its value is `None`. Version is already present transitively; direct use makes the production boundary explicit. |
| `objc2-foundation = 0.3.2`                      | Add only `NSAppleEventManager`, `NSAppleEventDescriptor`, and directly required collection/error features                                                                                                  | Receives the documented login-item launch property and supports the two framework adapters. No event sending or Automation permission.                                                                                                                    |
| `security-framework-sys = 2.17.0`               | Keep version/features; add narrow local `SecTask` FFI declarations                                                                                                                                         | Avoids another wrapper dependency and derives the real access group. The FFI safety contract and CF ownership are unit/native tested.                                                                                                                     |
| `libc = 0.2.189`                                | Keep version/features; use descriptor-relative atomic-file calls                                                                                                                                           | Already pinned. Adds no package, permission, or network path.                                                                                                                                                                                             |
| `sha2 = 0.10.9`                                 | Reuse current dependency                                                                                                                                                                                   | Checksums the public fixed health record; no new cryptographic trust claim.                                                                                                                                                                               |
| release profile                                 | Change `panic = "abort"` to `panic = "unwind"`                                                                                                                                                             | Enables worker panic containment/join and fail-closed cleanup; increases unwind metadata.                                                                                                                                                                 |
| Tauri macOS config                              | Set minimum system version `15.0` and add exact commands to the main capability                                                                                                                            | Expresses the I08 floor and grants only narrow IPC. This is not final I15 packaging/signing.                                                                                                                                                              |

The exact feature list must be verified against the resolved crate metadata
before manifest editing. `cargo tree -e features`, duplicate-version review,
license inventory, and lockfile diff are approval checks. If enabling a listed
feature pulls a network client, remote loader, scripting engine, updater,
generic file/dialog/shell command, or second Objective-C/runtime version,
implementation stops for renewed approval.

### Maintenance, license, supply chain, and alternatives

Tauri is already the application framework. `objc2-service-management` and
`objc2-user-notifications` are generated members of the same actively
maintained `objc2` binding family already used by Aeterna. Their crate metadata
uses the `objc2` workspace's permissive Apache-2.0/MIT/Zlib licensing model.
They bind Apple system frameworks and do not ship a service, account, remote
code, telemetry, or runtime updater. The new service-management crate is still
a supply-chain addition and must be recorded in `docs/DEPENDENCIES.md` with its
resolved checksum and feature graph.

Rejected alternatives:

- `tauri-plugin-autostart`: its macOS implementation wraps broader
  cross-platform launch mechanisms rather than making the macOS 15
  `SMAppService` status/approval contract the authoritative boundary; it also
  adds plugin commands not needed here.
- `tauri-plugin-notification`: its generic notification command surface accepts
  more content than the single fixed health notification. A private native
  adapter is smaller and keeps authorization context in Rust.
- LaunchAgent plist written by the application: creates a filesystem/system
  registration surface, arguments, and cleanup burden that `SMAppService`
  avoids.
- AppleScript/login-items scripting: may prompt for Automation and is less
  deterministic than the public framework API.
- a helper daemon or privileged helper: unnecessary authority and lifecycle
  complexity.
- polling process lists or inferring login launch from process arguments:
  undocumented and spoofable.
- storing health in the encrypted vault: health must be available while the
  vault is locked and must not hold or prolong a vault key.
- SQLite for the health record: adds schema/transaction coupling for a single
  fixed record and expands corrupt-database recovery.
- Tauri single-instance plugin: macOS LaunchServices handles the supported
  bundled launch path; direct duplicate development executable starts are
  unsupported and report an agent ownership error rather than adding a global
  socket/command surface.

### Permissions and entitlements

No new macOS privacy permission or entitlement is proposed. Specifically, I08
does not request Accessibility, Input Monitoring, Screen Recording, Automation,
Full Disk Access, Contacts, Files and Folders, Apple Events sending, location,
camera, microphone, network extension, privileged helper, or background-task
entitlements.

UserNotifications presents its standard authorization sheet only after an
explicit in-context action. Login-item approval/status is owned by macOS System
Settings and is not bypassed. Keychain access uses the current signed
application's existing application-identifier/access-group entitlement and
does not add a sharing group. Final production identifier, Team ID, hardened
runtime, distribution entitlements, notarization, and uninstall packaging are
deferred to I15.

## Localization and accessibility

All WebView, native tray, native menu, confirmation, status, error, and
notification strings are resource keys with English source and Simplified
Chinese translation. Locale is one of the two fixed enum values in the health
record so the tray and background notification do not depend on localStorage
or a running WebView. The frontend may perform a one-time strict migration from
the existing supported localStorage locale and then calls the typed setter.

The settings surface groups activity, start-at-login, notification, and future
service health under semantic headings. State is conveyed by text and accessible
name, not color alone. Controls are keyboard reachable, focus returns to the
invoking control after native UI, errors use a polite live region, and changing
locale preserves focus. The close-to-tray explanation and destructive health
reset require localized confirmation. Native menu items have stable order and
standard keyboard behavior.

Animations honor `prefers-reduced-motion`; there is no pulsing background-health
animation. Long English and Chinese strings, 200% zoom, VoiceOver reading order,
full keyboard navigation, high contrast, denied permissions, unavailable native
services, and hidden/reopened window focus are acceptance cases.

## Diagnostic and privacy policy

Production logs use fixed codes and coarse facets only. They may include a
monotonic generation/count but never raw idle values, event times, user/session
names, access groups, Keychain dictionaries/values, filesystem paths, signing
identities, vault/item/contact data, notification text, or candidates.

A diagnostic activity trace exists only behind the existing development-only
feature or a dedicated test build. It is compiled out of production, stored
under ignored build output, bounded to 1 MiB or 10,000 redacted records
whichever is smaller, and removed after the native run. It records stable event
codes and ordering, not raw activity ages or user content. Native evidence uses
synthetic Keychain namespaces and synthetic vault data. Result ledgers contain
sanitized summaries and hashes, not raw profiles or secrets.

## Threat model and mitigations

| Threat                              | Trigger and impact                                                                                          | Required mitigation and test                                                                                                                                                                      |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Forged/tampered activity input      | Malformed ages, reordering, duplicates, overflow, or Combined-only activity could create a false candidate. | Strict type/range/staleness checks, one monotonic owner, intervening gate read, two HID epochs, clear on contradiction/overflow; property and burst tests.                                        |
| Keychain wrong-item access          | Broad query, duplicate, wrong metadata, or access group could treat an unrelated item as the gate.          | Complete exact query, derive signed access group, request data+attributes, require one result, validate every field/value every read; synthetic wrong-field matrix.                               |
| Locked/unavailable Keychain         | Sleep, lock, session switch, signing mismatch, or Keychain failure could leave a candidate active.          | No UI authentication, fail closed, clear policy/candidate, publish `gate_unavailable`, require fresh baselines; lock/switch/signing native matrix.                                                |
| Worker panic/hang                   | Agent stops sampling while health remains green or plaintext survives.                                      | Unwind profile, `catch_unwind`, sticky health error, supervised stop/join with bounded tests, lock/drop first; injected panic and stalled-worker tests.                                           |
| Event storms/backpressure           | Native callbacks fill memory or block system threads.                                                       | Capacity-32 nonblocking queue, coalescing, sticky overflow error, no callback I/O; rapid burst and disconnect tests.                                                                              |
| Restart/stale replay                | Persisted or queued candidate sends after quit/restart.                                                     | Candidate never persisted, capacity one, 15-minute expiry, fresh process baseline/two epochs, conservative cooldown only; crash/restart tests.                                                    |
| Wall-clock manipulation             | Rollback bypasses cooldown/rate limit or forward jump invents activity/success.                             | Monotonic current-process decisions, tolerance-checked persisted walls, rollback fail-closed, forward jump cannot create candidate/acceptance; clock matrix with approval.                        |
| Health-file tampering               | Symlink/hardlink/special file, partial write, parent swap, corruption, or low disk redirects/loses state.   | Descriptor-relative no-follow validation, owner/mode/link checks, fixed bytes/checksum, exclusive same-dir temp, fsync/rename/fsync, no silent overwrite; hostile-file and fault-injection tests. |
| IPC privilege expansion             | Compromised WebView creates candidates, success, notifications, files, or arbitrary system calls.           | Five exact main-window commands, strict schemas/focus check, private candidate/acceptance boundary, minimal capability/CSP; hostile IPC and capability snapshot tests.                            |
| Autostart persistence abuse         | App silently adds/repairs login item or lies about registration.                                            | Explicit visible action, public `SMAppService`, re-read status, separate desired/observed state, no silent settings open; denial/drift/uninstall tests.                                           |
| Notification privacy leak/spam      | Sensitive content appears on lock screen or repeated stale alerts reveal behavior.                          | Fixed generic localized content, no attachment/deep link/sound, explicit permission, authorized-only, transition plus 24-hour limit; content/rate/denial tests.                                   |
| Remote content/network drift        | New UI or dependency loads scripts/assets or transmits diagnostics.                                         | Strict CSP, no network capability/client/plugin, local frameworks only, dependency/source scans and release inspection.                                                                           |
| Screen Sharing misclassification    | Remote HID is described as physical presence.                                                               | Product language says authenticated remote activity only; native Screen Sharing case and copy review.                                                                                             |
| Sensitive diagnostics               | Raw input, entitlement, Keychain, path, or vault data lands in logs/results.                                | Fixed codes, production trace removal, bounded redacted test trace, automated forbidden-field assertions and cleanup inventory.                                                                   |
| Regression in vault/transfer lock   | Window close, sleep, or quit leaves decrypted state or racing transfer.                                     | Invoke one existing lock/drop/cancel/join boundary before agent shutdown; regression tests across window/session/power paths.                                                                     |
| KDF regression under resident agent | Agent/tray memory or scheduling causes accepted Argon2 profile to miss latency/RSS floor.                   | Exact profile replay under representative release pressure on both machines; no silent parameter change.                                                                                          |

## Verification and evidence plan

### Automated commands after implementation

Run focused Rust and frontend tests first, then:

- `cargo fmt --check` for the affected Rust workspace;
- `cargo clippy` with all production features/targets used by the repository;
- `cargo test` including hostile-file, policy, lifecycle, adapter-mock, and panic
  cases;
- frontend unit/integration/accessibility/i18n tests;
- capability, CSP, dependency-tree, license, lockfile, and remote-origin checks;
- `npm run check`; and
- `npm run desktop:build` for the unsigned host plus the separately approved
  signed release-shaped native bundle.

No test may pass by weakening an assertion, disabling a check, swallowing a
native error, or making the production agent a mock. Framework adapters use
replaceable ports for unit tests; native matrix evidence covers the real APIs.

### Native runbook contract

Before native execution, create a checked-in I08 runbook with one row per
scenario. Every row includes:

- scenario ID, host role, commit/app hash, OS build, Apple Silicon model, and
  sanitized signing class;
- starting app/window/vault/agent/login-item/notification/Keychain state;
- exact action and whether it mutates the system or may prompt;
- expected policy, health facet, window/tray, and persistent-state outcome;
- approval record for that exact disruptive action;
- rollback/cleanup action and final-state proof; and
- redacted artifact identifier/checksum.

Required scenarios include:

- manual launch, login-item launch hidden, open/reopen, close-to-tray, lock,
  controlled quit, forced termination, and relaunch;
- autostart unavailable, enable, approval required, externally disabled drift,
  explicit disable, logout/login verification, and cleanup;
- notification not requested, first prompt, allow, deny, settings revocation,
  authorized generic stale fixture, 24-hour rate limit, and cleanup;
- screen lock/unlock, sleep/wake, fast user switch-out/in, and rapid repeated
  transitions;
- missing, locked, wrong-value, wrong-accessibility, synchronizable,
  wrong-access-group, duplicate, update, and exact-delete synthetic Keychain
  items;
- local input, Combined-only input, two HID epochs, idle transition, Screen
  Sharing activity labeled remote, queue burst, candidate expiry, and no replay
  after restart;
- clock rollback and forward jump with no invented success/candidate;
- corrupt/partial/hostile health record, interrupted write, low disk, and
  explicit reset; and
- localized tray/UI/notification, VoiceOver, keyboard/focus, reduced-motion,
  long-copy, energy, and KDF scenarios.

The matrix runs on the current host and on a separate fully updated Apple
Silicon macOS 15 machine. The floor machine may use an approved development
signature solely for evidence, but its signing class, bundle identifier, and
entitlements are recorded. Evidence from a newer host does not waive the
macOS 15 run.

### Energy budget

After five minutes of release-shaped warmup with the window hidden and no
synthetic activity, measure 15 minutes using platform instruments that expose
CPU, wakeups/timer firings, threads, and RSS. Acceptance:

- activity-agent scheduled samples are 12 per minute and total agent wakeups
  average no more than 18 per minute;
- average process CPU is no more than 0.5%, with no sustained busy-loop plateau;
- RSS grows no more than 5 MiB after warmup; total process RSS is reported
  separately; and
- exactly one worker and expected observer set remain, with no growth across
  window hide/show or sleep/wake cycles.

A miss is investigated before changing the 5-second interval. Any timing
change that alters product semantics returns to review.

### Exact KDF replay

Use the accepted Argon2id profile only: version `0x13`, 262144 KiB, two
iterations, one lane, 32-byte output, fixed synthetic password/salt corpus.
Run three warmups and at least 20 measured derives while the signed
release-shaped app is running its agent/tray, a representative synthetic vault
is open, and a repository-owned fixture holds a bounded 512 MiB allocation.
Record p50/p95, peak RSS, page faults, pressure state, and swap delta.

Acceptance is p50 250–500 ms, p95 no more than 750 ms, peak process RSS no more
than 384 MiB during the derive, and zero swap attributable to the run. The
fixture must release memory and the app must lock/drop the synthetic vault at
cleanup. Failure does not authorize lowering Argon2 parameters; it keeps I08 in
progress and triggers a separate security/migration proposal.

## Cleanup and rollback

Repository rollback before format publication is removal of the I08 source/
manifest/config changes and lockfile entries while retaining result ledgers.
After the health format ships, rollback must continue to recognize version 1
and fail closed; it may not reinterpret or silently discard the file.

Each native run ends by:

- explicitly unregistering the I08 development main-app service and confirming
  it is not registered;
- removing only the exact synthetic notification requests delivered by the
  run, without changing the user's unrelated authorization setting;
- deleting only exact synthetic activity-gate items and confirming the I02
  signing-key item was untouched;
- deleting synthetic health/vault data and bounded traces from the test
  namespace;
- restoring any approved clock change, user/session state, power settings, and
  Screen Sharing state;
- terminating test builds and confirming no worker/helper process remains; and
- recording an inventory proving no launch item, trace, prompt workflow, test
  account, temporary bundle, or synthetic data remains.

If cleanup fails, the iteration remains in progress and the residual exact
item plus manual recovery steps are reported. No broad Keychain deletion,
LaunchServices reset, preference-domain deletion, or recursive application-data
removal is allowed.

## Open approval questions

Approval is requested for the complete proposal, including these material
choices:

1. one in-process supervised worker with a 5-second poll and capacity-32 signal
   queue;
2. the exact activity-gate identity/value/metadata and runtime access-group
   derivation;
3. the 96-byte health format, path, permissions, atomic-write strategy, and
   explicit-only reset;
4. `SMAppService`, Tauri built-in tray, direct UserNotifications bindings, and
   no autostart/notification/single-instance plugins;
5. changing release panic strategy to unwind for worker containment;
6. setting the macOS build floor to 15.0 without making I15 signing/bundle
   decisions;
7. the five exact main-window lifecycle commands and CSP hardening;
8. the generic notification content and 24-hour transition/rate limit; and
9. the two-host native, energy, accessibility/localization, and KDF acceptance
   gates with just-in-time approval for disruptive actions.

## References

- Apple Developer Documentation, `SMAppService`:
  <https://developer.apple.com/documentation/servicemanagement/smappservice>
- Apple Developer Documentation, `mainAppService`:
  <https://developer.apple.com/documentation/servicemanagement/smappservice/mainappservice>
- Apple Developer Documentation, UserNotifications authorization guidance:
  <https://developer.apple.com/documentation/usernotifications/asking-permission-to-use-notifications>
- Apple Developer Documentation, `UNUserNotificationCenter`:
  <https://developer.apple.com/documentation/usernotifications/unusernotificationcenter>
- Apple Developer Documentation, `keyAELaunchedAsLogInItem`:
  <https://developer.apple.com/documentation/coreservices/kaelaunchedasloginitem>
- Apple Technical Note TN3125, macOS Keychain access groups:
  <https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles>
- Tauri 2 documentation, system tray:
  <https://v2.tauri.app/learn/system-tray/>
- Tauri 2 configuration reference, macOS minimum system version:
  <https://v2.tauri.app/reference/config/#macconfig.minimumsystemversion>
- `objc2-service-management` 0.3.2 crate documentation:
  <https://docs.rs/objc2-service-management/0.3.2/objc2_service_management/>
- `objc2-user-notifications` 0.3.2 crate documentation:
  <https://docs.rs/objc2-user-notifications/0.3.2/objc2_user_notifications/>
