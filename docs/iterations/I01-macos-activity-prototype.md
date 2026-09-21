# I01 — macOS Activity-Detection Risk Prototype

## Objective

Determine whether Aeterna can recognize meaningful activity on macOS without
capturing input content, installing a global event tap, or treating startup,
wake, session switching, or locked-screen interaction as owner activity.

This iteration produces a local-only prototype and evidence. It does not send a
heartbeat, persist a successful heartbeat, or establish a production-supported
macOS version range.

## Why this is a risk prototype

Apple documents APIs for:

- the elapsed time since the most recent keyboard, mouse, or tablet event;
- user-session switch-in and switch-out notifications;
- system and display sleep/wake notifications; and
- a limited set of Window Server session properties.

The documented Window Server properties do not expose a direct screen-lock
property. A session becoming active after fast user switching is also not
automatically equivalent to a screen unlock. The approved recovery design uses
availability of a fixed nonsecret Data Protection Keychain item as the unlock
gate, then requires two distinct HID input epochs separated by a successful
gate check. It also samples Combined input so Combined-only activity can be
rejected. Authenticated remote login that advances HID state counts as activity;
the prototype must not claim that HID age proves local physical presence. The
prototype must prove these properties on a real machine.

Primary references:

- [NSWorkspace notifications](https://developer.apple.com/documentation/AppKit/NSWorkspace)
- [CGEventSourceSecondsSinceLastEventType](https://developer.apple.com/documentation/coregraphics/cgeventsource/secondssincelasteventtype(_:eventtype:))
- [CGEventSourceStateID](https://developer.apple.com/documentation/coregraphics/cgeventsourcestateid)
- [CGSessionCopyCurrentDictionary](https://developer.apple.com/documentation/coregraphics/cgsessioncopycurrentdictionary())
- [Window Server Session Properties](https://developer.apple.com/documentation/coregraphics/window-server-session-properties)
- [Keychain item accessibility](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly)
- [Data Protection Keychain](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain)
- [Tauri state and setup lifecycle](https://v2.tauri.app/develop/state-management/)

## Required reading

- `AGENTS.md`
- `docs/DESIGN.md`: sections 1.2, 3, 5.3, 6, 14, 18.1, and Phase 0 in section 19
- `docs/DEVELOPMENT_PLAN.md`: iteration rules, I01, G0, and known prerequisites
- `README.md`
- `docs/DEPENDENCIES.md`
- The I00 implementation under `src-tauri/` and its current verification scripts

## Preconditions

- I00 remains accepted and the complete baseline checks still pass.
- Development is performed on the current Apple Silicon host running macOS 26.3.
- Raw diagnostic output is local, temporary, ignored by Git, and contains no
  username, device identifier, window title, application name, URL, input value,
  key code, pointer position, or captured event object.
- Before adding a direct native-system dependency, document its purpose,
  maintenance, license, permissions, runtime network behavior, and alternatives,
  then obtain explicit user approval as required by `AGENTS.md`. Pure policy
  code and tests may be prepared before that checkpoint.

## Questions this iteration must answer

1. Can the process read a useful recent-input age without requesting
   Accessibility or Input Monitoring permission?
2. Does the noninteractive Data Protection Keychain sentinel reliably fail
   while locked and become accessible after unlock, including sleep/wake and
   fast-user-switch paths?
3. Does password entry at the lock screen reset HID or Combined input age, and
   does the post-unlock baseline always discard it?
4. What happens when the screen locks without system sleep, and when the system
   wakes while still locked?
5. Do fast user switching, Screen Sharing, and other remote sessions advance
   HID state or only Combined state, and does the classifier apply the approved
   HID-class/Combined-only rule?
6. Can observers start and stop cleanly with the Tauri lifecycle without a
   dangling callback, blocked main thread, or shutdown crash?
7. What polling interval detects first input promptly without high CPU usage or
   creating a behavioral history?

## Required architecture

Keep three boundaries separate:

1. **Policy engine:** a platform-neutral, deterministic Rust state machine that
   consumes coarse observations and a monotonic clock. It decides whether an
   activity candidate would be eligible and why observations are suppressed.
2. **macOS observation adapter:** the smallest native boundary that subscribes
   to supported lifecycle notifications, reads only the fixed nonsecret
   Keychain sentinel, and samples elapsed HID and Combined input ages. All
   native and `unsafe` code stays here, with documented safety invariants and
   focused tests where possible.
3. **Diagnostic harness:** an explicitly development-only mechanism that records
   redacted decisions for manual scenario testing. It must not expose raw native
   callbacks to React or add a general event bridge to the WebView.

The policy engine must fail closed. `locked`, `inactive`, `sleeping`, `unknown`,
missing, contradictory, stale, or failed native observations cannot generate an
activity candidate. One HID epoch only arms a candidate. A later distinct HID
epoch confirms it only after a successful gate check. Combined-only input
suppresses and disarms the pending confirmation.

Use a monotonic clock for durations. Wall-clock changes must not create an
activity candidate or bypass cooldown. The engine may accept injected clocks and
configuration for tests, but the design defaults remain:

- post-unlock input window: 2 minutes;
- idle-recovery threshold: 30 minutes;
- continuous-use refresh: 4 hours;
- candidate cooldown: 30 minutes.

Compressed diagnostic thresholds may be used to exercise long-duration paths,
but they must be visibly labeled as test-only and must not replace the design
defaults.

## Implementation stages

### Stage A — Baseline and API evidence

1. Run the complete I00 checks before changing code.
2. Review the current Apple and Tauri documentation.
3. Inventory supported API candidates and any required native Rust crates.
4. Write the dependency proposal and obtain approval before adding a direct
   native-system dependency.
5. Record the current macOS version, architecture, and permission state without
   recording account or machine identifiers.

### Stage B — Deterministic policy engine

Implement typed observations and decisions sufficient to represent:

- process start;
- session active, inactive, locked, unlocked, and unknown states;
- sleep and wake;
- recent-input-age samples and sample failures;
- monotonic elapsed time;
- emitted activity candidates and explicit suppression reasons.

Do not model network delivery, device binding, signatures, service deadlines, or
server acceptance. The output is only a local `ActivityCandidate` suitable for a
future heartbeat client.

### Stage C — macOS observation adapter

Use supported Apple frameworks to evaluate session, power, Keychain
availability, and recent-input signals. The Keychain item must contain only a
fixed nonsecret marker and use the Data Protection Keychain,
`WhenUnlockedThisDeviceOnly`, non-synchronization, and authentication-UI
suppression. Never query a device signing key as the gate.

Prefer Quartz HID and Combined recent-input ages over event taps. Do not install
keyboard, mouse, HID-event, accessibility, or screen-capture hooks. Do not
request Accessibility, Input Monitoring, Screen Recording, or Automation
permission.

If lock/unlock detection requires an undocumented notification name, private
session key, private framework, or fragile parsing of command output, isolate it
as an experiment only. It cannot satisfy the production feasibility gate and
must be called out as a blocker in the results and proposed ADR.

The adapter must compile on macOS and preserve cross-platform compilation using
`cfg` boundaries and explicit unsupported-platform behavior. The existing CI
uses all Cargo features on Linux, macOS, and Windows, so a diagnostic feature
must not break non-macOS checks.

### Stage D — Local diagnostic harness

Provide one documented command that runs the prototype locally. The harness may
emit structured JSON Lines or another easily reviewed local format containing
only:

- monotonic elapsed duration;
- coarse event or sample type;
- coarse session state;
- rounded or bounded HID and Combined input ages;
- coarse Keychain-gate and input-source classifications;
- candidate/suppression decision and fixed reason code;
- prototype configuration version.

Raw traces must be Git-ignored and deleted or left under an ignored local
artifact directory after summarization. Commit only the scenario matrix and
sanitized conclusions. The React UI must not receive raw input events or a
timeline of user behavior.

### Stage E — Real-machine scenario matrix

Run and document these scenarios on the current host:

| ID | Scenario | Required result |
| --- | --- | --- |
| M01 | Start the application and provide no new input | No activity candidate |
| M02 | Background/system work while the screen is locked | No activity candidate |
| M03 | Lock, interact only with the login screen, and remain locked | No activity candidate |
| M04 | Unlock and provide no input after unlock | No activity candidate |
| M05 | Unlock, then provide input within two minutes | Exactly one eligible candidate |
| M06 | Wake the system and provide no subsequent input | No activity candidate |
| M07 | Wake while locked, then interact only with the login screen | No activity candidate |
| M08 | Recover from a long idle period and provide the first new input | Exactly one eligible candidate |
| M09 | Continue using the session with compressed test-only timing | Refresh is bounded by cooldown |
| M10 | Switch to another local user and back without subsequent input | No activity candidate |
| M11 | Repeat a qualifying input sequence inside cooldown | No second candidate |
| M12 | Stop and restart the observer | Clean shutdown; startup remains non-activity |
| M13 | Move wall clock forward and backward during the run | No duration or cooldown bypass |
| M14 | Connect and disconnect a macOS Screen Sharing or equivalent remote session | HID-class remote interaction counts; Combined-only interaction is suppressed |

The user performs credential entry, lock/unlock, sleep/wake, user switching, and
remote-session actions. The development task must never request, record, or type
an operating-system password.

Unit tests may use synthetic clocks and observations. They cannot replace M02-M08,
M10, and M14, which require real-system evidence. If a second local user or
remote macOS peer is unavailable, mark the relevant evidence missing and the
iteration `Blocked` unless G0 explicitly waives that scenario with the missing
coverage documented; do not reinterpret a waiver as a pass.

### Stage F — Evidence and proposed decision

Create:

- `docs/research/I01-macos-activity-results.md` with environment, API/dependency
  review, sanitized scenario matrix, permission observations, CPU/polling
  measurements, failures, and limitations;
- `docs/adr/0001-macos-activity-detection.md` with status `Proposed`, the supported
  and rejected approaches, privacy analysis, operational limitations, and the
  recommended production contract; and
- updates to `docs/DEPENDENCIES.md` for every approved direct dependency.

Do not mark the ADR `Accepted`; G0 owns architecture approval.

## Required automated tests

At minimum, cover:

- startup never emits a candidate;
- recent input while locked, inactive, sleeping, or unknown is suppressed;
- unlock alone is suppressed;
- post-unlock input inside and outside the two-minute window;
- the first new input after at least 30 minutes idle;
- input before the idle threshold;
- repeated input inside the 30-minute cooldown;
- continuous-use refresh after four hours and suppression before four hours;
- sleep/wake without input;
- switching out/in without input;
- stale, decreasing, non-finite, negative, missing, and failed input-age samples;
- wall-clock changes have no effect on monotonic decisions;
- observer initialization failure and clean shutdown;
- fixed redacted diagnostics that contain none of the prohibited fields;
- non-macOS builds compile with explicit unsupported behavior.

Prefer property tests for ordering and timing invariants if they can be added
without introducing a new dependency; otherwise use table-driven unit tests.

## Out of scope

- Sending or retrying a network heartbeat
- Device registration, device signatures, or heartbeat sequences
- Persisting `last_successful_heartbeat_at`
- Autostart, tray health, or local notifications
- Windows or Linux activity implementations
- Production support guarantees for macOS versions not tested here
- Keychain, device keys, vault cryptography, or recovery
- A production React activity screen or user-history timeline
- Changing the product's timing defaults

## Acceptance criteria

I01 is `Accepted` only when all of the following are true:

1. The platform-neutral policy engine and macOS adapter follow the required
   boundaries and fail closed.
2. No key content, pointer position, application name, window title, URL, event
   object, username, or device identifier is captured, logged, persisted, sent,
   or exposed to the WebView.
3. The prototype uses no global event tap and requests no Accessibility, Input
   Monitoring, Screen Recording, or Automation permission.
4. Startup, wake, screen-locked interaction, session switching, and unlock
   without later input cannot emit a candidate.
5. A real first input after a verified unlock or long idle emits one candidate
   within the designed observation interval and cannot bypass cooldown.
6. M01-M14 have real evidence on the current host or an explicit G0 waiver with
   the missing coverage documented. A waiver is not reported as a pass.
7. Observer startup, callback ownership, thread boundaries, failure handling,
   and shutdown are documented and tested as far as the native API permits.
8. Polling overhead is measured during an idle run and justified; no behavioral
   history is retained after the summarized result is written.
9. Every new direct dependency received explicit approval, is pinned in the
   lockfile, and is documented with maintenance, license, permission, network,
   and alternative analysis.
10. The proposed ADR makes clear whether production implementation is feasible
    using supported APIs. Any reliance on undocumented behavior makes I01
    `Blocked` pending a product or architecture decision.
11. `npm run check` and `npm run desktop:build` pass after the prototype changes.
12. No I02, heartbeat, vault, server, or production activity-agent work is
    included.

## Completion and blocking rules

Update the I01 row and progress log in `docs/DEVELOPMENT_PLAN.md` only after the
evidence is complete:

- mark `Accepted` only when every criterion above passes;
- mark `Blocked` when supported APIs cannot distinguish the required states,
  permissions violate the privacy boundary, required real-machine scenarios are
  unavailable, or a required dependency is not approved; and
- include the exact recovery action for every blocker.

End with a report containing changed files, dependency decisions, automated
commands and results, manual scenario results, measured overhead, permission
prompts observed, privacy scan results, unsupported or undocumented APIs found,
and the ADR recommendation.

Do not start I02 in the same task. Do not commit, push, publish, or deploy unless
the user explicitly requests it.
