# ADR 0001: macOS activity detection

- Status: Proposed — G0 recommends acceptance after the final digest and baseline checkpoint are approved
- Date: 2026-09-21
- Decision owner: G0 architecture and security review
- Evidence: [`../research/I01-macos-activity-results.md`](../research/I01-macos-activity-results.md)

## Context

Aeterna needs a privacy-preserving indication of meaningful activity in the
target macOS login session. Startup, wake, background work, lock-screen input,
session switching, and unlock without later input must not create an activity
candidate. The client must not capture input content, install a global event
tap, or expose raw activity to React.

Apple documents an elapsed-input-age query and workspace notifications for
sleep, wake, session switch-in, and session switch-out. Apple's documented
Window Server session properties do not expose screen lock. Session switch-in
is not equivalent to verified screen unlock. That distinction is necessary to
exclude login-screen credential entry and to open the two-minute post-unlock
input window safely.

I01 is a risk prototype. Its initial 2026-09-20 feasibility result was Blocked:
workspace and Window Server APIs alone did not establish verified lock/unlock.
On 2026-09-21, the user explicitly approved a revised product rule: use a
Data Protection Keychain availability gate, sample both HID and Combined input
sources, require two-stage automatic confirmation, and reject Combined-only
remote or synthetic input by default. The revised implementation completed the
mandatory real-machine matrix subject to the explicit M10 and M13 waivers. M14
showed that Screen Sharing advances both Quartz sources on the target host. On
2026-09-21 the user explicitly clarified that authenticated remote login is
valid user activity; the boundary is therefore HID-class interaction in the
unlocked target session, not proof of local physical presence.

## Proposed decision

Keep three boundaries:

1. A platform-neutral deterministic Rust policy consumes only coarse typed
   observations and monotonic durations. It emits a local activity candidate or
   a fixed suppression reason.
2. A narrow macOS adapter reads a fixed nonsecret Data Protection Keychain
   sentinel, samples both `HIDSystemState` and `CombinedSessionState` elapsed
   input ages with `CGEventSourceSecondsSinceLastEventType`, and observes
   documented `NSWorkspace` session and power notifications. Native ownership
   and unsafe code remain inside this adapter.
3. A development-only diagnostic harness writes redacted, bounded JSON Lines to
   an ignored local artifact. It does not add a WebView command or event bridge.

The policy defaults remain:

- post-unlock input window: two minutes;
- idle-recovery threshold: 30 minutes;
- continuous-use refresh: four hours; and
- candidate cooldown: 30 minutes; and
- two-stage confirmation window: two minutes.

The Keychain sentinel uses `WhenUnlockedThisDeviceOnly`, the Data Protection
Keychain, explicit non-synchronization, and a query that skips authentication
UI. It is separate from all signing keys and contains only a fixed public marker.
The adapter fails closed on lock, missing entitlement, missing or malformed
sentinel data, Keychain unavailability, sleep, switch-out, invalid input ages,
or observer error.

Startup and the first gate-accessible sample establish baselines. After a
locked, sleeping, switched-out, or unknown interval, the first gate-accessible
sample establishes fresh HID and Combined baselines so login-screen credential
input cannot qualify. The first later HID epoch only arms a candidate. Because
the adapter reads HID and Combined ages before it reads the Keychain gate, the
successful gate check at the end of that sample occurs after the first epoch.
Only a distinct HID epoch observed by a later sample confirms the candidate.
Combined-only input never arms or confirms and clears a pending confirmation.

## Supported approaches

- A fixed nonsecret Data Protection Keychain generic-password item as an
  unlock-availability gate. No signing secret, vault key, password, or recovery
  material is queried.
- Quartz elapsed input age for both the hardware-system and combined current
  login-session sources, using the documented any-input event type. Only the
  two numeric ages are retained, and diagnostics round and cap them.
- `NSWorkspace` sleep and wake notifications to clear eligibility across power
  transitions.
- `NSWorkspace` session resign/become-active notifications to fail closed across
  fast user switching. Become-active alone does not establish unlock.
- Rust `Instant`-derived monotonic durations for ordering, cooldown, and all
  policy windows. Wall time is not a policy input.
- RAII observer ownership: remove notification registrations, signal the polling
  worker, and join it before shutdown completes.

## Rejected approaches

- Global keyboard, mouse, HID event, or event-tap monitoring: captures more
  capability than the product needs and may require sensitive permissions.
  Reading the documented aggregate HID-system input age is not an event tap and
  exposes no event content.
- Accessibility, Input Monitoring, Screen Recording, or Automation permission:
  outside the privacy and least-privilege contract.
- Input event objects, key codes, pointer positions, application metadata,
  window titles, URLs, or values: unnecessary and prohibited.
- Undocumented distributed-notification names, private frameworks,
  `CGSSessionScreenIsLocked`, private dictionary keys, or fragile command-output
  parsing: unsuitable for a supported production security decision.
- Treating `NSWorkspaceSessionDidBecomeActiveNotification` as unlock: it means a
  session switched in and cannot prove the screen is unlocked.
- Treating recent input immediately after unlock, or a single later input
  epoch, as activity: either can be credential entry or an unconfirmed action.
- A Swift helper process: increases IPC, lifecycle, packaging, and signing
  surface without providing a documented lock signal.

## Privacy and security consequences

The proposed data is deliberately coarse. The policy sees session/power enums,
a three-state Keychain gate result, monotonic elapsed durations, and two input
age numbers. The diagnostic schema contains fixed codes, separate five-second
HID and Combined age buckets capped at 30 minutes, a coarse source
classification, and a configuration version. It contains no identity, content,
application, window, URL, key, pointer, or native-event field.

No observation is sent over the network or exposed to the WebView. The I01
candidate is not a heartbeat and is not persisted as a successful heartbeat.
Raw diagnostic traces are temporary and Git-ignored; only sanitized scenario
conclusions are committed.

The combined-session input-age source may include synthetic or remote-session
input. Such Combined-only changes are suppressed and disarm confirmation by
default. M14 demonstrated that Screen Sharing also advances the HID source on
the target host. The remote-only sequence entered two-stage confirmation and
was prevented from producing a candidate only by a pre-existing cooldown. This
is accepted behavior because authenticated remote login counts as activity. The
implementation and diagnostics must call this source `hid_class`, not local or
physical hardware input.

## Operational limitations

- A one-second polling interval is proposed for initial measurement. I01 must
  measure idle CPU overhead before recommending an interval.
- Notification callbacks can arrive on framework-controlled threads. Callbacks
  must perform only a bounded send of a coarse enum; policy evaluation and file
  output stay off the callback.
- Lock, wake, session switch-in, and session switch-out reset eligibility and
  require fresh gate and input baselines.
- A gate transition or a single HID epoch never emits a candidate.
- Observer initialization, channel failure, callback contradiction, invalid
  input age, and shutdown failure all fail closed.
- The prototype does not define production macOS version support.
- The prototype reads and validates the sentinel value, but the normal gate
  read does not yet request and validate the persisted accessibility and
  synchronization attributes. I08 must fail closed on unexpected sentinel
  metadata before this adapter becomes a production activity agent.
- Real activity and Keychain evidence currently covers one Apple Silicon host
  on macOS 26.3. The proposed product floor is Apple Silicon macOS 15.0, but
  I08 must replay the activity, lifecycle, fast-user-switch, and sentinel
  metadata matrix on that floor and on the then-current macOS release before a
  support claim is made.

## Feasibility gate

The approved product-rule revision supplies a supported unlock-availability
gate without treating workspace switch-in as unlock. Automated policy tests and
signed target-host evidence validate the boundary. Screen Sharing evidence also
confirms the approved rule that HID-class remote interaction counts while
Combined-only input does not.

This ADR must remain Proposed and I01 must return to Blocked if any mandatory
scenario shows one of the following:

1. the Keychain sentinel remains accessible while the screen is locked;
2. login-screen input survives baseline establishment and can confirm a
   candidate;
3. one HID epoch or a Combined-only epoch emits a candidate;
4. the gate requires a user prompt or a sensitive permission.

## G0 disposition and remaining verification

G0 recommends accepting the activity policy, remote-session semantic, privacy
boundary, and fail-closed lifecycle design. This recommendation does not become
an Accepted ADR until the user approves the G0 digest and the reviewed client
baseline has a recoverable commit reference.

The M10 fast-user-switch scenario and M13 manual wall-clock scenario remain
explicit Phase 0 waivers, not Pass results. I08 owns a real fast-user-switch
run on the minimum supported macOS floor. The deterministic monotonic-clock
tests remain the primary evidence for wall-clock independence; any later manual
run must not weaken that invariant.

- Canonical pinned-toolchain checks and unsigned desktop build pass.
- The macOS adapter starts and stops cleanly with the Tauri lifecycle.
- No prohibited permission prompt appears.
- Idle polling overhead is measured.
- M01-M14 have real, sanitized evidence or an explicit G0 waiver for an
  unavailable or disruptive setup. M14 requires a real remote macOS session and
  cannot be waived by an automated test.
- Source and trace privacy scans find no prohibited field or network path.
- Direct native dependencies are explicitly approved, locked, and documented.
- I08 validates the sentinel's value and security attributes on every
  production read, reruns the minimum-floor and current-release matrices, and
  retains the rule that authenticated remote HID-class interaction is valid
  activity without claiming local physical presence.
