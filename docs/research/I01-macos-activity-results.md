# I01 macOS activity-detection results

Status: **Accepted**  
Initial research date: 2026-09-20  
Revised-design validation date: 2026-09-21  
Decision input: [ADR 0001](../adr/0001-macos-activity-detection.md)

## Current outcome

The initial I01 design was blocked because supported workspace and Window Server
APIs do not expose verified screen lock/unlock. On 2026-09-21 the user
explicitly approved a revised product rule:

- use availability of a fixed nonsecret Data Protection Keychain item as the
  unlock gate;
- sample both Quartz HID-system and Combined-session input ages;
- require two distinct HID input epochs separated by a successful gate check;
  and
- suppress Combined-only remote or synthetic input by default.

The revised implementation, automated policy tests, signed feature build, and
real-machine matrix are complete. M14 demonstrated
that macOS Screen Sharing input advances both sampled Quartz sources and can
traverse the qualifying HID path. On 2026-09-21 the user explicitly clarified
that remote login is valid activity. The product boundary is therefore
HID-class interaction in the unlocked target session, not proof of local
physical presence.

## Implemented boundary

The feature-gated adapter keeps native behavior inside Rust:

1. It samples `HIDSystemState` and `CombinedSessionState` ages without an
   event tap or native event object.
2. It then reads a generic-password sentinel from the Data Protection Keychain.
   The item uses a dedicated I01 service/account,
   `WhenUnlockedThisDeviceOnly`, non-synchronization, and authentication-UI
   suppression. Its fixed marker is public and unrelated to device-signing or
   vault secrets.
3. One atomic coarse sample is sent to the deterministic policy. Reading input
   ages before the gate means that the successful gate check at the end of the
   first HID sample occurs before any later distinct HID epoch can confirm it.
4. Documented workspace sleep/wake and switch-in/switch-out notifications clear
   eligibility. Switch-in never represents unlock by itself.

Startup establishes baselines and cannot emit a candidate. A locked,
inaccessible, unavailable, missing, or malformed gate; sleep; switch-out;
invalid age; stale sample; observer failure; or shutdown clears the pending
confirmation. The first gate-accessible sample after such a transition replaces
both input baselines, excluding login-screen credential input.

The first later qualifying HID epoch only arms a candidate. A second distinct
HID epoch confirms it within the two-minute confirmation window. Combined-only
input is always suppressed and clears the pending confirmation. Post-unlock,
30-minute idle-recovery, four-hour continuous-use, and 30-minute cooldown
decisions use monotonic time only.

## Supported API evidence

| API                                                                                 | Use                                            | Finding                                                                                                                                                                                                                                                                   |
| ----------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kSecUseDataProtectionKeychain` with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Nonsecret unlock-availability gate             | Apple's public contract makes the item data available only while the device is unlocked. The previously accepted I02 signed-host matrix observed locked denial and recovery of the same item after unlock. I01 uses a separate public sentinel, never the signing secret. |
| `kSecUseAuthenticationUI` with `kSecUseAuthenticationUISkip`                        | Prevent authentication UI                      | Gate reads fail rather than prompting.                                                                                                                                                                                                                                    |
| `CGEventSourceSecondsSinceLastEventType` with `HIDSystemState`                      | HID-class input age                            | Returns only an aggregate age and requires no event tap or input content. M14 proved that Screen Sharing also advances this state on the target host; authenticated remote HID-class interaction intentionally counts.                                                    |
| The same Quartz API with `CombinedSessionState`                                     | Detect broader session input                   | A Combined-only change is classified and suppressed.                                                                                                                                                                                                                      |
| `NSWorkspace` sleep/wake and session activity notifications                         | Clear eligibility across lifecycle transitions | Documented and retained. Become-active remains only a switch signal, not unlock proof.                                                                                                                                                                                    |

The documented Window Server session dictionary still has no lock field.
Undocumented notifications, private session keys, private frameworks, global
event taps, Accessibility, Input Monitoring, Screen Recording, Automation, and
command-output lock parsing remain rejected.

## Privacy and diagnostics

The prototype sends no network heartbeat, persists no successful heartbeat,
and exposes no activity data to the WebView. The local JSON Lines trace remains
under the ignored `src-tauri/target/i01-diagnostics` directory.

Each current v3 record contains only:

- monotonic elapsed milliseconds;
- a fixed event code and coarse session state;
- `accessible`, `locked`, `unavailable`, or `not_sampled` gate state;
- separate five-second HID and Combined age buckets capped at 30 minutes;
- `hid_class`, `combined_only`, `none`, `invalid`, or
  `not_applicable` source classification;
- a candidate/suppressed decision and fixed reason; and
- the `i01-keychain-hid-v3` or visibly compressed test configuration label.

The signed matrix was captured with the behaviorally identical v2 diagnostic
label and source code `hardware`. Those terms were renamed in v3 after M14 to
avoid implying that Quartz proves local physical presence.

It contains no username, device identifier, application name, window title,
URL, input value, key code, pointer position, native event object, password,
secret, Keychain payload, or signing identity. No permission prompt appeared in
the signed startup run.

## Automated verification

The activity module currently has 22 focused tests. They cover:

- startup and unlock baselines;
- login-screen credential exclusion;
- locked and unavailable gates;
- two-stage post-unlock, idle-recovery, and continuous-use confirmation;
- Combined-only suppression and disarming;
- confirmation expiry and candidate cooldown;
- sleep and inactive-session failure;
- malformed, stale, future, and decreasing samples;
- wall-clock independence;
- diagnostic redaction and bounds; and
- prompt idempotent observer shutdown.

The final canonical pinned-toolchain `npm run check` passed on 2026-09-21 after
the matrix and semantic closeout. It included formatting, ESLint, strict
TypeScript, 7 frontend tests, the production frontend build and local-asset
scan, Clippy with warnings denied, 47 Rust tests, and all-target/all-feature
Rust checking. `npm run desktop:build` also produced the release host
executable. Its known non-fatal `rust-objcopy`/`libLLVM.dylib` stripping warning
remained.

## Signed-host evidence

The current feature-enabled debug bundle was built with the approved private
development App ID, embedded time-limited provisioning profile, and existing
Apple development signing identity. Strict deep signature verification passed.
No identity value or profile identifier is recorded here.

On first launch, the gate sentinel was created and immediately re-read. The
first trace sample reported an accessible gate and established input baselines;
startup and the following quiet interval emitted no candidate. This satisfies
M01 for the revised adapter. The first lock cycle also proved that login-screen
input advanced both input ages while the Keychain gate remained locked, then
unlock established a fresh baseline. The next HID epoch armed confirmation and
a later distinct HID epoch produced exactly one post-unlock candidate. This
satisfies M03 and M05. The prototype remains network-local and sends no
heartbeat.

A second lock cycle retained the locked gate across background samples, ignored
login-screen input, established a fresh unlock baseline, and produced several
no-new-input samples before later interaction. That evidence satisfies M02 and
M04. The later two-HID sequence was correctly rejected by the still-active
default cooldown, satisfying M11.

The previous one-second polling measurement was 0.0%-0.7% CPU and approximately
32 MiB memory on the same Apple Silicon host. Three samples of the signed debug
compressed-timing process after the sustained interactive matrix measured
0.0%-0.1% CPU and 84.6 MiB RSS. The debug figure is evidence for prototype
overhead, not a production memory target.

The revised observer then stopped cleanly with a terminal `observer_stopped`
record and no remaining process. A newly signed compressed-timing bundle
restarted as one observer, selected the explicit compressed configuration, and
established a new accessible startup baseline without a candidate. This
satisfies M12 without carrying eligibility across processes.

After the terminology correction, a freshly bundled v3 app was embedded with
the approved development profile, signed with the existing development
identity, and passed strict deep signature verification. Its signed-host startup
trace used `i01-keychain-hid-v3` and again established only an accessible input
baseline without a candidate.

In the compressed-timing run, a quiet interval advanced both input-age buckets
well beyond the 20-second idle threshold. The first later HID-class epoch only
armed confirmation; the next sampled epoch emitted exactly one
`idle_recovery` candidate. Later input before the 30-second cooldown expired
was suppressed, satisfying M08 and providing additional cooldown evidence.

The user then maintained HID-class activity under the same compressed
configuration. Once the 20-second continuous-use threshold was exceeded, a
confirmed pair inside the existing cooldown was suppressed. A later pair after
the cooldown expired emitted `continuous_use_refresh`; continued activity
remained subject to the same two-stage and cooldown rules. This satisfies M09.

For M14, the user connected remotely, performed all input from the remote Mac,
and confirmed that nobody touched the target Mac's mouse, keyboard, or trackpad.
The v2 target trace classified those samples as `hardware`: both HID-system and
Combined-session ages advanced. Remote input armed two-stage confirmation and
reached `candidate_cooldown`; only the pre-existing cooldown prevented a
candidate in that interval. The user explicitly confirmed that remote login
counts as activity, so this satisfies M14. V3 renames the classification to
`hid_class` and makes no local-physical claim.

## Real-machine scenario matrix

`Pass` means the revised signed adapter produced the required host trace.
`Waived` means the user explicitly accepted a documented host-environment
blocker without treating an automated test as real-machine evidence. `Pending`
means further user action or a remote peer is still required. Deterministic
tests do not substitute for these runs.

| ID  | Scenario                                                           | Result | Revised evidence / remaining action                                                                                                                                      |
| --- | ------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| M01 | Start the application and provide no new input                     | Pass   | Signed v2 startup established accessible gate/HID/Combined baselines and emitted no candidate during the quiet interval.                                                 |
| M02 | Background/system work while the screen is locked                  | Pass   | A repeated locked interval produced multiple locked-gate samples while input ages advanced normally; every sample was suppressed.                                        |
| M03 | Lock, interact only with the login screen, and remain locked       | Pass   | HID and Combined ages reset while the gate stayed locked for later samples; every locked sample was suppressed.                                                          |
| M04 | Unlock and provide no input after unlock                           | Pass   | Unlock established a new baseline, followed by multiple no-new-input samples and no candidate before later interaction.                                                  |
| M05 | Unlock, then provide input within two minutes                      | Pass   | Unlock established a new baseline; the first distinct HID epoch armed confirmation and the next distinct epoch emitted exactly one candidate.                            |
| M06 | Wake the system and provide no subsequent input                    | Pass   | Apple-menu sleep produced `will_sleep` then `did_wake`; wake stayed locked, unlock established a fresh baseline, and the following quiet interval emitted no candidate.  |
| M07 | Wake while locked, then interact only with the login screen        | Pass   | After `did_wake`, Combined-only and later HID changes occurred while the gate remained locked; all were suppressed until unlock replaced the baselines.                  |
| M08 | Recover from a long idle period and provide new input              | Pass   | With the compressed label visible, a long quiet interval was followed by one pending HID epoch and one confirmed `idle_recovery` candidate.                              |
| M09 | Continue using the session with compressed test-only timing        | Pass   | Sustained HID-class input crossed the 20-second threshold; confirmation was first cooldown-suppressed, then emitted `continuous_use_refresh` after cooldown.             |
| M10 | Switch to another local user and back without subsequent input     | Waived | The host has no second local account; on 2026-09-21 the user explicitly approved skipping this unavailable real-machine scenario.                                        |
| M11 | Repeat a qualifying sequence inside cooldown                       | Pass   | A later post-unlock two-HID sequence armed normally, but confirmation was suppressed by `candidate_cooldown` because M05 remained inside the default cooldown.           |
| M12 | Stop and restart the observer                                      | Pass   | The revised observer emitted `observer_stopped`, exited with no remaining process, then restarted once with a fresh baseline and no carried candidate.                   |
| M13 | Move wall clock forward and backward during the run                | Waived | Automated monotonic tests pass; on 2026-09-21 the user explicitly approved skipping the disruptive manual system-time change.                                            |
| M14 | Connect and disconnect Screen Sharing or equivalent remote session | Pass   | Confirmed remote-only input advanced HID and Combined and entered two-stage confirmation, matching the approved rule that authenticated remote login counts as activity. |

No test asks for, types, captures, stores, or records an operating-system
password. Credentialed, system-time, local-user, and remote-session actions are
manual user responsibilities.

## Historical blocked result

The 2026-09-20 implementation used only Combined-session age plus workspace
notifications. M01 and M12 passed, but lock-dependent scenarios were blocked
because switch-in could not prove unlock. That failure remains valid evidence:
the revised implementation does not reinterpret switch-in. It introduces the
explicitly approved Keychain availability gate and stricter two-stage HID rule.

## Acceptance boundary

I01 is Accepted. M10 and M13 have explicit user waivers rather than false pass
results. M14 passes under the clarified product semantic that authenticated
remote login counts as activity. The implementation must be described as
detecting HID-class interaction in an unlocked target session and must not be
described as proving local physical presence. ADR 0001 remains Proposed for G0
architecture and security review.
