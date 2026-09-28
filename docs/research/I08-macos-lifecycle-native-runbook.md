# I08 macOS native validation runbook

## Status and approval boundary

Validation resumed on 2026-09-28, without acceptance. The old checkpoint's
startup and Keychain metadata failures are recorded in the result ledger and
do not qualify the integrated I09-I14 revision. The integrated revision now
passes signed startup on both the macOS 26.3 development host and a distinct
macOS 15.5 Apple Silicon MacBook. Standard-path Login Item registration and
rollback passed on both hosts. The development host's and MacBook's exact
synthetic Keychain gates were deleted with the fixed, signed probe and
independently verified absent at the recorded checkpoint. Later app launches
can recreate them. The remaining native lifecycle cases, full-length named
thread energy count, and final cleanup remain open.
Record further evidence in the result ledger.

Use the validation order in the I08 iteration plan. Do not run another deep
native or performance case while a known implementation issue or repository
check failure is open. Preserve completed evidence and rerun only cases that a
subsequent code change could affect. A diagnostic probe is justified by a
specific uncertainty in a required case; it is not an additional gate.

For the current task, the user explicitly authorized all operations needed to
finish validation on 2026-09-28, superseding the per-step approval procedure
below. Credential entry and acceptance of Apple legal terms remain user-operated.
For later tasks, use the approval procedure below unless the user again gives
equivalent task-specific authorization. Without such authorization, every
numbered mutation below needs a fresh, explicit just-in-time approval
immediately before execution. Approval for implementation alone does not
authorize a Login Item change, notification permission prompt, screen lock,
sleep/wake, user switch, Screen Sharing session, clock change,
signing/profile change, or cleanup mutation. Computer-use rules can still
require confirmation at action time for a permanent deletion or a security
access change, and credentials remain owner-entered.

If preflight finds an existing Aeterna process, stopping that exact process is
a separate approved precondition and is not implicit in approval for the next
numbered step. State the executable path and unsaved-work risk before requesting
termination.

Read-only preflight and automated repository checks may run without native
mutation approval. Record the exact host, OS, architecture, build identity,
start state, end state, and cleanup outcome in the I08 result ledger. Use only
synthetic vault and Keychain material.

## Required environments

Run the complete applicable matrix on:

1. the current Apple Silicon development host; and
2. a distinct Apple Silicon host running the supported macOS 15 floor.

A newer macOS result is not a substitute for the floor host. Without floor-host
evidence, I08 cannot be accepted. Its current status is **In progress**.

## Read-only preflight

Without changing system state:

- confirm the repository revision and clean/expected worktree;
- record `sw_vers`, `uname -m`, Login Items status, notification status, and
  the absence/presence of the synthetic activity-gate item without printing
  its value or access group;
- build the release-shaped unsigned host and record its bundle identifier,
  minimum system version, capabilities, CSP, linked frameworks, and signing
  state;
- verify a signed candidate in the host trust context with
  `codesign --verify --deep --strict`, use
  `codesign -d --entitlements -` to inspect its modern entitlement blob, and
  confirm `Contents/MacOS` contains only the main executable;
- confirm the test vault contains only synthetic content; and
- confirm no Aeterna process, transfer, or prior native fixture is active.

Do not use the deprecated `codesign -d --entitlements :-` spelling. On current
macOS it can misreport valid DER entitlements as invalid. A sandboxed signature
check can also report `CSSMERR_TP_NOT_TRUSTED` when the host identity and trust
settings are unavailable; the authoritative strict verification must run in
the host trust context.

## Mutation steps requiring separate approval

Request approval for one step at a time. Before each request, state the exact
command or UI action, expected prompt/side effect, rollback, and evidence to be
captured. Do not combine approvals.

1. **Synthetic Keychain gate creation.** Launch the release-shaped app and
   allow it to create only service `aeterna.desktop.activity-gate.v1`, account
   `unlock-availability`. Verify value and full metadata through the same
   signed test bundle's fixed `--i08-gate-probe metadata` action. The
   `i08-native-probe` feature is permitted only for this test bundle and adds
   no IPC or configurable Keychain query. Roll back later with its fixed
   `--i08-gate-probe delete` action, which first validates the complete item,
   deletes only the exact identity, and verifies not-found afterward.
2. **Login Item enable.** Use the visible, focused Aeterna control once. Record
   `SMAppService` before/after state and any approval-required state. Roll back
   with the Aeterna disable control.
3. **Login Item approval/settings navigation.** If macOS requires approval,
   use the Aeterna Open Login Items action and make only the exact Aeterna
   change. Roll back to the recorded initial state.
4. **Login launch/logout cycle.** End the test session only after approval.
   Verify a single hidden process, tray availability, locked vault, no stale
   candidate, and manual reopen focus. Restore the original session state.
5. **Notification first-use prompt.** Invoke only from the visible focused
   Aeterna action. Test authorization on a reset test profile. Restore the
   profile/authorization state when the environment supports it.
6. **Notification denial and Settings change.** Deny once, verify no repeated
   prompt and truthful status, then separately approve a Settings change and
   verify status refresh. Restore the initial authorization state.
7. **Window/tray/quit lifecycle.** With synthetic unsaved edits and transfers,
   exercise cancel/save/discard close paths, lock, reopen, quit, and relaunch.
   Verify transfers join, WebView content is cleared, and the vault reopens
   locked. Remove generated exports/import staging artifacts.
8. **Screen lock/unlock.** Lock the screen, verify the gate fails closed and
   the vault/candidate clear, then unlock and verify a fresh baseline. Restore
   the unlocked test session.
9. **Sleep/wake.** Sleep the host, verify pre-sleep locking and post-wake fresh
   baselines. Restore the original power state.
10. **Fast user switch.** Switch out and back using a synthetic secondary test
    user. Verify immediate lock and no cross-session candidate. Remove the test
    user only if its creation/removal was separately approved.
11. **Screen Sharing.** Use a named synthetic remote session, record Quartz
    source behavior, and verify it never becomes a physical-presence claim.
    End the remote session and remove only its test artifacts.
12. **Wall-clock change.** Record the authoritative time source, apply one
    bounded test offset, verify policy remains monotonic and health future-time
    validation fails closed, then restore automatic time and verify it.
13. **Keychain negative metadata.** Using only a disposable test identity,
    exercise inaccessible, missing, wrong-value, wrong-service/account,
    synchronizable, access-group, and accessibility mismatches. Restore/delete
    every exact fixture.
14. **Rapid lifecycle/input burst.** Run the bounded synthetic event harness,
    verify queue overflow becomes `agent_error`, vault lock, candidate drop,
    and clean recovery. Stop and remove the harness.
15. **Energy measurement.** After warmup, measure a hidden-window idle signed
    release-shaped process for 15 minutes. Target at most 0.5% average CPU, at
    most 30 agent wakeups/minute, no sustained polling leak, and no more than
    5 MiB RSS growth.
16. **Exact Argon2 replay.** With the approved synthetic pressure fixture,
    replay version `0x13`, 262144 KiB, two iterations, one lane, 32-byte output,
    three warmups, and at least 20 samples. The repository-owned
    `i08_memory_pressure` engineering binary fills exactly 512 MiB with
    synthetic bytes, locks the allocation in physical memory, and verifies its
    checksum after one byte arrives on stdin or stdin closes. Confirm
    `pressure_locked=true`, stable process RSS, `pressure_released=true`, and
    process exit at cleanup. The existing
    `i02_argon2_benchmark E` engineering binary supplies the fixed synthetic
    password/salt and 3/20 derive counts. Measure each process separately and
    record page faults, swap delta, pressure state, and the app's vault/agent
    state. Do not change stored parameters.
17. **Cleanup.** Disable/restore the Login Item, restore notification and clock
    state, terminate test sessions, delete only exact synthetic Keychain and
    file fixtures, and verify the final state matches preflight.

Any unexpected prompt, identity, filesystem target, or external recipient
stops the step. Record the failure without broadening permissions or cleanup
scope.
