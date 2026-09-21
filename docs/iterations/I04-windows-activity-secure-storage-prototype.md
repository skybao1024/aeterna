# I04 — Windows Activity and Secure-Storage Risk Prototype

## Objective

Determine whether Aeterna can implement its accepted activity-candidate policy
and device-signing-secret storage contract on a supported Windows client using
only documented Microsoft APIs, without capturing input content, installing
global hooks, broadening application privileges, or adding a plaintext fallback.

I04 is a local risk prototype. It does not send a heartbeat, persist a vault,
freeze the production Windows lifecycle, or establish support beyond the exact
Windows editions and builds that are tested.

## Required reading

- `AGENTS.md`
- `docs/DESIGN.md`: sections 3, 4.1, 6, 8.1, 10.2-10.3, 13-15, 17.1-17.2,
  18.1, and Phase 0 in section 19
- `docs/DEVELOPMENT_PLAN.md`: iteration rules, I04, GW, verification ownership,
  and known prerequisites
- `docs/iterations/I01-macos-activity-prototype.md`
- `docs/iterations/I02-crypto-secure-storage-prototype.md`
- `docs/adr/0001-macos-activity-detection.md`
- `docs/adr/0002-cryptographic-envelope-and-key-storage.md`
- `docs/research/I01-macos-activity-results.md`
- `docs/research/I02-crypto-results.md`
- `docs/DEPENDENCIES.md`, manifests, lockfiles, adjacent Rust modules, and tests

## Scope

The activity prototype must implement the existing platform activity boundary
behind `cfg(target_os = "windows")`. It must observe documented target-session
login, lock/unlock, console and remote connect/disconnect, fast-user-switch,
sleep, and resume transitions. It may sample only a coarse elapsed age for the
last input in the process's Windows session.

The secure-storage prototype must implement `DeviceSecretStore` with Windows
Credential Manager, or a demonstrably stronger supported Windows store approved
at the dependency checkpoint. It must cover create, read, duplicate create,
replace, delete, repeated delete, not found, metadata, restart continuity,
identity separation, and cleanup for a synthetic 32-byte signing secret.

The implementation may add development-only probes and a temporary per-user
autostart exercise. It must not implement the I08 production agent, installer,
tray behavior, updater, or startup user experience.

## Privacy and security boundaries

- Never collect or retain key values, mouse coordinates, input device details,
  raw input, window titles, application names, URLs, clipboard data, input
  content, native input events, usernames, domains, remote addresses, or
  sensitive paths.
- Do not install a keyboard, mouse, low-level, event, or raw-input hook. Do not
  request UIAccess, administrator, accessibility, screen-capture, input-capture,
  service, or broad session-enumeration privileges.
- The activity adapter may read only the process's target session ID, coarse
  connection/lock state, local-versus-RDP classification, and elapsed input age.
  It must ignore notifications for every other session.
- Diagnostics are fixed-schema, bounded, redacted, local-only, and temporary.
  They contain monotonic elapsed time, coarse event/state codes, a rounded input
  age, decision codes, and a configuration version. They are never sent to the
  WebView or network.
- The Windows credential target is application-specific and device-specific.
  It is never logged. The credential blob is exactly the bounded signing-secret
  size and is zeroized in application-controlled buffers as soon as practical.
- Credential storage is not an unlock detector. The activity adapter must use
  Windows session state, never availability of the signing credential, as its
  unlock gate.
- There is no fallback to files, registry values, environment variables,
  SQLite, browser storage, legacy APIs, or another credential manager.
- The user performs every credentialed lock/unlock, sign-in, user-switching,
  system-time, sleep/wake, and Remote Desktop action. The probe never requests,
  receives, types, stores, or records the user's Windows password or PIN.

## Mandatory dependency and design approval checkpoint

Before changing source, `Cargo.toml`, `Cargo.lock`, Tauri configuration,
capabilities, Windows application manifests, permissions, persistence formats,
or production behavior:

1. Prepare `docs/research/I04-windows-dependency-proposal.md` from official
   Microsoft documentation and the primary Rust binding sources.
2. Record exact versions and features, maintenance, license, transitive impact,
   system libraries, unsafe/native boundaries, privileges, storage and network
   behavior, alternatives, and the reason existing direct dependencies are
   insufficient.
3. Define the session/input approach, Credential Manager item policy,
   cross-platform storage metadata, development autostart mechanism, error
   mapping, and known semantic limitations.
4. Obtain explicit user approval for the combined proposal in this task.

Documentation and dependency-free test planning may proceed while approval is
pending. Native implementation may not.

## Deferred real-Windows validation gate

The author has directed that interactive Windows testing wait until the complete
application is available. The current implementation checkpoint may therefore
proceed after dependency/design approval without an attached Windows host, but
it must run and pass the canonical macOS regression suite and may not describe
untested Windows behavior as passing.

Final I04 acceptance still requires a real interactive Microsoft-supported
Windows 11 client
with current security updates. A VM is acceptable only if it exposes genuine
Windows lock, sleep/resume, fast-user-switch, Credential Manager, and Remote
Desktop behavior and the user can operate those flows interactively. macOS,
Wine, cross-compilation, CI, mocks, unit tests, and an SSH-only shell are not
functional acceptance evidence.

Before the deferred matrix is eventually run, record without machine
identifiers or account data:

- Windows edition, version, OS build, and architecture;
- physical or virtual host category;
- local console versus RDP execution;
- exact Node, npm, Rust, Cargo, and Tauri versions;
- debug or release mode and packaged, signed, or unpackaged identity; and
- relevant policy restrictions or permission prompts.

Evidence supports only the exact tested builds. GW owns the eventual minimum
supported Windows version.

## Required architecture

Keep these boundaries separate:

1. **Shared policy:** retain the platform-neutral monotonic state machine,
   two-distinct-input-epoch confirmation, post-unlock window, idle recovery,
   continuous-use refresh, and cooldown. Do not duplicate policy in the Windows
   adapter or weaken it for a platform limitation.
2. **Windows observation adapter:** isolate the supported Win32 calls, window
   procedure, raw pointers, allocated native buffers, registration ownership,
   and cleanup. Convert native observations immediately into coarse typed data.
3. **Windows credential adapter:** isolate Credential Manager identities,
   blobs, error codes, zeroization, and native allocations behind
   `DeviceSecretStore`.
4. **Development probes:** expose only fixed action names and synthetic values.
   Probes must not accept secrets or identities as command-line arguments.
5. **Diagnostic harness:** write a bounded trace below the ignored Cargo target
   directory. It must not create a React command or generic event bridge.

Windows must establish a fresh input baseline on process start and after every
lock, unlock, login/logoff, console or remote connection boundary, session
uncertainty, suspend/resume boundary, native error, or observer restart.
Startup, unlock alone, wake alone, a session transition alone, and activity
while locked or disconnected never emit a candidate.

The adapter must fail closed if session state, target session identity, input
age, event ordering, or native API behavior is missing, inconsistent, stale, or
unsupported. Wall time is not a policy input.

Microsoft documents `GetLastInputInfo` as session-specific, but also documents
that its tick can be non-incremental and can be supplied by `SendInput`. The
prototype must not rename that signal as physical or authenticated HID input.
If supported APIs cannot reject injected input without a prohibited hook or raw
input capture, the corresponding activity requirement is Blocked and requires
an explicit GW design decision; a two-epoch sequence does not cure provenance.

## Implementation stages

### Stage A — Baseline, research, and approval

1. Inspect the current uncommitted baseline without resetting or cleaning it.
2. Run the canonical suite on the current host and record limitations.
3. Research only documented Microsoft APIs and maintained primary Rust binding
   sources.
4. Create the combined proposal and Proposed ADR.
5. Obtain explicit dependency/design approval before native source changes.
6. Record that real-Windows validation is intentionally deferred by the author
   and is not a current source-work prerequisite or a passing result.

### Stage B — Cross-platform contracts and deterministic tests

Narrowly generalize any macOS-specific storage metadata or activity diagnostic
names. Preserve macOS behavior with focused regression tests. Add deterministic
tests for all Windows event mappings, fresh-baseline boundaries, target-session
filtering, invalid ages, tick wrap/regression, missing or failed native state,
remote classification, duplicate storage operations, bounds, redaction, and
cleanup state.

### Stage C — Windows activity adapter

Use a dedicated invisible native window on an owned thread for documented
session and power messages. Register for the window's own session, filter every
message by the captured target session ID, sample only current-session input
age, and re-query coarse session state before eligibility. Registration,
unregistration, window destruction, thread stop, and callback ownership must be
deterministic and idempotent.

### Stage D — Windows Credential Manager adapter

Use a generic credential with local-machine persistence for the current user's
credential set and a fixed application/device target. Verify the platform
supports the required persistence before writing. Validate type, target,
persistence, blob length, and absence of unexpected attributes on reads.
Zeroize the returned blob before releasing its native allocation. Map expected
Windows errors to fixed non-sensitive codes and fail closed on everything else.

Because `CredWriteW` is an upsert, duplicate-safe create and existing-only
replace behavior must be tested explicitly and their concurrency limitation
must be documented. Do not claim native atomic create-only semantics that the
API does not provide.

### Stage E — Development probes and autostart

Provide fixed commands for the activity trace and credential matrix. A
development-only per-user autostart exercise may install one clearly named
temporary `HKCU` `Run` value pointing to the exact probe executable with a fixed
argument. It must require an explicit install action, report no path, implement
an idempotent remove action, and be removed immediately after the restart test.
It is not the I08 production autostart design.

### Stage F — Real-Windows matrices

Deferred until the complete application is available. Then run every matrix
item below on the connected host. The user performs privileged or credentialed
interactions. Preserve only sanitized conclusions; delete raw traces after
summarization. Until then every matrix item remains `Not run`.

### Stage G — Evidence and closeout

For the current checkpoint, record implementation and macOS regression results,
update the Proposed Windows ADR, and add approved dependency documentation.
After the deferred Windows matrix, complete the platform evidence. Update the
I04 plan row and progress log only when the evidence supports `Accepted` or
`Blocked`.

## Required real-Windows activity matrix

| ID  | Scenario | Required result |
| --- | --- | --- |
| W01 | Cold startup and normal restart | Fresh baselines only; no candidate |
| W02 | Locked background or system work | No candidate |
| W03 | Login-screen interaction while remaining locked | No candidate |
| W04 | Unlock with no later input | No candidate |
| W05 | Unlock followed by qualifying input within the configured window | Exactly one candidate after two distinct eligible epochs |
| W06 | Sleep/wake with no later input, including wake while locked | Fresh baseline; no candidate |
| W07 | Long idle followed by new input | One candidate only after required confirmation |
| W08 | Continuous use with visibly compressed test timing | Refresh follows shared policy and cooldown |
| W09 | A second qualifying sequence inside cooldown | No duplicate candidate |
| W10 | Fast user switch away and back | Other-session activity is rejected; target session needs a fresh baseline |
| W11 | Authenticated RDP connect, use, disconnect, and reconnect | Transitions are observed; target-session remote input follows the approved remote rule |
| W12 | Observer/process stop and restart | Registrations are removed; no ghost event or carried candidate |
| W13 | Wall clock moved forward and backward | Monotonic decisions and cooldown are unchanged, or the user grants an explicit labeled waiver |
| W14 | Development-only per-user autostart | Startup creates only a fresh baseline and the temporary registration is removed |
| W15 | Documented synthetic input negative case | It fails closed, or I04 is Blocked pending an explicit GW design change |

## Required real-Windows credential matrix

| ID  | Scenario | Required result |
| --- | --- | --- |
| C01 | Create synthetic device signing item | Succeeds without secret or target output |
| C02 | Restart process and retrieve/sign | Same public key verifies a new signature |
| C03 | Duplicate create | Fails as already exists without replacing the item |
| C04 | Wrong device identity | Not found; no fallback |
| C05 | Intentional replace | Public key changes and persists; old key no longer signs |
| C06 | Delete, repeated delete, and read | Deleted, not found, and not found respectively |
| C07 | Lock/unlock while probe remains alive | Actual access behavior is observed without treating it as the activity gate |
| C08 | Different Windows user / fast-user-switch session | Cannot read the target user's item |
| C09 | Metadata inspection | Generic type, exact blob size, local-machine persistence, and non-enterprise roaming are confirmed |
| C10 | Debug-to-release continuity | Behavior is recorded for the same application target and user |
| C11 | Policy-disabled, access-denied, invalid, and interrupted paths where safely reproducible | Fixed fail-closed classifications; no fallback |
| C12 | Final cleanup | Repeated delete reports not found and no development item remains |

## Required automated verification

At minimum, cover:

- every Windows session message mapping and unrelated-session rejection;
- startup, unlock, wake, reconnect, switch-in, and observer restart baselines;
- locked, disconnected, inactive, sleeping, unknown, and failed-state rejection;
- two distinct eligible epochs for post-unlock, idle, and continuous-use paths;
- cooldown, confirmation expiry, stale observations, regressions, tick wrap,
  invalid lengths, and wall-clock independence;
- observer partial-initialization cleanup, repeated stop, channel closure, and
  failure to register or unregister;
- fixed diagnostic schema, bounded ages, fixed English codes, and prohibited
  field/source scans;
- storage identity construction and redacted formatting;
- 32-byte secret bounds, malformed returned credentials, wrong type,
  unexpected persistence, not found, access denied, session unavailable, and
  unknown error mapping;
- sequential create/read/duplicate/replace/delete behavior and interruption
  around native calls;
- zeroization of Rust-owned copies and accurate documentation of native-copy
  limitations;
- explicit unsupported behavior on non-Windows/non-macOS platforms; and
- unchanged macOS policy and Keychain tests.

On Windows run the pinned-toolchain focused tests, `npm run check`,
`npm run desktop:build`, and the exact probe commands recorded in the results.
Compilation or CI alone is not functional acceptance.

## Deliverables

- `docs/iterations/I04-windows-activity-secure-storage-prototype.md`
- `docs/research/I04-windows-dependency-proposal.md`
- `docs/research/I04-windows-results.md`
- a Proposed Windows activity and secure-storage ADR
- approved `cfg(target_os = "windows")` adapters and development probes
- deterministic policy, lifecycle, storage, redaction, and cleanup tests
- `docs/DEPENDENCIES.md` updates for approved direct dependencies
- `README.md` probe instructions after implementation
- `docs/DEVELOPMENT_PLAN.md` outcome update only after evidence is complete

## Acceptance criteria

I04 is finally `Accepted` only when all of the following are true. The current
implementation checkpoint may complete with Windows verification explicitly
deferred, but that checkpoint is not I04 acceptance.

1. The combined dependency/design proposal received explicit approval before
   native source, manifests, lockfiles, permissions, or persistence changed.
2. A real supported interactive Windows host ran the complete activity and
   credential matrices; no mock, CI, cross-build, Wine, or inferred behavior is
   labeled as a pass.
3. Windows differences remain inside narrow adapters. Shared policy stays
   authoritative and macOS behavior does not regress.
4. Startup, unlock, wake, session switching, reconnect, locked activity, and
   other-session activity cannot independently emit a candidate.
5. Qualifying activity still requires two distinct epochs separated by a
   successful target-session gate check and remains bounded by cooldown.
6. The input signal's provenance is described truthfully. If injected input
   can qualify under supported APIs, the requirement is Blocked unless an
   explicit approved design change replaces it.
7. Authenticated RDP behavior matches the approved remote-activity rule and is
   never misrepresented as local physical presence.
8. No prohibited input or identity data is captured, logged, persisted, sent,
   or exposed to the WebView; no sensitive permission or global hook is added.
9. Credential Manager behavior passes C01-C12 with no plaintext fallback, no
   secret output, accurate metadata, and proven cleanup.
10. Windows Credential Manager protection and lock behavior are documented
    separately from macOS Keychain semantics and from activity gating.
11. Development autostart is exercised and removed without choosing the I08
    production lifecycle.
12. Every approved dependency is exact, locked, documented, and feature-limited.
13. Focused tests, `npm run check`, and `npm run desktop:build` pass on Windows
    with exact commands and results recorded.
14. The ADR remains Proposed for GW and identifies every remaining platform,
    signing, storage, provenance, lifecycle, and support-version decision.
15. No network heartbeat, vault, recovery, notification, telemetry, updater,
    production autostart, server, or I05+ behavior is included.

## Blocked conditions

Mark I04 `Blocked` with evidence and an explicit recovery decision when:

- dependency/design approval is withheld;
- supported APIs cannot meet the target-session, lock-screen, injected-input,
  Remote Desktop, lifecycle, or cleanup semantics without a prohibited API;
- Credential Manager cannot provide the required current-user/local-machine
  persistence, isolation, bounds, continuity, or deterministic cleanup;
- a development credential or autostart registration cannot be removed;
- a sensitive permission, raw-input path, undocumented message/structure, or
  plaintext fallback would be required; or
- canonical Windows checks cannot run with the pinned toolchains.

The author-approved absence of a Windows host during the current implementation
checkpoint is `Deferred`, not `Blocked`. Lack of a suitable host becomes a
blocker only when the deferred Windows acceptance matrix is scheduled.

A failed prototype is valid GW evidence. Do not weaken an acceptance criterion,
convert missing evidence into Pass, or redesign product behavior without explicit
approval.

## Cleanup and completion reporting

Before closeout:

- stop and join every observer thread;
- unregister every session notification and destroy its hidden window;
- remove the development autostart value and verify it is absent;
- delete the exact development credential, repeat delete, and verify not found;
- delete temporary traces after recording sanitized conclusions; and
- confirm no password, PIN, secret, target identity, username, or sensitive path
  entered source, logs, command history, screenshots, or tracked artifacts.

The current completion report must list behavior changed, principal files,
approved dependencies, exact macOS commands and results, cleanup proof,
unverified Windows scope, known risk, and all remaining GW decisions. The later
Windows report must additionally list every manual matrix result,
OS/build/architecture and local-versus-RDP context, prompts and policy failures,
and performance observations. Do not commit, push, publish, or deploy.
