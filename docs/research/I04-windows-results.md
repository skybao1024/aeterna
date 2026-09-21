# I04 Windows Activity and Secure-Storage Prototype Results

Status: **Implementation checkpoint complete; real-Windows validation deferred by the author**  
Research date: 2026-09-21  
Iteration brief: [`../iterations/I04-windows-activity-secure-storage-prototype.md`](../iterations/I04-windows-activity-secure-storage-prototype.md)  
Dependency proposal: [`I04-windows-dependency-proposal.md`](./I04-windows-dependency-proposal.md)  
Proposed ADR: [`ADR 0003`](../adr/0003-windows-activity-and-secure-storage.md)

## Current outcome

I04 now has a Windows-targeted implementation but no Windows acceptance result.
The author explicitly approved the combined dependency/native-API proposal on
2026-09-21. On the same date, the author directed that real-Windows testing wait
until the complete application is available and that the current checkpoint
guarantee only macOS regression checks. The missing Windows host is therefore
deferred rather than treated as a current implementation blocker.

The current machine reports Darwin/macOS 26.3 on arm64. Two known remote shell
aliases were tested read-only and both connection attempts timed out; neither
provided an interactive Windows surface. No Windows credential, lock/unlock,
sleep/wake, fast-user-switch, Remote Desktop, autostart, build, or probe command
has run. macOS execution, source inspection, Microsoft documentation, and Rust
binding documentation are research evidence only.

## Baseline and source review

- The full repository `AGENTS.md` and relevant design, development-plan, I01,
  I02, ADR, evidence, manifest, source, and test material were reviewed.
- The entire repository baseline remains uncommitted and user-owned. No reset,
  clean, commit, push, publish, or deploy occurred.
- No source, manifest, lockfile, permission, capability, application manifest,
  or persistence format was changed before approval. After approval, only the
  exact proposed Windows dependency and scoped implementation changed.
- The shared policy already provides monotonic ordering, fresh-baseline
  behavior, two-stage confirmation, idle recovery, continuous refresh, and
  cooldown. The Windows adapter must consume it rather than duplicate it.
- `StorageMetadata` was generalized to typed backend, protection, and roaming
  enums. The macOS adapter retains its verified semantics, while Windows cannot
  claim `WhenUnlockedThisDeviceOnly` protection.

## Supported-API research result

Microsoft's documented WTS notification and query APIs expose the required
target-session transition classes, including lock/unlock and console/remote
connect/disconnect. `WM_POWERBROADCAST` exposes suspend and resume boundaries.
`GetLastInputInfo` supplies content-free age information for only the calling
session. These are sufficient to build a narrow observation prototype that
fails closed on uncertain state.

They do not establish input provenance. Microsoft documents that the last-input
tick is not guaranteed to increase and may be supplied by `SendInput`.
Therefore, current-session input age cannot be described as proof of physical
or non-injected HID input. A real-host negative test is mandatory. If injected
input qualifies, the current requirement is Blocked unless GW explicitly
changes the product rule.

Credential Manager's documented generic credential operations provide
current-user credential-set isolation, a bounded application-defined blob, and
`CRED_PERSIST_LOCAL_MACHINE`, which is visible to subsequent sessions of the
same user on the same computer but not to the same user on other computers.
The API does not promise lock denial and is not an activity unlock gate.

`CredWriteW` is an upsert. Sequential duplicate-safe create can preflight and
verify, but the API offers no atomic create-only operation. The cross-process
race remains a GW concern even if the required sequential matrix passes.

## Approved dependency result

The proposal recommends one exact Windows-only direct dependency:
`windows-sys` 0.61.2, defaults disabled, with only Foundation, Credentials,
LibraryLoader, Power, Registry, RemoteDesktop, SystemInformation,
KeyboardAndMouse, and WindowsAndMessaging features. It is maintained by
Microsoft under MIT OR Apache-2.0, requires only `windows-link` 0.2.1, is
already present in the lockfile transitively, adds no runtime network behavior,
and introduces no privilege or Tauri capability.

This dependency was explicitly approved on 2026-09-21. The exact Windows-only
manifest declaration and root lockfile edge were added. No package version or
checksum changed because the exact release was already locked transitively.

## Implementation result

The current checkpoint implements:

- a feature-gated Windows activity adapter with one owned invisible native window
  thread, own-session WTS registration and filtering, power/session event
  mapping, deterministic stop/join, and current-session input-age sampling;
- sampled WTS connection, lock, and console-versus-RDP state as the unlock gate,
  with unknown, disconnected, inactive, malformed, and failed state closed;
- wrap-aware input tick conversion and deterministic tests for normal progress,
  wrap, future ambiguity, and regression;
- platform-neutral `eligible`/`broader` activity fields and versioned redacted
  diagnostics; Windows has no fabricated broader source;
- a Windows Credential Manager `DeviceSecretStore` using one exact generic,
  current-user/local-machine item, strict metadata validation, bounded native
  reads, returned-blob zeroization, fixed error mapping, sequential duplicate
  preflight, post-write verification, and no fallback;
- typed cross-platform storage metadata that keeps Windows protection distinct
  from macOS Keychain semantics;
- a fixed Windows credential probe; and
- explicit install/status/remove actions for one temporary per-user Run value.
  The actions reject overlong commands and conflicting values, print no path,
  remove only their exact value, and require an activity-prototype build.

The implementation adds no Tauri capability, Windows application permission,
service, hook, raw input, WebView bridge, network call, heartbeat, vault, or
production startup choice. The `CredWriteW` cross-process create race and
`GetLastInputInfo` synthetic-input provenance limitation remain explicit GW
issues.

## Real-Windows environment

| Property                          | Result        |
| --------------------------------- | ------------- |
| Interactive Windows host          | Not connected |
| Windows edition/version/build     | Not available |
| Architecture                      | Not available |
| Physical/virtual                  | Not available |
| Local console session             | Not available |
| RDP session                       | Not available |
| Application identity/signing mode | Not available |
| Windows toolchain                 | Not run       |

The host must be a currently supported Windows 11 client with current security
updates and interactive access to the required manual flows. Evidence will be
recorded without usernames, machine identifiers, remote addresses, passwords,
PINs, signing secrets, target identities, or sensitive paths.

## Activity matrix

No item below is a Pass. Deterministic tests, cross-compilation, CI, mocks, and
inferred API contracts cannot replace these runs.

| ID  | Scenario                                 | Result                                                      |
| --- | ---------------------------------------- | ----------------------------------------------------------- |
| W01 | Cold startup and normal restart          | Not run — Windows host required                             |
| W02 | Locked background/system work            | Not run — Windows host required                             |
| W03 | Login-screen interaction while locked    | Not run — Windows host required                             |
| W04 | Unlock with no later input               | Not run — Windows host required                             |
| W05 | Unlock plus qualifying two-epoch input   | Not run — Windows host required                             |
| W06 | Sleep/wake, including wake locked        | Not run — Windows host required                             |
| W07 | Long-idle recovery                       | Not run — Windows host required                             |
| W08 | Continuous-use refresh                   | Not run — Windows host required                             |
| W09 | Cooldown duplicate suppression           | Not run — Windows host required                             |
| W10 | Fast user switching                      | Not run — Windows host and second user required             |
| W11 | Authenticated RDP connect/use/disconnect | Not run — Windows host and RDP peer required                |
| W12 | Observer/process shutdown and restart    | Not run — Windows host required                             |
| W13 | Wall-clock changes                       | Not run — user action or explicit waiver required           |
| W14 | Development autostart                    | Not run — Windows host required                             |
| W15 | Synthetic input negative case            | Not run — Windows host required; documented provenance risk |

## Credential matrix

No item below is a Pass.

| ID  | Scenario                                     | Result                                          |
| --- | -------------------------------------------- | ----------------------------------------------- |
| C01 | Create                                       | Not run — Windows host required                 |
| C02 | Restart and sign/read                        | Not run — Windows host required                 |
| C03 | Duplicate create                             | Not run — Windows host required                 |
| C04 | Wrong identity                               | Not run — Windows host required                 |
| C05 | Replace and persistence                      | Not run — Windows host required                 |
| C06 | Delete/repeated delete/not found             | Not run — Windows host required                 |
| C07 | Lock/unlock behavior                         | Not run — Windows host and user action required |
| C08 | Different Windows user isolation             | Not run — Windows host and second user required |
| C09 | Metadata/protection/persistence              | Not run — Windows host required                 |
| C10 | Debug-to-release continuity                  | Not run — Windows host required                 |
| C11 | Denied, disabled, invalid, interrupted paths | Not run — Windows host required                 |
| C12 | Final cleanup                                | Not run — probe not executed; no item created   |

## Verification performed

The following checks were performed on the current host:

- `git status --short`: confirmed the complete repository is untracked and
  user-owned.
- `uname -a`: confirmed Darwin/macOS 26.3 arm64, not Windows.
- pre-change manifest and Cargo metadata inspection: confirmed no direct Windows
  native dependency and confirmed `windows-sys` 0.61.2 / `windows-link` 0.2.1
  were already present transitively in `Cargo.lock`;
- `ssh zaas "uname -s; uname -m"`: timed out.
- `ssh ailab "uname -s; uname -m"`: timed out.
- tool versions: Node 24.21.0, npm 11.19.0, Rust 1.98.1, and Cargo 1.98.1;
- `npm run check`: **Pass**. Prettier, ESLint, strict TypeScript, seven frontend
  tests, the production frontend build and remote-asset scan, Rustfmt, Clippy
  with warnings denied, 54 Rust tests, and `cargo check` all passed with locked
  dependencies and all features/targets requested by the repository scripts;
- the 54 Rust tests include deterministic Windows session/gate/tick logic,
  platform-neutral diagnostic behavior, storage metadata separation, and all
  pre-existing macOS/cryptographic regressions; and
- `npm run desktop:build`: **Pass**. It produced the unsigned macOS arm64
  `aeterna-desktop` executable. The known non-fatal `rust-objcopy` warning about
  missing `libLLVM.dylib` recurred; Cargo completed the optimized build and the
  Tauri command exited zero.

Windows compilation, probes, and manual matrices remain `Not run` until
application-level Windows validation. No macOS pass is recorded as evidence for
any W/C matrix row.

## Cleanup status

- Windows credential created: no.
- Windows registry/autostart value created: no.
- Windows observer registration created: no.
- Raw activity trace created: no.
- Password, PIN, signing secret, target identity, OS username, or sensitive path
  recorded: no.

## Required next actions

1. When the complete application is available, connect a real interactive
   supported Windows 11 host, run the canonical Windows checks and complete
   matrices, and replace every `Not run` entry with truthful evidence.
2. Resolve the synthetic-input provenance and `CredWriteW` create-only race at
   GW using the eventual Windows evidence; do not silently broaden either rule.

Until the deferred Windows work is complete, I04 cannot be finally Accepted and
GW remains pending. Under the explicitly approved macOS-first sequence, this
does not block macOS G0 or the approved implementation checkpoint.
