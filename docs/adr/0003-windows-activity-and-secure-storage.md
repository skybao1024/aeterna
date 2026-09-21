# ADR 0003: Windows activity detection and device-secret storage

- Status: Proposed
- Date: 2026-09-21
- Decision owner: GW Windows platform qualification gate
- Evidence: [`../research/I04-windows-results.md`](../research/I04-windows-results.md)
- Dependency review: [`../research/I04-windows-dependency-proposal.md`](../research/I04-windows-dependency-proposal.md)

## Context

Aeterna needs a Windows implementation of the same local activity-candidate and
device-signing-secret boundaries already prototyped on macOS. Startup, wake,
lock-screen input, session switching, unlock without later input, and activity
from another Windows session must not create a candidate. Authenticated Remote
Desktop interaction in the target session counts as activity under the approved
product rule, but the client must not claim proof of local physical presence.

The implementation must capture no input content, install no global hook, add no
sensitive permission, expose no raw observation or secret to React, and create
no network heartbeat. Device secret storage must be current-user and local to
the computer, with no plaintext fallback. Credential storage and session unlock
state are separate concerns.

This ADR remains Proposed during implementation. The dependency proposal was
explicitly approved on 2026-09-21, and the narrow adapters and development
probes are implemented. None of the required Windows matrix is complete. The
author has deferred real-Windows testing until the complete application is
available; the current implementation checkpoint instead preserves and passes
the macOS regression suite without treating that as Windows evidence.

## Proposed decision

### Activity observation

Keep the platform-neutral monotonic policy authoritative. The implemented
Windows adapter uses:

- a dedicated invisible window registered with
  `WTSRegisterSessionNotification(NOTIFY_FOR_THIS_SESSION)`;
- `WM_WTSSESSION_CHANGE` for login/logoff, lock/unlock, console and remote
  connect/disconnect, and remote-control boundaries;
- `WTSQuerySessionInformationW` for the target session ID, connection state,
  lock flag, and console-versus-RDP protocol;
- `WM_POWERBROADCAST` for suspend and resume boundaries; and
- `GetLastInputInfo` for only the process session's coarse input age.

The observer owns one invisible top-level system `STATIC` window on a dedicated
thread so it can receive power broadcasts. It subclasses the window only for
the observer lifetime, restores the prior procedure and user-data value before
destruction, and joins the thread during idempotent shutdown. This avoids adding
a Graphics/GDI binding solely to register a private window class.

The adapter ignores other-session notifications and never enumerates users.
Every start, lock, unlock, login/logoff, console/RDP boundary, switch,
suspend/resume, observer restart, and uncertain native result clears pending
confirmation and requires a fresh baseline. A transition alone is never
activity.

Policy durations continue to use Rust `Instant`. The input-age conversion uses
documented Windows uptime ticks with wrap/regression checks. Invalid,
non-incremental, stale, contradictory, or unavailable data fails closed.

The shared sample and diagnostic field names become platform-neutral. macOS
continues to classify Quartz HID as eligible and Combined-only input as
ineligible. Windows classifies `GetLastInputInfo` only as `current_session`.
Both platforms retain two distinct eligible epochs separated by a successful
gate check, the same post-unlock/idle/continuous rules, and the same cooldown.

### Input provenance limitation

Microsoft explicitly documents that `GetLastInputInfo` is session-specific, but
also that its tick may be supplied by `SendInput`. WTS session state cannot
distinguish injected from physical or authenticated RDP input. Therefore the
Windows signal is not described as authenticated HID or physical input.

The real-host matrix must attempt the documented synthetic-input negative case.
If supported aggregate APIs allow injected input to qualify, I04 is Blocked
under the current product requirement. Global hooks, raw input, private
Winlogon signals, and event capture are not acceptable workarounds. GW must
explicitly accept a revised Windows rule or redesign the signal before this ADR
can be Accepted.

### Device-secret storage

The implemented storage adapter stores the existing 32-byte Ed25519 signing seed as one
`CRED_TYPE_GENERIC` item in the current user's Credential Manager set:

- application/device-specific target;
- fixed non-identifying application username;
- `CRED_PERSIST_LOCAL_MACHINE`;
- no attributes, comment, alias, or enterprise persistence; and
- exact blob-size and metadata validation on every read.

Local-machine persistence means later sessions of the same user on the same
computer can access the item, while the same user on another computer cannot.
It does not mean hardware-backed storage or access denial while the workstation
is locked. The Windows activity gate uses WTS state and never reads this secret.

Create, retrieve, replace, delete, repeated delete, not found, metadata,
restart, wrong identity, different user, and debug-to-release continuity are
tested with a development-only identity. Native returned blob bytes are
zeroized before `CredFree`; Rust-owned secrets retain the accepted zeroizing
wrapper. No file, registry, environment, SQLite, browser, legacy, or remote
fallback exists.

Cross-platform `StorageMetadata` reports typed backend, protection scope, and
roaming policy. It must not reuse macOS-only boolean field names or imply that
Windows Credential Manager has `WhenUnlockedThisDeviceOnly` semantics.

`CredWriteW` is an upsert, not an atomic create-only operation. The prototype
preflights and verifies sequential create and replace operations but documents
the cross-process race. Production must enforce an approved single-instance or
serialization boundary, or revise the storage port, before relying on atomic
create semantics.

### Development autostart

The development probe can exercise only one explicit, temporary per-user `HKCU` `Run` value for the fixed
I04 probe. It is installed and removed through fixed probe actions, contains no
secret, requests no elevation, refuses to overwrite or delete a conflicting
value, and is deleted immediately after W14. This does not select I08's
production startup mechanism.

## Dependency decision

The approved implementation adds exact Windows-only `windows-sys` 0.61.2 with
only the Foundation, Credentials, LibraryLoader, Power, Registry,
RemoteDesktop, SystemInformation, KeyboardAndMouse, and WindowsAndMessaging
features. It is Microsoft's maintained raw Windows binding, is licensed MIT OR
Apache-2.0, and depends only on the already locked `windows-link` 0.2.1.

All raw pointers, handles, message dispatch, allocated buffers, and unsafe calls
remain in small `cfg(windows)` adapters with documented ownership and safety
invariants. The dependency adds no runtime network, privilege, Tauri capability,
prompt, service, installer, or application permission.

## Alternatives rejected

- Handwritten FFI: unnecessary signature and layout risk.
- Broad `windows`/WinRT projection: COM and WinRT behavior are not needed for
  the selected C-style APIs.
- Unmaintained or convenience wrapper crates: obscure persistence, upsert,
  allocation, metadata, and error behavior.
- DPAPI plus a file or registry blob: adds a new persistence format and fallback
  location outside the requested store.
- PasswordVault/Credential Locker: package and roaming semantics are less
  explicit for the unpackaged prototype.
- CNG or Windows Hello key generation: changes the accepted Ed25519 protocol
  rather than storing its existing secret.
- Task Scheduler, service, machine-wide startup, or packaged startup task: adds
  production lifecycle and privilege decisions owned by I08.
- Raw input, low-level hooks, ETW, private structures/messages, desktop-name
  heuristics, or command parsing: violates the privacy/supported-API boundary.

## Security and privacy consequences

The activity policy receives only coarse enums, a monotonic timestamp, and one
rounded current-session input age. Diagnostics contain fixed English codes and
bounded values, and remain in an ignored local artifact. No username, domain,
remote address, input content, application/window metadata, pointer, native
event, credential target, secret, or sensitive path is logged or exposed to the
WebView.

Credential Manager protects against ordinary direct plaintext persistence and
provides user/device scoping according to its documented contract. It does not
protect an already compromised unlocked account, guarantee denial while locked,
prove hardware backing, or solve input provenance. Zeroization is best effort
and cannot erase copies owned by Windows, the kernel, compiler, crash dumps,
swap, or previously copied memory.

The development registry value is a temporary lifecycle test artifact, not a
secret store. It must be absent at closeout.

## Feasibility and acceptance gate

This ADR remains Proposed. Implementation may proceed after explicit proposal
approval while Windows validation is deferred. Before GW can accept or replace
this ADR:

1. the approved dependency/native-API scope must remain unchanged;
2. a real interactive supported Windows 11 host must pass every required
   activity and credential scenario, with any waiver labeled and not counted as
   Pass;
3. synthetic-input provenance must either fail closed or trigger an explicit
   GW product decision;
4. the `CredWriteW` create-only concurrency limitation must receive an explicit
   production decision;
5. Credential Manager lock, cross-user, local-machine, non-roaming,
   debug/release, error, and cleanup behavior must be observed;
6. observer registration, partial failure, shutdown, restart, and autostart
   cleanup must be proven;
7. canonical pinned-toolchain Windows checks and build must pass; and
8. GW must decide the supported Windows version floor, production signing and
   application identity, startup mechanism, and independent native/security
   review.

During the current checkpoint, missing Windows evidence is deferred rather than
reported as a failure. At the later acceptance gate, missing Windows evidence,
a residual credential/autostart item, a sensitive permission, an undocumented
dependency, or an injected-input false positive keeps I04 Blocked. Compilation
is not functional acceptance.
