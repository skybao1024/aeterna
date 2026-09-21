# I04 Windows Dependency and Native-API Proposal

Status: **Approved for implementation**  
Research date: 2026-09-21  
Approval date: 2026-09-21  
Iteration brief: [`../iterations/I04-windows-activity-secure-storage-prototype.md`](../iterations/I04-windows-activity-secure-storage-prototype.md)

## Approval boundary

This is the combined I04 dependency and native-behavior proposal. No Windows
native source, dependency manifest, lockfile, permission, capability,
application manifest, or persistence format may change until the user explicitly
approves it in the I04 task.

The proposal adds one Windows-only direct dependency already resolved
transitively in `src-tauri/Cargo.lock`:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
windows-sys = { version = "=0.61.2", default-features = false, features = [
  "Win32_Foundation",
  "Win32_Security_Credentials",
  "Win32_System_LibraryLoader",
  "Win32_System_Power",
  "Win32_System_Registry",
  "Win32_System_RemoteDesktop",
  "Win32_System_SystemInformation",
  "Win32_UI_Input_KeyboardAndMouse",
  "Win32_UI_WindowsAndMessaging",
] }
```

Approval covers only the documented API plan, cross-platform contract changes,
development probes, and temporary per-user autostart exercise below. It does
not approve a production autostart agent, installer capability, background
service, network heartbeat, telemetry, vault persistence, or Windows support
range.

## Baseline evidence

- The repository directly depends on no Windows native binding today.
- `windows-sys` 0.61.2 and `windows-link` 0.2.1 are already frozen transitively
  in the existing lockfile, but transitive availability is not authorization to
  use them directly.
- The current activity policy is platform-neutral, but its input field and
  diagnostic names encode the macOS HID/Combined implementation.
- The current `StorageMetadata` fields are macOS-specific and would be false if
  returned for Windows Credential Manager.
- The current host is macOS 26.3 arm64. No real interactive Windows host is
  connected to this task. The author has deferred real-Windows testing until the
  complete application is available, so none of the API behavior below is
  acceptance evidence and no Windows result will be inferred in this checkpoint.

## Primary sources

Microsoft documentation:

- [`GetLastInputInfo`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getlastinputinfo)
- [`WM_WTSSESSION_CHANGE`](https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change)
- [`WTSRegisterSessionNotification`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification)
- [`WTSUnRegisterSessionNotification`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsunregistersessionnotification)
- [`WTSQuerySessionInformation`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw)
- [`WTS_INFO_CLASS`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_info_class)
- [`WTSINFOEX_LEVEL1_W`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w)
- [`WM_POWERBROADCAST`](https://learn.microsoft.com/en-us/windows/win32/power/wm-powerbroadcast)
- [`GetTickCount`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount)
- [`GetTickCount64`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64)
- [`CredWriteW`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew)
- [`CredReadW`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw)
- [`CredDeleteW`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creddeletew)
- [`CredGetSessionTypes`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credgetsessiontypes)
- [`CREDENTIALW`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)
- [`CredFree`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credfree)
- [Run and RunOnce registry keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Supported Windows client versions](https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client)

Primary Rust binding sources:

- [`microsoft/windows-rs`](https://github.com/microsoft/windows-rs)
- [`windows-sys` 0.61.2 manifest and features](https://docs.rs/crate/windows-sys/0.61.2/source/Cargo.toml.orig)
- [`windows-sys` 0.61.2 API documentation](https://docs.rs/windows-sys/0.61.2/windows_sys/)

## Proposed activity APIs

| Need                              | Supported API                                                                                                                      | Proposed use and boundary                                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Target-session transitions        | `WTSRegisterSessionNotification` with `NOTIFY_FOR_THIS_SESSION`; `WM_WTSSESSION_CHANGE`; paired `WTSUnRegisterSessionNotification` | Receive console/remote connect and disconnect, logon/logoff, lock/unlock, and remote-control changes on an owned invisible window. Filter the message session ID against the captured target ID even though registration is session-scoped.                                                                                                 |
| Initial and sampled session state | `WTSQuerySessionInformationW` with `WTSSessionId`, `WTSConnectState`, `WTSClientProtocolType`, and `WTSSessionInfoEx`              | Read only session ID, active/disconnected state, console/RDP protocol, and lock flag. Do not copy or log the username/domain fields returned inside `WTSINFOEX`; clear the allocated buffer before `WTSFreeMemory`. Windows 7's documented reversed lock flag is irrelevant because I04 accepts only a currently supported Windows 11 host. |
| Suspend/resume                    | `WM_POWERBROADCAST` with `PBT_APMSUSPEND`, `PBT_APMRESUMEAUTOMATIC`, and `PBT_APMRESUMESUSPEND`                                    | Clear eligibility before suspend and on every resume. Resume messages never count as activity.                                                                                                                                                                                                                                              |
| Current-session input age         | `GetLastInputInfo` and `LASTINPUTINFO`, compared with `GetTickCount`/`GetTickCount64` using checked wrap handling                  | Read one coarse age from the process's own session. Never receive an event object or content. A non-incremental/regressing/ambiguous result resets the baseline and fails closed.                                                                                                                                                           |
| Policy durations                  | Rust `Instant` already in the repository                                                                                           | Preserve monotonic policy ordering, confirmation, idle, and cooldown. Windows wall time is diagnostic environment data only.                                                                                                                                                                                                                |

The observer thread will register a private invisible window class, create one
non-visible window, register session notifications, run a message loop, and
translate only session/power messages into typed observations. The callback does
no policy work and records no native pointer or identity. Stop posts a private
message, unregisters exactly once, destroys the window, unregisters the class,
and joins the thread. Partial initialization unwinds each completed step.

`WTSQuerySessionInformationW` can fail when Remote Desktop Services is
unavailable. The adapter will not enumerate other sessions or request another
user's query permission. It will classify that state as unavailable and fail
closed.

## Input provenance limitation and required decision

Microsoft documents two relevant properties of `GetLastInputInfo`:

1. it reports input only for the session that invokes it, which supports
   rejection of other-session activity; and
2. its last-input tick is not guaranteed to increase and may come from
   `SendInput`, which supplies its own tick count.

The first property is useful. The second means the supported aggregate API does
not attest whether an epoch came from physical input, authenticated RDP input,
or injected input. WTS protocol state can distinguish console from RDP, but it
cannot prove the provenance of a `GetLastInputInfo` change.

The proposal therefore preserves the shared two-distinct-epoch confirmation
mechanics but describes the Windows signal as **current-session input**, not
`HID`, `physical`, or `local`. A documented `SendInput` negative test is part of
the real-host matrix. If injection can arm or confirm a candidate, I04 is
Blocked under the current requirement. The only known ways to inspect event
provenance require per-message observation, low-level hooks, or raw input, all
of which are prohibited. Proceeding in that case requires an explicit G0
product-rule change, not an implementation workaround.

This approval does not waive that blocker. It authorizes implementing and
testing the documented signal so G0 receives concrete Windows evidence.

## Shared activity-contract adjustment

The policy mechanics remain unchanged, but macOS-specific plumbing names should
not be used for Windows:

- replace internal `hid`/`combined` sample field names with platform-neutral
  `eligible`/`broader` names;
- replace `HidClass` with a typed eligible source class that diagnostics can
  render as `hid_class` on macOS and `current_session` on Windows;
- retain a broader-only class for macOS Combined-only rejection;
- retain two distinct eligible epochs and the same intervening successful gate
  check, time windows, and cooldown; and
- version the redacted diagnostic schema instead of silently changing v3.

The macOS adapter continues to map Quartz HID to `eligible` and Quartz Combined
to `broader`; its observed behavior and fixed codes receive regression tests.
Windows maps its one supported session signal to `eligible` and has no broader
source. Missing broader evidence is an explicit platform representation, not a
fabricated second measurement.

The Windows unlock gate is the sampled WTS session state. Lock, inactive,
disconnected, unknown, or query failure is closed. Unlock, reconnect, switch-in,
and resume only request a fresh baseline. They are never candidates themselves.

## Proposed Credential Manager policy

Use the Unicode Credentials Management API with one `CRED_TYPE_GENERIC` item:

| Property                 | Proposed value                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Target name              | `dev.aeterna.desktop.i02.device-signing/v1/` plus the existing 32 lowercase device-ID hexadecimal characters |
| Credential blob          | Exactly the existing 32-byte Ed25519 signing seed                                                            |
| Persistence              | `CRED_PERSIST_LOCAL_MACHINE`                                                                                 |
| Username                 | Fixed non-identifying application value `aeterna-device-signing-v1`                                          |
| Attributes/comment/alias | None                                                                                                         |
| Flags                    | Zero                                                                                                         |

Microsoft documents `CRED_PERSIST_LOCAL_MACHINE` as visible to subsequent logon
sessions of the same user on the same computer, and not to the same user on
other computers. `CRED_PERSIST_ENTERPRISE` is rejected because it may roam.
Before create, `CredGetSessionTypes` must show that generic credentials support
at least local-machine persistence.

Each read validates exact type, target, persistence, blob length, zero
attributes, and expected fixed username before constructing a `SigningSecret`.
The target, username, blob, native error text, and OS account identity are not
logged. After copying the blob into the zeroizing Rust secret wrapper, the
adapter zeroizes the mutable native blob bytes before calling `CredFree`.
Zeroization cannot guarantee erasure of Credential Manager internals, kernel
buffers, crash dumps, swap, compiler copies, or copies made inside Windows.

There is no lock-derived access promise. A process may be able to read a generic
credential while the workstation is locked. I04 will measure and document the
actual behavior, but the activity adapter will never use it as an unlock gate.

### Operation semantics

- **Create:** check the exact target first; return `StorageAlreadyExists` if it
  exists, otherwise call `CredWriteW`, re-read, and verify exact metadata and
  public key. No write occurs in the ordinary sequential duplicate case.
- **Retrieve:** call `CredReadW`, validate all metadata and exact length, copy
  into `SigningSecret`, zero the native blob, and free the allocation.
- **Replace:** require an existing exact item, call `CredWriteW`, re-read, and
  verify the replacement public key.
- **Delete:** map success to `Deleted` and `ERROR_NOT_FOUND` to `NotFound`.
- **Metadata:** return only typed backend, protection/persistence, and roaming
  facts; never return target text or OS identity.

`CredWriteW` is documented as create-or-replace. It has no create-only flag, so
the port cannot honestly claim an atomic cross-process conditional create. The
preflight and verification satisfy the sequential I04 matrix but retain a race
if multiple processes write the same target concurrently. I04 will document
this limitation for G0; production must either enforce a reviewed single-instance
boundary, add a correctly scoped cross-process serialization primitive, or
revise the storage port. This proposal does not hide the race with an unsafe
global mutex or treat an unconditional upsert as create.

### Error mapping

| Windows result                                                         | Fixed project result                             |
| ---------------------------------------------------------------------- | ------------------------------------------------ |
| `ERROR_NOT_FOUND`                                                      | `StorageNotFound` (or `DeleteOutcome::NotFound`) |
| `ERROR_ACCESS_DENIED`                                                  | `StorageAccessDenied`                            |
| `ERROR_NO_SUCH_LOGON_SESSION`                                          | new `StorageSessionUnavailable`                  |
| invalid flags, parameter, username, type, persistence, target, or blob | `StorageInvalidConfiguration`                    |
| unsupported local-machine persistence                                  | new `StoragePolicyUnsupported`                   |
| any unexpected failure                                                 | `StorageUnavailable`                             |

Windows does not return macOS entitlement or Keychain errors. Platform-specific
error variants remain internal where possible; stable external strings remain
English, fixed, and non-sensitive.

## Cross-platform storage metadata redesign

Replace the misleading macOS booleans with explicit enums:

```text
StorageMetadata {
  backend: MacOsDataProtectionKeychain | WindowsCredentialManager,
  protection: WhenUnlockedThisDeviceOnly | CurrentUserLocalMachine,
  roaming: Disabled,
}
```

The macOS adapter maps its existing verified attributes to
`MacOsDataProtectionKeychain`, `WhenUnlockedThisDeviceOnly`, and `Disabled`.
The Windows adapter maps validated generic type plus
`CRED_PERSIST_LOCAL_MACHINE` to `WindowsCredentialManager`,
`CurrentUserLocalMachine`, and `Disabled`. The metadata does not imply
hardware-backed storage, a Windows lock gate, or atomic create-only behavior.

The existing `DeviceSecretStore` operations stay unchanged. Tests cover both
metadata representations and prevent one platform from returning the other's
protection semantics.

## Development-only autostart exercise

Use the documented per-user key
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` only through an explicit
probe action. Store one fixed value name, `AeternaI04ActivityProbe`, whose data
is the quoted absolute probe executable plus a fixed `--i04-autostart-probe`
argument. The probe will:

- reject a command longer than Microsoft's documented 260-character limit;
- install no machine-wide value and request no elevation;
- never print or persist the path outside the registry value;
- expose explicit `install-dev-autostart`, `status-dev-autostart`, and
  `remove-dev-autostart` actions;
- remove only the exact value, never a key or another application's data; and
- verify absence after the W14 scenario.

Microsoft does not guarantee prompt or ordered launch from `Run`; W14 evaluates
only that an eventual logon launch establishes a fresh baseline. Production
startup registration, enable/disable UX, packaging, and signing belong to I08.

## Direct dependency review

### `windows-sys` 0.61.2

- **Owner and maintenance:** Microsoft `windows-rs`; active repository and
  generated Windows API projections. Version 0.61.2 is the current docs.rs
  `windows-sys` release reviewed on 2026-09-21 and is already present in the
  lockfile.
- **License:** MIT OR Apache-2.0.
- **Rust/toolchain:** crate manifest declares Rust 1.71; compatible with the
  repository's pinned Rust 1.98.1.
- **Enabled features:** exactly the nine features in the proposed manifest.
  Defaults remain disabled. No COM or WinRT projection is enabled.
- **Transitive impact:** `windows-link` 0.2.1 only, already present and locked.
- **Runtime libraries:** documented imports from system `User32.dll`,
  `Wtsapi32.dll`, `Advapi32.dll`, and `Kernel32.dll`. No bundled native binary,
  installer, service, or runtime download.
- **Unsafe boundary:** raw generated FFI is unsafe. All calls, pointers,
  `WNDPROC` dispatch, native strings, allocated WTS/Credential buffers, registry
  handles, and HWND ownership stay in small `cfg(windows)` modules with a safety
  invariant on every unsafe block. Safe Rust types cross into shared code.
- **Permissions/capabilities:** no administrator requirement, sensitive privacy
  prompt, Tauri capability, UIAccess, service permission, input permission,
  firewall rule, or Windows application capability is added. Domain policy may
  disable credentials or session information; that fails closed.
- **Storage behavior:** only the exact generic credential and the temporary
  per-user development `Run` value are written. No file, environment, browser,
  SQLite, or machine-wide registry fallback exists.
- **Network behavior:** none. The APIs are local OS calls and the crate contains
  bindings only.
- **Serialization/interoperability:** no persisted project format is added.
  The signing seed remains the existing exact 32-byte representation.

## Why existing dependencies are insufficient

The standard library exposes threads, channels, and monotonic `Instant`, but it
does not expose WTS session notifications, Windows input age, Credential
Manager, native window messages, or registry APIs. Tauri wraps application
windows but does not provide the target-session state, Credential Manager
operations, or the lifecycle ownership needed by this backend-only prototype.
Existing macOS crates compile only on macOS and cannot represent Windows
semantics.

## Alternatives considered

- **Handwritten `extern "system"` declarations:** rejected because duplicating
  SDK signatures, constants, unions, and architecture layouts enlarges the
  unsafe and maintenance surface.
- **`windows` high-level crate:** maintained by the same Microsoft project but
  adds typed COM/WinRT support not needed for these C-style APIs. Most selected
  functions remain unsafe. `windows-sys` is smaller and already locked.
- **`winapi` and convenience credential crates:** rejected in favor of the
  maintained Microsoft projection and direct visibility into every persistence,
  metadata, error, and cleanup decision. Convenience APIs commonly expose
  upsert semantics without the required validation.
- **Windows App SDK/WinRT startup tasks:** rejected for I04 because package
  identity and production startup manifest choices belong to I08.
- **Task Scheduler, service, or machine `Run` key:** rejected because they add
  privileges, credentials, or production lifecycle surface.
- **Startup-folder scripts or command-output parsing:** rejected because they
  add file artifacts and fragile shell behavior.
- **DPAPI plus an encrypted file/registry blob:** rejected because it introduces
  a new persistence format and storage location, and the task explicitly
  requires Credential Manager or a stronger supported platform store with no
  fallback.
- **WinRT PasswordVault/Credential Locker:** rejected because its package and
  roaming semantics are less explicit for this unpackaged desktop prototype.
- **CNG/Windows Hello key generation:** rejected because it would change the
  accepted Ed25519 signing representation and protocol decision rather than
  store the existing secret.
- **Global input hooks, raw input, ETW, private Winlogon messages, desktop-name
  heuristics, or command parsing:** rejected by the privacy and supported-API
  boundary. They are not an acceptable workaround for injected-input
  provenance.

## Planned changes after approval

- Add the exact Windows-only dependency declaration; keep lockfile changes to
  Cargo's authoritative resolution.
- Generalize activity sample/diagnostic naming without changing shared policy.
- Add `src-tauri/src/activity/windows.rs` and Windows lifecycle tests.
- Extend the feature-gated prototype and ignored trace path for Windows.
- Generalize `StorageMetadata`, add Windows-specific storage errors as needed,
  and add `src-tauri/src/secure_storage/windows.rs`.
- Add fixed development activity, Credential Manager, and autostart probe
  commands without WebView exposure.
- Update `README.md` and `docs/DEPENDENCIES.md`.
- Run focused tests, the canonical macOS checks/build, and privacy scans for the
  current checkpoint; record Windows compilation and runtime behavior as
  unverified.
- When the complete application is available, run canonical Windows checks,
  manual matrices, and cleanup; then complete the Windows results and Proposed
  ADR evidence.

## Approval record

The user explicitly approved the combined proposal in the I04 task on
2026-09-21. The approved scope adds Windows-only
`windows-sys = 0.61.2` with the exact features above; generalize the activity
and storage metadata names; use documented WTS, User32, Credential Manager, and
per-user development `Run` APIs; and implement the probes under the stated
limitations. Approval authorizes implementation and evidence collection, but
does not accept injected-input behavior, waive the deferred real-Windows matrix,
accept the ADR, or approve production lifecycle behavior.
