# I00 dependency review

Review date: 2026-09-20.

I00 intentionally has no cryptography, storage, native-system, updater, telemetry,
or production network plugin. Exact direct versions are recorded in
`package.json` and `src-tauri/Cargo.toml`; transitive versions and checksums are
frozen by both lockfiles.

## Runtime dependencies

| Dependency                                                           | Purpose                                   | License                                                                  | Maintenance observation                                                                                      |
| -------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Tauri 2.11.6 and JavaScript API 2.11.1                               | Desktop runtime and narrow IPC            | Apache-2.0 OR MIT                                                        | Official Tauri v2 releases; 2.11.6 was the current stable runtime and included a security fix when reviewed. |
| React and React DOM 19.3.0                                           | Local UI rendering                        | MIT                                                                      | Official Meta project with an active 19.x release line.                                                      |
| i18next 26.4.2 and react-i18next 17.0.14                             | Localized UI resources                    | MIT                                                                      | Established projects with current releases and no required remote service.                                   |
| Tailwind Merge 3.7.0, clsx 2.1.1, and Class Variance Authority 0.7.1 | Shadcn-compatible local class composition | MIT for Tailwind Merge and clsx; Apache-2.0 for Class Variance Authority | Small, established frontend utilities; no runtime network behavior.                                          |
| serde 1.0.228                                                        | Typed Rust IPC serialization              | Apache-2.0 OR MIT                                                        | Widely used Rust serialization project; only derive support is enabled directly.                             |

## Development dependencies

The Tauri CLI/build crate, Vite, Tailwind CSS, TypeScript, ESLint,
typescript-eslint, Vitest, Testing Library, jsdom, and Prettier are maintained
upstream developer tools under permissive licenses (MIT, Apache-2.0, or dual
Apache-2.0/MIT as declared by each project). They are build/test-only and are
locked. GitHub Actions are pinned to immutable commits in CI.

The repository does not execute package lifecycle scripts during the documented
`npm ci` flow. A dependency change must review maintenance activity, license,
permissions, runtime network behavior, and lockfile changes before merge.

## I01 approved macOS native dependencies

Approval date: 2026-09-20. The user explicitly approved the following direct
dependencies after reviewing the proposal in
[`research/I01-macos-activity-results.md`](./research/I01-macos-activity-results.md).
They are declared only for `target_os = "macos"`, use exact versions already
present in the I00 lockfile through Tauri, and disable default features.

| Dependency                  | Purpose                                                          | License                   | Maintenance observation                                                             | Permissions and network behavior                                       |
| --------------------------- | ---------------------------------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `objc2` 0.6.4               | Objective-C ownership and the narrow notification observer class | MIT                       | Active `madsmtm/objc2` project; exact release already resolved by Tauri             | Adds no entitlement or permission request; no runtime network behavior |
| `objc2-foundation` 0.3.2    | Notification registration/removal and base Objective-C types     | MIT                       | Generated binding from the same active release family; exact release already locked | Adds no entitlement or permission request; no runtime network behavior |
| `objc2-app-kit` 0.3.2       | Documented `NSWorkspace` session and sleep/wake notifications    | Zlib OR Apache-2.0 OR MIT | Generated binding from the same active release family; exact release already locked | Adds no entitlement or permission request; no runtime network behavior |
| `objc2-core-graphics` 0.3.2 | Documented elapsed-input-age query and typed state/event values  | Zlib OR Apache-2.0 OR MIT | Generated binding from the same active release family; exact release already locked | Adds no entitlement or permission request; no runtime network behavior |

Enabled features are restricted to `std`, `NSWorkspace`, `NSNotification`,
`NSObject`, `NSString`, `CGEventSource`, and `CGEventTypes`. Alternatives were
rejected as follows: handwritten FFI would enlarge the unsafe ownership surface;
the older `core-graphics` crate does not cover AppKit lifecycle notifications; a
Swift helper adds a process and IPC boundary without solving lock detection; and
event taps, HID hooks, undocumented signals, and command parsing violate the I01
contract.

On 2026-09-21 the user approved the revised I01 Keychain-gated, dual-input,
two-stage policy. I01 reuses the already approved and exactly pinned
`core-foundation` 0.10.1 and `security-framework-sys` 2.17.0 dependencies
listed below; it adds no dependency or feature. Its Keychain query is limited to
a separate fixed nonsecret sentinel service/account, requests no authentication
UI, performs no enumeration, and has no runtime network behavior. Reading the
aggregate Quartz HID-system age adds no event tap or sensitive permission.

## I02 approved cryptography and secure-storage dependencies

Approval date: 2026-09-20. The user explicitly approved the combined dependency
and format proposal before these manifest changes. Full maintenance dates,
alternatives, interoperability, audit claims, unsafe boundaries, permissions,
and transitive impact are recorded in
[`research/I02-crypto-dependency-proposal.md`](./research/I02-crypto-dependency-proposal.md).
All versions below are exact direct pins; Cargo.lock freezes transitive releases
and checksums.

| Dependency                      | Scope and enabled features                       | Purpose and review result                                                                                                                                                              |
| ------------------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `argon2` 0.5.3                  | Runtime; defaults off; `zeroize`                 | Argon2id v=0x13 with Aeterna-owned zeroizing memory. PHC, random, and default allocation APIs stay disabled. MIT OR Apache-2.0; no storage/network behavior.                           |
| `aes-gcm` 0.10.3                | Runtime; defaults off; `aes`, `alloc`, `zeroize` | AES-256-GCM only. This is the patched release for RUSTSEC-2023-0096. Apache-2.0 OR MIT; no I/O/network behavior.                                                                       |
| `hkdf` 0.12.4 and `sha2` 0.10.9 | Runtime; defaults off                            | Fixed HKDF-SHA-256. Both MIT OR Apache-2.0; architecture acceleration is confined to upstream intrinsic boundaries.                                                                    |
| `getrandom` 0.3.4               | Runtime; defaults off                            | Sole production randomness source, backed by the operating system on supported targets. MIT OR Apache-2.0; platform syscall boundary only.                                             |
| `ed25519-dalek` 2.2.0           | Runtime; defaults off; `fast`, `zeroize`         | Ed25519 key derivation/sign/strict verify. Cargo.lock resolves `curve25519-dalek` 4.1.3, the patched floor for RUSTSEC-2024-0344. BSD-3-Clause; no I/O/network behavior.               |
| `zeroize` 1.9.0                 | Runtime; defaults off; `alloc`                   | Best-effort clearing for owned secret buffers and Argon2 memory. MIT OR Apache-2.0; volatile-write/fence unsafe boundary; no guarantee for compiler/OS/framework copies.               |
| `bech32` 0.12.0                 | Runtime; defaults off; `alloc`                   | Bech32m ERC representation and checksum. MIT; no transitive runtime packages, unsafe code, permissions, or network behavior.                                                           |
| `core-foundation` 0.10.1        | macOS runtime; `link`                            | Owned Core Foundation dictionaries, strings, data, and returned objects in the narrow Keychain adapter. MIT OR Apache-2.0; links only Apple system frameworks.                         |
| `security-framework-sys` 2.17.0 | macOS runtime; `OSX_10_15`                       | Raw SecItem/data-protection constants and functions. MIT OR Apache-2.0; Keychain access is restricted to the exact prototype service/account, with no enumeration or network behavior. |
| `serde_json` 1.0.151            | Development/test only; defaults                  | Parses the conspicuously synthetic deterministic JSON fixture. MIT OR Apache-2.0; not used as a production crypto serialization.                                                       |

No I02 dependency adds a Tauri capability, entitlement, remote service,
telemetry path, runtime download, or WebView API. The macOS bindings compile
only on macOS; other targets expose a fixed unsupported secure-storage result.
The prototype's native real-machine matrix passed in an explicitly approved,
time-limited Personal Team development profile. The production Tauri
configuration still adds no entitlement. Unsigned and incomplete signing
contexts failed closed, and no dependency or storage fallback was substituted;
see [`research/I02-crypto-results.md`](./research/I02-crypto-results.md).

### G0 dependency disposition

G0 accepts the exact primitive pins and restricted feature sets above as the
implementation basis for I05. This is not an independent audit, a
production dependency freeze, or approval of a persistence container. ADR 0002
owns primitive and wrapper semantics; ADR 0004 owns macOS Keychain policy and
identity continuity; ADR 0005 owns the I05/I07 container and migration decision
boundaries. G1 must repeat vulnerability, maintenance, license, native-storage,
side-channel, and supply-chain review before release.

The provisional Argon2 profile is valid only as an explicitly persisted
Apple-Silicon development profile until I08 validates the accepted macOS 15
floor and the current macOS release under realistic application memory load.
No new dependency is approved by G0.

## I04 approved Windows native dependency

Approval date: 2026-09-21. The user explicitly approved the combined dependency
and native-API proposal in
[`research/I04-windows-dependency-proposal.md`](./research/I04-windows-dependency-proposal.md).

| Dependency           | Scope and enabled features                                                                                                                                               | Purpose and review result                                                                                                                                                                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `windows-sys` 0.61.2 | Windows runtime only; defaults off; Foundation, Credentials, LibraryLoader, Power, Registry, RemoteDesktop, SystemInformation, KeyboardAndMouse, and WindowsAndMessaging | Microsoft-maintained MIT OR Apache-2.0 raw bindings for documented session, power, elapsed-input-age, Credential Manager, and development-only per-user Run APIs. It adds no Tauri capability, application permission, service, runtime download, telemetry, or network behavior. |

`windows-sys` resolves only `windows-link` 0.2.1 for this release, already
present transitively in the lockfile before I04. Its generated declarations are
the narrow unsafe boundary; Aeterna owns validation, lifecycle, zeroization, and
fixed error mapping around them. Global hooks, raw input, ETW, undocumented
Winlogon signals, shell commands, and additional wrapper crates were rejected.
Real-Windows build and behavior validation is intentionally deferred until the
complete application is available and must not be inferred from macOS checks.

## I05 approved SQLite dependency

Approval date: 2026-09-21. The user explicitly approved the exact dependency,
feature set, native surface, schema/container design, and migration policy in
[`research/I05-vault-format-and-dependency-proposal.md`](./research/I05-vault-format-and-dependency-proposal.md)
before implementation.

| Dependency                              | Scope and enabled features                            | Purpose and review result                                                                                                                                       |
| --------------------------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rusqlite` 0.40.2                       | Runtime; defaults off; `backup`, `bundled`, `limits`  | Narrow synchronous SQLite ownership, online migration-backup support, and hostile-input limits. MIT; no runtime network behavior or WebView API.                |
| `libsqlite3-sys` 0.38.2 / SQLite 3.53.2 | Transitive native runtime/build; bundled amalgamation | One exact SQLite baseline across supported hosts. The sys crate is MIT and SQLite is public domain. Its C/FFI and build-script surface is reviewed again at G1. |

The lockfile added exactly the approved expected packages: `rusqlite 0.40.2`,
`libsqlite3-sys 0.38.2`, `fallible-iterator 0.3.0`,
`fallible-streaming-iterator 0.1.9`, and the build-only `vcpkg 0.2.15` helper.
Already-resolved `bitflags`, `smallvec`, `cc`, and `pkg-config` satisfy the
remaining edges. No OpenSSL, SQLCipher, bindgen, async runtime, URL, pool,
serialization, virtual-table, hook, or WebAssembly feature was selected.

The bundled C build contains SQLite's load-extension capability, but the
`rusqlite` load-extension feature is disabled and Aeterna exposes neither a
generic SQL endpoint nor an extension-loading API. Aeterna adds no project
`unsafe` for SQLite. ATTACH create/write are disabled through safe connection
configuration and all ATTACH is independently capped by `SQLITE_LIMIT_ATTACHED=0`;
defensive mode, untrusted schema, disabled triggers/views/double-quoted string
literals, fixed limits, and static parameterized SQL further constrain the
native boundary. The repository adds no entitlement, operating-system
permission, telemetry, updater, remote service, or runtime network path.

## I07 approved macOS file-panel and filesystem boundary

Approval date: 2026-09-22. The user explicitly approved the exact native and
format proposal in
[`research/I07-export-import-format-and-dependency-proposal.md`](./research/I07-export-import-format-and-dependency-proposal.md),
including the corrected 15-byte canonical migration identifier.

| Dependency / feature change             | Scope                                                                                                                                                              | Purpose and review result                                                                                                                                                                                                                                                                                                      |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `libc` 0.2.189                          | Direct macOS-only runtime pin; defaults off                                                                                                                        | Exposes only `open`, `openat`, `fstat`, `fstatat`, `fchmod`, `fsync`, `linkat`, `unlinkat`, and `geteuid` behind one audited module for no-follow, descriptor-relative, mode-0600, no-replace publication. MIT OR Apache-2.0; already present transitively in the accepted lockfile; no network behavior or permission prompt. |
| `objc2-app-kit` 0.3.2 feature expansion | Existing exact macOS binding; adds `NSApplication`, `NSOpenPanel`, `NSPanel`, `NSResponder`, `NSSavePanel`, and `NSWindow` while retaining `std` and `NSWorkspace` | Uses the public AppKit open/save panels for one selected `.aeterna-vault` file. Zlib OR Apache-2.0 OR MIT; no Tauri plugin, entitlement, runtime download, or network behavior.                                                                                                                                                |

I07 adds no npm package, archive/compression/serialization crate, cryptographic
crate, filesystem/dialog/shell plugin, broad capability, entitlement, remote
service, telemetry path, or updater. It reuses the exact accepted
`aes-gcm`/`hkdf`/`sha2` primitives and the existing `rusqlite` repository. The
project-owned `unsafe` code is confined to the small macOS syscall adapter;
Objective-C lifetime and main-thread rules remain owned by the generated
`objc2` bindings.
