# Aeterna desktop client

Aeterna is a local-first desktop application. This repository contains the I00
Tauri/React engineering foundation, development-only I01/I04 platform activity
probes, I02/I04 cryptography and secure-storage risk prototypes, the accepted
I05 encrypted SQLite record store, and the I06 local vault-item workflow. It
does not implement production activity detection, recovery, backup/export,
device registration, synchronization, or network services.

The application identifier is `dev.aeterna.desktop.foundation`. It is
explicitly development-only and does not reserve a production signing identity.
I06 uses that development identifier's fixed application-local-data directory,
so its local vault must not be treated as production or irreplaceable storage.

## Prerequisites

The repository pins Node.js 24.21.0 in `.nvmrc`, npm 11.19.0 in `package.json`,
and Rust 1.98.1 with rustfmt and Clippy in `rust-toolchain.toml`.

Install the current [Tauri v2 system prerequisites](https://v2.tauri.app/start/prerequisites/)
for your platform:

- macOS desktop development requires Xcode Command Line Tools (`xcode-select --install`)
  or a completed Xcode installation.
- Windows requires Microsoft C++ Build Tools with Desktop development with C++
  and the WebView2 runtime.
- Linux requires the WebKitGTK 4.1 and related packages listed by Tauri for the
  distribution.

Install Node through a version manager that honors `.nvmrc`. Install Rust through
`rustup`; entering this repository selects the pinned toolchain and components.
Verify the selected tools before installing dependencies:

```sh
node --version
npm --version
rustc --version
cargo --version
```

The expected Node and npm outputs are `v24.21.0` and `11.19.0`. The Rust release
must be `1.98.1`.

## Set up and run

```sh
npm ci --ignore-scripts
npm run desktop:dev
```

`desktop:dev` starts Vite on the loopback-only address `127.0.0.1:1420`, builds
the Rust host, and opens the native window. The development CSP permits only
that loopback origin in addition to Tauri IPC. The production CSP contains no
remote origin.

## Verification

Run the complete deterministic local suite:

```sh
npm run check
npm run desktop:build
```

The individual entry points are:

```sh
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
npm run rust:fmt
npm run rust:clippy
npm run rust:test
npm run rust:check
```

`npm run build` also inspects the production bundle for remote runtime assets.
`npm run desktop:build` produces an unsigned host executable without an installer
bundle. CI repeats these checks on explicit Linux, macOS, and Windows runners and
does not use release credentials.

## I01/I04 activity probe

On macOS or Windows, run the local-only feasibility probe with:

```sh
npm run activity:probe
```

On macOS, the probe samples the accepted Quartz HID/Combined elapsed ages and
documented workspace power/session notifications. On Windows, it uses
current-session `GetLastInputInfo`, WTS session state/notifications, and power
messages. It does not install a hook, inspect input content, request a sensitive
permission, send a network heartbeat, or expose observations to the WebView.
Redacted JSON Lines are written under the Git-ignored
`src-tauri/target/i01-diagnostics` directory on macOS and
`src-tauri/target/i04-diagnostics` on Windows. Quit normally to exercise orderly
observer cleanup.

For the explicitly test-only compressed timing used by the I01 matrix:

```sh
AETERNA_I01_TEST_ONLY_COMPRESSED=1 npm run activity:probe
```

The Windows equivalent uses `AETERNA_I04_TEST_ONLY_COMPRESSED=1`. The compressed
configuration is visibly labeled `i04-platform-activity-test-only-compressed-v1`
in the trace and is never the default. The macOS feasibility result is documented in
[`docs/research/I01-macos-activity-results.md`](docs/research/I01-macos-activity-results.md).
The Windows implementation and deferred validation matrix are documented in
[`docs/research/I04-windows-results.md`](docs/research/I04-windows-results.md).

## I02 cryptography and secure-storage prototype

I02 provides backend-only, versioned test adapters for Argon2id,
HKDF-SHA-256, AES-256-GCM, Bech32m ERC handling, Ed25519 device signing, and a
narrow macOS data-protection Keychain port. It exposes no new Tauri command or
WebView data. The JSON fixture contains conspicuously synthetic values and is
not a production vault format.

The opt-in release benchmark accepts only a named profile, never a password or
key:

```sh
cargo run --manifest-path src-tauri/Cargo.toml \
  --release --bin i02_argon2_benchmark -- A
```

The manual Keychain probe accepts only a fixed action name and generates its
synthetic signing key internally:

```sh
cargo run --manifest-path src-tauri/Cargo.toml \
  --bin i02_keychain_probe -- create
```

I02 is Accepted. The profile-signed macOS real-machine matrix passed create,
restart/retrieve/sign, wrong identity, replace, delete/not-found, lock denial,
unlock recovery, signed-release continuity, metadata, and final cleanup. The
ad-hoc release probe failed closed with a missing-entitlement result and no
plaintext fallback. The Personal Team profile was development evidence only;
production signing remains a G0 decision. See
[`docs/research/I02-crypto-results.md`](docs/research/I02-crypto-results.md) and
Proposed
[`ADR 0002`](docs/adr/0002-cryptographic-envelope-and-key-storage.md).

## I04 Windows Credential Manager and autostart probes

On Windows, the fixed credential probe supports create, read/sign, wrong
identity, replace, typed metadata, lock observation, and idempotent cleanup:

```powershell
cargo run --manifest-path src-tauri/Cargo.toml `
  --bin i04_windows_credential_probe -- create
```

The activity-prototype executable manages only the temporary current-user Run
value named `AeternaI04ActivityProbe`. Build and invoke every action with the
same profile and path:

```powershell
cargo run --manifest-path src-tauri/Cargo.toml `
  --features activity-prototype --bin aeterna-desktop -- install-dev-autostart
cargo run --manifest-path src-tauri/Cargo.toml `
  --features activity-prototype --bin aeterna-desktop -- status-dev-autostart
cargo run --manifest-path src-tauri/Cargo.toml `
  --features activity-prototype --bin aeterna-desktop -- remove-dev-autostart
```

Removal verifies the exact value is absent and never deletes the Run key or an
unexpected conflicting value. The Windows implementation has not yet been run
on Windows; build and interactive matrices are intentionally deferred until the
complete application is available. macOS checks are regression evidence only.

## Security boundary

The main WebView receives exactly fourteen purpose-specific I06 permissions for
vault status, development initialization, unlock/lock, item CRUD, and bounded
attachment prepare/commit/cancel/read/remove. Rust owns the fixed app-local
path, unlocked session, validation, canonical item payload, encryption, and
persistence. Attachment upload/download uses bounded raw IPC; no arbitrary
path, raw SQL, raw key, generic crypto, filesystem, dialog, shell, HTTP,
clipboard, updater, telemetry, or network permission/plugin is present.

I06 initialization deliberately discards recovery material. The UI warns that
recovery, account binding, backup, and export are unavailable, losing the
master password loses access, and irreplaceable data must not be stored. The
feature-gated I01 native adapter, I02/I04 storage modules, and opt-in probes add
no WebView capability. See `docs/DESIGN.md`, ADR 0007, ADR 0008, and
`docs/DEPENDENCIES.md` for the governing boundaries.
