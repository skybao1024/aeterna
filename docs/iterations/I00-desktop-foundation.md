# I00 — Desktop Engineering Foundation

## Objective

Create a reproducible, least-privilege desktop development baseline for the
public Aeterna client. This iteration proves that the selected frontend, Tauri,
and Rust toolchains work together and establishes the checks every later client
iteration must pass.

This is an engineering-foundation iteration, not a product-feature iteration.

## Required reading

- `AGENTS.md`
- `docs/DESIGN.md`: sections 1, 3, 4, 10.3, 16, 17.1, 18, and 19
- `docs/DEVELOPMENT_PLAN.md`: sections 1-4 and I00

## Scope

1. Inspect installed tooling and official Tauri v2 prerequisites before
   scaffolding.
2. Create a Tauri v2 desktop application using React and strict TypeScript.
3. Select one package manager, commit its lockfile, and expose stable scripts
   for formatting, linting, type checking, unit tests, and builds.
4. Pin the Rust toolchain and add formatting, Clippy, and unit-test entry points.
5. Establish Tailwind CSS and a minimal Shadcn-compatible component foundation
   without building product screens.
6. Configure `react-i18next` with English as the default locale and a Simplified
   Chinese resource. All visible strings must use translation keys.
7. Configure the smallest practical Tauri capability set and a strict CSP. Do
   not add filesystem, shell, updater, autostart, global-input, SQL, or network
   permissions that this iteration does not use.
8. Add a small application shell and one Rust command solely to prove typed,
   narrow IPC. The command must not accept generic command names, SQL, shell
   text, or filesystem paths.
9. Add frontend rendering/interaction tests and Rust unit tests for the baseline
   behavior.
10. Add contributor-facing setup and verification documentation in English.
11. Add CI configuration for the checks that can run deterministically without
    signing credentials. Keep platform build coverage explicit.

## Out of scope

- Activity or idle detection
- Autostart and tray behavior
- Vault database or attachments
- Production cryptography, passwords, ERC, VDK, or SRS
- Device registration, signing keys, heartbeats, or service APIs
- Installer signing, auto-update, telemetry, and crash reporting
- Product onboarding or finished visual design
- Changes to `aeterna-control-plane`

## Required boundaries

- Use a clearly documented development-only application identifier. Do not
  imply that signing identity or production persistence paths are frozen.
- The WebView must not receive privileged capabilities merely for convenience.
- Do not load remote scripts, fonts, or other runtime code.
- Do not add telemetry or send any network request.
- Source, comments, documentation, logs, errors, and configuration descriptions
  must be English. Simplified Chinese appears only in locale resources.
- Do not create empty speculative domain layers. Introduce only the structure
  needed by this iteration and record the intended future boundaries in docs.

## Acceptance criteria

1. A new contributor can install documented prerequisites and run the desktop
   application using repository commands.
2. The application launches on the current macOS development host and renders
   without a JavaScript or Rust error.
3. English is the default UI language; switching to Simplified Chinese changes
   the baseline UI without hard-coded user-visible strings.
4. Frontend code is strict TypeScript and passes formatting, linting, type
   checking, unit tests, and production build.
5. Rust code passes `cargo fmt --check`, Clippy with warnings denied, unit tests,
   and a development build/check for the current host.
6. The narrow IPC smoke test succeeds and invalid input produces a safe English
   error without exposing internal paths or stack details.
7. Tauri capabilities and CSP contain no permissions or origins beyond the
   baseline application needs.
8. The dependency and lock files are committed together and no generated build
   output, credential, `.env`, log, or local database is tracked.
9. CI uses the same documented checks and does not depend on release secrets.
10. No product behavior from later iterations is partially implemented.

## Required test scenarios

- Render the baseline shell in the default locale.
- Switch locale and verify translated text and persisted preference behavior.
- Invoke the typed IPC smoke command with valid input.
- Reject invalid IPC input at the Rust boundary.
- Verify a missing or unsupported saved locale falls back to English.
- Confirm a production frontend build contains no remote runtime dependency.
- Inspect the generated Tauri capability and CSP configuration.

## Completion report

At the end of the development task, report:

- the toolchain and application versions actually pinned;
- the main files and commands introduced;
- every verification command run and its real result;
- whether a native desktop window was launched and manually observed;
- platform checks not run and why;
- dependencies added, including license/maintenance observations;
- any ADR or design question created;
- whether every acceptance criterion passed.

Do not start I01 in the same task. Update `docs/DEVELOPMENT_PLAN.md` only after
I00 is fully verified; otherwise mark I00 `Blocked` with the exact recovery
action.
