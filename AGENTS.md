# Aeterna Repository Guidance

This file contains durable engineering conventions and agent behavior that should apply to every development task in this repository.

Do not record the current iteration, milestone, temporary priority, completion status, task list, or mutable product parameters here. Put that information in design documents, ADRs, plans, or the issue tracker. Keep this file concise and extend it only when a recurring implementation mistake or review comment should become a permanent rule.

## Scope and instruction routing

- This file applies to the entire repository. When a target directory contains a more specific `AGENTS.md` or `AGENTS.override.md`, follow the instructions closest to the code being changed.
- Explicit instructions in the current user task take precedence over repository guidance. Platform and system instructions always have higher priority.
- [`docs/DESIGN.md`](docs/DESIGN.md) is the source of truth for product behavior, trust boundaries, and high-level architecture. Read only the sections relevant to the task instead of loading the entire document for every change.
- Accepted ADRs are the source of truth for technical decisions. If implementation and documentation disagree, report the conflict and determine whether it is an implementation defect, stale documentation, or a design change requiring approval.
- Do not infer the current development phase from status text in a design document. Determine the active scope from the user's task, the current code, and the maintained project plan.
- Once the directory structure is stable, place component-specific commands and constraints in nested `AGENTS.md` files rather than expanding this root file.

## Working behavior

Before editing:

1. Inspect the target files, adjacent implementation, tests, manifests, and existing workspace changes.
2. Find the repository's actual build, format, lint, and test entry points. Do not invent commands that are not configured.
3. Read only the design sections or ADRs directly relevant to the task.
4. Determine whether the change affects public behavior, persisted data, protocols, permissions, or security boundaries.

While implementing:

- Complete the requested change rather than stopping at a plan or example.
- Fix root causes and keep the diff small and cohesive. Do not include unrelated refactors, repository-wide formatting, or directory reorganizations.
- Follow existing style and module boundaries. Do not add abstractions, compatibility layers, or speculative features unless the task requires them.
- Preserve user changes and unrelated work. In a dirty workspace, modify only files required by the task.
- Make reasonable, reversible assumptions for routine details. Ask before choosing an option that changes a security boundary, data semantics, or user-visible behavior.
- Do not use destructive Git or filesystem operations. Do not commit, push, publish, or deploy unless explicitly requested.
- Never make a change pass by disabling checks, deleting assertions, swallowing errors, or weakening types.
- Do not expand the task to unrelated issues. Report an unrelated issue when it blocks the task or creates a serious risk.

## Architecture and boundaries

- Keep presentation and interaction in the UI. Keep core business logic, security decisions, persistence, and system capabilities in controlled Rust or server-side modules.
- Isolate platform-specific behavior behind small interfaces instead of scattering Windows and macOS conditionals throughout domain code.
- Do not duplicate domain rules across routes, queue consumers, UI components, and repositories. Give critical rules one authoritative implementation with focused tests.
- Treat IPC, network, file, environment, and database inputs as untrusted. Use typed schemas and validate type, range, size, and version at the receiving boundary.
- Do not expose arbitrary SQL, shell execution, unrestricted filesystem paths, or generic execution endpoints.
- Avoid dependency cycles and cross-layer shortcuts. Keep dependency direction explicit and record non-obvious architectural decisions in an ADR.

## Project language

English is the canonical language for source code and repository engineering artifacts. This requirement supports an international product and a globally accessible contributor base.

- Write identifiers, source comments, doc comments, Rustdoc, JSDoc/TSDoc, developer-facing documentation, READMEs, ADRs, API documentation, schema descriptions, migration comments, test names, and assertion messages in English.
- Write runtime logs, tracing fields, diagnostic output, CLI output, panic text, internal error text, and server-side operational messages in English.
- Use English for API error codes, response field names, response messages, validation messages, event names, audit descriptions, and machine-readable status values.
- Keep error codes stable and machine-readable. Localize user-facing explanations at the presentation layer instead of returning locale-specific server messages.
- Do not hardcode English UI copy. Store user-visible text in the i18n system with English as the source/default locale and add translations through locale resources.
- Non-English text is allowed only in localization resources, translated user-facing documentation, language-specific test fixtures, or user-provided content.
- Conversation with the user may follow the user's language; committed source and engineering artifacts remain in English unless they fall under an exception above.

## Coding conventions

### Rust

- Use stable Rust and the toolchain pinned by the repository.
- Before completion, run `cargo fmt --check`, `cargo clippy`, and `cargo test` for the affected workspace or package. Prefer a repository-provided aggregate command when one exists.
- Avoid `unwrap()`, `expect()`, and `panic!()` in production paths. Propagate recoverable failures through explicit error types.
- Use `unsafe` only at a narrow platform boundary that cannot be implemented with safe APIs. Document the safety invariant for every `unsafe` block and cover it with focused tests or review evidence.
- Make time, randomness, storage, and external services replaceable so failures, timeouts, and races can be tested.
- Do not derive or implement `Debug` or `Display` in a way that exposes credentials or secret values.

### TypeScript and React

- Keep TypeScript strict. Do not use `any`, unjustified type assertions, or non-null assertions to bypass a problem.
- Validate external data at runtime; TypeScript types alone are not boundary validation.
- Do not implement cryptography, authorization, persistence transactions, or server state-machine decisions in React components.
- Avoid untrusted HTML, dynamic string execution, and remote scripts in privileged windows.
- Put all user-visible text through the project's i18n system. Format dates, times, and numbers with locale-aware APIs.
- Use the package manager and scripts selected by `package.json` and the lockfile. Do not switch between npm, pnpm, yarn, or bun without an explicit decision.

### Database and background jobs

- Change schemas through versioned migrations. Do not rewrite a migration that has been shared or applied.
- Define transaction boundaries, foreign keys, unique constraints, and idempotency keys explicitly. Do not implement concurrent transitions with an unconditional read-then-write sequence.
- Design scheduled jobs, queue consumers, and callbacks for at-least-once execution, with idempotent external effects.
- Store server-side time in UTC and convert time zones only for presentation.
- A destructive migration requires a backup, compatibility, and recovery plan plus explicit approval before execution.

### General

- Use English identifiers. Comments should explain intent, invariants, or platform limitations rather than restating visible code.
- Do not scatter protocol values, timeouts, state names, or user-facing text as literals. Use typed constants, configuration, or enums.
- Keep public APIs and complex modules small and explicit. Remove unused code and never retain debugging backdoors.
- Make errors actionable without exposing credentials, secrets, personal data, or sensitive filesystem paths.

## Security and privacy

Aeterna handles encrypted content, device activity, and delayed recovery. Tasks in these areas must read the relevant trust-boundary and threat-model sections of `docs/DESIGN.md`; do not duplicate detailed product flows in this file.

- Do not implement cryptographic primitives or invent encryption formats. Changes to algorithms, KDF parameters, key hierarchy, serialization formats, or recovery conditions require an ADR, a security impact analysis, and user approval.
- Passwords, keys, recovery material, tokens, complete contact details, and user content must not appear in logs, panic output, telemetry, error messages, test snapshots, or example files.
- Use operating-system secure storage, least privilege, narrow IPC, and strict CSP. Do not broaden permanent permissions for development convenience.
- Minimize plaintext secret lifetimes and clear sensitive values promptly. Tests must use clearly synthetic data, never copied production data.
- Validate integrity and size for imports, encrypted containers, IPC, and API inputs. Account for malformed input and resource exhaustion.
- Do not add telemetry, remote code, a new third-party data recipient, or a production secret-access path without explicit approval and corresponding design and privacy documentation.
- Before adding a cryptography, native-system, auto-update, telemetry, or production cloud-service dependency, document its maintenance status, license, permissions, network behavior, and alternatives, then obtain approval.

## Testing and verification

- Test observable behavior and failure modes rather than mirroring implementation details.
- When fixing a defect, prefer a regression test that fails before the fix and passes afterward.
- For security, concurrency, migration, recovery, import, and background-job code, cover invalid input, tampering, replay, duplicate execution, timeout, interruption, and race conditions as applicable.
- Run the most focused checks first, then run package or workspace tests, lint, typecheck, and build according to the affected scope.
- Report only commands that were actually run and their real results. A mock passing is not end-to-end verification, and successful compilation is not functional acceptance.
- If the environment or missing scaffolding prevents a check, state the reason and the unverified scope in the completion report.
- After a stable toolchain is introduced, add its canonical verification commands here or in the nearest component-level `AGENTS.md`.

### Canonical desktop commands

- Install locked frontend dependencies with `npm ci --ignore-scripts`.
- Run the complete formatting, lint, type, frontend, and Rust suite with `npm run check`.
- Build the unsigned host executable with `npm run desktop:build`.
- Launch the local native development application with `npm run desktop:dev`.

## Dependencies and generated files

- Prefer existing dependencies. A new production dependency must provide clear value and be checked for maintenance, license, and supply-chain risk.
- Keep lockfiles synchronized. Do not edit generated files manually; use their authoritative generator.
- Do not execute untrusted or unpinned remote installation scripts, and do not load remote code at runtime.
- Do not commit credentials, `.env` files, build output, temporary databases, or local logs. Example configuration must contain placeholders only.

## Documentation and change control

- Update relevant documentation in the same change when behavior, APIs, schemas, permissions, or operating procedures change.
- Write an ADR before implementing a major architecture, security-boundary, persistence-format, or third-party-service decision. Include context, the decision, alternatives, risks, migration, and verification.
- Do not rewrite product design for implementation convenience. If the current design is infeasible, present the concrete issue, evidence, and alternatives first.
- Do not put phase status, temporary plans, or release checklists in `AGENTS.md`. Maintain them in dedicated planning or task artifacts.
- Keep comments and documentation aligned with implementation. Remove obsolete guidance and avoid ownerless TODO comments.

## Code review rules

Review in this priority order:

1. Security, privacy, permissions, and secret exposure.
2. Data loss, recovery failure, race conditions, and irreversible side effects.
3. Behavioral correctness, compatibility, migrations, and error handling.
4. Test gaps and long-term maintainability.
5. Readability issues that formatters and linters cannot enforce.

Each finding must identify a concrete trigger, impact, file and line, and a practical fix direction. Do not report personal preferences as defects or use vague statements such as "this may be a problem." When no actionable finding exists, say so and identify any verification gaps.

## Completion report

At the end of a task, report concisely:

- The behavior that changed.
- The main files modified.
- The checks or tests that were run and their results.
- Any unverified scope, known risk, or remaining decision.

Do not claim completion until the relevant checks pass, documentation is synchronized, and no hidden temporary bypass remains.
