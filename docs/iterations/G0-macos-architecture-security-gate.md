# G0 — macOS Phase 0 Architecture and Security Gate

## Objective

Decide whether the accepted Phase 0 evidence is sufficient to begin the
macOS-first production path. G0 is a review and decision gate, not a feature
iteration. It must not implement I05 or later behavior.

Windows is explicitly outside this gate. I04 remains In Progress and ADR 0003
remains Proposed until GW completes the unchanged real-Windows matrices.

## Required sources

Read before making a decision:

- repository `AGENTS.md`;
- the relevant trust boundaries and release sequencing in `docs/DESIGN.md`;
- G0, I01-I04, verification ownership, prerequisites, and progress history in
  `docs/DEVELOPMENT_PLAN.md`;
- I01-I04 briefs, proposals, ADRs, and result ledgers;
- the implemented client modules and focused tests affected by I01, I02, and
  the I04 shared-interface changes;
- the I03 server implementation, migration, PostgreSQL tests, result ledger,
  and server ADR in its exact reviewed worktree or integrated baseline; and
- dependency, signing, CI, and verification documentation in both repositories.

Do not treat task summaries as evidence when the exact artifact is available.

## Gate scope

G0 owns these macOS-first decisions:

1. the initial supported platform statement and macOS version/testing floor;
2. the activity algorithm, unlock gate, two-epoch confirmation, cooldown,
   remote-session semantics, privacy boundary, lifecycle failure behavior, and
   accepted waivers;
3. macOS device-key storage, signing identity continuity requirements, secret
   redaction, and fail-closed behavior;
4. cryptographic primitives, dependency pins, prototype KDF recommendation,
   versioning rules, and which production-format or UX decisions must be split
   into later ADRs instead of being falsely claimed complete;
5. server state-machine transaction winner semantics, outage recovery,
   transactional Outbox atomicity, and idempotency boundary;
6. public protocol ownership, schema/versioning direction, and the rule that
   neither private server code nor client implementation silently becomes the
   contract source of truth; and
7. the exact prerequisites and verification commands for I05.

## Explicit exclusions

G0 must not:

- accept I04, ADR 0003, or any Windows matrix row;
- authorize Windows production lifecycle work, packaging, support claims, or
  release;
- claim an independent external cryptographic audit, penetration test,
  production signing identity, final container format, or recovery UX that has
  not occurred;
- implement the vault, public protocol, heartbeat, notification, recovery,
  updater, telemetry, or production autostart behavior; or
- weaken a prior acceptance criterion to make the gate pass.

## Baseline integrity checkpoint

Before G0 can be Accepted, every reviewed implementation must have a recoverable
and unambiguous source-control reference.

- The I03 implementation currently lives in an isolated server worktree. Verify
  its exact diff and evidence, then obtain explicit user authorization before
  integrating or committing it to the authoritative server development branch.
- The client Phase 0 baseline is currently uncommitted. Review its complete
  scope and obtain explicit user authorization before creating a Phase 0
  checkpoint commit.
- Never reset, clean, discard, commit, merge, push, publish, or deploy without
  the corresponding explicit authorization.

A dangling worktree or an all-untracked client tree may be reviewed, but G0
cannot be Accepted while those are the only copies of the approved baseline.

## Review method

For each proposed decision:

1. cite the exact design requirement and evidence artifact;
2. distinguish automated tests, compilation, build evidence, and real-machine
   evidence;
3. identify every waiver, unverified assumption, and deferred decision;
4. state whether the decision is accepted, rejected, split into a later ADR, or
   blocks I05;
5. verify implementation and documentation agree; and
6. provide a concise approval digest for explicit user confirmation.

Security review priority is: premature release or data loss, secret exposure,
platform/session false positives, cryptographic misuse, persistence/migration
ambiguity, protocol drift, then maintainability.

## Required deliverables

- `docs/research/G0-macos-gate-review.md` with the evidence map, findings,
  accepted decisions, deferred decisions with owners, baseline references, and
  final recommendation;
- accepted or revised macOS/client ADRs, with new narrowly scoped ADRs where a
  proposed document combines G0 decisions with later production decisions;
- an accepted or revised server state-machine ADR in the authoritative server
  baseline;
- synchronized `docs/DESIGN.md`, `docs/DEVELOPMENT_PLAN.md`, dependency records,
  and verification instructions; and
- exact source-control checkpoint references for the client and server Phase 0
  baselines.

All repository artifacts must be in English. Do not copy secrets, device
identifiers, usernames, raw activity traces, or sensitive paths into the review.

## Acceptance criteria

G0 is `Accepted` only when:

1. I01, I02, and I03 remain Accepted with their evidence intact;
2. the I04 implementation checkpoint is isolated from the macOS release path,
   while I04 and GW remain visibly incomplete;
3. no unresolved macOS activity, secure-storage, cryptographic-core, or server
   concurrency risk blocks I05;
4. every decision needed by I05 is approved or assigned to a specific later
   iteration without creating a circular dependency;
5. production signing, container, migration, UX, audit, and release decisions
   are described truthfully and are not claimed complete early;
6. client and server Phase 0 implementations have recoverable, exact baseline
   references;
7. relevant canonical checks are rerun against the reviewed baselines and their
   real results are recorded;
8. `docs/DESIGN.md`, ADRs, implementation, and the development plan agree; and
9. the user explicitly approves the final G0 decision digest.

If any criterion fails, keep G0 `Pending` or mark it `Blocked` with concrete
evidence and the exact decision or work needed. Do not start I05 in the same
task.

## Completion report

Report:

- the gate outcome and what it authorizes;
- approved, revised, split, and still-Proposed ADRs;
- client and server baseline references;
- checks run and exact results;
- waivers and deferred decisions with owning iterations/gates;
- Windows exclusions and GW status; and
- the exact next eligible iteration.
