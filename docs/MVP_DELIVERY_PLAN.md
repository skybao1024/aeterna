# Aeterna MVP Delivery Plan

> Updated: 2026-09-28
> Product behavior and trust boundaries: [DESIGN.md](./DESIGN.md)
> Historical iteration results: [DEVELOPMENT_PLAN.md](./DEVELOPMENT_PLAN.md)

## Why the plan changed

I05-I14 accepted important storage, protocol, cryptographic, and control-plane
components. Their acceptance did **not** demonstrate that a person can complete
the Aeterna journey in the desktop app. In particular, the macOS activity agent
still holds confirmed candidates locally, the signed heartbeat coordinator is
not connected to it, and the desktop has no complete account, contact, or claim
workflow. The old sequence jumped from component acceptance to the G1 security
gate. That omitted runtime integration and let an exhaustive I08 native matrix
block ordinary feature development.

I08 remains `In Progress`. Its code may be integrated as a reviewed, committed
implementation checkpoint without calling I08 `Accepted`. Outstanding native
qualification is a release-evidence obligation, not a dependency for the next
feature-development task. Windows qualification, billing, signing, and
production deployment likewise do not block the macOS MVP build.

## What "MVP complete" means

Use three distinct claims; never substitute one for another:

- **MVP feature-complete:** A person can complete macOS setup, automatic
  heartbeat, warning, release, and local recovery through the app and
  controlled contact pages against the development service. Critical failure
  cases pass with synthetic data and injected email/KMS providers. No AWS
  account or real delivery is required.
- **MVP pilot-validated:** The same journey works in a non-production
  environment with approved real KMS and SES resources, controlled test
  mailboxes, two real Macs, and recovery from a separate local copy. Failed
  delivery and unavailable KMS fail closed. User-provided staging access is
  required.
- **Public-release ready:** G1 independent security, native, and recovery
  evidence; I15 release operations; signed artifacts; backup and shutdown
  procedures; and explicit human release approval all pass.

"Feature-complete" is a development milestone, not permission to trust the
system with irreplaceable data or to enable real notifications. No iteration is
`Accepted` merely because its modules compile; its declared user-visible exit
path must work. Existing I09-I14 `Accepted` statuses retain their original
component-scoped meaning and are not retroactively relabeled as an MVP pass.

### Feature-complete scope

The minimum coherent macOS journey is:

1. Create and reopen a locally encrypted vault; edit notes and bounded
   attachments; export and restore a separate encrypted copy.
2. Verify Owner email, bind a device, enroll its delayed recovery record, and
   set an inactivity policy without uploading vault content, MP, ERC, or VDK.
3. Bind a second device to the same account. Confirmed local activity on either
   device yields a signed, server-accepted heartbeat; startup, lock, stale
   input, and network failure do not fabricate one. The UI shows real service
   status and the most recent accepted heartbeat. Each device keeps its own
   local vault; this is not device-to-device content synchronization.
4. Configure at least one accepted and verified Recovery Contact, including a
   controlled test message. Both confirm-now and private-until-release modes
   retain the distinct authority and disclosure rules in `DESIGN.md`.
5. Exercise warning, grace, cancellation by a valid heartbeat, and release
   through the development service's controlled clock and Outbox. Only a
   verified contact can claim after release.
6. Complete the claim-link/OTP/SRS flow, unlock a local vault with ERC plus SRS,
   and perform the mandatory post-release rekey before normal content access.
   Wrong factors, pre-release claims, wrong-device SRS, and interrupted rekey
   fail closed.

These paths must be reachable through actual desktop and recipient interfaces,
not only direct API calls, Rust unit tests, or database fixtures. A test-only
email sink and injected KMS provider may stand in for external providers at
this milestone, but they must be isolated from production configuration.

Owner-forgot-MP recovery, proactive ERC rotation, complete multi-device
rotation UX, Windows, payments, and commercial operations remain v1 or later
work, not blockers for this _internal_ MVP feature-complete claim. Their
existing security rules and accepted component evidence remain in force; no
public v1 release may silently omit a feature promised by `DESIGN.md`.

## Development sequence

The IDs below are new delivery slices, not renumberings of I00-I16. M00 is
`Accepted`; M01-M06 and V01-V02 remain `Pending`. Each slice must leave a
reviewed, recoverable commit and an English result note. A slice may start from a committed
implementation checkpoint even while unrelated native qualification remains
open. Never have two writers edit the same checkout concurrently.

1. **M00 (P0, Accepted 2026-09-28): I08 implementation checkpoint.** Reconcile the current dirty
   client worktree with I14, fix actual code regressions, run focused tests and
   one canonical client check/build, then commit a clearly labeled checkpoint.
   Do not run the remaining native matrix. I08 stays `In Progress`.
   The I08 implementation was reviewed against the I09-I14 client baseline.
   The review removed a stale native close marker that could hide the window
   after a cancelled close, restored visible startup on non-macOS platforms,
   and kept the macOS-only pressure fixture from requiring macOS dependencies
   on other targets. Focused close and strict IPC regressions passed. Pinned
   Node 24.21.0, npm 11.19.0, and Rust 1.98.1 completed `npm run check`:
   28 frontend tests, 135 Rust library tests, two main-binary tests, and 15
   vault integration tests passed; the existing exact 1 GiB package test was
   ignored. `npm run desktop:build` produced the unsigned host executable.
   Release debug stripping remains unverified because `rust-objcopy` could not
   load `libLLVM.dylib`. I08 native qualification remains open.
2. **M01 (P0): Owner identity and device binding.** A person verifies email,
   binds the first and second device, and sees the real binding state in the
   desktop. The Rust side owns keys, signatures, transport, and secure storage.
   Restart, invalid grants, and rejected binding are exercised against Docker.
   Depends on M00 and the accepted I09 contract.
3. **M02 (P0): Policy and recovery enrollment.** A bound Owner configures the
   inactivity policy, creates a local vault, receives the ERC handoff, and
   confirms a per-device recovery record using an injected development KMS
   provider. Restart and partial-enrollment failure stay truthful and safe.
   Depends on M01 and the accepted I13 contract.
4. **M03 (P0): Automatic signed heartbeat.** Connect the private macOS candidate
   to the I10 coordinator, bounded transport/retry, authenticated response, and
   visible health state. Two devices extend one account; startup, lock, stale
   candidates, and network loss do not fabricate acceptance. Depends on M02,
   approved activity ADRs, and the accepted I10 contract.
5. **M04 (P0): Contacts and notification setup.** Add Owner contact/template
   controls and isolated recipient acceptance/verification pages. Confirm-now
   and private-until-release retain different authority; cancellation,
   redaction, bounce state, and controlled test delivery use a local mail sink.
   Depends on M01 and the accepted I11/I12 service boundary.
6. **M05 (P0): Claim and end-to-end recovery.** Add desktop claim/OTP/SRS and
   local ERC recovery UI. Run one controlled warning-to-release-to-claim-to-rekey
   journey, a two-copy restore, and the critical rejection/interruption cases.
   Declare **MVP feature-complete** only when every scope item above works
   through the actual interfaces. Depends on M03-M04 and accepted I13/I14 core.
7. **M06 (P1): Remaining v1 recovery UX.** Complete Owner self-recovery and ERC
   rotation UI, including cancellation and partial-device status. This is
   development, not a deep-test task, and does not redefine the internal MVP.
   Depends on M05 and accepted I14 core.
8. **V01 (P1): Staging service validation.** After the single readiness request
   below, provision approved SES/KMS test resources and repeat the journey with
   controlled real delivery and a real KMS key. Declare **MVP pilot-validated**
   only after evidence passes. Depends on M05 and user-provided prerequisites.
9. **V02 (P1): Release-depth validation.** Finish I08 native qualification,
   independent crypto/security review, fuzzing, backup/restore, and provider-
   failure drills. Resolve findings before G1. Depends on M06 and staging and
   reviewer availability.

M00-M05 are development work, not a long-running hardware test campaign. The
next action is M01. V01/V02 may be prepared without blocking M01-M05,
but real AWS calls, production flags, and broad native matrices wait until MVP
feature completion and the prerequisites below. G1 is a release-readiness gate
after M06 and V01/V02, not the next coding task. I15 follows G1. The historical
I08 row stays open until its native evidence is complete; M00 does not disguise
that status. Do not invent a calendar completion date from the old component
count; after M00 and M01, report a measured estimate for the remaining slices.

## Verification budget and stop rules

- During M00-M05, run the smallest test that covers each changed behavior and
  its relevant failure mode. Run the affected repository's canonical suite and
  build once when a slice is otherwise complete. Do not repeat unchanged
  Argon2 benchmarks, 15-minute energy captures, OS permission matrices,
  independent audits, or full release drills for each code edit.
- A failed required check is a code problem to fix, not a reason to delete the
  check. After one focused reproduction and one corrective attempt, record the
  remaining blocker and choose a narrower diagnostic; do not start unrelated
  probes or silently extend the test matrix.
- The development service may accelerate time and use synthetic recipients and
  provider doubles. No synthetic result counts as real SES delivery, real KMS
  resilience, macOS floor qualification, or production readiness.
- An implementation slice is `Accepted` immediately after its own observable
  exit checks pass, documentation is current, and its changes are committed.
  A pending release-only test must be tracked in V01/V02 rather than quietly
  added to the slice's exit criteria. A required slice test cannot be deferred
  merely to obtain `Accepted`.
- Reuse approved ADRs. Request one consolidated decision only for a genuinely
  new security, persistence, protocol, third-party, or product boundary. Normal
  implementation and tests do not require repeated approval. External emails,
  cloud provisioning, irreversible changes, credential entry, and disruptive
  OS operations retain their actual human authorization requirements.

## One staging-readiness request, after M05

Do not ask the Owner for AWS credentials during M00-M05. Before V01, present one
consolidated checklist and ask the Owner to provide access through the relevant
AWS account, IAM roles, DNS controls, and test devices—not by pasting secrets in
chat or committing them to either repository. The checklist is:

- an approved staging AWS account and budget, the already selected
  `ap-southeast-1` KMS Region, a customer-managed test key, and separate
  provision/decrypt workload roles with narrowly scoped permissions;
- an approved SES sending Region, verified sender/domain, DNS ownership for
  DKIM/SPF/DMARC, a configuration set, exact SNS topic/callback subscription,
  and any provider approval needed for the intended test recipients;
- an HTTPS staging service endpoint, controlled Owner and contact mailboxes,
  two test Macs (including the macOS 15 floor host), an Apple Development
  identity/profile valid for signed test builds on both Macs, synthetic vault
  material, and a separate encrypted local backup copy; and
- written authorization for bounded real messages, cloud resource creation,
  expected cost, data jurisdiction, and cleanup/rollback responsibilities.

Production enablement is a later I15 decision. V01 must not turn staging
credentials or a successful test into permission to enable production. If a
prerequisite is unavailable, report exactly that prerequisite; continue
independent development or review rather than labeling the entire project
blocked.

## Scope control

At the start of each new development task, state its single user-visible
journey, dependencies, exact exit checks, and explicit non-goals. Do not attach
G1's independent review or I08's remaining native matrix to M01-M05. Add a
new task only when a discovered dependency is needed for an MVP journey; record
its reason and how it changes the critical path. Keep component acceptance,
MVP feature completion, pilot validation, and public-release approval separate
in every status report.
