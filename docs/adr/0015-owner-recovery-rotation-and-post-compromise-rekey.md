# ADR 0015: Owner recovery, recovery generations, and post-compromise rekey

- Status: Accepted for implementation scope
- Date: 2026-09-27
- Decision owner: I14 Owner recovery and post-release protection boundary
- Approval: Explicit user approval on 2026-09-27
- Proposal: [I14 owner recovery, rotation, and post-compromise rekey proposal](../research/I14-owner-recovery-rotation-rekey-proposal.md)
- Governing decisions: [ADR 0002](./0002-cryptographic-envelope-and-key-storage.md),
  [ADR 0007](./0007-local-vault-format-v1.md),
  [ADR 0009](./0009-portable-export-package-and-atomic-restore-v1.md),
  and [ADR 0014](./0014-delayed-recovery-kms-and-claim-protocol.md)

## Context

The accepted design requires Owner self-recovery to combine a recent bound
device, device signature, Owner mailbox verification, a 24-hour cooldown, and
the ERC before a local Vault can open. It also requires pre-release ERC/SRS
rotation and a fresh VDK after release or claim.

Existing decisions intentionally stop short of these operations. ADR 0014
forbids pre-release SRS decrypt except for a future approved Owner flow, ADR
0007 does not define atomic whole-Vault VDK replacement, and the accepted I11
server state machine makes `RELEASED` terminal. Directly resetting that row or
silently reusing old factors would weaken already accepted security claims.

## Decision

Adopt the complete design in the linked proposal and prepare public protocol
v1.3.0 without publishing or deploying it.

Owner recovery is accepted only from the exact still-bound active device with
a sealed local recovery binding and a server-received signed heartbeat no more
than 15 minutes old. It requires a single-use Owner mailbox OTP, notices to all
configured verified Owner channels, and an inclusive 24-hour server cooldown.
Any active bound device may submit a signed cancellation before release. The
release and cancellation paths lock and recheck the same request so only one
can commit.

At maturity, only the initiating device may receive only its bound SRS. A
released SRS may be redelivered to that same freshly active device for a
bounded 24-hour completion window because the first response is already
copyable and crash recovery must not persist SRS or VDK. Completion requires a
new master password and an atomic new device SRS plus Recovery Wrapper around
the existing VDK. Email, support, and new devices never receive this authority.

A signed heartbeat in a historical `RELEASED` epoch may update only the bound
device's replay-protected recent-presence evidence. It cannot change policy
state, deadlines, release evidence, grants, or notifications. This is the sole
I11 heartbeat exception and exists only so a returned Owner can satisfy the
same recent-device requirement after release.

Pre-release ERC rotation uses a new recovery generation. The initiating device
first confirms one working wrapper under the fresh ERC and a fresh SRS. Its
confirmation atomically activates the generation and revokes the old live SRS
authorization. Every other active device remains explicitly pending until it
uses the same new ERC and its own fresh SRS to confirm a replacement wrapper.
Partial state is never reported as full completion.

Post-release or post-claim protection uses immutable policy epochs. An old
released epoch remains terminal with its records, grants, audit, and claims.
After Owner device signature and mailbox verification, the first successful
local rekey confirmation creates a successor active epoch. Old grants remain
scoped to old ciphertext and are not presented as revoked. Only rekeyed devices
may extend the successor epoch; other devices remain visibly migration-pending.

The Rust core requires a fresh VDK, master password, ERC, and per-device SRS
after compromise. In one SQLite immediate transaction it authenticates and
re-encrypts every bounded item/attachment record, increments record
generations, replaces both VDK wrappers, replaces the full master, recovery,
header, and record nonce ledger, and
recomputes header authentication. Failure before commit leaves the complete
old Vault; success leaves the complete new Vault. No crypto format, wrapper
encoding, record frame, item format, export format, or KDF parameter changes.

## Security impact

- Database or mailbox compromise alone still cannot decrypt a Vault.
- The pre-release KMS decrypt exception is bound to a mature Owner request,
  exact recent device, exact local wrapper, and ERC that never reaches the
  service.
- Bounded same-device redelivery improves crash recovery without pretending an
  already returned SRS can be made cryptographically one-time.
- Immediate generation activation prevents an indefinite period in which the
  old ERC/SRS remains a live service authorization, at the cost of visibly
  incomplete recovery on devices not yet rotated.
- Immutable epochs preserve I11 release evidence and prevent old grants from
  being accidentally applied to new VDK ciphertext.
- Fresh VDK/ERC/SRS prevents copied old factors from opening new ciphertext,
  but cannot erase old ciphertext or factor copies held by another party.
- `RELEASED` presence-only heartbeats increase the accepted server write
  surface but cannot undo release or influence any deadline.
- Atomic local rekey can require substantial temporary disk space. Disk-full,
  short-write, interruption, and confirmation failure must fail closed and are
  acceptance tests, not best-effort behavior.

## Alternatives rejected

- Reset the released policy row: loses the meaning of irreversible release.
- Leave every released account permanently terminal: cannot restore delayed
  recovery protection for new data.
- Reuse an old VDK, ERC, or SRS: keeps new data in the old compromise boundary.
- Keep old SRS live until all devices rotate: makes partial rotation an
  unbounded period of old-factor validity.
- Persist SRS or VDK locally for resume: creates a new durable secret target.
- Let email, support, or a new device release SRS: collapses independent
  recovery factors.
- Claim physical erasure of copied material: impossible across exports,
  backups, recipients, SSD snapshots, and already returned secrets.

## Approval effect

Explicit acceptance authorizes only the exact protocol, persistence,
authorization, local transaction, UI disclosure, migration, testing, and
documentation boundary in this ADR and its proposal. It does not authorize
algorithm or byte-format changes, a live AWS operation, real email, resource
creation, deployment, production migration, protocol tag publication, signing,
or a production release. G1 remains the independent security gate and I15
remains the production operations gate.
