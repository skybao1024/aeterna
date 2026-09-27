# ADR 0010: v1 email notification and contact disclosure modes

- Status: Accepted
- Date: 2026-09-22
- Decision owner: Product notification, consent, and recovery UX
- Approval: Explicit user approval on 2026-09-22
- Governing documents: [`../DESIGN.md`](../DESIGN.md),
  [`../DEVELOPMENT_PLAN.md`](../DEVELOPMENT_PLAN.md)

## Context

Aeterna must serve two materially different Owner expectations:

1. some Owners will not disclose that Aeterna or a recovery arrangement exists
   before release; and
2. other Owners will tell a person that they have been selected, allowing the
   address and consent to be confirmed before release.

Treating both cases as an already verified Recovery Contact would either violate
the first Owner's privacy choice or weaken the consent and claim boundary. A
silent recipient cannot be pre-tested, so Aeterna also cannot honestly promise
that the address is correct, remains active, or will be read later.

SMS was considered as a higher-attention channel, particularly for recipients
in mainland China. v1 has no approved sender entity, provider, country policy,
consent flow, cost model, or delivery evidence that would support a reliable SMS
claim. Adding phone data and an SMS provider now would expand privacy and abuse
boundaries without resolving the silent-recipient verification problem.

## Decision

### Email-only v1

All automated remote notifications in v1 use email. v1 does not:

- collect or persist contact phone numbers;
- expose an SMS setting or quota;
- integrate an SMS provider or international SMS fallback; or
- advertise multichannel delivery.

Owner warnings continue to use email plus local desktop notification. Contact
invitations, release notices, claim links, OTPs, delivery tests, and delivery
status use email.

### Separate an unverified target from an authorized contact

A **Notification Target** is an Owner-designated email address that has not yet
accepted and verified the role. It has no recovery authority and cannot receive
a recovery claim or SRS.

A **Recovery Contact** is a recipient who explicitly accepted the role and
verified control of the email address. Only a Recovery Contact can enter the
claim flow, and the claim still requires the release boundary and fresh email
OTP defined by the recovery protocol.

### Two disclosure modes

The Owner UI asks one question: tell the person now, or keep the setup private
until release. It does not expose a workflow builder.

**Confirm now** is the recommended default:

- Aeterna sends a neutral invitation during setup.
- The invitation identifies Owner and the requested role but reveals no custom
  message, trigger condition, vault content, credential, or recovery material.
- The recipient can accept or decline without creating a password.
- Acceptance plus email verification promotes the Notification Target to
  Recovery Contact.
- A constrained test email may be sent after confirmation.

**Private until release** preserves pre-release secrecy:

- Aeterna sends no setup or test email.
- Owner UI labels the target unverified and delivery as best-effort rather than
  guaranteed.
- At `RELEASED`, the service may send only a fixed neutral invitation. It
  identifies Owner by default for legitimacy but contains no Owner-authored
  message, trigger reason, location, instruction, claim, credential, or secret.
- The target must accept and verify the email before promotion to Recovery
  Contact. Only then may the service issue a separate recovery claim email.

The service applies stable idempotency, recipient/account/IP limits, constrained
templates, decline and deletion handling, and redacted delivery audit to both
modes. Provider acceptance or delivery is never presented as proof of human
readership.

## Consequences

- I12 owns both disclosure modes, email delivery, invitation state, consent,
  verification, bounce handling, tests, retries, abuse controls, and audit.
- I13 must prove that an unverified Notification Target cannot obtain a claim
  and that release-time acceptance cannot bypass the `RELEASED` boundary.
- Private mode is less reliable by design. A mistyped, abandoned, filtered, or
  unread address cannot be detected before release, and the UI must state this
  rather than imply equivalent assurance to a confirmed contact.
- The first email to an unverified target is system-controlled. Owner-authored
  content remains unavailable until acceptance and verification.
- Removing phone collection reduces stored third-party personal data and keeps
  the v1 provider and operational boundary limited to email.
- Launching private-until-release requires provider-policy and jurisdictional
  review of the one-time neutral email to a previously unverified recipient. If
  that review does not approve the flow, the mode must fail closed or remain
  unavailable in the affected jurisdiction; it must not fall back to SMS.
- SMS is not scheduled in the current development plan. Adding it later is a
  new product, privacy, abuse, country-policy, provider, and protocol decision
  requiring a separate approved ADR and iteration.

## Alternatives rejected

- **Require every contact to verify during setup:** higher reachability, but it
  prevents the explicitly supported private-until-release use case.
- **Treat a silent address as a Recovery Contact:** rejected because an
  unconsented and unverified target must not receive recovery authority.
- **Send Owner-authored content in the first private-mode email:** rejected due
  to wrong-address disclosure, phishing, and harassment risk.
- **Use international SMS as a v1 fallback:** rejected because it does not
  provide a dependable or approved production path and would broaden the data
  and compliance boundary.
