import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const protocolDirectory = fileURLToPath(
  new URL("../protocol/v1/", import.meta.url),
);
const signaturePath = `${protocolDirectory}fixtures/signatures/device-binding-request.json`;
const validPath = `${protocolDirectory}fixtures/valid/device-binding-request.json`;
const approvalSignaturePath = `${protocolDirectory}fixtures/signatures/device-binding-approval.json`;
const approvalValidPath = `${protocolDirectory}fixtures/valid/device-binding-approval-request.json`;
const wrongKeyPath = `${protocolDirectory}fixtures/signatures/device-binding-request-wrong-key.json`;
const modifiedSignaturePath = `${protocolDirectory}fixtures/signatures/device-binding-request-modified-signature.json`;
const crossDomainPath = `${protocolDirectory}fixtures/signatures/device-binding-cross-domain-replay.json`;
const canonicalizationPath = `${protocolDirectory}fixtures/signatures/jcs-unicode-and-escaping.json`;
const paddedSignaturePath = `${protocolDirectory}fixtures/invalid/device-binding-request-signature-padding.json`;
const duplicateMemberPath = `${protocolDirectory}fixtures/invalid/account-challenge-duplicate-member.json`;
const heartbeatSignaturePath = `${protocolDirectory}fixtures/signatures/heartbeat-request.json`;
const heartbeatValidPath = `${protocolDirectory}fixtures/valid/heartbeat-request.json`;
const heartbeatResponsePath = `${protocolDirectory}fixtures/valid/heartbeat-response.json`;
const heartbeatModifiedPath = `${protocolDirectory}fixtures/signatures/heartbeat-modified-payload.json`;
const heartbeatCrossDomainPath = `${protocolDirectory}fixtures/signatures/heartbeat-cross-domain-replay.json`;
const heartbeatForbiddenPath = `${protocolDirectory}fixtures/invalid/heartbeat-request-forbidden-data.json`;
const deviceStatusSignaturePath = `${protocolDirectory}fixtures/signatures/device-status-change.json`;
const deviceStatusValidPath = `${protocolDirectory}fixtures/valid/device-status-change-request.json`;
const deviceStatusResponsePath = `${protocolDirectory}fixtures/valid/device-status-change-response.json`;
const recoveryProvisionSignaturePath = `${protocolDirectory}fixtures/signatures/recovery-record-provision.json`;
const recoveryProvisionValidPath = `${protocolDirectory}fixtures/valid/recovery-record-provision-request.json`;
const recoveryProvisionResponsePath = `${protocolDirectory}fixtures/valid/recovery-record-provision-response.json`;
const recoveryConfirmSignaturePath = `${protocolDirectory}fixtures/signatures/recovery-record-confirm.json`;
const recoveryConfirmValidPath = `${protocolDirectory}fixtures/valid/recovery-record-confirm-request.json`;
const recoveryRecordResponsePath = `${protocolDirectory}fixtures/valid/recovery-record-response.json`;
const recoveryClaimStartPath = `${protocolDirectory}fixtures/valid/recovery-claim-start-request.json`;
const recoveryClaimStartResponsePath = `${protocolDirectory}fixtures/valid/recovery-claim-start-response.json`;
const recoveryClaimVerifyPath = `${protocolDirectory}fixtures/valid/recovery-claim-verify-request.json`;
const recoveryClaimVerifyResponsePath = `${protocolDirectory}fixtures/valid/recovery-claim-verify-response.json`;
const recoverySecretRequestPath = `${protocolDirectory}fixtures/valid/recovery-secret-request.json`;
const recoverySecretResponsePath = `${protocolDirectory}fixtures/valid/recovery-secret-response.json`;
const recoveryProvisionForbiddenPath = `${protocolDirectory}fixtures/invalid/recovery-record-provision-forbidden-data.json`;
const ownerRecoveryStartSignaturePath = `${protocolDirectory}fixtures/signatures/owner-recovery-start.json`;
const ownerRecoveryStartPath = `${protocolDirectory}fixtures/valid/owner-recovery-start-request.json`;
const ownerRecoveryVerifyPath = `${protocolDirectory}fixtures/valid/owner-recovery-verify-request.json`;
const ownerRecoveryActionSignaturePath = `${protocolDirectory}fixtures/signatures/owner-recovery-action.json`;
const ownerRecoveryActionPath = `${protocolDirectory}fixtures/valid/owner-recovery-action-request.json`;
const ownerRecoveryResponsePath = `${protocolDirectory}fixtures/valid/owner-recovery-response.json`;
const ownerRecoverySecretResponsePath = `${protocolDirectory}fixtures/valid/owner-recovery-secret-response.json`;
const ownerRecoveryForbiddenPath = `${protocolDirectory}fixtures/invalid/owner-recovery-start-forbidden-data.json`;
const rotationProvisionSignaturePath = `${protocolDirectory}fixtures/signatures/recovery-rotation-provision.json`;
const rotationProvisionPath = `${protocolDirectory}fixtures/valid/recovery-rotation-provision-request.json`;
const rotationConfirmSignaturePath = `${protocolDirectory}fixtures/signatures/recovery-rotation-confirm.json`;
const rotationConfirmPath = `${protocolDirectory}fixtures/valid/recovery-rotation-confirm-request.json`;
const rotationProvisionResponsePath = `${protocolDirectory}fixtures/valid/recovery-rotation-provision-response.json`;
const rotationResponsePath = `${protocolDirectory}fixtures/valid/recovery-rotation-response.json`;
const checkOnly = process.argv.includes("--check");

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("JCS forbids non-finite numbers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new Error("Unsupported JCS value.");
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function keyPair(seedByte) {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed,
    ]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey)
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return { seed, privateKey, publicKey };
}

function pretty(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const primary = keyPair(0x11);
const secondary = keyPair(0x22);
const { seed, privateKey, publicKey } = primary;

const document = {
  binding_grant_id: "00000000-0000-4000-8000-000000000002",
  canonicalization: "jcs-rfc8785",
  device_id: "00000000-0000-4000-8000-000000000003",
  device_label: "Synthetic Mac",
  domain: "aeterna.device-binding.request.v1",
  operation: "device_binding.request",
  protocol_version: 1,
  public_key: base64url(publicKey),
  request_id: "00000000-0000-4000-8000-000000000001",
  signature_version: 1,
};
const canonicalBytes = Buffer.from(canonicalize(document), "utf8");
const signature = sign(null, canonicalBytes, privateKey);
const encodedSignature = base64url(signature);

const signatureFixture = pretty({
  fixture_version: 1,
  seed: base64url(seed),
  public_key: base64url(publicKey),
  canonical_bytes: base64url(canonicalBytes),
  signature: encodedSignature,
  document,
});
const validEnvelope = {
  protocol_version: 1,
  signed: document,
  signature: encodedSignature,
};
const validFixture = pretty(validEnvelope);

const approvalDocument = {
  account_id: "00000000-0000-4000-8000-000000000020",
  approving_device_id: "00000000-0000-4000-8000-000000000003",
  binding_id: "00000000-0000-4000-8000-000000000021",
  canonicalization: "jcs-rfc8785",
  challenge: base64url(Buffer.alloc(32, 0x33)),
  device_id: "00000000-0000-4000-8000-000000000004",
  domain: "aeterna.device-binding.approval.v1",
  operation: "device_binding.approval",
  protocol_version: 1,
  public_key: base64url(secondary.publicKey),
  request_id: "00000000-0000-4000-8000-000000000022",
  signature_version: 1,
};
const approvalCanonicalBytes = Buffer.from(
  canonicalize(approvalDocument),
  "utf8",
);
const approvalSignature = sign(
  null,
  approvalCanonicalBytes,
  primary.privateKey,
);
const approvalSignatureFixture = pretty({
  fixture_version: 1,
  seed: base64url(primary.seed),
  public_key: base64url(primary.publicKey),
  canonical_bytes: base64url(approvalCanonicalBytes),
  signature: base64url(approvalSignature),
  document: approvalDocument,
});
const approvalValidFixture = pretty({
  protocol_version: 1,
  signed: approvalDocument,
  signature: base64url(approvalSignature),
});

const modifiedSignature = Buffer.from(signature);
modifiedSignature[0] ^= 0x01;
const wrongKeyFixture = pretty({
  fixture_version: 1,
  expected: "device.proof_invalid",
  verification_public_key: base64url(secondary.publicKey),
  envelope: validEnvelope,
});
const modifiedSignatureFixture = pretty({
  fixture_version: 1,
  expected: "device.proof_invalid",
  verification_public_key: base64url(primary.publicKey),
  envelope: { ...validEnvelope, signature: base64url(modifiedSignature) },
});
const crossDomainDocument = {
  ...document,
  domain: "aeterna.device-binding.approval.v1",
};
const crossDomainFixture = pretty({
  fixture_version: 1,
  expected: "device.proof_invalid",
  verification_public_key: base64url(primary.publicKey),
  envelope: { ...validEnvelope, signed: crossDomainDocument },
});
const paddedSignatureFixture = pretty({
  ...validEnvelope,
  signature: `${encodedSignature}=`,
});

const canonicalizationDocument = {
  "😀": "astral",
  z: 'line\nquote"slash\\',
  é: "NFC",
  a: "alpha",
  "€": "euro",
};
const canonicalizationFixture = pretty({
  fixture_version: 1,
  canonical_bytes: base64url(
    Buffer.from(canonicalize(canonicalizationDocument), "utf8"),
  ),
  document: canonicalizationDocument,
});
const duplicateMemberFixture = `{
  "protocol_version": 1,
  "request_id": "00000000-0000-4000-8000-000000000010",
  "email": "first@example.test",
  "email": "second@example.test",
  "purpose": "account_onboarding"
}
`;

const heartbeatDocument = {
  account_id: "00000000-0000-4000-8000-000000000020",
  canonicalization: "jcs-rfc8785",
  device_id: "00000000-0000-4000-8000-000000000003",
  domain: "aeterna.heartbeat.submit.v1",
  operation: "heartbeat.submit",
  protocol_version: 1,
  request_id: "00000000-0000-4000-8000-000000000030",
  sequence: 41,
  signature_version: 1,
};
const heartbeatCanonicalBytes = Buffer.from(
  canonicalize(heartbeatDocument),
  "utf8",
);
const heartbeatSignature = sign(
  null,
  heartbeatCanonicalBytes,
  primary.privateKey,
);
const heartbeatEnvelope = {
  protocol_version: 1,
  signed: heartbeatDocument,
  signature: base64url(heartbeatSignature),
};
const heartbeatSignatureFixture = pretty({
  fixture_version: 1,
  seed: base64url(primary.seed),
  public_key: base64url(primary.publicKey),
  canonical_bytes: base64url(heartbeatCanonicalBytes),
  signature: base64url(heartbeatSignature),
  document: heartbeatDocument,
});
const heartbeatModifiedFixture = pretty({
  fixture_version: 1,
  expected: "device.proof_invalid",
  verification_public_key: base64url(primary.publicKey),
  envelope: {
    ...heartbeatEnvelope,
    signed: { ...heartbeatDocument, sequence: heartbeatDocument.sequence + 1 },
  },
});
const heartbeatCrossDomainFixture = pretty({
  fixture_version: 1,
  expected: "device.proof_invalid",
  verification_public_key: base64url(primary.publicKey),
  envelope: {
    ...heartbeatEnvelope,
    signed: {
      ...heartbeatDocument,
      domain: "aeterna.device-status.change.v1",
    },
  },
});
const heartbeatForbiddenFixture = pretty({
  ...heartbeatEnvelope,
  signed: {
    ...heartbeatDocument,
    client_deadline: "2040-01-01T00:00:00Z",
  },
});
const heartbeatResponseFixture = pretty({
  protocol_version: 1,
  request_id: heartbeatDocument.request_id,
  data: {
    accepted_at: "2030-01-02T03:04:05Z",
    accepted_sequence: heartbeatDocument.sequence,
    account_id: heartbeatDocument.account_id,
    device_id: heartbeatDocument.device_id,
    next_heartbeat_not_before: "2030-01-02T03:34:05Z",
  },
});

const deviceStatusDocument = {
  account_id: heartbeatDocument.account_id,
  action: "mark_lost",
  authorizing_device_id: heartbeatDocument.device_id,
  canonicalization: "jcs-rfc8785",
  domain: "aeterna.device-status.change.v1",
  operation: "device_status.change",
  protocol_version: 1,
  request_id: "00000000-0000-4000-8000-000000000031",
  signature_version: 1,
  target_device_id: "00000000-0000-4000-8000-000000000004",
};
const deviceStatusCanonicalBytes = Buffer.from(
  canonicalize(deviceStatusDocument),
  "utf8",
);
const deviceStatusSignature = sign(
  null,
  deviceStatusCanonicalBytes,
  primary.privateKey,
);
const deviceStatusEnvelope = {
  protocol_version: 1,
  signed: deviceStatusDocument,
  signature: base64url(deviceStatusSignature),
};
const deviceStatusSignatureFixture = pretty({
  fixture_version: 1,
  seed: base64url(primary.seed),
  public_key: base64url(primary.publicKey),
  canonical_bytes: base64url(deviceStatusCanonicalBytes),
  signature: base64url(deviceStatusSignature),
  document: deviceStatusDocument,
});
const deviceStatusResponseFixture = pretty({
  protocol_version: 1,
  request_id: deviceStatusDocument.request_id,
  data: {
    account_id: deviceStatusDocument.account_id,
    changed_at: "2030-01-02T03:04:05Z",
    device_id: deviceStatusDocument.target_device_id,
    status: "lost",
  },
});

const recoveryIds = {
  request: "00000000-0000-4000-8000-000000000040",
  recovery: "00000000-0000-4000-8000-000000000041",
  vault: "00000000-0000-4000-8000-000000000042",
  confirmRequest: "00000000-0000-4000-8000-000000000043",
  claimStartRequest: "00000000-0000-4000-8000-000000000044",
  challenge: "00000000-0000-4000-8000-000000000045",
  claimVerifyRequest: "00000000-0000-4000-8000-000000000046",
  secretRequest: "00000000-0000-4000-8000-000000000047",
};
const syntheticSrs = base64url(Buffer.alloc(32, 0x55));
const syntheticWrapperDigest = base64url(Buffer.alloc(32, 0x66));
const syntheticClaimLinkToken = base64url(Buffer.alloc(32, 0x77));
const syntheticClaimToken = base64url(Buffer.alloc(32, 0x88));
const ownerRecoveryIds = {
  ownerRecovery: "00000000-0000-4000-8000-000000000050",
  challenge: "00000000-0000-4000-8000-000000000051",
  verifyRequest: "00000000-0000-4000-8000-000000000052",
  actionRequest: "00000000-0000-4000-8000-000000000053",
  rotation: "00000000-0000-4000-8000-000000000054",
  targetRecovery: "00000000-0000-4000-8000-000000000055",
  provisionRequest: "00000000-0000-4000-8000-000000000056",
  confirmRequest: "00000000-0000-4000-8000-000000000057",
};

function signedRecoveryFixture(document) {
  const canonical = Buffer.from(canonicalize(document), "utf8");
  const documentSignature = sign(null, canonical, primary.privateKey);
  return {
    signatureFixture: pretty({
      fixture_version: 1,
      seed: base64url(primary.seed),
      public_key: base64url(primary.publicKey),
      canonical_bytes: base64url(canonical),
      signature: base64url(documentSignature),
      document,
    }),
    envelope: {
      protocol_version: 1,
      signed: document,
      signature: base64url(documentSignature),
    },
  };
}

const recoveryProvisionDocument = {
  account_id: heartbeatDocument.account_id,
  canonicalization: "jcs-rfc8785",
  crypto_format_version: 1,
  device_id: heartbeatDocument.device_id,
  domain: "aeterna.recovery-record.provision.v1",
  operation: "recovery_record.provision",
  protocol_version: 1,
  recovery_context_version: 1,
  recovery_id: recoveryIds.recovery,
  request_id: recoveryIds.request,
  signature_version: 1,
  vault_id: recoveryIds.vault,
};
const recoveryProvision = signedRecoveryFixture(recoveryProvisionDocument);
const recoveryConfirmDocument = {
  account_id: heartbeatDocument.account_id,
  canonicalization: "jcs-rfc8785",
  device_id: heartbeatDocument.device_id,
  domain: "aeterna.recovery-record.confirm.v1",
  operation: "recovery_record.confirm",
  protocol_version: 1,
  recovery_id: recoveryIds.recovery,
  request_id: recoveryIds.confirmRequest,
  signature_version: 1,
  vault_id: recoveryIds.vault,
  wrapper_digest: syntheticWrapperDigest,
};
const recoveryConfirm = signedRecoveryFixture(recoveryConfirmDocument);

const recoveryProvisionResponseFixture = pretty({
  protocol_version: 1,
  request_id: recoveryIds.request,
  data: {
    account_id: heartbeatDocument.account_id,
    device_id: heartbeatDocument.device_id,
    expires_at: "2030-01-03T03:04:05Z",
    kms_context_version: 1,
    recovery_id: recoveryIds.recovery,
    srs: syntheticSrs,
    state: "pending_confirmation",
    vault_id: recoveryIds.vault,
  },
});
const recoveryRecordResponseFixture = pretty({
  protocol_version: 1,
  request_id: recoveryIds.confirmRequest,
  data: {
    account_id: heartbeatDocument.account_id,
    device_id: heartbeatDocument.device_id,
    recovery_id: recoveryIds.recovery,
    state: "sealed",
    updated_at: "2030-01-02T03:05:05Z",
    vault_id: recoveryIds.vault,
  },
});
const recoveryClaimStartFixture = pretty({
  protocol_version: 1,
  request_id: recoveryIds.claimStartRequest,
  claim_link_token: syntheticClaimLinkToken,
});
const recoveryClaimStartResponseFixture = pretty({
  protocol_version: 1,
  request_id: recoveryIds.claimStartRequest,
  data: {
    challenge_id: recoveryIds.challenge,
    expires_in_seconds: 600,
    resend_after_seconds: 60,
  },
});
const recoveryClaimVerifyFixture = pretty({
  protocol_version: 1,
  request_id: recoveryIds.claimVerifyRequest,
  challenge_id: recoveryIds.challenge,
  claim_link_token: syntheticClaimLinkToken,
  code: "12345678",
});
const recoveryClaimVerifyResponseFixture = pretty({
  protocol_version: 1,
  request_id: recoveryIds.claimVerifyRequest,
  data: {
    account_id: heartbeatDocument.account_id,
    claim_token: syntheticClaimToken,
    device_id: heartbeatDocument.device_id,
    expires_at: "2030-01-02T03:10:05Z",
    recovery_id: recoveryIds.recovery,
    scope: "recovery.srs.read",
    vault_id: recoveryIds.vault,
    wrapper_digest: syntheticWrapperDigest,
  },
});
const recoverySecretRequestFixture = pretty({
  protocol_version: 1,
  request_id: recoveryIds.secretRequest,
  claim_token: syntheticClaimToken,
  device_id: heartbeatDocument.device_id,
  recovery_id: recoveryIds.recovery,
  vault_id: recoveryIds.vault,
  wrapper_digest: syntheticWrapperDigest,
});
const recoverySecretResponseFixture = pretty({
  protocol_version: 1,
  request_id: recoveryIds.secretRequest,
  data: {
    account_id: heartbeatDocument.account_id,
    device_id: heartbeatDocument.device_id,
    policy_epoch: 1,
    recovery_generation: 1,
    recovery_id: recoveryIds.recovery,
    rekey_required: true,
    srs: syntheticSrs,
    vault_id: recoveryIds.vault,
    wrapper_digest: syntheticWrapperDigest,
  },
});
const recoveryProvisionForbiddenFixture = pretty({
  ...recoveryProvision.envelope,
  signed: {
    ...recoveryProvisionDocument,
    vault_content: "forbidden",
  },
});

const ownerRecoveryStartDocument = {
  account_id: heartbeatDocument.account_id,
  canonicalization: "jcs-rfc8785",
  device_id: heartbeatDocument.device_id,
  domain: "aeterna.owner-recovery.start.v1",
  operation: "owner_recovery.start",
  policy_epoch: 1,
  protocol_version: 1,
  recovery_generation: 1,
  recovery_id: recoveryIds.recovery,
  request_id: ownerRecoveryIds.ownerRecovery,
  signature_version: 1,
  vault_id: recoveryIds.vault,
  wrapper_digest: syntheticWrapperDigest,
};
const ownerRecoveryStart = signedRecoveryFixture(ownerRecoveryStartDocument);
const ownerRecoveryVerifyFixture = pretty({
  protocol_version: 1,
  request_id: ownerRecoveryIds.verifyRequest,
  owner_recovery_id: ownerRecoveryIds.ownerRecovery,
  challenge_id: ownerRecoveryIds.challenge,
  code: "12345678",
});
const ownerRecoveryActionDocument = {
  account_id: heartbeatDocument.account_id,
  action: "release",
  canonicalization: "jcs-rfc8785",
  device_id: heartbeatDocument.device_id,
  domain: "aeterna.owner-recovery.action.v1",
  operation: "owner_recovery.action",
  owner_recovery_id: ownerRecoveryIds.ownerRecovery,
  protocol_version: 1,
  recovery_id: recoveryIds.recovery,
  request_id: ownerRecoveryIds.actionRequest,
  signature_version: 1,
  vault_id: recoveryIds.vault,
  wrapper_digest: syntheticWrapperDigest,
};
const ownerRecoveryAction = signedRecoveryFixture(ownerRecoveryActionDocument);
const ownerRecoveryResponseFixture = pretty({
  protocol_version: 1,
  request_id: ownerRecoveryIds.verifyRequest,
  data: {
    account_id: heartbeatDocument.account_id,
    challenge_id: ownerRecoveryIds.challenge,
    cooldown_seconds: 86400,
    device_id: heartbeatDocument.device_id,
    expires_at: "2030-01-04T03:04:05Z",
    owner_recovery_id: ownerRecoveryIds.ownerRecovery,
    ready_at: "2030-01-03T03:04:05Z",
    rekey_required: false,
    state: "cooling_down",
  },
});
const ownerRecoverySecretResponseFixture = pretty({
  protocol_version: 1,
  request_id: ownerRecoveryIds.actionRequest,
  data: {
    account_id: heartbeatDocument.account_id,
    device_id: heartbeatDocument.device_id,
    owner_recovery_id: ownerRecoveryIds.ownerRecovery,
    policy_epoch: 1,
    recovery_generation: 1,
    recovery_id: recoveryIds.recovery,
    rekey_required: false,
    srs: syntheticSrs,
    vault_id: recoveryIds.vault,
    wrapper_digest: syntheticWrapperDigest,
  },
});
const ownerRecoveryForbiddenFixture = pretty({
  ...ownerRecoveryStart.envelope,
  signed: {
    ...ownerRecoveryStartDocument,
    erc: "forbidden",
  },
});

const rotationProvisionDocument = {
  account_id: heartbeatDocument.account_id,
  canonicalization: "jcs-rfc8785",
  device_id: heartbeatDocument.device_id,
  domain: "aeterna.recovery-rotation.provision.v1",
  kind: "post_compromise",
  operation: "recovery_rotation.provision",
  owner_recovery_id: ownerRecoveryIds.ownerRecovery,
  protocol_version: 1,
  recovery_id: ownerRecoveryIds.targetRecovery,
  request_id: ownerRecoveryIds.provisionRequest,
  rotation_id: ownerRecoveryIds.rotation,
  signature_version: 1,
  source_generation: 1,
  source_policy_epoch: 1,
  target_generation: 2,
  target_policy_epoch: 2,
  vault_id: recoveryIds.vault,
};
const rotationProvision = signedRecoveryFixture(rotationProvisionDocument);
const rotationConfirmDocument = {
  account_id: heartbeatDocument.account_id,
  canonicalization: "jcs-rfc8785",
  device_id: heartbeatDocument.device_id,
  domain: "aeterna.recovery-rotation.confirm.v1",
  operation: "recovery_rotation.confirm",
  protocol_version: 1,
  recovery_id: ownerRecoveryIds.targetRecovery,
  request_id: ownerRecoveryIds.confirmRequest,
  rotation_id: ownerRecoveryIds.rotation,
  signature_version: 1,
  target_generation: 2,
  target_policy_epoch: 1,
  vault_id: recoveryIds.vault,
  wrapper_digest: syntheticWrapperDigest,
};
const rotationConfirm = signedRecoveryFixture(rotationConfirmDocument);
const rotationProvisionResponseFixture = pretty({
  protocol_version: 1,
  request_id: ownerRecoveryIds.provisionRequest,
  data: {
    account_id: heartbeatDocument.account_id,
    device_id: heartbeatDocument.device_id,
    expires_at: "2030-01-03T03:04:05Z",
    recovery_id: ownerRecoveryIds.targetRecovery,
    rotation_id: ownerRecoveryIds.rotation,
    srs: syntheticSrs,
    target_generation: 2,
    target_policy_epoch: 1,
    vault_id: recoveryIds.vault,
  },
});
const rotationResponseFixture = pretty({
  protocol_version: 1,
  request_id: ownerRecoveryIds.confirmRequest,
  data: {
    account_id: heartbeatDocument.account_id,
    complete: false,
    devices: [
      {
        device_id: heartbeatDocument.device_id,
        device_label: "Owner Mac",
        state: "complete",
        updated_at: "2030-01-02T03:04:05Z",
      },
      {
        device_id: "00000000-0000-4000-8000-000000000004",
        device_label: "Travel Mac",
        state: "pending",
        updated_at: "2030-01-02T03:04:05Z",
      },
    ],
    kind: "erc_rotation",
    rotation_id: ownerRecoveryIds.rotation,
    state: "active",
    target_generation: 2,
    target_policy_epoch: 1,
  },
});

async function updateOrCheck(path, expected) {
  if (!checkOnly) {
    await writeFile(path, expected, "utf8");
    return;
  }
  const actual = await readFile(path, "utf8");
  if (actual !== expected) {
    throw new Error(`Generated protocol fixture is stale: ${path}`);
  }
}

await updateOrCheck(signaturePath, signatureFixture);
await updateOrCheck(validPath, validFixture);
await updateOrCheck(approvalSignaturePath, approvalSignatureFixture);
await updateOrCheck(approvalValidPath, approvalValidFixture);
await updateOrCheck(wrongKeyPath, wrongKeyFixture);
await updateOrCheck(modifiedSignaturePath, modifiedSignatureFixture);
await updateOrCheck(crossDomainPath, crossDomainFixture);
await updateOrCheck(canonicalizationPath, canonicalizationFixture);
await updateOrCheck(paddedSignaturePath, paddedSignatureFixture);
await updateOrCheck(duplicateMemberPath, duplicateMemberFixture);
await updateOrCheck(heartbeatSignaturePath, heartbeatSignatureFixture);
await updateOrCheck(heartbeatValidPath, pretty(heartbeatEnvelope));
await updateOrCheck(heartbeatResponsePath, heartbeatResponseFixture);
await updateOrCheck(heartbeatModifiedPath, heartbeatModifiedFixture);
await updateOrCheck(heartbeatCrossDomainPath, heartbeatCrossDomainFixture);
await updateOrCheck(heartbeatForbiddenPath, heartbeatForbiddenFixture);
await updateOrCheck(deviceStatusSignaturePath, deviceStatusSignatureFixture);
await updateOrCheck(deviceStatusValidPath, pretty(deviceStatusEnvelope));
await updateOrCheck(deviceStatusResponsePath, deviceStatusResponseFixture);
await updateOrCheck(
  recoveryProvisionSignaturePath,
  recoveryProvision.signatureFixture,
);
await updateOrCheck(
  recoveryProvisionValidPath,
  pretty(recoveryProvision.envelope),
);
await updateOrCheck(
  recoveryProvisionResponsePath,
  recoveryProvisionResponseFixture,
);
await updateOrCheck(
  recoveryConfirmSignaturePath,
  recoveryConfirm.signatureFixture,
);
await updateOrCheck(recoveryConfirmValidPath, pretty(recoveryConfirm.envelope));
await updateOrCheck(recoveryRecordResponsePath, recoveryRecordResponseFixture);
await updateOrCheck(recoveryClaimStartPath, recoveryClaimStartFixture);
await updateOrCheck(
  recoveryClaimStartResponsePath,
  recoveryClaimStartResponseFixture,
);
await updateOrCheck(recoveryClaimVerifyPath, recoveryClaimVerifyFixture);
await updateOrCheck(
  recoveryClaimVerifyResponsePath,
  recoveryClaimVerifyResponseFixture,
);
await updateOrCheck(recoverySecretRequestPath, recoverySecretRequestFixture);
await updateOrCheck(recoverySecretResponsePath, recoverySecretResponseFixture);
await updateOrCheck(
  recoveryProvisionForbiddenPath,
  recoveryProvisionForbiddenFixture,
);
await updateOrCheck(
  ownerRecoveryStartSignaturePath,
  ownerRecoveryStart.signatureFixture,
);
await updateOrCheck(
  ownerRecoveryStartPath,
  pretty(ownerRecoveryStart.envelope),
);
await updateOrCheck(ownerRecoveryVerifyPath, ownerRecoveryVerifyFixture);
await updateOrCheck(
  ownerRecoveryActionSignaturePath,
  ownerRecoveryAction.signatureFixture,
);
await updateOrCheck(
  ownerRecoveryActionPath,
  pretty(ownerRecoveryAction.envelope),
);
await updateOrCheck(ownerRecoveryResponsePath, ownerRecoveryResponseFixture);
await updateOrCheck(
  ownerRecoverySecretResponsePath,
  ownerRecoverySecretResponseFixture,
);
await updateOrCheck(ownerRecoveryForbiddenPath, ownerRecoveryForbiddenFixture);
await updateOrCheck(
  rotationProvisionSignaturePath,
  rotationProvision.signatureFixture,
);
await updateOrCheck(rotationProvisionPath, pretty(rotationProvision.envelope));
await updateOrCheck(
  rotationConfirmSignaturePath,
  rotationConfirm.signatureFixture,
);
await updateOrCheck(rotationConfirmPath, pretty(rotationConfirm.envelope));
await updateOrCheck(
  rotationProvisionResponsePath,
  rotationProvisionResponseFixture,
);
await updateOrCheck(rotationResponsePath, rotationResponseFixture);
console.log(
  checkOnly
    ? "Verified generated protocol signature fixtures."
    : "Generated protocol signature fixtures.",
);
