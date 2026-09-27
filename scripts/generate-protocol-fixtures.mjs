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
console.log(
  checkOnly
    ? "Verified generated protocol signature fixtures."
    : "Generated protocol signature fixtures.",
);
