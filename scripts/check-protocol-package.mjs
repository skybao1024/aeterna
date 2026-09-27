import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const protocolDirectory = fileURLToPath(
  new URL("../protocol/v1/", import.meta.url),
);
const forbiddenKeys = new Set([
  "activity_type",
  "application",
  "application_name",
  "contact",
  "erc",
  "input_value",
  "srs",
  "url",
  "vault",
  "vault_content",
  "vdk",
  "window",
  "window_title",
]);

const recoverySecretPaths = new Set([
  "schemas/recovery-record-provision-response.schema.json",
  "schemas/recovery-secret-response.schema.json",
  "fixtures/valid/recovery-record-provision-response.json",
  "fixtures/valid/recovery-secret-response.json",
]);

function inspectKeys(value, path, sourcePath = path) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      inspectKeys(entry, `${path}[${index}]`, sourcePath),
    );
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (
      forbiddenKeys.has(key.toLowerCase()) &&
      !(key.toLowerCase() === "srs" && recoverySecretPaths.has(sourcePath))
    ) {
      throw new Error(`Forbidden protocol field ${key} at ${path}.`);
    }
    inspectKeys(entry, `${path}.${key}`, sourcePath);
  }
}

const manifest = JSON.parse(
  await readFile(`${protocolDirectory}manifest.json`, "utf8"),
);
for (const entry of manifest.files) {
  if (!entry.path.endsWith(".json") || entry.path === "errors.json") {
    continue;
  }
  if (entry.path.startsWith("fixtures/invalid/")) {
    continue;
  }
  const value = JSON.parse(
    await readFile(`${protocolDirectory}${entry.path}`, "utf8"),
  );
  inspectKeys(value, entry.path);
}

console.log(
  `Verified ${manifest.files.length} protocol files contain no forbidden data fields.`,
);
