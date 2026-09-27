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

function inspectKeys(value, path) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => inspectKeys(entry, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (forbiddenKeys.has(key.toLowerCase())) {
      throw new Error(`Forbidden protocol field ${key} at ${path}.`);
    }
    inspectKeys(entry, `${path}.${key}`);
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
