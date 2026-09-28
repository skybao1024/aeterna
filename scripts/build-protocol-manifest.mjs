import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const protocolDirectory = fileURLToPath(
  new URL("../protocol/v1/", import.meta.url),
);
const manifestPath = resolve(protocolDirectory, "manifest.json");
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

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = await Promise.all(
    entries.map(async (entry) => {
      const path = resolve(directory, entry.name);
      return entry.isDirectory() ? collectFiles(path) : [path];
    }),
  );
  return paths.flat();
}

const paths = (await collectFiles(protocolDirectory))
  .filter((path) => path !== manifestPath)
  .sort((first, second) => first.localeCompare(second, "en"));
const files = [];
for (const path of paths) {
  const bytes = await readFile(path);
  files.push({
    path: relative(protocolDirectory, path).split(sep).join("/"),
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
}

const unsignedManifest = {
  manifest_version: 1,
  protocol_version: 1,
  release: "1.3.0",
  release_tag: "protocol-v1.3.0",
  files,
};
const manifest = {
  ...unsignedManifest,
  release_digest: createHash("sha256")
    .update(canonicalize(unsignedManifest), "utf8")
    .digest("hex"),
};
const expected = `${JSON.stringify(manifest, null, 2)}\n`;

if (checkOnly) {
  const actual = await readFile(manifestPath, "utf8");
  if (actual !== expected) {
    throw new Error("protocol/v1/manifest.json is stale.");
  }
  console.log(`Verified protocol manifest ${manifest.release_digest}.`);
} else {
  await writeFile(manifestPath, expected, "utf8");
  console.log(`Generated protocol manifest ${manifest.release_digest}.`);
}
