import { readdir, readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const distributionDirectory = fileURLToPath(
  new URL("../dist/", import.meta.url),
);
const inspectedExtensions = new Set([".css", ".html", ".js"]);
const remoteRuntimePatterns = [
  /<(?:audio|iframe|img|link|script|source|video)\b[^>]*(?:href|src)=["']https?:\/\//iu,
  /@import\s+(?:url\()?\s*["']?https?:\/\//iu,
  /url\(\s*["']?https?:\/\//iu,
  /(?:fetch|import)\(\s*["']https?:\/\//u,
  /new\s+(?:EventSource|WebSocket)\(\s*["'](?:https?|wss?):\/\//u,
];

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory() ? collectFiles(path) : [path];
    }),
  );
  return paths.flat();
}

const files = (await collectFiles(distributionDirectory)).filter((file) =>
  inspectedExtensions.has(extname(file)),
);

for (const file of files) {
  const content = await readFile(file, "utf8");
  if (remoteRuntimePatterns.some((pattern) => pattern.test(content))) {
    throw new Error(`Remote runtime asset reference detected in ${file}.`);
  }
}

console.log(
  `Verified ${files.length} built assets contain no remote runtime dependencies.`,
);
