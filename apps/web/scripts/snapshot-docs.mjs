#!/usr/bin/env node
import { execFileSync, execSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { docSpecs, docsUpdated } from "../src/_data/docs-specs.js";
import {
  docsVersionNumber,
  normalizeDocsVersionId,
  publicDocSpecs,
  resolveDocsVersionPath,
  resolvePublicDocPath,
} from "../src/_data/public-docs.js";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");

const args = process.argv.slice(2);
let force = false;
let fromRef = "";
let requested = "";
let archiveRoot = path.join(repoRoot, "public/docs-versions");
let publicDocsMetadataPath = path.join(repoRoot, "public/docs-metadata.json");

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === "--") {
    continue;
  } else if (arg === "--force") {
    force = true;
  } else if (arg === "--from-ref") {
    fromRef = args[index + 1] || "";
    index += 1;
  } else if (arg === "--archive-root") {
    archiveRoot = path.resolve(repoRoot, args[index + 1] || "");
    index += 1;
  } else if (arg === "--metadata-path") {
    publicDocsMetadataPath = path.resolve(repoRoot, args[index + 1] || "");
    index += 1;
  } else if (arg.startsWith("--")) {
    usage();
  } else if (!requested) {
    requested = arg;
  } else {
    usage();
  }
}

function usage() {
  console.error("Usage: pnpm -C apps/web docs:snapshot -- v0.1.37 [--force] [--from-ref v0.1.37] [--archive-root path] [--metadata-path path]");
  process.exit(2);
}

if (!requested) {
  usage();
}

function commandOutput(command) {
  try {
    return execSync(command, { cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

function gitOutput(args) {
  try {
    return execFileSync("git", args, { cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

function gitBlob(ref, source) {
  try {
    return execFileSync("git", ["show", `${ref}:${source}`], { cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return "";
  }
}

function docsVersioningInputs() {
  const inputsPath = path.join(repoRoot, "scripts/docs-versioning-inputs.txt");
  return fs.readFileSync(inputsPath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function matchingBracketIndex(source, openIndex, openChar, closeChar) {
  let depth = 0;
  let quote = "";
  let escaping = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = openIndex; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1] || "";
    if (lineComment) {
      if (char === "\n") {
        lineComment = false;
      }
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (escaping) {
        escaping = false;
      } else if (char === "\\") {
        escaping = true;
      } else if (char === quote) {
        quote = "";
      }
      continue;
    }
    if (char === "/" && next === "/") {
      lineComment = true;
      index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      index += 1;
      continue;
    }
    if (char === "'" || char === "\"" || char === "`") {
      quote = char;
      continue;
    }
    if (char === openChar) {
      depth += 1;
    } else if (char === closeChar) {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}

function legacyStringValue(source, start) {
  const quote = source[start];
  let value = "";
  let index = start + 1;
  for (; index < source.length; index += 1) {
    const char = source[index];
    if (char === quote) {
      return { value, end: index + 1 };
    }
    if (char !== "\\") {
      value += char;
      continue;
    }
    index += 1;
    if (index >= source.length) {
      throw new Error("Unterminated legacy docs string escape");
    }
    const escaped = source[index];
    if (escaped === "n") value += "\n";
    else if (escaped === "r") value += "\r";
    else if (escaped === "t") value += "\t";
    else if (escaped === "b") value += "\b";
    else if (escaped === "f") value += "\f";
    else value += escaped;
  }
  throw new Error("Unterminated legacy docs string");
}

function tokenizeLegacyJs(source, { loose = false } = {}) {
  const tokens = [];
  for (let index = 0; index < source.length;) {
    const char = source[index];
    const next = source[index + 1] || "";
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && next === "/") {
      const newline = source.indexOf("\n", index + 2);
      index = newline === -1 ? source.length : newline + 1;
      continue;
    }
    if (char === "/" && next === "*") {
      const close = source.indexOf("*/", index + 2);
      if (close === -1) {
        throw new Error("Unterminated legacy docs block comment");
      }
      index = close + 2;
      continue;
    }
    if ("{}[]:,".includes(char)) {
      tokens.push({ type: char, value: char });
      index += 1;
      continue;
    }
    if (char === "'" || char === "\"") {
      const parsed = legacyStringValue(source, index);
      tokens.push({ type: "string", value: parsed.value });
      index = parsed.end;
      continue;
    }
    if (char === "`") {
      const parsed = legacyStringValue(source, index);
      if (parsed.value.includes("${")) {
        throw new Error("Template expressions are not allowed in legacy docs metadata");
      }
      tokens.push({ type: "string", value: parsed.value });
      index = parsed.end;
      continue;
    }
    if (/[A-Za-z_$]/.test(char)) {
      let end = index + 1;
      while (end < source.length && /[A-Za-z0-9_$]/.test(source[end])) {
        end += 1;
      }
      tokens.push({ type: "identifier", value: source.slice(index, end) });
      index = end;
      continue;
    }
    if (/[0-9]/.test(char)) {
      let end = index + 1;
      while (end < source.length && /[0-9.]/.test(source[end])) {
        end += 1;
      }
      tokens.push({ type: "number", value: Number(source.slice(index, end)) });
      index = end;
      continue;
    }
    if (!loose) {
      throw new Error(`Unsupported legacy docs metadata token: ${char}`);
    }
    index += 1;
  }
  return tokens;
}

function tokenValue(tokens, index, type) {
  const token = tokens[index];
  if (!token || token.type !== type) {
    throw new Error(`Expected ${type} in legacy docs metadata`);
  }
  return token;
}

function parseLegacyObject(tokens, index) {
  tokenValue(tokens, index, "{");
  index += 1;
  const object = {};
  while (tokens[index]?.type !== "}") {
    const keyToken = tokens[index];
    if (!keyToken || !["identifier", "string"].includes(keyToken.type)) {
      throw new Error("Expected object key in legacy docs metadata");
    }
    index += 1;
    tokenValue(tokens, index, ":");
    index += 1;
    const valueToken = tokens[index];
    if (!valueToken || !["string", "number"].includes(valueToken.type)) {
      throw new Error(`Unsupported value for ${keyToken.value} in legacy docs metadata`);
    }
    object[keyToken.value] = valueToken.value;
    index += 1;
    if (tokens[index]?.type === ",") {
      index += 1;
    }
  }
  return { object, index: index + 1 };
}

function parseLegacySpecsArray(arraySource) {
  const tokens = tokenizeLegacyJs(arraySource);
  let index = 0;
  tokenValue(tokens, index, "[");
  index += 1;
  const specs = [];
  while (tokens[index]?.type !== "]") {
    const parsed = parseLegacyObject(tokens, index);
    specs.push(parsed.object);
    index = parsed.index;
    if (tokens[index]?.type === ",") {
      index += 1;
    }
  }
  tokenValue(tokens, index, "]");
  return specs;
}

function legacySpecsSource(source) {
  const match = source.match(/\b(?:const|let|var)\s+specs\s*=/);
  if (!match) {
    return "";
  }
  const openIndex = source.indexOf("[", match.index + match[0].length);
  if (openIndex === -1) {
    return "";
  }
  const closeIndex = matchingBracketIndex(source, openIndex, "[", "]");
  if (closeIndex === -1) {
    return "";
  }
  return source.slice(openIndex, closeIndex + 1);
}

function legacyUpdatedLabel(source) {
  const tokens = tokenizeLegacyJs(source, { loose: true });
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (tokens[index].value === "updated" && tokens[index + 1]?.type === ":" && tokens[index + 2]?.type === "string") {
      return tokens[index + 2].value;
    }
  }
  return docsUpdated;
}

function docsSourceCatalog(source) {
  const specsSource = legacySpecsSource(source);
  if (!specsSource) {
    return null;
  }
  const specs = parseLegacySpecsArray(specsSource);
  if (specs.length === 0) {
    return null;
  }
  return {
    docsUpdated: legacyUpdatedLabel(source),
    docSpecs: specs,
  };
}

function validateDocSpecs(value, ref, source) {
  if (!Array.isArray(value)) {
    throw new Error(`Could not find docSpecs array in ${ref}:${source}`);
  }
  for (const [index, spec] of value.entries()) {
    if (!spec || typeof spec !== "object" || Array.isArray(spec)) {
      throw new Error(`Invalid docs spec at ${ref}:${source}[${index}]`);
    }
    for (const key of ["source", "slug", "section", "title", "description"]) {
      if (typeof spec[key] !== "string" || spec[key].trim() === "") {
        throw new Error(`Invalid docs spec ${key} at ${ref}:${source}[${index}]`);
      }
    }
    if (typeof spec.order !== "number" || !Number.isFinite(spec.order)) {
      throw new Error(`Invalid docs spec order at ${ref}:${source}[${index}]`);
    }
  }
  return value;
}

function validateDocsCatalog(value, ref, source) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid docs catalog in ${ref}:${source}`);
  }
  if (typeof value.docsUpdated !== "string" || value.docsUpdated.trim() === "") {
    throw new Error(`Invalid docsUpdated in ${ref}:${source}`);
  }
  return {
    docSpecs: publicDocSpecs(validateDocSpecs(value.docSpecs, ref, source)),
    docsUpdated: value.docsUpdated,
  };
}

function docsMetadataFromRef(ref) {
  const specsSource = "apps/web/src/_data/docs-specs.json";
  const specsData = gitBlob(ref, specsSource);
  if (!specsData) {
    const legacySource = "apps/web/src/_data/docs.js";
    const legacyData = gitBlob(ref, legacySource);
    const legacyCatalog = docsSourceCatalog(legacyData);
    if (legacyCatalog) {
      return validateDocsCatalog(legacyCatalog, ref, legacySource);
    }
    throw new Error(`Could not find docs catalog in ${ref}:${specsSource}`);
  }
  try {
    return validateDocsCatalog(JSON.parse(specsData), ref, specsSource);
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`Invalid JSON docs catalog in ${ref}:${specsSource}: ${error.message}`);
    }
    throw error;
  }
}

const historicalPublicDocRewriteRules = [
  {
    name: "drop future mac app bullet",
    pattern: /\n- the future native macOS app surface under `apps\/macos\/`\n/g,
    replacement: "\n",
  },
  {
    name: "replace private repo scope",
    pattern: /This repo does not contain the marketing site, the future cloud control plane,\nor the internal product\/research docs used in the source-of-truth repo\./g,
    replacement: "This public repo is limited to the server/CLI release surface. Closed-source\napps, hosted services, marketing assets, and private planning docs stay outside\nthis export.",
  },
  {
    name: "replace formal assurance release note",
    pattern: /- Add the setup password formal-assurance lane: finite TLA\+ model checking,\n  generated Go conformance traces, abstract fuzz\/property coverage, targeted\n  mutation evidence, and the published assurance artifact for CONF-SETUP-002\./g,
    replacement: "- Harden setup password handling around empty input, retry behavior, interrupt\n  handling, and existing-vault password prompts.",
  },
  {
    name: "drop private assurance boundary bullet",
    pattern: /- Document adjacent assurance boundaries for keychain\/convenience unlock,\n  daemon\/session behavior, import\/binding side effects, and whole-program\n  release gates without widening the setup password proof\.\n/g,
    replacement: "",
  },
  {
    name: "rename web docs surface",
    pattern: /- Update public docs and the web docs surface with repo-target guidance,/g,
    replacement: "- Update public docs and the docs site with repo-target guidance,",
  },
  {
    name: "summarize private competition note",
    pattern: /- Reconcile the competitive baseline against shipped v0\.1\.31 behavior:[\s\S]*?`docs\/competition\/v1-v4-market-landscape\.md`\./g,
    replacement: "- Reconcile the competitive baseline against shipped v0.1.31 behavior and drop outdated onboarding and generic-compatible first-proof notes from the public release story.",
  },
  { name: "web dev target", pattern: /\bweb\.dev\b/g, replacement: "server.dev" },
  { name: "mac debug target", pattern: /\bmacos\.debug\b/g, replacement: "build.config" },
  { name: "deploy target", pattern: /\bdeploy\.production\b/g, replacement: "release.sign" },
  { name: "web env path", pattern: /apps\/web\/\.env\.example/g, replacement: "apps/server/.env.example" },
  { name: "web app path", pattern: /apps\/web/g, replacement: "apps/server" },
  { name: "mac generated secrets path", pattern: /apps\/macos\/Config\/Secrets\.generated\.xcconfig/g, replacement: "apps/server/Config/Secrets.generated.xcconfig" },
  { name: "mac generated other path", pattern: /apps\/macos\/Config\/Other\.generated\.xcconfig/g, replacement: "apps/server/Config/Other.generated.xcconfig" },
  { name: "mac example secrets path", pattern: /apps\/macos\/Config\/Secrets\.example\.xcconfig/g, replacement: "apps/server/Config/Secrets.example.xcconfig" },
  { name: "mac app path", pattern: /apps\/macos/g, replacement: "apps/server" },
  { name: "native swift app phrase", pattern: /native Swift macOS app/g, replacement: "desktop app" },
  { name: "native app phrase", pattern: /native macOS app/g, replacement: "desktop app" },
  { name: "mac app phrase", pattern: /macOS app/g, replacement: "desktop app" },
  { name: "debug config phrase", pattern: /Debug build config for the desktop app/g, replacement: "Build config for the server app" },
  { name: "debug configuration phrase", pattern: /Debug build configuration for the desktop app/g, replacement: "Build configuration for the server app" },
  { name: "local web dev phrase", pattern: /Local web app development/g, replacement: "Local server development" },
  { name: "web worker token phrase", pattern: /Server-side API token for the web worker/g, replacement: "Server-side API token for local broker development" },
  { name: "beads tracker jargon", pattern: /roadmap review beads/g, replacement: "roadmap review work items" },
];

function sanitizeHistoricalPublicDoc(source, markdown) {
  let updated = markdown;
  for (const rule of historicalPublicDocRewriteRules) {
    updated = updated.replace(rule.pattern, rule.replacement);
  }

  if (source === "public/docs/install-and-release.md") {
    updated = updated.replace(/```bash\npnpm -C apps\/server[^\n]*\n```\n/g, "");
  }
  return updated;
}

const version = fs.readFileSync(path.join(repoRoot, "VERSION"), "utf8").trim();
const versionId = normalizeDocsVersionId(requested);
const versionsPath = path.join(archiveRoot, "versions.json");

if (!fromRef && docsVersionNumber(versionId) !== docsVersionNumber(version)) {
  console.error(`Refusing to snapshot ${versionId}: repo VERSION is ${version}.`);
  process.exit(1);
}

const snapshotRoot = resolveDocsVersionPath(archiveRoot, versionId);
const snapshotMetadata = fromRef ? docsMetadataFromRef(fromRef) : { docSpecs: publicDocSpecs(docSpecs), docsUpdated };
const routeSpecs = fromRef
  ? snapshotMetadata.docSpecs.filter((spec) => gitBlob(fromRef, spec.source))
  : snapshotMetadata.docSpecs;
const preWriteStatus = fromRef ? "" : gitOutput(["status", "--short", "--", ...docsVersioningInputs(), ...routeSpecs.map((spec) => spec.source)]);

if (fs.existsSync(snapshotRoot)) {
  if (!force) {
    console.error(`Snapshot already exists: ${path.relative(repoRoot, snapshotRoot)}. Pass --force to replace it.`);
    process.exit(1);
  }
  fs.rmSync(snapshotRoot, { recursive: true, force: true });
}

fs.mkdirSync(snapshotRoot, { recursive: true });

const copied = [];
const sourceFileSha256 = {};
const sourceFileOriginalSha256 = {};
const sourceFileSanitizedSha256 = {};
const sanitizedSourceFiles = [];
const sourceFileOriginalMissing = [];
for (const spec of routeSpecs) {
  const currentSource = resolvePublicDocPath(repoRoot, spec.source, "docs source");
  const refSource = fromRef ? gitBlob(fromRef, spec.source) : "";
  if (fromRef ? !refSource : !fs.existsSync(currentSource)) {
    console.error(`Missing docs source: ${spec.source}`);
    process.exit(1);
  }
  const target = resolvePublicDocPath(snapshotRoot, spec.source, "docs snapshot target");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const originalMarkdown = fromRef ? refSource : fs.readFileSync(currentSource, "utf8");
  const markdown = fromRef ? sanitizeHistoricalPublicDoc(spec.source, originalMarkdown) : originalMarkdown;
  fs.writeFileSync(target, markdown);
  copied.push(spec.source);
  sourceFileSha256[spec.source] = sha256Hex(markdown);
  if (fromRef) {
    sourceFileOriginalSha256[spec.source] = sha256Hex(originalMarkdown);
    sourceFileSanitizedSha256[spec.source] = sha256Hex(markdown);
    if (markdown !== originalMarkdown) {
      sanitizedSourceFiles.push(spec.source);
    }
  }
}

fs.writeFileSync(path.join(snapshotRoot, "VERSION"), `${docsVersionNumber(versionId)}\n`);

const sourceCommit = fromRef ? gitOutput(["rev-parse", fromRef]) || null : commandOutput("git rev-parse HEAD") || null;
const createdAt = new Date().toISOString();
const manifest = {
  schemaVersion: 1,
  version: versionId,
  versionNumber: docsVersionNumber(versionId),
  createdAt,
  updatedLabel: snapshotMetadata.docsUpdated,
  sourceCommit,
  dirty: process.env.HASP_DOCS_SNAPSHOT_SKIP_CHECK === "1" ? false : Boolean(preWriteStatus),
  defaultRouteSlug: "overview",
  specs: routeSpecs,
  sourceFiles: copied,
  sourceFileSha256,
};
if (fromRef) {
  manifest.sourceArchiveTransform = "public-docs-sanitized-v1";
  manifest.sourceFilesSanitized = sanitizedSourceFiles;
  manifest.sourceFileOriginalSha256 = sourceFileOriginalSha256;
  manifest.sourceFileSanitizedSha256 = sourceFileSanitizedSha256;
  manifest.sourceFileOriginalMissing = sourceFileOriginalMissing;
}

fs.writeFileSync(path.join(snapshotRoot, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

let versions = { latest: versionId, versions: [] };
if (fs.existsSync(versionsPath)) {
  versions = JSON.parse(fs.readFileSync(versionsPath, "utf8"));
}
const previousLatest = normalizeDocsVersionId(versions.latest || versionId);

const existing = new Map((versions.versions || []).map((entry) => {
  const id = normalizeDocsVersionId(entry.id);
  return [id, { ...entry, id }];
}));
existing.set(versionId, {
  id: versionId,
  label: versionId,
  version: docsVersionNumber(versionId),
  path: `/docs/${versionId}/`,
  snapshot: `${versionId}/manifest.json`,
  createdAt,
  sourceCommit,
});

versions = {
  latest: docsVersionNumber(versionId) === docsVersionNumber(version) ? versionId : previousLatest,
  versions: [...existing.values()].sort((a, b) => b.version.localeCompare(a.version, undefined, { numeric: true })),
};

fs.mkdirSync(archiveRoot, { recursive: true });
fs.writeFileSync(versionsPath, `${JSON.stringify(versions, null, 2)}\n`);
if (!fromRef && versions.latest === versionId) {
  fs.writeFileSync(publicDocsMetadataPath, `${JSON.stringify({
    schemaVersion: 1,
    latest: versionId,
    updatedLabel: snapshotMetadata.docsUpdated,
    sourceFiles: copied,
    specs: routeSpecs,
  }, null, 2)}\n`);
}

if (process.env.HASP_DOCS_SNAPSHOT_SKIP_CHECK !== "1") {
  execSync("pnpm -C apps/web check", { cwd: repoRoot, stdio: "inherit" });
}

console.log(`Snapshot written: public/docs-versions/${versionId}`);
console.log(`Latest docs: /docs/`);
console.log(`Version docs: /docs/${versionId}/`);
