#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  normalizeDocsVersionId,
  publicDocSpecs,
  resolveDocsVersionPath,
} from "../src/_data/public-docs.js";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const siteRoot = path.join(repoRoot, "apps/web/_site");
const archiveRoot = fs.existsSync(path.join(repoRoot, "public/docs-versions"))
  ? path.join(repoRoot, "public/docs-versions")
  : path.join(repoRoot, "docs-versions");
const registryPath = path.join(archiveRoot, "versions.json");

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function readSite(relPath) {
  const absolute = path.join(siteRoot, relPath);
  if (!fs.existsSync(absolute)) {
    fail(`Missing generated file: ${relPath}`);
    return "";
  }
  return fs.readFileSync(absolute, "utf8");
}

function expectIncludes(relPath, needle) {
  const html = readSite(relPath);
  if (!html.includes(needle)) {
    fail(`Expected ${relPath} to include ${needle}`);
  }
}

function expectMatches(relPath, pattern, label) {
  const html = readSite(relPath);
  if (!pattern.test(html)) {
    fail(`Expected ${relPath} to match ${label}`);
  }
}

function expectExcludes(relPath, needle) {
  const html = readSite(relPath);
  if (html.includes(needle)) {
    fail(`Expected ${relPath} not to include ${needle}`);
  }
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function quotedAttrPattern(name, value) {
  return `${name}=["']${escapeRegex(value)}["']`;
}

execFileSync("python3", [path.join(repoRoot, "scripts/check-public-docs-versioning.py")], {
  cwd: repoRoot,
  stdio: "inherit",
});

const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
const latestId = normalizeDocsVersionId(registry.latest || "");
const versions = registry.versions || [];

readSite("docs/index.html");
readSite("docs/versions/index.html");

for (const version of versions) {
  const versionId = normalizeDocsVersionId(version.id);
  const manifestPath = path.join(resolveDocsVersionPath(archiveRoot, versionId), "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  readSite(`docs/${versionId}/index.html`);

  for (const spec of publicDocSpecs(manifest.specs || [])) {
    readSite(`docs/${versionId}/${spec.slug}/index.html`);
    if (versionId === latestId) {
      readSite(`docs/${spec.slug}/index.html`);
    }
  }
}

expectMatches(
  "docs/index.html",
  new RegExp(`<option\\b(?=[^>]*\\b${quotedAttrPattern("value", `/docs/${latestId}/`)})(?=[^>]*\\bselected\\b)[^>]*>`),
  `selected latest docs option for ${latestId}`,
);
expectIncludes("docs/versions/index.html", latestId);
expectMatches("docs/versions/index.html", new RegExp(`<a\\b(?=[^>]*\\b${quotedAttrPattern("href", `/docs/${latestId}/`)})[^>]*>`), `version link for ${latestId}`);
expectMatches(
  `docs/${latestId}/install/index.html`,
  new RegExp(`<a\\b(?=[^>]*\\b${quotedAttrPattern("href", `/docs/${latestId}/after-homebrew/`)})[^>]*>`),
  "install page after-homebrew link",
);
expectMatches(
  `docs/${latestId}/index.html`,
  new RegExp(`<a\\b(?=[^>]*\\b${quotedAttrPattern("href", `/docs/${latestId}/install/`)})[^>]*>`),
  "docs home install link",
);
expectExcludes("docs/index.html", `/docs/${latestId}/install/`);

if (process.exitCode) {
  process.exit(process.exitCode);
}

console.log("Docs versioning output looks consistent.");
