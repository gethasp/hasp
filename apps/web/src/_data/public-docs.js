import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dataDir = path.dirname(fileURLToPath(import.meta.url));
const policyPath = path.resolve(dataDir, "../../../../scripts/public-docs-policy.json");
export const publicDocsPolicy = JSON.parse(fs.readFileSync(policyPath, "utf8"));

export const blockedDocSources = new Set(publicDocsPolicy.blocked_doc_sources);
export const blockedDocSlugs = new Set(publicDocsPolicy.blocked_doc_slugs);

const publicDocSourcePrefixes = publicDocsPolicy.public_doc_source_prefixes;
const docSourcePattern = new RegExp(publicDocsPolicy.doc_source_pattern);
const docSlugSegmentPattern = new RegExp(publicDocsPolicy.doc_slug_segment_pattern);
const docsVersionIdPattern = new RegExp(publicDocsPolicy.docs_version_id_pattern);

function assertRelativePath(value, label) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    throw new Error(`Invalid ${label}: value is empty`);
  }
  if (normalized.includes("\0") || normalized.includes("\\") || path.isAbsolute(normalized) || /^[A-Za-z]:[\\/]/.test(normalized)) {
    throw new Error(`Invalid ${label}: ${normalized}`);
  }
  const segments = normalized.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new Error(`Invalid ${label}: ${normalized}`);
  }
  const canonical = path.posix.normalize(normalized);
  if (canonical !== normalized || canonical === "." || canonical.startsWith("../")) {
    throw new Error(`Invalid ${label}: ${normalized}`);
  }
  return canonical;
}

export function normalizeDocSource(source) {
  const normalized = assertRelativePath(source, "docs source");
  if (!docSourcePattern.test(normalized) || !normalized.endsWith(".md")) {
    throw new Error(`Invalid docs source: ${normalized}`);
  }
  return normalized;
}

export function normalizeDocSlug(slug) {
  const normalized = assertRelativePath(slug, "docs slug");
  const segments = normalized.split("/");
  if (!segments.every((segment) => docSlugSegmentPattern.test(segment))) {
    throw new Error(`Invalid docs slug: ${normalized}`);
  }
  return normalized;
}

export function normalizeDocsVersionId(value) {
  const trimmed = String(value || "").trim();
  const versionId = trimmed.startsWith("v") ? trimmed : `v${trimmed}`;
  if (!docsVersionIdPattern.test(versionId)) {
    throw new Error(`Invalid docs version id: ${trimmed}`);
  }
  return versionId;
}

export function docsVersionNumber(value) {
  return normalizeDocsVersionId(value).replace(/^v/, "");
}

function isAllowedPublicDocSource(source) {
  return publicDocSourcePrefixes.some((prefix) => source.startsWith(prefix));
}

function normalizeDocSpecIdentity(spec, index) {
  if (!spec || typeof spec !== "object" || Array.isArray(spec)) {
    throw new Error(`Invalid docs spec at index ${index}`);
  }
  return {
    source: normalizeDocSource(spec.source),
    slug: normalizeDocSlug(spec.slug),
  };
}

function normalizePublicDocSpec(spec, index, identity = normalizeDocSpecIdentity(spec, index)) {
  for (const key of ["section", "title", "description"]) {
    if (typeof spec[key] !== "string" || spec[key].trim() === "") {
      throw new Error(`Invalid docs spec ${key} at index ${index}`);
    }
  }
  if (typeof spec.order !== "number" || !Number.isFinite(spec.order)) {
    throw new Error(`Invalid docs spec order at index ${index}`);
  }
  return {
    ...spec,
    source: identity.source,
    slug: identity.slug,
    section: spec.section.trim(),
    title: spec.title.trim(),
    description: spec.description.trim(),
  };
}

export function isPublicDocSpec(spec) {
  const source = normalizeDocSource(spec.source);
  const slug = normalizeDocSlug(spec.slug);
  return !blockedDocSources.has(source) && !blockedDocSlugs.has(slug);
}

export function publicDocSpecs(routeSpecs) {
  if (!Array.isArray(routeSpecs)) {
    throw new Error("Docs specs must be an array");
  }
  const output = [];
  const seenSources = new Set();
  const seenSlugs = new Set();
  for (const [index, spec] of routeSpecs.entries()) {
    const identity = normalizeDocSpecIdentity(spec, index);
    if (blockedDocSources.has(identity.source) || blockedDocSlugs.has(identity.slug)) {
      continue;
    }
    const normalized = normalizePublicDocSpec(spec, index, identity);
    if (!isAllowedPublicDocSource(normalized.source)) {
      throw new Error(`Docs source is outside public docs roots: ${normalized.source}`);
    }
    if (seenSources.has(normalized.source)) {
      throw new Error(`Duplicate docs source: ${normalized.source}`);
    }
    if (seenSlugs.has(normalized.slug)) {
      throw new Error(`Duplicate docs slug: ${normalized.slug}`);
    }
    seenSources.add(normalized.source);
    seenSlugs.add(normalized.slug);
    output.push(normalized);
  }
  return output;
}

export function resolveUnder(root, relativePath, label = "path") {
  const absoluteRoot = path.resolve(root);
  const resolved = path.resolve(absoluteRoot, relativePath);
  const relative = path.relative(absoluteRoot, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Invalid ${label}: ${relativePath}`);
  }
  return resolved;
}

export function resolvePublicDocPath(root, source, label = "docs source") {
  const normalized = normalizeDocSource(source);
  const primary = resolveUnder(root, normalized, label);
  if (fs.existsSync(primary) || !normalized.startsWith("public/")) {
    return primary;
  }
  const exportedPath = normalized.slice("public/".length);
  const fallback = resolveUnder(root, exportedPath, label);
  return fs.existsSync(fallback) ? fallback : primary;
}

export function resolveDocsVersionPath(archiveRoot, versionId) {
  return resolveUnder(archiveRoot, normalizeDocsVersionId(versionId), "docs version");
}
