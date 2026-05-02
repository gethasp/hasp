import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { docSpecs, docsUpdated } from "./docs-specs.js";
import {
  docsVersionNumber,
  normalizeDocsVersionId,
  publicDocSpecs,
  resolveDocsVersionPath,
  resolvePublicDocPath,
} from "./public-docs.js";

const require = createRequire(import.meta.url);
const dataDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(dataDir, "../../../..");
const githubBase = "https://github.com/gethasp/hasp/blob/main";

const specs = publicDocSpecs(docSpecs);

function resolveMarkdownIt() {
  const eleventyEntry = require.resolve("@11ty/eleventy");
  const eleventyNodeModules = path.resolve(path.dirname(eleventyEntry), "../../..");
  return require(path.join(eleventyNodeModules, "markdown-it"));
}

const MarkdownIt = resolveMarkdownIt();
const currentVersion = fs.readFileSync(path.join(repoRoot, "VERSION"), "utf8").trim();
const archiveRoot = fs.existsSync(path.join(repoRoot, "public/docs-versions"))
  ? path.join(repoRoot, "public/docs-versions")
  : path.join(repoRoot, "docs-versions");
const versionsPath = path.join(archiveRoot, "versions.json");
const versionIndexUrl = "/docs/versions/";

function slugify(value) {
  return String(value)
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "section";
}

function headingLabel(value) {
  return String(value)
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[*_~]/g, "")
    .trim();
}

function stripFrontMatter(markdown) {
  return markdown.replace(/^---\n[\s\S]*?\n---\n/, "");
}

function stripFirstH1(markdown) {
  return markdown.replace(/^# .*(?:\n+|$)/, "");
}

function firstParagraph(markdown) {
  return stripFirstH1(stripFrontMatter(markdown))
    .split(/\n{2,}/)
    .map((block) => block.replace(/\n/g, " ").trim())
    .find((block) => block && !block.startsWith("```") && !block.startsWith("- ")) || "";
}

function plainText(markdown) {
  return stripFrontMatter(markdown)
    .replace(/<[^>]+>/g, " ")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[#>*_~|-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function truncateSearchText(value, maxLength = 220) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (text.length <= maxLength) {
    return text;
  }
  const shortened = text.slice(0, maxLength - 1);
  const lastSpace = shortened.lastIndexOf(" ");
  return `${shortened.slice(0, lastSpace > 120 ? lastSpace : shortened.length).trim()}...`;
}

function markdownHeadingSections(markdown) {
  const body = stripFirstH1(stripFrontMatter(markdown));
  const matcher = /^(#{2,3})\s+(.+)$/gm;
  const matches = [...body.matchAll(matcher)];
  const seenIds = new Map();

  return matches.map((match, index) => {
    const rawTitle = match[2];
    const title = headingLabel(rawTitle);
    const base = slugify(title);
    const count = seenIds.get(base) || 0;
    seenIds.set(base, count + 1);
    const id = count ? `${base}-${count + 1}` : base;
    const start = match.index + match[0].length;
    const end = matches[index + 1]?.index ?? body.length;
    const text = plainText(body.slice(start, end));

    return {
      id,
      title,
      level: match[1].length,
      text,
      snippet: truncateSearchText(text),
    };
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function token(className, value) {
  return `<span class="code-${className}">${escapeHtml(value)}</span>`;
}

const haspCommands = [
  "init",
  "setup",
  "bootstrap",
  "doctor",
  "import",
  "set",
  "capture",
  "secret",
  "app",
  "agent",
  "project",
  "run",
  "inject",
  "write-env",
  "check-repo",
  "proof",
  "daemon",
  "session",
  "vault",
  "status",
  "ping",
  "audit",
  "export-backup",
  "restore-backup",
  "upgrade",
  "docs",
  "internals",
  "help",
  "completion",
  "mcp",
  "add",
  "update",
  "rotate",
  "delete",
  "get",
  "retrieve",
  "show",
  "reveal",
  "copy",
  "list",
  "diff",
  "expose",
  "hide",
  "connect",
  "install",
  "shell",
  "disconnect",
  "supported",
  "grant-plaintext",
  "tail",
  "lock",
  "forget-device",
  "rekey",
  "exit-codes",
];
const haspCommandPattern = haspCommands.map((command) => command.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
const haspLeadingCommandPattern = new RegExp(`^(${haspCommandPattern})(\\s{2,}|$)`);
const haspInvocationPattern = new RegExp(`\\bhasp(?:\\s+(?:${haspCommandPattern})){0,5}\\b`, "g");

function highlightJson(code) {
  const matcher = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]/g;
  let html = "";
  let offset = 0;
  for (const match of code.matchAll(matcher)) {
    html += escapeHtml(code.slice(offset, match.index));
    if (match[1]) {
      html += token(match[2] ? "key" : "string", match[1]);
      if (match[2]) {
        html += token("punctuation", match[2]);
      }
    } else if (match[3]) {
      html += token("literal", match[0]);
    } else if (/^-?\d/.test(match[0])) {
      html += token("number", match[0]);
    } else {
      html += token("punctuation", match[0]);
    }
    offset = match.index + match[0].length;
  }
  return html + escapeHtml(code.slice(offset));
}

function splitShellComment(line) {
  const comment = line.match(/(^|\s)#/);
  if (!comment) {
    return [line, ""];
  }
  const index = comment.index + comment[1].length;
  return [line.slice(0, index), line.slice(index)];
}

function highlightShellBody(body) {
  const matcher = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(?<![\w./-])(--?[a-zA-Z0-9][\w-]*(?:=[^\s]+)?)|(?<![\w./-])(hasp|brew|curl|sh|chmod|mkdir|cd|export|echo|cat|go|make|gpg|sha256sum|tar|git|pnpm|bunx)(?![\w-])|(\b[A-Z][A-Z0-9_]*(?==)|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/g;
  let html = "";
  let offset = 0;
  for (const match of body.matchAll(matcher)) {
    html += escapeHtml(body.slice(offset, match.index));
    if (match[1]) {
      html += token("string", match[1]);
    } else if (match[2]) {
      html += token("option", match[2]);
    } else if (match[3]) {
      html += token("command", match[3]);
    } else {
      html += token("variable", match[4]);
    }
    offset = match.index + match[0].length;
  }
  return html + escapeHtml(body.slice(offset));
}

function highlightCliHelpBody(body) {
  const leadingCommand = body.match(haspLeadingCommandPattern);
  if (leadingCommand) {
    return `${token("command", leadingCommand[1])}${escapeHtml(body.slice(leadingCommand[1].length))}`;
  }

  const matcher = new RegExp(
    `("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*')|(<[^>\\s]+>)|(?<![\\w./-])(--?[a-zA-Z0-9][\\w-]*(?:=[^\\s]+)?)|(?<![\\w./-])(${haspInvocationPattern.source})(?![\\w-])|(\\b[A-Z][A-Z0-9_]*(?:_[A-Z0-9]+)+\\b)|(?<![\\w./-])(brew|curl|sh|chmod|mkdir|cd|export|echo|cat|go|make|gpg|sha256sum|tar|git|pnpm|bunx|jq)(?![\\w-])`,
    "g"
  );
  let html = "";
  let offset = 0;
  for (const match of body.matchAll(matcher)) {
    html += escapeHtml(body.slice(offset, match.index));
    if (match[1]) {
      html += token("string", match[1]);
    } else if (match[2]) {
      html += token("variable", match[2]);
    } else if (match[3]) {
      html += token("option", match[3]);
    } else if (match[4]) {
      html += token("command", match[4]);
    } else if (match[5]) {
      html += token("variable", match[5]);
    } else {
      html += token("command", match[6]);
    }
    offset = match.index + match[0].length;
  }
  return html + escapeHtml(body.slice(offset));
}

function highlightShell(code) {
  return code
    .split("\n")
    .map((line) => {
      const prompt = line.match(/^(\s*(?:[$>#]|->)\s*)/);
      const prefix = prompt ? token("prompt", prompt[1]) : "";
      const rest = prompt ? line.slice(prompt[1].length) : line;
      const [body, comment] = splitShellComment(rest);
      return `${prefix}${highlightShellBody(body)}${comment ? token("comment", comment) : ""}`;
    })
    .join("\n");
}

function highlightCliHelp(code) {
  return code
    .split("\n")
    .map((line) => {
      if (line === "") {
        return `<span class="code-line" style="--indent:0;--hang:0"></span>`;
      }
      const indent = line.match(/^ */)?.[0].length || 0;
      const body = line.slice(indent);
      const descriptionGap = body.match(/\s{2,}\S/);
      const hang = descriptionGap ? indent + descriptionGap.index + descriptionGap[0].length - 1 : indent;
      return `<span class="code-line" style="--indent:${indent};--hang:${hang}">${highlightCliHelpBody(body)}</span>`;
    })
    .join("");
}

function highlightCode(code, lang) {
  const language = String(lang || "").toLowerCase();
  if (["bash", "sh", "shell", "zsh"].includes(language)) {
    return highlightShell(code);
  }
  if (language === "json") {
    return highlightJson(code);
  }
  if (!language || language === "text" || language === "txt") {
    return highlightCliHelp(code);
  }
  return escapeHtml(code);
}

function joinDocsUrl(basePath, slug = "") {
  const normalizedBase = basePath.endsWith("/") ? basePath : `${basePath}/`;
  if (!slug) {
    return normalizedBase;
  }
  return `${normalizedBase}${slug}/`;
}

function buildPageBySource(routeSpecs, basePath) {
  const pageBySource = new Map();
  for (const spec of routeSpecs) {
    pageBySource.set(spec.source, joinDocsUrl(basePath, spec.slug));
  }
  pageBySource.set("public/docs/README.md", joinDocsUrl(basePath));
  return pageBySource;
}

function rewriteHref(rawHref, sourcePath, pageBySource) {
  if (
    rawHref.startsWith("#") ||
    rawHref.startsWith("http://") ||
    rawHref.startsWith("https://") ||
    rawHref.startsWith("mailto:")
  ) {
    return rawHref;
  }

  const [hrefPath, hash = ""] = rawHref.split("#");
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(sourcePath), hrefPath));
  const normalized = resolved.replace(/\/README\.md$/, "/README.md");

  if (pageBySource.has(normalized)) {
    return `${pageBySource.get(normalized)}${hash ? `#${hash}` : ""}`;
  }

  if (normalized.endsWith(".md") && pageBySource.has(normalized.replace(/\/index\.md$/, "/README.md"))) {
    return `${pageBySource.get(normalized.replace(/\/index\.md$/, "/README.md"))}${hash ? `#${hash}` : ""}`;
  }

  return `${githubBase}/${normalized}${hash ? `#${hash}` : ""}`;
}

function renderMarkdown(markdown, sourcePath, pageBySource) {
  const md = new MarkdownIt({
    html: true,
    linkify: true,
    typographer: false,
    highlight: highlightCode,
  });
  const headings = [];
  const seenIds = new Map();

  md.renderer.rules.heading_open = (tokens, index, options, env, self) => {
    const token = tokens[index];
    const next = tokens[index + 1];
    const level = Number(token.tag.replace("h", ""));
    const text = headingLabel(next?.content || "");
    const base = slugify(text);
    const count = seenIds.get(base) || 0;
    seenIds.set(base, count + 1);
    const id = count ? `${base}-${count + 1}` : base;
    token.attrSet("id", id);
    if (level >= 2 && level <= 3) {
      env.headings.push({ level, id, title: text });
    }
    return self.renderToken(tokens, index, options);
  };

  md.renderer.rules.link_open = (tokens, index, options, env, self) => {
    const href = tokens[index].attrGet("href");
    if (href) {
      const rewritten = rewriteHref(href, env.sourcePath, pageBySource);
      tokens[index].attrSet("href", rewritten);
      if (rewritten.startsWith("http")) {
        tokens[index].attrSet("rel", "noopener noreferrer");
      }
    }
    return self.renderToken(tokens, index, options);
  };

  const html = md.render(stripFirstH1(stripFrontMatter(markdown)), {
    sourcePath,
    headings,
  });

  return { html, headings };
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function latestAliasUrl(slug = "") {
  return joinDocsUrl("/docs/", slug);
}

function canonicalVersionUrl(versionId, slug = "") {
  return joinDocsUrl(`/docs/${versionId}/`, slug);
}

function readVersionSources() {
  if (!fs.existsSync(versionsPath)) {
    const versionId = normalizeDocsVersionId(currentVersion);
    return {
      latestId: versionId,
      sources: [{
        id: versionId,
        label: versionId,
        version: docsVersionNumber(versionId),
        sourceRoot: repoRoot,
        specs,
        updated: docsUpdated,
        sourceCommit: null,
        createdAt: null,
      }],
    };
  }

  const registry = readJson(versionsPath);
  const latestId = normalizeDocsVersionId(registry.latest || currentVersion);
  const sources = (registry.versions || []).map((entry) => {
    const id = normalizeDocsVersionId(entry.id);
    const snapshotRoot = resolveDocsVersionPath(archiveRoot, id);
    const manifestPath = path.join(snapshotRoot, "manifest.json");
    const manifest = fs.existsSync(manifestPath) ? readJson(manifestPath) : {};
    return {
      id,
      label: entry.label || id,
      version: entry.version || manifest.versionNumber || docsVersionNumber(id),
      sourceRoot: snapshotRoot,
      specs: publicDocSpecs(manifest.specs || specs),
      updated: manifest.updatedLabel || docsUpdated,
      sourceCommit: entry.sourceCommit || manifest.sourceCommit || null,
      createdAt: entry.createdAt || manifest.createdAt || null,
      hidden: Boolean(entry.hidden),
    };
  });

  if (!sources.length) {
    const versionId = normalizeDocsVersionId(currentVersion);
    sources.push({
      id: versionId,
      label: versionId,
      version: docsVersionNumber(versionId),
      sourceRoot: repoRoot,
      specs,
      updated: docsUpdated,
      sourceCommit: null,
      createdAt: null,
    });
  }

  return { latestId, sources };
}

const { latestId, sources: versionSources } = readVersionSources();
const visibleVersions = versionSources.filter((version) => !version.hidden);

function versionTargetUrl(version, slug = "") {
  const hasPage = !slug || version.specs.some((spec) => spec.slug === slug);
  return canonicalVersionUrl(version.id, hasPage ? slug : "");
}

function versionOptions(activeVersionId, slug = "") {
  return visibleVersions.map((version) => ({
    id: version.id,
    label: version.label,
    selected: version.id === activeVersionId,
    url: versionTargetUrl(version, slug),
  }));
}

function buildSections(routePages) {
  return [...new Set(routePages.map((page) => page.section))].map((section) => ({
    title: section,
    pages: routePages
      .filter((page) => page.section === section)
      .sort((a, b) => a.order - b.order),
  }));
}

function buildSearch(routePages, sourceRoot) {
  return routePages.map((page) => ({
    kind: "Page",
    title: page.title,
    pageTitle: page.title,
    section: page.section,
    url: page.url,
    description: page.description,
    text: page.searchText,
    heading: "",
  })).flatMap((pageItem) => {
    const page = routePages.find((candidate) => candidate.url === pageItem.url);
    const sectionItems = markdownHeadingSections(fs.readFileSync(resolvePublicDocPath(sourceRoot, page.source, "docs search source"), "utf8"))
      .filter((heading) => heading.level >= 2 && heading.level <= 3)
      .map((heading) => ({
        kind: "Section",
        title: heading.title,
        pageTitle: page.title,
        section: page.section,
        url: `${page.url}#${heading.id}`,
        description: heading.snippet || page.description,
        text: heading.text,
        heading: heading.title,
      }));
    return [pageItem, ...sectionItems];
  });
}

function buildRoute(version, basePath, routeKind) {
  const pageBySource = buildPageBySource(version.specs, basePath);
  const routePages = version.specs.map((spec) => {
    const absolute = resolvePublicDocPath(version.sourceRoot, spec.source, "docs route source");
    const markdown = fs.readFileSync(absolute, "utf8");
    const rendered = renderMarkdown(markdown, spec.source, pageBySource);
    const text = plainText(markdown);

    return {
      ...spec,
      versionId: version.id,
      versionLabel: version.label,
      versionNumber: version.version,
      routeKind,
      routeBasePath: basePath,
      homeUrl: joinDocsUrl(basePath),
      url: joinDocsUrl(basePath, spec.slug),
      canonicalVersionUrl: canonicalVersionUrl(version.id, spec.slug),
      latestUrl: version.id === latestId ? latestAliasUrl(spec.slug) : null,
      githubUrl: `${githubBase}/${spec.source}`,
      html: rendered.html,
      headings: rendered.headings,
      searchText: text,
      description: spec.description || firstParagraph(markdown),
      versionIndexUrl,
    };
  });

  const sections = buildSections(routePages);
  const search = buildSearch(routePages, version.sourceRoot);
  const pagesBySlug = new Map(routePages.map((page) => [page.slug, page]));
  const startCardSlugs = ["mental-model", "quickstart", "command-guide", "agent-profiles"];

  for (const page of routePages) {
    page.sections = sections;
    page.versionOptions = versionOptions(version.id, page.slug);
    page.allVersionsUrl = versionIndexUrl;
  }

  return {
    version,
    basePath,
    routeKind,
    pages: routePages,
    sections,
    search,
    home: {
      url: joinDocsUrl(basePath),
      versionId: version.id,
      versionLabel: version.label,
      versionNumber: version.version,
      routeKind,
      sections,
      search,
      startCards: startCardSlugs
        .map((slug, index) => ({ ...pagesBySlug.get(slug), number: String(index + 1).padStart(2, "0") }))
        .filter((page) => page.url),
      versionOptions: versionOptions(version.id),
      versionIndexUrl,
      allVersionsUrl: versionIndexUrl,
    },
  };
}

const routes = versionSources.flatMap((version) => {
  const versionRoute = buildRoute(version, `/docs/${version.id}/`, "version");
  if (version.id !== latestId) {
    return [versionRoute];
  }
  return [buildRoute(version, "/docs/", "latest"), versionRoute];
});

const homes = routes.map((route) => route.home);
const pages = routes.flatMap((route) => route.pages);
const latestRoute = routes.find((route) => route.routeKind === "latest") || routes[0];
const versions = visibleVersions.map((version) => ({
  id: version.id,
  label: version.label,
  version: version.version,
  latest: version.id === latestId,
  url: versionTargetUrl(version),
  canonicalUrl: canonicalVersionUrl(version.id),
  latestUrl: version.id === latestId ? latestAliasUrl() : null,
  createdAt: version.createdAt,
  sourceCommit: version.sourceCommit,
}));

export default {
  homes,
  pages,
  sections: latestRoute.sections,
  search: latestRoute.search,
  versions,
  latestVersion: versions.find((version) => version.latest) || versions[0],
  versionIndexUrl,
  updated: docsUpdated,
  version: currentVersion,
};
