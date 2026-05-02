#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../..");
const snapshotOutputRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hasp-docs-snapshot-out-"));
const snapshotArchiveRoot = path.join(snapshotOutputRoot, "docs-versions");
const snapshotMetadataPath = path.join(snapshotOutputRoot, "docs-metadata.json");
const versioningStatusBefore = run("git", ["status", "--short", "--", "public/docs-versions", "public/docs-metadata.json"], { encoding: "utf8" });
const currentVersion = fs.readFileSync(path.join(repoRoot, "VERSION"), "utf8").trim();
const currentVersionId = currentVersion.startsWith("v") ? currentVersion : `v${currentVersion}`;
const syntheticFixturePaths = [
  "apps/web/src/_data/docs-specs.json",
  "apps/web/src/_data/docs.js",
  "apps/web/src/_data/docs-specs.js",
  "public/README.md",
  "public/docs/install-and-release.md",
];

const oneDocSpec = {
  source: "public/README.md",
  slug: "overview",
  section: "Start",
  order: 1,
  title: "Overview",
  description: "A safe docs metadata wrapper should snapshot.",
};

const installDocSpec = {
  ...oneDocSpec,
  source: "public/docs/install-and-release.md",
  slug: "install-and-release",
  title: "Install and Release",
};

function docsCatalog(overrides = {}) {
  return {
    docsUpdated: "April 2026",
    docSpecs: [oneDocSpec],
    ...overrides,
  };
}

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: repoRoot,
    stdio: "pipe",
    ...options,
  });
}

function runVisible(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
    ...options,
  });
}

function gitPathExists(ref, source) {
  try {
    run("git", ["cat-file", "-e", `${ref}:${source}`]);
    return true;
  } catch {
    return false;
  }
}

function gitBlob(ref, source) {
  return run("git", ["show", `${ref}:${source}`], { encoding: "utf8" });
}

function resetFixtureRoot(fixtureRoot, baseRef) {
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
  for (const source of syntheticFixturePaths) {
    if (!gitPathExists(baseRef, source)) {
      continue;
    }
    const target = path.join(fixtureRoot, source);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, gitBlob(baseRef, source));
  }
}

function writeSyntheticTree(entries, prefix = "") {
  const files = [];
  const dirs = new Map();
  for (const entry of entries) {
    const rel = prefix ? entry.path.slice(prefix.length + 1) : entry.path;
    const parts = rel.split("/");
    if (parts.length === 1) {
      files.push({ name: parts[0], oid: entry.oid });
      continue;
    }
    const dir = parts[0];
    if (!dirs.has(dir)) {
      dirs.set(dir, []);
    }
    dirs.get(dir).push(entry);
  }

  const treeLines = [];
  for (const file of files.sort((left, right) => left.name.localeCompare(right.name))) {
    treeLines.push(`100644 blob ${file.oid}\t${file.name}`);
  }
  for (const [dir, nested] of [...dirs.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const nextPrefix = prefix ? `${prefix}/${dir}` : dir;
    const oid = writeSyntheticTree(nested, nextPrefix);
    treeLines.push(`040000 tree ${oid}\t${dir}`);
  }
  return run("git", ["mktree"], {
    input: `${treeLines.join("\n")}\n`,
    encoding: "utf8",
  }).trim();
}

function createSyntheticCommit(fixtureRoot, baseRef) {
  const env = {
    ...process.env,
    GIT_AUTHOR_NAME: "HASP Test",
    GIT_AUTHOR_EMAIL: "hasp@example.invalid",
    GIT_COMMITTER_NAME: "HASP Test",
    GIT_COMMITTER_EMAIL: "hasp@example.invalid",
  };
  const entries = [];
  for (const source of syntheticFixturePaths) {
    const sourcePath = path.join(fixtureRoot, source);
    if (!fs.existsSync(sourcePath)) {
      continue;
    }
    const blob = run("git", ["hash-object", "-w", "--stdin"], {
      env,
      input: fs.readFileSync(sourcePath),
      encoding: "utf8",
    }).trim();
    entries.push({ path: source, oid: blob });
  }
  const tree = writeSyntheticTree(entries);
  return run("git", ["commit-tree", tree, "-p", baseRef, "-m", "hostile docs fixture"], { env, encoding: "utf8" }).trim();
}

function withHostileWorktree(callback) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hasp-docs-fixture-"));
  try {
    const baseRef = run("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    callback(fixtureRoot, baseRef);
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

function hostileRef(fixtureRoot, baseRef, mutator) {
  resetFixtureRoot(fixtureRoot, baseRef);
  try {
    mutator(fixtureRoot);
    return createSyntheticCommit(fixtureRoot, baseRef);
  } catch (err) {
    process.stderr.write(err.stdout || "");
    process.stderr.write(err.stderr || "");
    throw err;
  }
}

function snapshotCommandArgs(ref) {
  return [
    path.join(scriptDir, "snapshot-docs.mjs"),
    "v0.0.0",
    "--from-ref",
    ref,
    "--force",
    "--archive-root",
    snapshotArchiveRoot,
    "--metadata-path",
    snapshotMetadataPath,
  ];
}

function assertVersioningStatusUnchanged() {
  const current = run("git", ["status", "--short", "--", "public/docs-versions", "public/docs-metadata.json"], { encoding: "utf8" });
  if (current !== versioningStatusBefore) {
    throw new Error(`docs versioning test mutated tracked snapshot outputs\nbefore:\n${versioningStatusBefore}\nafter:\n${current}`);
  }
}

function dirtyDocsTemplateFixture() {
  const stubRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hasp-docs-git-stub-"));
  const archiveRoot = path.join(stubRoot, "docs-versions");
  const metadataPath = path.join(stubRoot, "docs-metadata.json");
  const gitLog = path.join(stubRoot, "git.log");
  const realGit = execFileSync("bash", ["-lc", "command -v git"], { encoding: "utf8" }).trim();
  const fakeGit = path.join(stubRoot, "git");
  fs.writeFileSync(fakeGit, [
    "#!/usr/bin/env bash",
    `printf '%s\\n' "$*" >>${JSON.stringify(gitLog)}`,
    'if [[ "$1" == "status" && "$2" == "--short" ]]; then',
    '  args=" $* "',
    '  if [[ "$args" == *"apps/web/src/docs.njk"* ]]; then',
    '    printf "%s\\n" " M apps/web/src/docs.njk"',
    "  fi",
    "  exit 0",
    "fi",
    'if [[ "$1" == "rev-parse" && "$2" == "HEAD" ]]; then',
    '  printf "%s\\n" "0000000000000000000000000000000000000000"',
    "  exit 0",
    "fi",
    `exec ${JSON.stringify(realGit)} "$@"`,
    "",
  ].join("\n"));
  fs.chmodSync(fakeGit, 0o755);

  try {
    run("node", [
      path.join(scriptDir, "snapshot-docs.mjs"),
      currentVersionId,
      "--force",
      "--archive-root",
      archiveRoot,
      "--metadata-path",
      metadataPath,
    ], {
      env: {
        ...process.env,
        PATH: `${stubRoot}:${process.env.PATH}`,
      },
    });
    const manifest = JSON.parse(fs.readFileSync(path.join(archiveRoot, currentVersionId, "manifest.json"), "utf8"));
    if (manifest.dirty !== true) {
      throw new Error("docs snapshot did not mark a dirty docs template input");
    }
    const log = fs.readFileSync(gitLog, "utf8");
    for (const expected of ["apps/web/src/docs.njk", "apps/web/src/_data/docs.js", "scripts/docs-versioning-inputs.txt"]) {
      if (!log.includes(expected)) {
        throw new Error(`docs snapshot dirty status did not include ${expected}`);
      }
    }
    assertVersioningStatusUnchanged();
  } finally {
    fs.rmSync(stubRoot, { recursive: true, force: true });
  }
}

function expectSnapshotFromRefFails(ref, pwnedPath = "") {
  try {
    run("node", snapshotCommandArgs(ref), {
      env: {
        ...process.env,
        HASP_DOCS_SNAPSHOT_SKIP_CHECK: "1",
      },
    });
    throw new Error(`expected docs snapshot from ${ref} to fail`);
  } catch (err) {
    if (err.message.startsWith("expected docs snapshot")) {
      throw err;
    }
  }
  assertVersioningStatusUnchanged();
  if (pwnedPath && fs.existsSync(pwnedPath)) {
    throw new Error(`hostile docs metadata executed code: ${pwnedPath}`);
  }
}

function expectSnapshotFromRefPass(ref) {
  try {
    run("node", snapshotCommandArgs(ref), {
      env: {
        ...process.env,
        HASP_DOCS_SNAPSHOT_SKIP_CHECK: "1",
      },
    });
  } catch (err) {
    process.stderr.write(err.stdout || "");
    process.stderr.write(err.stderr || "");
    throw err;
  }
  assertVersioningStatusUnchanged();
}

function writeDocsCatalog(fixtureRoot, catalog) {
  fs.writeFileSync(
    path.join(fixtureRoot, "apps/web/src/_data/docs-specs.json"),
    `${JSON.stringify(catalog, null, 2)}\n`,
  );
}

function docsCatalogFixture(worktree, baseRef, catalog) {
  const ref = hostileRef(worktree, baseRef, (fixtureRoot) => {
    writeDocsCatalog(fixtureRoot, catalog);
  });
  expectSnapshotFromRefFails(ref);
}

function docsCatalogPassFixture(worktree, baseRef, catalog) {
  const ref = hostileRef(worktree, baseRef, (fixtureRoot) => {
    writeDocsCatalog(fixtureRoot, catalog);
  });
  expectSnapshotFromRefPass(ref);
}

function invalidJsonFixture(worktree, baseRef) {
  const ref = hostileRef(worktree, baseRef, (fixtureRoot) => {
    fs.writeFileSync(path.join(fixtureRoot, "apps/web/src/_data/docs-specs.json"), "{ docsUpdated: ");
  });
  expectSnapshotFromRefFails(ref);
}

function legacySingleQuotedReorderedFixture(worktree, baseRef) {
  const ref = hostileRef(worktree, baseRef, (fixtureRoot) => {
    fs.rmSync(path.join(fixtureRoot, "apps/web/src/_data/docs-specs.json"), { force: true });
    fs.writeFileSync(path.join(fixtureRoot, "apps/web/src/_data/docs.js"), [
      "const specs = [",
      "  {",
      "    title: 'Overview',",
      "    source: 'public/README.md',",
      "    description: 'A legacy catalog can be formatted normally.',",
      "    order: 1,",
      "    section: 'Start',",
      "    slug: 'overview',",
      "  },",
      "];",
      "export default { docs: [], updated: 'April 2026' };",
      "",
    ].join("\n"));
  });
  expectSnapshotFromRefPass(ref);
}

function missingJsonIgnoresHostileJsFixture(worktree, baseRef, pwnedPath) {
  const ref = hostileRef(worktree, baseRef, (fixtureRoot) => {
    fs.rmSync(path.join(fixtureRoot, "apps/web/src/_data/docs-specs.json"), { force: true });
    fs.writeFileSync(path.join(fixtureRoot, "apps/web/src/_data/docs.js"), [
      "const specs = [",
      `  ${JSON.stringify(oneDocSpec).replace(/"([^"]+)":/g, "$1:")},`,
      "];",
      'export default { updated: "April 2026", docs: [] };',
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(fixtureRoot, "apps/web/src/_data/docs-specs.js"), [
      `export const docsUpdated = "April 2026";`,
      `export const docSpecs = this.constructor.constructor(${JSON.stringify(`return process.getBuiltinModule('node:fs').writeFileSync(${JSON.stringify(pwnedPath)}, 'pwned')`)})();`,
      "",
    ].join("\n"));
  });
  expectSnapshotFromRefPass(ref);
  if (fs.existsSync(pwnedPath)) {
    throw new Error(`hostile docs metadata executed code: ${pwnedPath}`);
  }
}

function historicalRewriteFixture(worktree, baseRef) {
  const ref = hostileRef(worktree, baseRef, (fixtureRoot) => {
    writeDocsCatalog(fixtureRoot, {
      docsUpdated: "April 2026",
      docSpecs: [oneDocSpec, installDocSpec],
    });
    fs.writeFileSync(path.join(fixtureRoot, "public/README.md"), [
      "# Historical rewrite fixture",
      "- the future native macOS app surface under `apps/macos/`",
      "This repo does not contain the marketing site, the future cloud control plane,",
      "or the internal product/research docs used in the source-of-truth repo.",
      "- Add the setup password formal-assurance lane: finite TLA+ model checking,",
      "  generated Go conformance traces, abstract fuzz/property coverage, targeted",
      "  mutation evidence, and the published assurance artifact for CONF-SETUP-002.",
      "- Document adjacent assurance boundaries for keychain/convenience unlock,",
      "  daemon/session behavior, import/binding side effects, and whole-program",
      "  release gates without widening the setup password proof.",
      "- Update public docs and the web docs surface with repo-target guidance,",
      "- Reconcile the competitive baseline against shipped v0.1.31 behavior:",
      "  private details in `docs/competition/v1-v4-market-landscape.md`.",
      "web.dev macos.debug deploy.production apps/web apps/web/.env.example",
      "apps/macos/Config/Secrets.generated.xcconfig apps/macos/Config/Other.generated.xcconfig apps/macos/Config/Secrets.example.xcconfig apps/macos",
      "native Swift macOS app native macOS app macOS app",
      "Debug build config for the desktop app",
      "Debug build configuration for the desktop app",
      "Local web app development",
      "Server-side API token for the web worker",
      "",
    ].join("\n"));
    fs.mkdirSync(path.join(fixtureRoot, "public/docs"), { recursive: true });
    fs.writeFileSync(path.join(fixtureRoot, "public/docs/install-and-release.md"), [
      "# Install and Release",
      "before",
      "```bash",
      "pnpm -C apps/server docs:snapshot",
      "```",
      "after",
      "",
    ].join("\n"));
  });
  expectSnapshotFromRefPass(ref);
  const readme = fs.readFileSync(path.join(snapshotArchiveRoot, "v0.0.0/public/README.md"), "utf8");
  for (const expected of [
    "This public repo is limited to the server/CLI release surface.",
    "- Harden setup password handling around empty input",
    "- Update public docs and the docs site with repo-target guidance,",
    "server.dev build.config release.sign apps/server apps/server/.env.example",
    "apps/server/Config/Secrets.generated.xcconfig apps/server/Config/Other.generated.xcconfig apps/server/Config/Secrets.example.xcconfig apps/server",
    "desktop app desktop app desktop app",
    "Build config for the server app",
    "Build configuration for the server app",
    "Local server development",
    "Server-side API token for local broker development",
  ]) {
    if (!readme.includes(expected)) {
      throw new Error(`historical docs rewrite did not include expected output: ${expected}`);
    }
  }
  for (const forbidden of [
    "future native macOS app",
    "future cloud control plane",
    "formal-assurance",
    "keychain/convenience unlock",
    "docs/competition",
    "web.dev",
    "apps/web",
    "apps/macos",
    "native Swift macOS app",
    "Local web app development",
    "web worker",
  ]) {
    if (readme.includes(forbidden)) {
      throw new Error(`historical docs rewrite left private text: ${forbidden}`);
    }
  }
  const installDoc = fs.readFileSync(path.join(snapshotArchiveRoot, "v0.0.0/public/docs/install-and-release.md"), "utf8");
  if (installDoc.includes("pnpm -C apps/server")) {
    throw new Error("historical install-and-release rewrite left server snapshot command");
  }
  if (!installDoc.includes("before") || !installDoc.includes("after")) {
    throw new Error("historical install-and-release rewrite removed surrounding content");
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(snapshotArchiveRoot, "v0.0.0/manifest.json"), "utf8"));
  if (manifest.sourceArchiveTransform !== "public-docs-sanitized-v1") {
    throw new Error("historical manifest did not record the public docs sanitizer transform");
  }
  if (!manifest.sourceFilesSanitized.includes("public/README.md") || !manifest.sourceFilesSanitized.includes("public/docs/install-and-release.md")) {
    throw new Error("historical manifest did not list sanitized source files");
  }
  if (manifest.sourceFileOriginalSha256["public/README.md"] === manifest.sourceFileSanitizedSha256["public/README.md"]) {
    throw new Error("historical manifest did not distinguish original and sanitized README hashes");
  }
  if (manifest.sourceFileSha256["public/README.md"] !== manifest.sourceFileSanitizedSha256["public/README.md"]) {
    throw new Error("historical manifest written hash must match sanitized README hash");
  }
}

dirtyDocsTemplateFixture();

const pwnedPath = path.join(os.tmpdir(), `hasp-docs-pwned-${process.pid}`);
fs.rmSync(pwnedPath, { force: true });
try {
  withHostileWorktree((worktree, baseRef) => {
    docsCatalogPassFixture(worktree, baseRef, docsCatalog());
    invalidJsonFixture(worktree, baseRef);
    docsCatalogFixture(worktree, baseRef, docsCatalog({ docsUpdated: "" }));
    docsCatalogFixture(worktree, baseRef, docsCatalog({ docSpecs: "bad" }));
    docsCatalogFixture(worktree, baseRef, docsCatalog({
      docSpecs: [{ ...oneDocSpec, source: "../../../VERSION", slug: "escape", title: "Traversal" }],
    }));
    docsCatalogFixture(worktree, baseRef, docsCatalog({
      docSpecs: [{ ...oneDocSpec, slug: "../escape", title: "Traversal" }],
    }));
    docsCatalogFixture(worktree, baseRef, docsCatalog({
      docSpecs: [{ ...oneDocSpec, order: "1" }],
    }));
    legacySingleQuotedReorderedFixture(worktree, baseRef);
    missingJsonIgnoresHostileJsFixture(worktree, baseRef, pwnedPath);
    historicalRewriteFixture(worktree, baseRef);
  });
} finally {
  fs.rmSync(snapshotOutputRoot, { recursive: true, force: true });
  fs.rmSync(pwnedPath, { force: true });
}

runVisible("node", [path.join(scriptDir, "check-docs-versioning.mjs")]);
console.log("Docs versioning negative checks behave correctly.");
