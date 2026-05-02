import { RELEASE_TARGETS } from "./release-targets.generated.js";

const RELEASE_METADATA_URL =
  "https://downloads.gethasp.com/hasp/releases/latest/release-metadata.json";
const RELEASE_METADATA_SIGNATURE_URL =
  "https://downloads.gethasp.com/hasp/releases/latest/release-metadata.json.asc";
const RELEASE_PUBLIC_KEY_URL =
  "https://downloads.gethasp.com/hasp/releases/latest/hasp-release-public-key.asc";
const RELEASE_BASE_URL = "https://downloads.gethasp.com/hasp/releases";
const GITHUB_RELEASES_URL = "https://github.com/gethasp/hasp/releases";
const HOMEBREW_TAP_URL = "https://github.com/gethasp/homebrew-tap";
const VERSION_PATTERN = /^[0-9]+[.][0-9]+[.][0-9]+$/;
const SHA256_PATTERN = /^[0-9a-fA-F]{64}$/;
const RELEASE_TARGET_SET = new Set(RELEASE_TARGETS.map(([os, arch]) => `${os}/${arch}`));

export default {
  async fetch(request, env = {}) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return textResponse("ok\n", 200);
    }

    if (url.pathname === "/robots.txt") {
      return textResponse("User-agent: *\nAllow: /\n", 200, "text/plain; charset=utf-8");
    }

    let release;
    try {
      release = await fetchReleaseBundle(env);
    } catch (error) {
      if (url.pathname.startsWith("/api/")) {
        return Response.json(
          { error: "release metadata unavailable", detail: String(error) },
          { status: 502 },
        );
      }
      return htmlResponse(renderErrorPage(String(error)), 502);
    }

    if (url.pathname === "/api/release-metadata") {
      return textResponse(release.metadataText, 200, "application/json; charset=utf-8");
    }

    if (url.pathname === "/api/release-metadata.asc") {
      return textResponse(release.metadataSignatureText, 200, "application/pgp-signature; charset=utf-8");
    }

    if (url.pathname === "/api/release-public-key.asc") {
      return textResponse(release.publicKeyText, 200, "application/pgp-keys; charset=utf-8");
    }

    if (url.pathname === "/api/release") {
      return Response.json(buildReleaseView(release.metadata), {
        headers: {
          "cache-control": "public, max-age=60",
        },
      });
    }

    if (url.pathname.startsWith("/download/")) {
      return redirectToArtifact(url, release.metadata);
    }

    return htmlResponse(renderPage(release.metadata), 200);
  },
};

async function fetchText(url, label, headers = {}) {
  const response = await fetch(url, {
    headers,
  });
  if (!response.ok) {
    throw new Error(`${label} fetch failed with status ${response.status}`);
  }
  return response.text();
}

async function fetchReleaseBundle(env = {}) {
  const metadataURL = normalizeReleaseMetadataURL(env.HASP_RELEASE_METADATA_URL || RELEASE_METADATA_URL);
  const metadataSignatureURL = `${metadataURL}.asc`;
  const publicKeyURL = `${metadataURL.slice(0, metadataURL.lastIndexOf("/") + 1)}hasp-release-public-key.asc`;
  const metadataText = await fetchText(metadataURL, "metadata", { accept: "application/json" });
  const metadataSignatureText = await fetchText(metadataSignatureURL, "metadata signature");
  const publicKeyText = await fetchText(publicKeyURL, "release public key");
  await verifyPinnedMetadataDigest(metadataText, env);
  const metadata = normalizeReleaseMetadata(JSON.parse(metadataText), {
    minReleaseSequence: env.HASP_RELEASE_MIN_SEQUENCE,
    now: env.HASP_RELEASE_METADATA_NOW,
  });
  return { metadata, metadataText, metadataSignatureText, publicKeyText };
}

function normalizeReleaseMetadataURL(value) {
  let url;
  try {
    url = new URL(String(value || ""));
  } catch {
    throw new Error("release metadata URL is invalid");
  }
  if (url.origin !== "https://downloads.gethasp.com") {
    throw new Error("release metadata URL is outside the canonical release host");
  }
  if (!/^\/hasp\/releases\/(?:latest|v[0-9]+[.][0-9]+[.][0-9]+)\/release-metadata[.]json$/.test(url.pathname)) {
    throw new Error("release metadata URL is outside the canonical release path");
  }
  url.search = "";
  url.hash = "";
  return url.toString();
}

async function verifyPinnedMetadataDigest(metadataText, env = {}) {
  const expected = normalizeHexDigest(env.HASP_RELEASE_METADATA_SHA256 || "");
  if (!expected) {
    throw new Error("release metadata digest pin is not configured");
  }
  const actual = await sha256Hex(metadataText);
  if (actual !== expected) {
    throw new Error("release metadata digest did not match the pinned value");
  }
}

function normalizeHexDigest(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) {
    return "";
  }
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error("release metadata digest pin is invalid");
  }
  return normalized;
}

async function sha256Hex(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function buildReleaseView(metadata) {
  const version = metadata.version;
  const tag = `v${version}`;
  const tagBase = canonicalTagBase(version);

  return {
    version,
    release_sequence: metadata.release_sequence,
    tag,
    githubReleaseUrl: `${GITHUB_RELEASES_URL}/tag/${tag}`,
    checksumsUrl: `${tagBase}/SHA256SUMS`,
    checksumsSignatureUrl: `${tagBase}/SHA256SUMS.asc`,
    publicKeyUrl: `${tagBase}/hasp-release-public-key.asc`,
    metadataUrl: "/api/release-metadata",
    metadataSignatureUrl: "/api/release-metadata.asc",
    formulaUrl: `${HOMEBREW_TAP_URL}/blob/main/Formula/hasp.rb`,
    artifacts: metadata.artifacts.map((artifact) => releaseArtifactView(artifact, version)),
  };
}

function normalizeReleaseMetadata(metadata, options = {}) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new Error("metadata response was not an object");
  }
  const version = String(metadata.version || "").trim();
  if (!VERSION_PATTERN.test(version)) {
    throw new Error("metadata response included an invalid release version");
  }
  const expectedSequence = versionSequence(version);
  const releaseSequence = metadata.release_sequence;
  if (!Number.isInteger(releaseSequence) || releaseSequence < 0) {
    throw new Error("metadata response included an invalid release sequence");
  }
  if (releaseSequence !== expectedSequence) {
    throw new Error("metadata release sequence did not match the release version");
  }
  const minReleaseSequence = normalizeReleaseSequence(options.minReleaseSequence);
  if (releaseSequence < minReleaseSequence) {
    throw new Error("metadata release sequence is older than the trusted worker sequence");
  }
  const issuedAt = parseReleaseTimestamp(metadata.issued_at, "issued_at");
  const expiresAt = parseReleaseTimestamp(metadata.expires_at, "expires_at");
  const now = options.now ? parseReleaseTimestamp(options.now, "now") : new Date();
  if (issuedAt.getTime() > expiresAt.getTime()) {
    throw new Error("metadata freshness window is invalid");
  }
  if (now.getTime() >= expiresAt.getTime()) {
    throw new Error("metadata response has expired");
  }
  const tagBase = canonicalTagBase(version);
  if (metadata.tag_base_url && String(metadata.tag_base_url).replace(/\/+$/, "") !== tagBase) {
    throw new Error("metadata tag_base_url is outside the canonical release host");
  }
  if (!Array.isArray(metadata.artifacts) || metadata.artifacts.length === 0) {
    throw new Error("metadata response did not include artifacts");
  }

  const artifacts = metadata.artifacts.map((artifact) => normalizeArtifact(artifact, version));
  const seenTargets = new Set();
  for (const artifact of artifacts) {
    const target = `${artifact.os}/${artifact.arch}`;
    if (seenTargets.has(target)) {
      throw new Error(`metadata includes duplicate artifact target: ${target}`);
    }
    seenTargets.add(target);
  }
  for (const [os, arch] of RELEASE_TARGETS) {
    const target = `${os}/${arch}`;
    if (!seenTargets.has(target)) {
      throw new Error(`metadata is missing artifact target: ${target}`);
    }
  }

  return {
    version,
    release_sequence: releaseSequence,
    issued_at: issuedAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    tag_base_url: tagBase,
    artifacts: artifacts.sort((left, right) => targetSortKey(left).localeCompare(targetSortKey(right))),
  };
}

function versionSequence(version) {
  const match = /^([0-9]+)[.]([0-9]+)[.]([0-9]+)$/.exec(version);
  if (!match) {
    throw new Error("release version cannot be converted to a sequence");
  }
  const [, major, minor, patch] = match;
  return Number(major) * 1_000_000 + Number(minor) * 1_000 + Number(patch);
}

function normalizeReleaseSequence(value) {
  if (value === undefined || value === null || value === "") {
    return 0;
  }
  const sequence = Number(value);
  if (!Number.isInteger(sequence) || sequence < 0) {
    throw new Error("trusted release sequence is invalid");
  }
  return sequence;
}

function parseReleaseTimestamp(value, label) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`metadata ${label} is missing`);
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`metadata ${label} is invalid`);
  }
  return new Date(timestamp);
}

function normalizeArtifact(artifact, version) {
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)) {
    throw new Error("metadata includes an invalid artifact");
  }
  const os = String(artifact.os || "").trim();
  const arch = String(artifact.arch || "").trim();
  const target = `${os}/${arch}`;
  if (!RELEASE_TARGET_SET.has(target)) {
    throw new Error(`metadata includes unsupported artifact target: ${target}`);
  }
  const name = `hasp_${version}_${os}_${arch}`;
  const tarball = `${name}.tar.gz`;
  const url = canonicalArtifactURL(version, tarball);
  if (artifact.name !== name) {
    throw new Error(`metadata artifact name mismatch for ${target}`);
  }
  if (artifact.tarball !== tarball) {
    throw new Error(`metadata artifact tarball mismatch for ${target}`);
  }
  if (artifact.url && String(artifact.url) !== url) {
    throw new Error(`metadata artifact URL is outside the canonical release host for ${target}`);
  }
  const sha256 = String(artifact.sha256 || "").trim();
  if (!SHA256_PATTERN.test(sha256)) {
    throw new Error(`metadata artifact sha256 is invalid for ${target}`);
  }
  return {
    name,
    version,
    os,
    arch,
    tarball,
    url,
    sha256: sha256.toLowerCase(),
  };
}

function releaseArtifactView(artifact, version) {
  return {
    ...artifact,
    url: canonicalArtifactURL(version, artifact.tarball),
    label: artifactLabel(artifact),
  };
}

function canonicalTagBase(version) {
  return `${RELEASE_BASE_URL}/v${version}`;
}

function canonicalArtifactURL(version, tarball) {
  return `${canonicalTagBase(version)}/${tarball}`;
}

function targetSortKey(artifact) {
  return `${artifact.os}/${artifact.arch}`;
}

function artifactLabel(artifact) {
  const os = artifact.os === "darwin" ? "macOS" : artifact.os === "linux" ? "Linux" : artifact.os;
  const arch =
    artifact.arch === "arm64"
      ? "ARM64"
      : artifact.arch === "amd64"
        ? "x86_64"
        : artifact.arch;
  return `${os} ${arch}`;
}

function redirectToArtifact(url, metadata) {
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length !== 3) {
    return textResponse("usage: /download/<os>/<arch>\n", 400);
  }

  const [, os, arch] = parts;
  const artifact = metadata.artifacts.find((item) => item.os === os && item.arch === arch);
  if (!artifact) {
    return textResponse("artifact not found\n", 404);
  }

  return Response.redirect(canonicalArtifactURL(metadata.version, artifact.tarball), 302);
}

function renderPage(metadata) {
  const release = buildReleaseView(metadata);
  const artifactCards = release.artifacts
    .map(
      (artifact) => `
        <a class="card" href="${escapeHtml(artifact.url)}">
          <strong>${escapeHtml(artifact.label)}</strong>
          <span>${escapeHtml(artifact.name)}</span>
          <code>${escapeHtml(artifact.sha256)}</code>
        </a>
      `,
    )
    .join("");

  const curlInstall = `curl -LO ${release.artifacts[0].url}
curl -LO ${release.checksumsUrl}
curl -LO ${release.checksumsSignatureUrl}
curl -LO ${release.publicKeyUrl}`;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HASP Downloads</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f5f3ee;
        --card: #fffdf8;
        --text: #171717;
        --muted: #5f5a53;
        --border: #d9d0c3;
        --accent: #1f6f5f;
        --accent-ink: #f8fffd;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Palatino, serif;
        color: var(--text);
        background:
          radial-gradient(circle at top left, rgba(31, 111, 95, 0.09), transparent 28%),
          radial-gradient(circle at bottom right, rgba(176, 111, 56, 0.08), transparent 30%),
          var(--bg);
      }
      main {
        max-width: 1040px;
        margin: 0 auto;
        padding: 48px 20px 72px;
      }
      .eyebrow {
        font: 600 12px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--accent);
      }
      h1 {
        font-size: clamp(40px, 8vw, 76px);
        line-height: 0.95;
        margin: 12px 0 16px;
      }
      p {
        font-size: 18px;
        line-height: 1.6;
        color: var(--muted);
        max-width: 760px;
      }
      .hero-actions, .meta-links {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 28px;
      }
      .button, .link-chip, .card {
        border: 1px solid var(--border);
        background: var(--card);
        color: var(--text);
        text-decoration: none;
        border-radius: 18px;
      }
      .button {
        padding: 14px 18px;
        font-weight: 700;
      }
      .button.primary {
        background: var(--accent);
        border-color: var(--accent);
        color: var(--accent-ink);
      }
      .link-chip {
        padding: 10px 14px;
        font-size: 14px;
      }
      section {
        margin-top: 48px;
      }
      h2 {
        font-size: 26px;
        margin-bottom: 16px;
      }
      .grid {
        display: grid;
        gap: 14px;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      }
      .card {
        display: flex;
        flex-direction: column;
        gap: 12px;
        padding: 18px;
      }
      .card span {
        color: var(--muted);
        font-size: 14px;
      }
      code, pre {
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      }
      code {
        font-size: 12px;
        word-break: break-all;
      }
      pre {
        margin: 0;
        background: #171717;
        color: #f7f4ef;
        border-radius: 18px;
        padding: 18px;
        overflow: auto;
        font-size: 13px;
        line-height: 1.5;
      }
      footer {
        margin-top: 56px;
        font-size: 14px;
        color: var(--muted);
      }
    </style>
  </head>
  <body>
    <main>
      <div class="eyebrow">Subdomain-only release surface</div>
      <h1>HASP Downloads</h1>
      <p>
        Latest public release: <strong>${escapeHtml(release.tag)}</strong>. This page is a release
        landing surface only. It does not touch the apex site and it always points at the live,
        signed artifacts already hosted on <code>downloads.gethasp.com</code>.
      </p>

      <div class="hero-actions">
        <a class="button primary" href="${escapeHtml(release.githubReleaseUrl)}">View GitHub Release</a>
        <a class="button" href="/download/darwin/arm64">Download macOS ARM64</a>
        <a class="button" href="/download/linux/amd64">Download Linux x86_64</a>
      </div>

      <div class="meta-links">
        <a class="link-chip" href="${escapeHtml(release.checksumsUrl)}">SHA256SUMS</a>
        <a class="link-chip" href="${escapeHtml(release.checksumsSignatureUrl)}">SHA256SUMS.asc</a>
        <a class="link-chip" href="${escapeHtml(release.publicKeyUrl)}">Public Key</a>
        <a class="link-chip" href="${escapeHtml(release.formulaUrl)}">Homebrew Formula</a>
        <a class="link-chip" href="/api/release">Release JSON</a>
      </div>

      <section>
        <h2>Release Assets</h2>
        <div class="grid">
          ${artifactCards}
        </div>
      </section>

      <section>
        <h2>Install</h2>
        <pre>${escapeHtml(curlInstall)}</pre>
      </section>

      <section>
        <h2>Homebrew</h2>
        <pre>brew tap gethasp/homebrew-tap
brew install hasp</pre>
      </section>

      <footer>
        Raw artifact host: <code>downloads.gethasp.com</code>.<br>
        Landing page host: <code>download.gethasp.com</code>.
      </footer>
    </main>
  </body>
</html>`;
}

function renderErrorPage(message) {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>HASP Downloads</title></head>
  <body style="font-family: ui-sans-serif, system-ui; padding: 48px;">
    <h1>HASP Downloads</h1>
    <p>Release metadata is temporarily unavailable.</p>
    <pre>${escapeHtml(message)}</pre>
  </body>
</html>`;
}

function htmlResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=60",
    },
  });
}

function textResponse(body, status, contentType = "text/plain; charset=utf-8") {
  return new Response(body, {
    status,
    headers: {
      "content-type": contentType,
      "cache-control": "public, max-age=60",
    },
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export {
  buildReleaseView,
  canonicalArtifactURL,
  sha256Hex,
  normalizeReleaseMetadata,
  redirectToArtifact,
  verifyPinnedMetadataDigest,
};
