#!/usr/bin/env node
import assert from "node:assert/strict";
import worker, { normalizeReleaseMetadata, sha256Hex } from "./worker.js";
import { RELEASE_TARGETS } from "./release-targets.generated.js";

const releaseVersion = "0.1.39";
const canonicalBase = `https://downloads.gethasp.com/hasp/releases/v${releaseVersion}`;
const sha256 = "a".repeat(64);
const releaseSequence = 1039;
const issuedAt = "2026-04-30T00:00:00Z";
const expiresAt = "2999-01-01T00:00:00Z";

function artifact(os, arch, overrides = {}) {
  const name = `hasp_${releaseVersion}_${os}_${arch}`;
  return {
    name,
    version: releaseVersion,
    os,
    arch,
    tarball: `${name}.tar.gz`,
    url: `${canonicalBase}/${name}.tar.gz`,
    sha256,
    ...overrides,
  };
}

function metadata(overrides = {}) {
  return {
    version: releaseVersion,
    release_sequence: releaseSequence,
    issued_at: issuedAt,
    expires_at: expiresAt,
    tag_base_url: canonicalBase,
    artifacts: RELEASE_TARGETS.map(([os, arch]) => artifact(os, arch)),
    ...overrides,
  };
}

let currentMetadataText = "";
const currentMetadataSignatureText = "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n";
const currentPublicKeyText = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n";

function installFetchFixture(payload) {
  currentMetadataText = JSON.stringify(payload);
  globalThis.fetch = async (url) => {
    if (url.endsWith("release-metadata.json")) {
      return new Response(currentMetadataText, { status: 200 });
    }
    if (url.endsWith("release-metadata.json.asc")) {
      return new Response(currentMetadataSignatureText, { status: 200 });
    }
    if (url.endsWith("hasp-release-public-key.asc")) {
      return new Response(currentPublicKeyText, { status: 200 });
    }
    assert.equal(url, "https://downloads.gethasp.com/hasp/releases/latest/release-metadata.json");
    return new Response("missing", { status: 404 });
  };
}

async function fetchPath(pathname) {
  return worker.fetch(new Request(`https://download.gethasp.com${pathname}`), {
    HASP_RELEASE_METADATA_SHA256: await sha256Hex(currentMetadataText),
    HASP_RELEASE_MIN_SEQUENCE: String(releaseSequence),
    HASP_RELEASE_METADATA_NOW: "2026-05-01T00:00:00Z",
  });
}

async function fetchPathWithEnv(pathname, env) {
  return worker.fetch(new Request(`https://download.gethasp.com${pathname}`), {
    HASP_RELEASE_METADATA_SHA256: await sha256Hex(currentMetadataText),
    HASP_RELEASE_MIN_SEQUENCE: String(releaseSequence),
    HASP_RELEASE_METADATA_NOW: "2026-05-01T00:00:00Z",
    ...env,
  });
}

async function fetchPathWithDigest(pathname, digest) {
  return worker.fetch(new Request(`https://download.gethasp.com${pathname}`), {
    HASP_RELEASE_METADATA_SHA256: digest,
    HASP_RELEASE_MIN_SEQUENCE: String(releaseSequence),
    HASP_RELEASE_METADATA_NOW: "2026-05-01T00:00:00Z",
  });
}

const normalized = normalizeReleaseMetadata(metadata({
  artifacts: RELEASE_TARGETS.map(([os, arch]) => artifact(os, arch, { url: undefined })),
}));
assert.equal(normalized.tag_base_url, canonicalBase);
assert.equal(normalized.artifacts.find((item) => item.os === "linux" && item.arch === "amd64").url, `${canonicalBase}/hasp_${releaseVersion}_linux_amd64.tar.gz`);

installFetchFixture(metadata());
const releaseResponse = await fetchPath("/api/release");
assert.equal(releaseResponse.status, 200);
const release = await releaseResponse.json();
assert.equal(release.release_sequence, releaseSequence);
assert.equal(release.checksumsUrl, `${canonicalBase}/SHA256SUMS`);
assert.equal(release.metadataSignatureUrl, "/api/release-metadata.asc");
assert.equal(release.artifacts.find((item) => item.os === "linux" && item.arch === "amd64").url, `${canonicalBase}/hasp_${releaseVersion}_linux_amd64.tar.gz`);

const metadataResponse = await fetchPath("/api/release-metadata");
assert.equal(await metadataResponse.text(), currentMetadataText);
assert.match(metadataResponse.headers.get("content-type"), /application\/json/);

const metadataSignatureResponse = await fetchPath("/api/release-metadata.asc");
assert.equal(await metadataSignatureResponse.text(), currentMetadataSignatureText);
assert.match(metadataSignatureResponse.headers.get("content-type"), /application\/pgp-signature/);

const publicKeyResponse = await fetchPath("/api/release-public-key.asc");
assert.equal(await publicKeyResponse.text(), currentPublicKeyText);
assert.match(publicKeyResponse.headers.get("content-type"), /application\/pgp-keys/);

const versionedMetadataResponse = await fetchPathWithEnv("/api/release", {
  HASP_RELEASE_METADATA_URL: `${canonicalBase}/release-metadata.json`,
});
assert.equal(versionedMetadataResponse.status, 200);
const versionedFetchResponse = await fetchPathWithEnv("/api/release", {
  HASP_RELEASE_METADATA_URL: "https://evil.example/hasp/releases/v0.1.39/release-metadata.json",
});
assert.equal(versionedFetchResponse.status, 502);

for (const [os, arch] of RELEASE_TARGETS) {
  const redirectResponse = await fetchPath(`/download/${os}/${arch}`);
  assert.equal(redirectResponse.status, 302);
  assert.equal(redirectResponse.headers.get("location"), `${canonicalBase}/hasp_${releaseVersion}_${os}_${arch}.tar.gz`);
}

assert.equal((await fetchPathWithDigest("/api/release", "")).status, 502);
assert.equal((await fetchPathWithDigest("/api/release", "b".repeat(64))).status, 502);

assert.throws(() => normalizeReleaseMetadata(metadata({ version: "0.1.39-rc.1" })), /invalid release version/);

installFetchFixture(metadata({
  tag_base_url: "https://evil.example/hasp/releases/v0.1.39",
}));
assert.equal((await fetchPath("/api/release")).status, 502);

installFetchFixture(metadata({ release_sequence: releaseSequence - 1 }));
assert.equal((await fetchPath("/api/release")).status, 502);

installFetchFixture(metadata({ expires_at: "2026-04-01T00:00:00Z" }));
assert.equal((await fetchPath("/api/release")).status, 502);

installFetchFixture(metadata({
  artifacts: RELEASE_TARGETS.map(([os, arch]) => artifact(os, arch, os === "linux" && arch === "amd64"
    ? { url: "https://evil.example/hasp.tar.gz" }
    : {})),
}));
assert.equal((await fetchPath("/download/linux/amd64")).status, 502);

console.log("download worker release metadata checks passed");
