# HASP Downloads

This app is the subdomain-only download landing surface for HASP.

It is intended for a non-apex hostname such as:

- `download.gethasp.com`

It does not replace or launch the apex marketing site.

## What it does

- fetches the latest published release metadata from `downloads.gethasp.com`
- rejects that metadata unless it matches the deploy-time `HASP_RELEASE_METADATA_SHA256` pin
- rejects stale metadata whose signed `release_sequence` is below the
  deploy-time `HASP_RELEASE_MIN_SEQUENCE`
- proxies the signed metadata and release public key that the install helper
  verifies before choosing an artifact
- renders direct download links for the current release
- exposes a small JSON API at `/api/release`
- redirects `/download/<os>/<arch>` to the matching artifact

The worker does not perform OpenPGP verification. Installer and release tooling
verify signed artifacts; this landing surface fail-closes on an exact metadata
digest selected at deploy time and serves the canonical signatures and public
key hosted with the release.

## Deploy

Tagged releases compute both values from the generated `release-metadata.json`,
rotate the Worker secrets, deploy the Worker, and smoke `/api/release`.
Hosted release deploys require `CLOUDFLARE_ACCOUNT_ID` and a durable
least-privilege `CLOUDFLARE_API_TOKEN` in the public repo Actions secrets.
Do not use a local Wrangler OAuth access token as CI configuration.
Manual deploys should use the same release metadata file.

```bash
wrangler secret put HASP_RELEASE_METADATA_SHA256 --config apps/web/downloads/wrangler.toml
wrangler secret put HASP_RELEASE_MIN_SEQUENCE --config apps/web/downloads/wrangler.toml
wrangler secret put HASP_RELEASE_METADATA_URL --config apps/web/downloads/wrangler.toml
wrangler deploy --config apps/web/downloads/wrangler.toml
```

## Verify locally

```bash
wrangler deploy --dry-run --config apps/web/downloads/wrangler.toml
```
