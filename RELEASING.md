# Releasing HASP

This file covers the public release flow for `gethasp/hasp`.

## Who cuts releases

Maintainers cut release tags and publish releases.

Contributors should not push release tags.

## What triggers a release

Push a `v*` tag on this repository.

Example:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

## What must be ready first

1. `main` contains the public code and docs you want to ship
2. the release workflow in `.github/workflows/release.yml` is current
3. `CHANGELOG.md` contains a `## [vX.Y.Z]` section for the tag
4. the public release secrets are available:
   - base64-encoded GPG signing key material
   - Cloudflare R2 credentials, if artifact mirroring is enabled

## What the release publishes

- GitHub Release assets for the supported platform matrix
- `SHA256SUMS`
- `SHA256SUMS.asc`
- detached signatures for the tarballs
- detached signatures for the packaged `bin/hasp` payloads
- `hasp-release-public-key.asc`
- optional mirrored assets on the Cloudflare R2 release host

## Publication model

The public release workflow builds and packages from this public repo, then
publishes immutable release assets.

If the R2 mirror is configured, it mirrors the same release bytes to the stable
download host. The release host must never point at mutable or rebuilt bytes.

## Contributor note

Pull requests are reviewed here.

If maintainers accept a public PR, they replay the change through the canonical
source tree and sync the result back here before merging or tagging.
