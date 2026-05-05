# Releasing HASP

This file covers the public release flow for `gethasp/hasp`.

## Who cuts releases

Maintainers cut release tags and publish releases.

Contributors should not push release tags.

## What triggers a release

Push a `v*` tag on this repository.

Example:

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

## What must be ready first

1. `main` contains the public code and docs you want to ship
2. the release workflow in `.github/workflows/release.yml` is current
3. `CHANGELOG.md` contains a `## [vX.Y.Z]` section for the tag
4. every changed command, public behavior, generated reference, install path,
   release contract, docs page, and web surface has been updated in the same
   change. Do not defer docs or reference updates to a follow-up release.
5. `/docs/` and `/docs/vX.Y.Z/` have both been regenerated from the exact
   source being tagged.
6. `make release-gate` passes. This runs the maintainer verification suite,
   integration-tagged tests, conformance, release smoke, and the Go coverage
   gate with `HASP_COVERAGE_TARGET=100`.
   The Go test wrapper defaults package parallelism to `-p 1` so daemon
   lifecycle tests stay process-bounded during release verification; only raise
   `HASP_GO_TEST_PACKAGE_PARALLELISM` for explicitly process-safe lanes.
7. the release-smoke matrix passes on every supported target. The workflow
   builds the signed multi-target release set once, then each smoke job tests
   the packaged tarball for its native target with
   `scripts/release-smoke.sh --release-dir ...`. Smoke-only jobs use
   `scripts/bootstrap_go_tools.sh release-smoke`; the full `verify` bootstrap
   remains reserved for release-gate and build jobs.
8. the published live smoke passes. The release workflow checks the hosted
   download metadata, runs `https://gethasp.com/install.sh` into a temporary
   install directory, and installs from the published Homebrew tap before the
   GitHub Release is created.
9. the public release secrets are available:
   - base64-encoded GPG signing key material
   - `HASP_RELEASE_GPG_PASSPHRASE` if that key is passphrase-protected
   - `HASP_UPGRADE_TRUST_ROOTS_HEX` and `HASP_UPGRADE_SIGNING_KEY_B64`
   - Cloudflare R2 credentials, if artifact mirroring is enabled

## Documentation and reference rule

Docs, generated references, web metadata, release notes, and tests are part of
the release artifact. If code changes any public behavior, update the matching
public docs and generated references before the tag. If docs change without
code, still update the versioned docs snapshot and run the docs checks.

Before every tag:

```bash
make build
./bin/hasp docs markdown --out public/docs/cli-reference.md
pnpm -C apps/web docs:snapshot -- vX.Y.Z --force
make release-gate
```

The public repository starts at v1.0.0. Do not add pre-v1 docs snapshots,
release notes, or tags to the public repository. Historical development notes
belong only in the canonical source repository.

## What the release publishes

- GitHub Release assets for the supported platform matrix
- `SHA256SUMS`
- `SHA256SUMS.asc`
- detached signatures for the tarballs
- detached signatures for the packaged `bin/hasp` payloads
- packaged SBOM, provenance, code-signing status, and reproducible-build
  status files inside each tarball
- `hasp-release-public-key.asc`
- optional mirrored assets on the Cloudflare R2 release host

## Publication model

The public release workflow builds and packages from this public repo, then
publishes immutable release assets.

The release workflow intentionally separates expensive validation from
publication. `build-public-release` runs the full public `make release-gate`
before exposing signing secrets, produces one signed release set, and uploads
that set as the `public-release` artifact. The release-smoke matrix downloads
that artifact and validates the exact bytes that later go to R2, Homebrew, and
GitHub Releases. Homebrew installation is intentionally verified only after R2
publication, so generated formulas never point at unpublished artifact URLs.

If the release signing key is passphrase-protected, the workflow supplies the
passphrase through `HASP_RELEASE_GPG_PASSPHRASE` and the signing scripts use
GPG loopback mode. Local maintainers can use the same path with either:

- `HASP_RELEASE_GPG_PASSPHRASE`
- `HASP_RELEASE_GPG_PASSPHRASE_FILE`

If the R2 mirror is configured, it mirrors the same release bytes to the stable
download host. The release host must never point at mutable or rebuilt bytes.

## Contributor note

Pull requests are reviewed here.

If maintainers accept a public PR, they replay the change through the canonical
source tree and sync the result back here before merging or tagging.
