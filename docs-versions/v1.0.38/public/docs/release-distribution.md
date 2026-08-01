# Release distribution

This page covers the public release path for the curated HASP repository.

## What ships

Public releases ship:

- versioned GitHub release assets
- optionally mirrored hosted artifacts backed by Cloudflare R2 when release
  mirror credentials are configured
- `SHA256SUMS`
- `SHA256SUMS.asc`
- detached signatures for the tarball and packaged binary
- packaged SBOM, provenance, code-signing status, and reproducible-build
  status files inside each tarball
- a public verification key
- a Homebrew formula pinned to the published artifact bytes

## Stable download contract

GitHub Releases are the canonical public release asset location.

When the [R2 mirror](https://download.gethasp.com/) is configured, the hosted release layout is `https://downloads.gethasp.com/hasp/releases/<tag>/`.

Each GitHub release and each mirrored release directory should include:

- `hasp_<version>_<os>_<arch>.tar.gz`
- `SHA256SUMS`
- `SHA256SUMS.asc`
- `hasp-release-public-key.asc`
- `hasp_<version>_<os>_<arch>.tar.gz.asc`
- `hasp_<version>_<os>_<arch>_bin.asc`
- `Formula/hasp.rb`

Each packaged tarball also contains:

- `sbom.spdx.json`
- `slsa-provenance.json`
- `CODE_SIGNING_STATUS.json`
- `REPRODUCIBLE_BUILD.json`

Those files are package metadata sidecars, not external attestations from a
remote CI system. On non-macOS hosts, code-signing status may report
`unsupported`; when the slower reproducible-build check is not enabled,
`REPRODUCIBLE_BUILD.json` may report `not_run`.

## Verify and install

```bash
scripts/hasp-verify-release.sh hasp_<version>_<os>_<arch>.tar.gz
scripts/hasp-install-release.sh --verify hasp_<version>_<os>_<arch>.tar.gz
```

The install helper verifies the signed checksum manifest, the tarball signature, and the packaged binary signature before it stages the install tree.

## Upgrade and uninstall

```bash
scripts/hasp-upgrade-release.sh --verify hasp_<version>_<os>_<arch>.tar.gz /path/to/install-dir
scripts/hasp-uninstall-release.sh /path/to/install-dir
```

The default uninstall path removes only the installed release tree.
It does not remove `HASP_HOME` or repo hooks unless the operator asks for that explicitly.

## Homebrew path

The Homebrew formula must consume the published artifact bytes, not rebuild from the repository source tree.

It should point at the canonical GitHub release asset URL unless the R2 mirror
has been verified for the same byte set.

## Docs before tag

Treat docs as part of the release payload. Before the tag is created, update the public docs for every command, package, install step, agent profile, error, or exposed behavior that changed.

Maintainers then publish the matching versioned docs from the canonical release
source. The release should not publish until `/docs/` and `/docs/vX.Y.Z/` match
the binary and package that are going out.

The public repository starts at v1.0.0. Keep pre-v1 development history,
snapshots, and release notes in the canonical source repository only.

## Operator note

The local packaged lifecycle and the hosted publication flow are separate concerns:

- local scripts verify, install, upgrade, and uninstall
- the publication flow uploads the signed bytes and may mirror the same bytes to
  hosted URLs

That separation is intentional. The local trust path must still work if the R2
hosted publication layer is unavailable.
