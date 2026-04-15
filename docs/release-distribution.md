# Release distribution

This page covers the public release path for the curated HASP repository.

## What ships

Public releases ship:

- versioned GitHub release assets
- versioned hosted artifacts backed by Cloudflare R2
- `SHA256SUMS`
- `SHA256SUMS.asc`
- detached signatures for the tarball and packaged binary
- a public verification key
- a Homebrew formula pinned to the published artifact bytes

## Stable download contract

The hosted release layout is:

```text
https://downloads.gethasp.com/hasp/releases/<tag>/
```

Each release directory should include:

- `hasp_<version>_<os>_<arch>.tar.gz`
- `SHA256SUMS`
- `SHA256SUMS.asc`
- `hasp-release-public-key.asc`
- `hasp_<version>_<os>_<arch>.tar.gz.asc`
- `hasp_<version>_<os>_<arch>_bin.asc`
- `Formula/hasp.rb`

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

It should point at the hosted artifact URL and the published SHA256.

## Operator note

The local packaged lifecycle and the hosted publication flow are separate concerns:

- local scripts verify, install, upgrade, and uninstall
- the publication flow uploads the signed bytes and keeps the hosted URLs stable

That separation is intentional. The local trust path must still work if the hosted publication layer is unavailable.
