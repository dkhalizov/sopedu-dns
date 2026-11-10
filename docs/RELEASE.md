# Releasing

A release is a Git tag `vX.Y.Z`. Pushing the tag runs
`.github/workflows/release.yml`, which builds everything and creates a draft
GitHub Release. That workflow publishes nothing itself. Publishing the draft
triggers `.github/workflows/image.yml` and `.github/workflows/crates.yml`
(see below).

## What the workflow does

1. Checks that the tag equals the version in `Cargo.toml`, or fails.
2. Builds static musl binaries for `x86_64-unknown-linux-musl` and
   `aarch64-unknown-linux-musl`, each natively with `--locked`, and checks
   that each is statically linked and runs (`--version`).
3. Packages one tarball per target, `sopedu-dns-vX.Y.Z-<target>.tar.gz`,
   with the binary, both licences, `README.md`, `CHANGELOG.md`,
   `config.example.toml` and the third-party licence notices
   (`THIRD-PARTY-LICENSES.html`, generated with `cargo-about`).
4. Writes a CycloneDX 1.5 JSON SBOM, `sopedu-dns-vX.Y.Z.cdx.json`.
5. Signs build provenance for the tarballs with GitHub artifact attestations
   (Sigstore, keyless) and attaches the bundle as `sopedu-dns-vX.Y.Z.intoto.jsonl`.
6. Attaches the tarballs, the SBOM, the provenance bundle and a `SHA256SUMS`
   file to a draft release named after the tag. A tag with a `-` suffix (for example `v1.1.0-rc.1`)
   becomes a pre-release.

## Manual steps

1. Bump `version` in `Cargo.toml` (and `Cargo.lock`) following
   [SemVer](https://semver.org/). A minor or patch release must stay
   backwards compatible for configuration and behaviour.
2. Move the `CHANGELOG.md` entries under a `## [X.Y.Z] - YYYY-MM-DD` heading.
3. Check that CI is green on the release commit.
4. Tag it and push the tag: `git tag -s vX.Y.Z -m "sopedu-dns vX.Y.Z"` and
   `git push origin vX.Y.Z`. Never move or reuse a tag.
5. When the workflow finishes, open the draft release, paste the changelog
   section into the notes, check the assets against `SHA256SUMS`, and publish.

## Container image

When you publish the draft release, `.github/workflows/image.yml` downloads
the released binaries, checks them against `SHA256SUMS` and pushes a
multi-arch (amd64, arm64) image to `ghcr.io/<owner>/<repo>`, tagged with the
version (and `latest` unless the release is a pre-release). It compiles
nothing. To build an image yourself, see
[Building and the container image](configuration.md#17-building-and-the-container-image). Deploy by digest, not by tag.

## Crate

When you publish the draft release, `.github/workflows/crates.yml` checks out
the tag, checks that it matches the crate version and runs
`cargo publish --locked`. The job runs in the `crates-io` environment, which
only accepts `v*` tags and waits for a maintainer to approve it, because a
published version cannot be changed or deleted. It uses crates.io trusted
publishing (a short-lived OIDC token) once that is set up for the repository;
until then it uses a `CARGO_REGISTRY_TOKEN` secret in the `crates-io`
environment.
