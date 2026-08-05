# Releasing Shar

Releases are stable SemVer tags whose version exactly matches the root, all
three npm package manifests, and the Cargo workspace. Run every local gate and
then create a protected `vX.Y.Z` tag from the reviewed commit.

The `release.yml` workflow uses the `release` GitHub environment and publishes:

- `@shar/server`, `@shar/widget`, and `@shar/cap-compat` through npm trusted
  publishing, with npm provenance;
- separate Rust and pure-JavaScript GHCR images for `linux/amd64` and
  `linux/arm64`, with BuildKit SBOM/provenance attestations, GitHub build
  provenance, and keyless Cosign signatures;
- npm tarballs, CycloneDX package SBOMs, exact amd64 and arm64 SPDX container
  SBOMs, SHA-256 checksum manifests, and Sigstore bundles as GitHub release
  assets.

Every container `FROM` reference is pinned to a multi-architecture manifest
index, not an architecture-specific child manifest. The registry-backed
`check:base-images` gate requires every pin to expose both linux/amd64 and
linux/arm64. Dependabot proposes digest refreshes weekly. CI and the protected-tag
workflow build each amd64 and arm64 image as a platform-specific Docker archive in
a read-only, credential-free job, retain a full Grype report for every archive
(including upstream-unfixed findings), and fail before the credential-bearing
publication job when a high or critical vulnerability has an available fix.
Do not bypass this gate. Review unfixed findings as part of the release record
and move to a supported base before its distribution reaches end of life.
The publishing build also attaches BuildKit SBOM/provenance records to each
platform manifest. The release extracts those exact attached SPDX documents by
platform, checksums them together, and signs both documents and the checksum
manifest; it does not rescan an ambiguous multi-architecture index to create a
host-only release artifact.

The tag workflow first runs an unprivileged preflight job that verifies every
npm and Cargo manifest, both lockfiles, exact internal package dependencies,
MIT-only metadata, and npm provenance settings. It builds the npm tarballs and
CycloneDX documents once, records relative-path checksums, and uploads them as a
one-day candidate artifact after installing the three exact tarballs together
and importing each public entry point from an isolated prefix. No publication
job starts until preflight and all four image/platform vulnerability gates pass.
The OIDC-enabled npm job downloads that candidate, verifies its checksums, signs
it, verifies every new Sigstore bundle against the exact tagged workflow
identity and GitHub OIDC issuer, and publishes the exact tested tarballs without
checking out or rebuilding source. The container jobs likewise verify the
Cosign signature on the immutable multi-architecture digest, verify GitHub's
registry-backed build-provenance attestation, and identity-verify every
platform SBOM bundle before uploading release evidence.

Publishing across npm, GHCR, and GitHub is not a distributed transaction. These
preflight barriers eliminate preventable publication after a known failed gate,
but a registry outage can still leave a partial release. If that happens, stop
and reconcile the immutable version rather than moving the tag or overwriting an
existing npm version.

Before the first release, configure the same trusted publisher for each npm
package using repository `shar-project/shar`, workflow `release.yml`,
environment `release`, and the `npm publish` permission. Protect the release
environment and stable tag pattern, require every CI job including RustSec and
both container vulnerability jobs, and disable legacy npm tokens after the OIDC
flow is verified.

Verify published artifacts with the repository identity rather than trusting a
download location alone:

```sh
cosign verify --certificate-identity-regexp 'github.com/shar-project/shar/.github/workflows/release.yml' --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/shar-project/shar/shar-rust:VERSION
cosign verify-blob --bundle ARTIFACT.sigstore.json --certificate-identity-regexp 'github.com/shar-project/shar/.github/workflows/release.yml' --certificate-oidc-issuer https://token.actions.githubusercontent.com ARTIFACT
gh attestation verify oci://ghcr.io/shar-project/shar/shar-rust:VERSION -R shar-project/shar
```

Publication is intentionally not tested from forks or local machines. A failed
partial publication must be investigated; never overwrite an npm version or
move an existing release tag.
