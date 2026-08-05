import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { format } from "prettier";

async function workflow(name) {
  const text = await readFile(
    new URL(`../.github/workflows/${name}.yml`, import.meta.url),
    "utf8",
  );
  await format(text, { parser: "yaml" });
  return text;
}

function job(text, name) {
  const start = text.indexOf(`\n  ${name}:\n`);
  assert.notEqual(start, -1, `workflow job is missing: ${name}`);
  const remainder = text.slice(start + 1);
  const next = remainder.slice(1).search(/^  [a-z][a-z0-9-]*:\n/m);
  return next === -1 ? remainder : remainder.slice(0, next + 1);
}

function requirePinnedActions(name, text) {
  const actions = [...text.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gm)].map(
    (match) => match[1],
  );
  assert.ok(actions.length > 0, `${name} must use at least one action`);
  for (const action of actions)
    assert.match(
      action,
      /^[^@\s]+@[0-9a-f]{40}$/,
      `${name} action must use an immutable full commit SHA: ${action}`,
    );
}

function requireContainerGate(name, text) {
  const security = job(text, "container-security");
  assert.match(security, /permissions:\n\s+contents: read/);
  assert.doesNotMatch(security, /packages: write|id-token: write/);
  assert.equal(
    security.match(
      /anchore\/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2/g,
    )?.length,
    2,
  );
  assert.equal(security.match(/arch: amd64/g)?.length, 2);
  assert.equal(security.match(/arch: arm64/g)?.length, 2);
  assert.match(
    security,
    /docker\/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130/,
  );
  assert.match(security, /platforms: linux\/\$\{\{ matrix\.arch \}\}/);
  assert.match(security, /outputs: type=docker,dest=/);
  assert.match(security, /image: docker-archive:/);
  assert.match(security, /provenance: false/);
  assert.doesNotMatch(security, /type=oci|oci-archive:/);
  assert.match(security, /push: false/);
  assert.doesNotMatch(security, /load: true|Build the host-platform image/);
  assert.match(security, /fail-build: true/);
  assert.match(security, /fail-build: false/);
  assert.match(security, /severity-cutoff: high/);
  assert.match(security, /only-fixed: false/);
  assert.match(security, /only-fixed: true/);
  assert.match(security, /output-format: json/);
  assert.match(security, /output-format: table/);
  assert.match(
    security,
    /actions\/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4/,
  );
  assert.doesNotMatch(security, /registry-password|GITHUB_TOKEN/);

  if (name === "release") {
    const preflight = job(text, "preflight");
    const packages = job(text, "packages");
    const containers = job(text, "containers");
    assert.doesNotMatch(
      preflight,
      /environment: release|id-token: write|packages: write/,
    );
    assert.match(
      preflight,
      /node scripts\/check-release\.mjs "\$GITHUB_REF_NAME"/,
    );
    assert.match(
      preflight,
      /rustup toolchain install 1\.94\.0 --profile minimal --target wasm32-unknown-unknown/,
    );
    assert.match(preflight, /scripts\/build-widget-wasm\.sh --check/);
    assert.match(preflight, /npm pack --workspaces --pack-destination release/);
    assert.match(
      preflight,
      /cd release && sha256sum \.\/\*\.tgz \.\/\*\.cdx\.json > SHA256SUMS/,
    );
    assert.match(
      preflight,
      /npm install --prefix "\$RUNNER_TEMP\/shar-release-smoke" --ignore-scripts --no-audit --no-fund release\/\*\.tgz/,
    );
    assert.match(preflight, /node scripts\/smoke-package-candidates\.mjs/);
    assert.match(preflight, /name: npm-release-candidate/);
    assert.match(preflight, /retention-days: 1/);
    assert.match(packages, /needs: \[preflight, container-security\]/);
    assert.match(
      packages,
      /actions\/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38/,
    );
    assert.match(packages, /registry-url: https:\/\/registry\.npmjs\.org/);
    assert.match(packages, /name: npm-release-candidate/);
    assert.match(packages, /cd release && sha256sum --check SHA256SUMS/);
    assert.match(packages, /cosign verify-blob --bundle/);
    assert.match(packages, /--certificate-identity "\$CERTIFICATE_IDENTITY"/);
    assert.match(packages, /--certificate-oidc-issuer "\$OIDC_ISSUER"/);
    assert.doesNotMatch(packages, /- run: npm (?:pack|test|ci)(?:\s|$)/);
    assert.match(security, /needs: preflight/);
    assert.match(containers, /needs: \[container-security, packages\]/);
    assert.match(containers, /platforms: linux\/amd64,linux\/arm64/);
    assert.match(containers, /provenance: mode=max/);
    assert.match(containers, /cosign verify --certificate-identity/);
    assert.match(containers, /gh attestation verify "oci:\/\/\$IMAGE_REF"/);
    assert.match(containers, /sbom: true/);
    assert.match(containers, /imagetools inspect/);
    assert.match(containers, /index \.SBOM "linux\/amd64"/);
    assert.match(containers, /index \.SBOM "linux\/arm64"/);
    assert.match(containers, /linux-amd64\.spdx\.json/);
    assert.match(containers, /linux-arm64\.spdx\.json/);
    assert.match(containers, /SBOM-SHA256SUMS/);
    assert.match(
      containers,
      /for artifact in release\/\*\.spdx\.json release\/\*-SBOM-SHA256SUMS/,
    );
    assert.match(
      containers,
      /cosign verify-blob --bundle "\$\{artifact\}\.sigstore\.json"/,
    );
    assert.doesNotMatch(containers, /anchore\/sbom-action/);
  }
}

const [ci, release, dependabot] = await Promise.all([
  workflow("ci"),
  workflow("release"),
  readFile(new URL("../.github/dependabot.yml", import.meta.url), "utf8"),
]);
await format(dependabot, { parser: "yaml" });
requirePinnedActions("CI", ci);
requirePinnedActions("release", release);
requireContainerGate("CI", ci);
requireContainerGate("release", release);
assert.match(
  release,
  /^concurrency:\n  group: release\n  cancel-in-progress: false$/m,
  "release runs must serialize without cancelling an in-flight publication",
);
assert.match(
  ci,
  /^on:\n  push:\n    branches: \[main\]\n  pull_request:\n/m,
  "CI must run feature branches through pull_request only to avoid duplicate matrices",
);
assert.match(job(ci, "packages"), /npm run check:base-images/);
assert.match(job(release, "preflight"), /npm run check:base-images/);
const packages = job(ci, "packages");
const releasePreflight = job(release, "preflight");
for (const source of [packages, releasePreflight]) {
  assert.match(
    source,
    /docker\.io\/grafana\/alloy:v1\.14\.0@sha256:f50931848bd8178774521767bb46b905e1a081301950ff28d7623c9db7c01076/,
  );
  assert.match(
    source,
    /validate \/etc\/shar-observability\/alloy-config\.alloy/,
  );
  assert.match(source, /docker run --rm --user 10001:10001/);
}
assert.match(packages, /ACTIONLINT_VERSION: 1\.7\.12/);
assert.match(
  packages,
  /ACTIONLINT_SHA256: 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8/,
);
assert.match(
  packages,
  /actionlint_\$\{ACTIONLINT_VERSION\}_linux_amd64\.tar\.gz/,
);
assert.match(packages, /sha256sum --check --strict/);
assert.doesNotMatch(packages, /go run github\.com\/rhysd\/actionlint/);

const rust = job(ci, "rust");
const durableStores = job(ci, "durable-store-interop");
assert.match(
  rust,
  /rustup toolchain install 1\.94\.0 --profile minimal --component rustfmt --component clippy --target wasm32-unknown-unknown/,
);
assert.match(rust, /scripts\/build-widget-wasm\.sh --check/);
assert.match(rust, /cargo install cargo-audit --version 0\.22\.2 --locked/);
assert.match(rust, /run: cargo audit/);
assert.match(
  durableStores,
  /cargo test --locked -p shar-server postgres::tests::terminated_client_is_not_retried_and_the_next_request_reconnects -- --ignored --exact/,
);
assert.doesNotMatch(rust, /GITHUB_TOKEN|checks: write/);
assert.match(
  rust,
  /cargo test --locked -p shar-server redis::tests::failed_connection_is_not_retried_and_the_next_request_reconnects -- --ignored --exact/,
);
assert.match(
  rust,
  /cargo test --locked -p shar-server --bin shar-server http_tests::container_healthcheck_accepts_a_ready_http_endpoint -- --ignored --exact/,
);
assert.doesNotMatch(ci, /version:\s*latest|ignore-unfixed:\s*true/);
assert.doesNotMatch(release, /version:\s*latest|ignore-unfixed:\s*true/);
assert.match(
  dependabot,
  /package-ecosystem: docker\n\s+directory: \/deploy\/docker\n\s+schedule:\n\s+interval: weekly/,
);

console.log("workflow pinning and vulnerability gates passed");
