import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { format } from "prettier";

async function source(path) {
  return readFile(new URL(`../${path}`, import.meta.url), "utf8");
}

function requires(text, pattern, message) {
  assert.match(text, pattern, message);
}

const [
  rustDocker,
  javascriptDocker,
  compose,
  kubernetes,
  alloyKubernetes,
  rustMain,
] = await Promise.all([
  source("deploy/docker/Dockerfile.rust"),
  source("deploy/docker/Dockerfile.javascript"),
  source("deploy/docker/compose.yaml"),
  source("deploy/kubernetes/deployment.yaml"),
  source("deploy/observability/alloy-kubernetes.yaml"),
  source("crates/shar-server/src/main.rs"),
]);

// Parsing through Prettier catches malformed YAML without adding a Node-only
// runtime dependency to any publishable Shar package.
await format(compose, { parser: "yaml" });
await format(kubernetes, { parser: "yaml" });
await format(alloyKubernetes, { parser: "yaml" });

for (const [name, dockerfile] of [
  ["Rust", rustDocker],
  ["JavaScript", javascriptDocker],
]) {
  requires(dockerfile, /^USER 10001:10001$/m, `${name} image must be non-root`);
  requires(dockerfile, /^HEALTHCHECK /m, `${name} image needs a healthcheck`);
  requires(
    dockerfile,
    /SHAR_LISTEN=0\.0\.0\.0:8080/,
    `${name} listen contract changed`,
  );
  const baseImages = [...dockerfile.matchAll(/^FROM\s+(\S+)/gm)].map(
    (match) => match[1],
  );
  assert.ok(baseImages.length >= 2, `${name} image must retain build stages`);
  for (const image of baseImages)
    assert.match(
      image,
      /^[^@\s]+@sha256:[0-9a-f]{64}$/,
      `${name} base image must use an immutable manifest digest: ${image}`,
    );
}
requires(
  javascriptDocker,
  /node", "\/app\/standalone\/js\/healthcheck\.mjs"/,
  "JavaScript image must use its configurable internal healthcheck",
);
for (const runtimeTool of [
  "node_modules/npm",
  "node_modules/corepack",
  "bin/npx",
])
  requires(
    javascriptDocker,
    new RegExp(`rm[^\\n]*${runtimeTool.replace("/", "\\/")}`),
    `JavaScript runtime must remove unused package manager: ${runtimeTool}`,
  );
requires(
  rustDocker,
  /shar-server", "--healthcheck"/,
  "Rust image must use its internal healthcheck",
);
requires(
  rustDocker,
  /COPY --from=build \/etc\/ssl\/certs\/ca-certificates\.crt \/etc\/ssl\/certs\/ca-certificates\.crt/,
  "Rust runtime must copy its CA bundle from a digest-pinned stage",
);
assert.doesNotMatch(
  rustDocker,
  /apt-get|apk add|dnf install|yum install/,
  "Rust image must not resolve mutable runtime packages during its build",
);
requires(
  rustMain,
  /GET \/readyz HTTP\/1\.1/,
  "Rust internal healthcheck must check readiness",
);

for (const pattern of [
  /read_only: true/,
  /cap_drop: \[ALL\]/,
  /no-new-privileges:true/,
  /127\.0\.0\.1:8080:8080/,
  /mode: 0400/,
  /SHAR_MAX_CONCURRENT_REQUESTS/,
  /SHAR_STATE_TIMEOUT_MS/,
  /SHAR_REQUEST_BODY_TIMEOUT_MS/,
  /SHAR_SHUTDOWN_TIMEOUT_MS/,
  /stop_grace_period: 30s/,
])
  requires(compose, pattern, `Compose invariant missing: ${pattern}`);

for (const pattern of [
  /automountServiceAccountToken: false/,
  /runAsNonRoot: true/,
  /runAsUser: 10001/,
  /runAsGroup: 10001/,
  /allowPrivilegeEscalation: false/,
  /readOnlyRootFilesystem: true/,
  /seccompProfile:\n\s+type: RuntimeDefault/,
  /capabilities:\n\s+drop: \["ALL"\]/,
  /startupProbe:\n\s+httpGet:\n\s+path: \/healthz/,
  /livenessProbe:\n\s+httpGet:\n\s+path: \/healthz/,
  /readinessProbe:\n\s+httpGet:\n\s+path: \/readyz/,
  /kind: PodDisruptionBudget/,
  /SHAR_POSTGRES_URL/,
  /SHAR_REDIS_URL/,
  /SHAR_MAX_CONCURRENT_REQUESTS/,
  /SHAR_STATE_TIMEOUT_MS/,
  /SHAR_REQUEST_BODY_TIMEOUT_MS/,
  /SHAR_SHUTDOWN_TIMEOUT_MS/,
  /terminationGracePeriodSeconds: 30/,
  /chmod 0400 \/output\/shar-keys\.json/,
  /chown 10001:10001 \/output\/shar-keys\.json/,
])
  requires(kubernetes, pattern, `Kubernetes invariant missing: ${pattern}`);

assert.doesNotMatch(
  kubernetes,
  /^\s+fsGroup:/m,
  "fsGroup can make the protected key file group-readable",
);
assert.doesNotMatch(
  kubernetes,
  /hostNetwork: true|hostPID: true|privileged: true/,
  "Kubernetes example enables a privileged host boundary",
);

for (const pattern of [
  /kind: Role\n/,
  /resources: \["pods"\]/,
  /resources: \["pods\/log"\]/,
  /verbs: \["get", "list", "watch"\]/,
  /docker\.io\/grafana\/alloy:v1\.14\.0@sha256:f50931848bd8178774521767bb46b905e1a081301950ff28d7623c9db7c01076/,
  /strategy:\n\s+type: Recreate/,
  /runAsNonRoot: true/,
  /runAsUser: 10001/,
  /runAsGroup: 10001/,
  /fsGroup: 10001/,
  /allowPrivilegeEscalation: false/,
  /readOnlyRootFilesystem: true/,
  /seccompProfile:\n\s+type: RuntimeDefault/,
  /capabilities:\n\s+drop: \["ALL"\]/,
  /path: \/-\/ready/,
  /--storage\.path=\/var\/lib\/alloy\/data/,
  /sizeLimit: 128Mi/,
  /name: SHAR_LOKI_URL/,
  /name: shar-observation-storage/,
])
  requires(
    alloyKubernetes,
    pattern,
    `Observation collector invariant missing: ${pattern}`,
  );
assert.doesNotMatch(
  alloyKubernetes,
  /kind: ClusterRole\n|hostNetwork: true|hostPID: true|privileged: true/,
  "Observation collection must stay namespace-scoped and unprivileged",
);

console.log("container and Kubernetes deployment invariants passed");
