import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const dockerfiles = [
  "deploy/docker/Dockerfile.rust",
  "deploy/docker/Dockerfile.javascript",
];
const references = new Map();

for (const path of dockerfiles) {
  const source = await readFile(new URL(`../${path}`, import.meta.url), "utf8");
  for (const match of source.matchAll(/^FROM\s+(\S+)/gm)) {
    const reference = match[1];
    const parsed = reference.match(
      /^(?<name>[a-z0-9._/-]+):(?<tag>[a-zA-Z0-9._-]+)@sha256:(?<digest>[0-9a-f]{64})$/,
    );
    assert.ok(
      parsed?.groups,
      `${path} has an invalid base reference: ${reference}`,
    );
    const previous = references.get(parsed.groups.name);
    if (previous)
      assert.deepEqual(
        previous,
        parsed.groups,
        `${parsed.groups.name} uses inconsistent tags or digests`,
      );
    references.set(parsed.groups.name, parsed.groups);
  }
}

const alloyDeploymentPath = "deploy/observability/alloy-kubernetes.yaml";
const alloyDeployment = await readFile(
  new URL(`../${alloyDeploymentPath}`, import.meta.url),
  "utf8",
);
const alloyReference = alloyDeployment.match(
  /image:\s+docker\.io\/(?<name>[a-z0-9._/-]+):(?<tag>[a-zA-Z0-9._-]+)@sha256:(?<digest>[0-9a-f]{64})/,
);
assert.ok(
  alloyReference?.groups,
  `${alloyDeploymentPath} must pin the Alloy image tag and index digest`,
);
references.set(alloyReference.groups.name, alloyReference.groups);

async function dockerHubToken(repository) {
  const query = new URLSearchParams({
    service: "registry.docker.io",
    scope: `repository:${repository}:pull`,
  });
  const response = await fetch(`https://auth.docker.io/token?${query}`, {
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(
    response.status,
    200,
    `Docker Hub token request failed: ${response.status}`,
  );
  const body = await response.json();
  assert.equal(
    typeof body.token,
    "string",
    "Docker Hub returned no bearer token",
  );
  return body.token;
}

for (const { name, tag, digest } of references.values()) {
  assert.doesNotMatch(
    name,
    /\./,
    `unsupported non-Docker-Hub registry: ${name}`,
  );
  const repository = name.includes("/") ? name : `library/${name}`;
  const token = await dockerHubToken(repository);
  const response = await fetch(
    `https://registry-1.docker.io/v2/${repository}/manifests/sha256:${digest}`,
    {
      headers: {
        accept: [
          "application/vnd.oci.image.index.v1+json",
          "application/vnd.docker.distribution.manifest.list.v2+json",
        ].join(", "),
        authorization: `Bearer ${token}`,
      },
      signal: AbortSignal.timeout(30_000),
    },
  );
  assert.equal(
    response.status,
    200,
    `${name}:${tag} manifest request failed: ${response.status}`,
  );
  const manifest = await response.json();
  assert.match(
    manifest.mediaType,
    /(?:image\.index|manifest\.list)/,
    `${name}:${tag}@sha256:${digest} is a single-platform child manifest`,
  );
  for (const architecture of ["amd64", "arm64"])
    assert.ok(
      manifest.manifests?.some(
        (entry) =>
          entry.platform?.os === "linux" &&
          entry.platform?.architecture === architecture,
      ),
      `${name}:${tag}@sha256:${digest} has no linux/${architecture} child`,
    );
  console.log(
    `${name}:${tag}@sha256:${digest} includes linux/amd64 and linux/arm64`,
  );
}
