# Kubernetes example

This example deploys two Shar replicas with separate liveness and readiness
probes. It deliberately requires PostgreSQL and Redis-compatible endpoints;
SQLite is a single-host adapter and must not back an HA deployment.

Before applying the manifest:

1. Replace the example image with an immutable digest from a release whose
   signature, provenance, checksum, and SBOM you verified.
2. Set exact browser origins and the proxy CIDRs that overwrite forwarding
   headers in the ConfigMap. Terminate TLS at that trusted proxy. Leave
   `SHAR_ASSURANCE_MODE` set to `off` unless that proxy also computes and
   overwrites the documented numeric assurance header; never forward a
   browser-supplied value.
3. Create `shar-keys` from a mode-0600 production key bundle, `shar-state`
   with `postgres-url` and `redis-url` entries, and the `shar-postgres-ca` and
   `shar-redis-ca` secrets with `ca.pem` entries. Use `rediss://` and
   certificate-verified PostgreSQL.
4. Run the live-store race, failover, reconnect, and partition tests against
   the exact managed services and proxies used by the cluster.

For example, after creating the key bundle locally:

```sh
kubectl create secret generic shar-keys \
  --from-file=shar-keys.json=./shar-keys.json
kubectl create secret generic shar-state \
  --from-literal=postgres-url='postgresql://shar:REDACTED@db.example/shar?sslmode=require' \
  --from-literal=redis-url='rediss://:REDACTED@redis.example:6379'
kubectl create secret generic shar-postgres-ca --from-file=ca.pem=./ca.pem
kubectl create secret generic shar-redis-ca --from-file=ca.pem=./redis-ca.pem
kubectl apply -f deploy/kubernetes/deployment.yaml
```

`/healthz` proves only that the process can serve HTTP. `/readyz` performs
read-only probes against configuration, pressure, and nonce storage, so a pod
is removed from service during a required-state outage without being restarted
solely for that outage. Audit storage is intentionally excluded because audit
writes are best-effort and may never invalidate or reject completed work.

The init container copies the projected key bundle into a memory-backed volume,
changes its owner to UID/GID 10001, and sets mode 0400. This is intentional:
using pod `fsGroup` directly on the Secret can add group-read permission, which
both Shar servers reject. Keep the init and application image digests identical
and do not weaken the mode check. The PostgreSQL CA is public certificate
material and is projected read-only with mode 0444; credentials remain in the
`shar-state` Secret.

The manifest uses the Rust image name. The independent JavaScript image has the
same configuration, port, UID/GID, and probe contract, so it can be substituted
after verifying its own digest. Resource values are conservative examples;
derive production requests, limits, autoscaling, and disruption policy from
load tests. Tune `SHAR_MAX_CONCURRENT_REQUESTS` and `SHAR_STATE_TIMEOUT_MS`
against the exact store service before rollout. This manifest is deployment
scaffolding, not evidence that Shar's open multi-host/failover release gate has
passed.

The optional namespace-scoped request-observation collector is in
[`../observability/alloy-kubernetes.yaml`](../observability/alloy-kubernetes.yaml).
It requires only pod and pod-log reads in this namespace and forwards the
privacy-filtered standalone observations to an operator-controlled Loki
endpoint. It is intentionally separate from the Shar Pods, so collector or
storage failure cannot affect challenge or verification traffic.
