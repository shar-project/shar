# Shar observability

Import `grafana-dashboard.json` with Prometheus and Loki datasources, and load
`prometheus-rules.yaml` into Prometheus or a compatible rule evaluator. Metric
queries use only Shar's unlabeled aggregate counters and ordinary scrape
`job`/`instance` labels. They never introduce tenant, site, action, network,
session, browser, or device dimensions.

Configure the scrape job name to begin with `shar`, or adjust only the external
`job` matcher in the target-down rule and ready-target panel. Scrape `/metrics`
and probe `/readyz` independently: a metrics scrape proves process visibility,
not dependency readiness. Route warnings to operators; alerts must never feed
proof validity or policy denial.

## Request-observation storage

Both standalones emit `request-observation-v1` JSON to standard error when
`SHAR_REQUEST_LOG=1`. It contains exactly a random request id, normalized
method and route, status, and duration. The production deployment enables that
output. `alloy-config.alloy` provides a separately deployed collection plane:

- namespace-scoped Kubernetes discovery selects only the `shar` application
  container;
- malformed JSON and every line other than `request-observation-v1` are
  discarded before export;
- request id, method, route, status, and duration are Loki structured metadata,
  not indexed labels;
- the exported log line is rebuilt from only those six allowlisted fields, so
  an unexpected extra JSON property cannot cross the collection boundary;
- only service, namespace, pod, container, and the constant observation version
  remain low-cardinality labels;
- collection or Loki failure cannot enter Shar's request path or affect proof
  validity.

`alloy-kubernetes.yaml` is a hardened, namespace-local deployment using a Role
rather than a ClusterRole and an immutable multi-architecture Alloy image. In
the same namespace as Shar, configure the full Loki push URL and apply it:

```sh
kubectl create secret generic shar-observation-storage \
  --from-literal=loki-url=https://loki.example/loki/api/v1/push
kubectl apply -f deploy/observability/alloy-kubernetes.yaml
```

Put authentication and TLS enforcement at the Loki gateway, or adapt the
`loki.write` endpoint to your secret-backed authentication mechanism. Do not
put credentials in the ConfigMap. Configure Loki retention to the shortest
operationally useful window; 24 hours is the recommended starting point.

The CI and protected release workflows validate the Alloy source with the same
checksum-pinned image used by the deployment. To validate an edited file
locally:

```sh
docker run --rm \
  --user 10001:10001 \
  -v "$PWD/deploy/observability:/etc/shar-observability:ro" \
  docker.io/grafana/alloy:v1.14.0@sha256:f50931848bd8178774521767bb46b905e1a081301950ff28d7623c9db7c01076 \
  validate /etc/shar-observability/alloy-config.alloy
```

The Grafana log panel queries only the constant `service_name` and
`observation_version` labels, then parses the already privacy-filtered JSON.
Access to Loki and Grafana remains an operator security boundary: require
authentication, audit administrative access, and verify retention in the
target environment.
