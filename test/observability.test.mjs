import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const expectedMetrics = new Set([
  "shar_challenges_issued_total",
  "shar_challenge_engine_duration_seconds_total",
  "shar_challenge_handler_duration_seconds_total",
  "shar_challenges_redeemed_total",
  "shar_site_verifications_total",
  "shar_fallback_completions_total",
  "shar_audit_events_dropped_total",
]);

function metricNames(source) {
  return new Set(source.match(/shar_[a-z_]+_total/g) ?? []);
}

function referencedMetrics(expressions) {
  return new Set(
    expressions.flatMap(
      (expression) => expression.match(/shar_[a-z_]+_total/g) ?? [],
    ),
  );
}

test("production observability assets match both privacy-safe metric expositions", async () => {
  const [rust, typescript, rules, kubernetes, alloy, alloyKubernetes] =
    await Promise.all([
      readFile(
        new URL("../crates/shar-server/src/main.rs", import.meta.url),
        "utf8",
      ),
      readFile(
        new URL("../packages/server/src/handler.ts", import.meta.url),
        "utf8",
      ),
      readFile(
        new URL(
          "../deploy/observability/prometheus-rules.yaml",
          import.meta.url,
        ),
        "utf8",
      ),
      readFile(
        new URL("../deploy/kubernetes/deployment.yaml", import.meta.url),
        "utf8",
      ),
      readFile(
        new URL("../deploy/observability/alloy-config.alloy", import.meta.url),
        "utf8",
      ),
      readFile(
        new URL(
          "../deploy/observability/alloy-kubernetes.yaml",
          import.meta.url,
        ),
        "utf8",
      ),
    ]);
  assert.deepEqual(metricNames(rust), expectedMetrics);
  assert.deepEqual(metricNames(typescript), expectedMetrics);

  const dashboard = JSON.parse(
    await readFile(
      new URL(
        "../deploy/observability/grafana-dashboard.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const dashboardExpressions = dashboard.panels.flatMap((panel) =>
    panel.targets.map((target) => target.expr),
  );
  assert.deepEqual(referencedMetrics(dashboardExpressions), expectedMetrics);
  assert.ok(
    dashboardExpressions.some((expression) => expression.includes("up{")),
  );
  for (const expression of dashboardExpressions)
    for (const selector of expression.matchAll(/\{([^}]*)\}/g))
      assert.doesNotMatch(
        selector[1],
        /(?:^|,)\s*(?:tenant|site|action|origin|session|network|backend|device|country|asn|user_agent|webdriver)\s*(?:=|!)/i,
      );

  const ruleExpressions = [...rules.matchAll(/^\s+expr: ["'](.+)["']$/gm)].map(
    (match) => match[1],
  );
  assert.equal(ruleExpressions.length, 3);
  for (const metric of referencedMetrics(ruleExpressions))
    assert.ok(expectedMetrics.has(metric), `unknown alert metric: ${metric}`);
  assert.match(rules, /alert: SharTargetDown/);
  assert.match(rules, /alert: SharAuditEventsDropped/);
  assert.match(rules, /alert: SharChallengeHandlerMeanHigh/);
  assert.match(kubernetes, /prometheus\.io\/scrape: "true"/);
  assert.match(kubernetes, /prometheus\.io\/path: \/metrics/);
  assert.match(kubernetes, /prometheus\.io\/port: "8080"/);

  assert.ok(
    dashboard.__inputs.some(
      (input) => input.name === "DS_LOKI" && input.pluginId === "loki",
    ),
  );
  const observationPanel = dashboard.panels.find(
    (panel) => panel.title === "Privacy-safe request observations",
  );
  assert.equal(observationPanel?.type, "logs");
  assert.equal(observationPanel?.datasource?.uid, "${DS_LOKI}");
  assert.equal(observationPanel?.options?.showLabels, false);
  assert.equal(
    observationPanel?.targets?.[0]?.expr,
    '{service_name="shar",observation_version="request-observation-v1"} | json',
  );

  assert.match(alloy, /namespaces \{\n\s+own_namespace = true/);
  assert.match(alloy, /label = "app\.kubernetes\.io\/name=shar"/);
  assert.match(alloy, /drop_malformed = true/);
  assert.match(
    alloy,
    /selector\s+= "\{observation_version!=\\"request-observation-v1\\"\}"/,
  );
  assert.match(alloy, /url = sys\.env\("SHAR_LOKI_URL"\)/);
  assert.match(alloy, /source\s+= "safe_line"/);
  assert.match(alloy, /template = `\{"version":\{\{ toJson/);
  assert.match(alloy, /stage\.output \{\n\s+source = "safe_line"/);
  const expressionBlock = alloy.match(
    /stage\.json \{[\s\S]*?expressions = \{([\s\S]*?)\n\s+\}\n\s+\}/,
  );
  assert.ok(expressionBlock?.[1]);
  const extractedFields = new Set(
    [...expressionBlock[1].matchAll(/^\s+([a-z_]+)\s*=/gm)].map(
      (match) => match[1],
    ),
  );
  assert.deepEqual(
    extractedFields,
    new Set([
      "observation_version",
      "request_id",
      "method",
      "route",
      "status",
      "duration_ms",
    ]),
  );
  const indexedLabels = alloy.match(
    /stage\.label_keep \{\n\s+values = \[([\s\S]*?)\n\s+\]/,
  );
  assert.ok(indexedLabels?.[1]);
  assert.doesNotMatch(
    indexedLabels[1],
    /request_id|method|route|status|duration/,
  );
  for (const label of [
    "service_name",
    "namespace",
    "pod",
    "container",
    "observation_version",
  ])
    assert.match(indexedLabels[1], new RegExp(`"${label}"`));

  const configMarker = "  config.alloy: |\n";
  const configStart = alloyKubernetes.indexOf(configMarker);
  assert.ok(configStart >= 0, "collector ConfigMap has no config.alloy");
  const configTail = alloyKubernetes.slice(configStart + configMarker.length);
  const configEnd = configTail.indexOf("\n---\n");
  assert.ok(configEnd >= 0, "collector ConfigMap has no document boundary");
  const embeddedConfig = configTail
    .slice(0, configEnd)
    .replace(/^ {4}/gm, "")
    .concat("\n");
  assert.equal(embeddedConfig, alloy);
  assert.match(alloyKubernetes, /kind: Role\n/);
  assert.doesNotMatch(alloyKubernetes, /kind: ClusterRole\n/);
  assert.match(alloyKubernetes, /resources: \["pods\/log"\]/);
  assert.match(
    alloyKubernetes,
    /grafana\/alloy:v1\.14\.0@sha256:f50931848bd8178774521767bb46b905e1a081301950ff28d7623c9db7c01076/,
  );
});
