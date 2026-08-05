import { mkdir, readFile, writeFile } from "node:fs/promises";
import { environment, workspace } from "./lib.mjs";

const inputName = process.env.SHAR_BENCH_CALIBRATION;
if (!inputName)
  throw new Error(
    "SHAR_BENCH_CALIBRATION is required; synthetic defaults are intentionally unavailable",
  );
const inputUrl = new URL(inputName, workspace);
const calibration = JSON.parse(await readFile(inputUrl, "utf8"));
if (calibration.schema !== "shar-cap-calibration-v1")
  throw new Error("unsupported calibration schema");

function positive(value, name) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0)
    throw new Error(`${name} must be finite and positive`);
  return value;
}
function nonnegative(value, name) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0)
    throw new Error(`${name} must be finite and nonnegative`);
  return value;
}
function samples(value, name) {
  if (!Number.isSafeInteger(value) || value < 30)
    throw new Error(`${name} requires at least 30 samples`);
}
function text(value, name) {
  if (typeof value !== "string" || !value.trim())
    throw new Error(`${name} is required`);
}

text(calibration.environment?.run_id, "environment.run_id");
text(calibration.environment?.captured_at, "environment.captured_at");
text(calibration.environment?.methodology_url, "environment.methodology_url");
for (const product of ["cap", "shar"]) {
  const benign = calibration.default_benign?.[product];
  text(benign?.device, `default_benign.${product}.device`);
  samples(benign?.samples, `default_benign.${product}.samples`);
  positive(benign?.p95_ms, `default_benign.${product}.p95_ms`);
  positive(benign?.median_joules, `default_benign.${product}.median_joules`);
}
const matched = calibration.attacker_equal_benign;
const target = positive(
  matched?.target_joules,
  "attacker_equal_benign.target_joules",
);
text(
  matched?.normalization_method,
  "attacker_equal_benign.normalization_method",
);
for (const product of ["cap", "shar"]) {
  const attacker = matched?.[product];
  text(attacker?.hardware, `attacker_equal_benign.${product}.hardware`);
  samples(attacker?.samples, `attacker_equal_benign.${product}.samples`);
  positive(
    attacker?.observed_benign_joules,
    `attacker_equal_benign.${product}.observed_benign_joules`,
  );
  nonnegative(
    attacker?.cost_usd_per_accepted_request,
    `attacker_equal_benign.${product}.cost_usd_per_accepted_request`,
  );
  const delta = Math.abs(attacker.observed_benign_joules - target) / target;
  if (delta > 0.05)
    throw new Error(
      `${product} benign energy differs from the matched target by ${(delta * 100).toFixed(2)}%, above 5%`,
    );
}
const revenue = nonnegative(
  calibration.sustained_abuse?.revenue_usd_per_accepted_request,
  "sustained_abuse.revenue_usd_per_accepted_request",
);
const tiers = calibration.sustained_abuse?.tiers;
if (!Array.isArray(tiers) || !tiers.length)
  throw new Error("sustained_abuse.tiers must not be empty");
const sustainedStart = calibration.sustained_abuse?.sustained_start_tier;
if (
  !Number.isSafeInteger(sustainedStart) ||
  sustainedStart < 1 ||
  sustainedStart > 32
)
  throw new Error("sustained_abuse.sustained_start_tier must be 1..32");
const seen = new Set();
for (const row of tiers) {
  if (
    !Number.isSafeInteger(row.tier) ||
    row.tier < 0 ||
    row.tier > 32 ||
    seen.has(row.tier)
  )
    throw new Error(
      "sustained abuse tiers must be unique integers from 0 through 32",
    );
  seen.add(row.tier);
  samples(row.samples, `sustained_abuse tier ${row.tier}`);
  nonnegative(
    row.attacker_cost_usd_per_accepted_request,
    `sustained_abuse tier ${row.tier} cost`,
  );
}
tiers.sort((left, right) => left.tier - right.tier);
for (let tier = sustainedStart; tier <= 32; tier++) {
  if (!seen.has(tier))
    throw new Error(`sustained_abuse is missing required tier ${tier}`);
}
for (let index = 1; index < tiers.length; index++) {
  if (
    tiers[index].attacker_cost_usd_per_accepted_request <
    tiers[index - 1].attacker_cost_usd_per_accepted_request
  )
    throw new Error(
      "sustained-abuse attacker cost must be nondecreasing by tier",
    );
}

const latencyRatio =
  calibration.default_benign.shar.p95_ms /
  calibration.default_benign.cap.p95_ms;
const energyRatio =
  calibration.default_benign.shar.median_joules /
  calibration.default_benign.cap.median_joules;
const attackerRatio =
  calibration.attacker_equal_benign.shar.cost_usd_per_accepted_request /
  calibration.attacker_equal_benign.cap.cost_usd_per_accepted_request;
if (!Number.isFinite(attackerRatio))
  throw new Error(
    "Cap attacker cost must be greater than zero for a finite ratio",
  );
const sustained = tiers.map((row) => ({
  ...row,
  profit_usd_per_accepted_request:
    revenue - row.attacker_cost_usd_per_accepted_request,
  economically_negative: row.attacker_cost_usd_per_accepted_request > revenue,
}));
const result = {
  schema: "shar-cap-economics-result-v1",
  evaluated_at: new Date().toISOString(),
  evaluator_environment: environment(),
  calibration,
  gates: {
    default_accelerated_p95: {
      threshold: 0.8,
      observed_ratio: latencyRatio,
      pass: latencyRatio <= 0.8,
    },
    default_energy: {
      threshold: 0.8,
      observed_ratio: energyRatio,
      pass: energyRatio <= 0.8,
    },
    equal_benign_attacker_cost: {
      threshold: 2,
      observed_ratio: attackerRatio,
      pass: attackerRatio >= 2,
    },
    sustained_abuse_economics: {
      revenue_usd_per_accepted_request: revenue,
      sustained_start_tier: sustainedStart,
      tiers: sustained.filter((row) => row.tier >= sustainedStart),
      pass: sustained
        .filter((row) => row.tier >= sustainedStart)
        .every((row) => row.economically_negative),
    },
  },
};
const output = process.env.SHAR_BENCH_OUTPUT
  ? new URL(process.env.SHAR_BENCH_OUTPUT, workspace)
  : new URL("results/local-economics.json", import.meta.url);
await mkdir(new URL("./", output), { recursive: true });
await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify(result, null, 2));
if (Object.values(result.gates).some((gate) => !gate.pass))
  process.exitCode = 2;
