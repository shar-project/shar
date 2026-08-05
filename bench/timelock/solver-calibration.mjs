import { mkdir, rename, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { solveTimeLock } from "../../packages/server/dist/index.js";
import { distribution, environment, workspace } from "../cap/lib.mjs";

// Public modulus from a generated 2048-bit RSW semiprime. The protected
// factors and Carmichael value are deliberately not retained or distributed.
// Client sequential-squaring throughput requires only this public value.
const modulus =
  "j-CW73o0_uWZbAGHpOP4btMsCRSfiBClFJTdNc3E5WzFVrdfERBxaQVnzJv_BukxExBNKlwzaL3tWg5_LWfDzHC1XzsPNJp-7jqfNyeAFMb3K0VEGk3Z9dYVFOq25FaRpeRH8yeMMDSgmpDfUWLbqmZYiNnzMjKPLTlGKm_tKjJlmi-yUJsSh2gRPb5CYlaI60xkdDFn6J60MxeSQQB4mfY5_CQTsDcxNZvV9mRP3UWMZE7IK7O_ikaRZfZe1Xl3v-49mT4agU3nEMPuUAGQbeamX2K8OzWhgPQvF5v9QbprAtjMDukLncIcysSuABnqjm97uXZB4h-ApdbcurGi9Q";
const iterations = 100_000;
const plan = {
  version: "rsw-v1",
  modulus_id: "public-calibration-modulus",
  modulus,
  input: "Ag",
  iterations: String(iterations),
};
solveTimeLock({ ...plan, iterations: "10000" });
const milliseconds = [];
let output = "";
for (let sample = 0; sample < 5; sample++) {
  const started = performance.now();
  output = solveTimeLock(plan).output;
  milliseconds.push(performance.now() - started);
}
const rates = milliseconds.map((duration) => (iterations * 1_000) / duration);
const rateDistribution = distribution(rates);
const result = {
  schema: "shar-timelock-solver-calibration-v1",
  environment: environment(),
  method: {
    implementation: "pure JavaScript BigInt solveTimeLock",
    modulus_bits: 2048,
    warmup_iterations: 10_000,
    measured_iterations: iterations,
    repetitions: milliseconds.length,
    caveat:
      "Local Node throughput validates conservative defaults only; browser/device and energy evidence remains required for GA.",
  },
  output,
  duration_ms: distribution(milliseconds),
  iterations_per_second: {
    samples: rateDistribution.samples,
    min: rateDistribution.min_ms,
    median: rateDistribution.median_ms,
    p95: rateDistribution.p95_ms,
    max: rateDistribution.max_ms,
    mean: rateDistribution.mean_ms,
  },
  default_policy: {
    iteration_allowance_per_second: 100_000,
    tier_32_additional_iterations: "4398046510080",
    estimated_tier_32_lifetime_seconds: 43_984_411,
    maximum_lifetime_seconds: 63_072_000,
  },
  gate: {
    requirement:
      "local minimum pure-JavaScript throughput exceeds the default lifetime allowance",
    observed: Math.min(...rates),
    threshold: 100_000,
    pass: Math.min(...rates) >= 100_000,
    ga_scope_pass: false,
  },
};
if (!result.gate.pass) throw new Error("timelock calibration gate failed");
const destination = process.env.SHAR_BENCH_OUTPUT
  ? new URL(process.env.SHAR_BENCH_OUTPUT, workspace)
  : new URL("results/local-solver-calibration.json", import.meta.url);
await mkdir(new URL("./", destination), { recursive: true });
const temporary = new URL(`${destination.pathname}.tmp`, destination);
await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`);
await rename(temporary, destination);
console.log(JSON.stringify(result, null, 2));
