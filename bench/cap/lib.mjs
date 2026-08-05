import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { arch, cpus, loadavg, platform, release, version } from "node:os";

export const workspace = new URL("../../", import.meta.url);
export const inputs = new URL("../../.bench/cap/", import.meta.url);

export async function manifest() {
  return JSON.parse(
    await readFile(new URL("manifest.json", import.meta.url), "utf8"),
  );
}

export function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? workspace,
      env: { ...process.env, ...options.env },
      stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
    });
    let stdout = "",
      stderr = "";
    child.stdout?.on("data", (chunk) => (stdout += chunk));
    child.stderr?.on("data", (chunk) => (stderr += chunk));
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve({ stdout, stderr });
      else
        reject(
          new Error(
            `${command} exited ${code ?? signal}${stderr ? `: ${stderr.trim()}` : ""}`,
          ),
        );
    });
  });
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function environment() {
  const processors = cpus();
  return {
    captured_at: new Date().toISOString(),
    node: process.version,
    v8: process.versions.v8,
    os: `${platform()} ${release()}`,
    arch: arch(),
    cpu: processors[0]?.model?.trim() ?? "unknown",
    logical_cpus: processors.length,
    load_average: loadavg(),
    host: version(),
  };
}

export function percentile(sorted, value) {
  if (!sorted.length) return null;
  return sorted[
    Math.min(
      sorted.length - 1,
      Math.max(0, Math.ceil(sorted.length * value) - 1),
    )
  ];
}

export function distribution(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((total, value) => total + value, 0);
  return {
    samples: sorted.length,
    min_ms: sorted[0] ?? null,
    median_ms: percentile(sorted, 0.5),
    p95_ms: percentile(sorted, 0.95),
    max_ms: sorted.at(-1) ?? null,
    mean_ms: sorted.length ? sum / sorted.length : null,
  };
}

export function relativeStandardDeviation(values) {
  if (!Array.isArray(values) || values.length < 2) return null;
  if (values.some((value) => !Number.isFinite(value) || value < 0))
    throw new Error("distribution values must be finite and non-negative");
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  if (mean === 0) return values.every((value) => value === 0) ? 0 : null;
  const variance =
    values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance) / mean;
}

/** Conservatively evaluates a threshold across every independent run. */
export function evaluateAllRunGate(values, threshold, direction) {
  if (
    !Array.isArray(values) ||
    values.length < 1 ||
    values.some((value) => !Number.isFinite(value)) ||
    !Number.isFinite(threshold) ||
    !["minimum", "maximum"].includes(direction)
  )
    throw new Error("invalid all-run gate");
  const passing = values.map((value) =>
    direction === "minimum" ? value >= threshold : value <= threshold,
  );
  const status = passing.every(Boolean)
    ? "pass"
    : passing.every((value) => !value)
      ? "fail"
      : "inconclusive";
  return {
    threshold,
    direction,
    status,
    pass: status === "pass",
    observed_min: Math.min(...values),
    observed_median: percentile(
      [...values].sort((a, b) => a - b),
      0.5,
    ),
    observed_max: Math.max(...values),
  };
}

export function rssSummary(samples) {
  const values = samples
    .map((sample) => (typeof sample === "number" ? sample : sample.bytes))
    .filter((value) => Number.isSafeInteger(value) && value >= 0);
  return {
    sample_count: values.length,
    baseline_rss_bytes: values[0] ?? null,
    peak_rss_bytes: values.length ? Math.max(...values) : null,
    final_rss_bytes: values.at(-1) ?? null,
  };
}
