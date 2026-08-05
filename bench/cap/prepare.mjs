import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { inputs, manifest, run } from "./lib.mjs";

const expected = await manifest();
const source = new URL("source/", inputs);
const artifacts = new URL("artifacts/", inputs);
const extracted = new URL("extracted/", inputs);
await mkdir(source, { recursive: true });
await mkdir(artifacts, { recursive: true });
await mkdir(extracted, { recursive: true });

async function checkout(name, item) {
  const target = new URL(`${name}/`, source);
  const git = new URL(".git/", target);
  try {
    await readFile(new URL("HEAD", git));
  } catch {
    await run("git", [
      "clone",
      "--depth",
      "1",
      "--branch",
      item.tag,
      item.repository ?? expected.standalone.repository,
      fileURLToPath(target),
    ]);
  }
  const { stdout } = await run("git", ["rev-parse", "HEAD"], {
    cwd: target,
    capture: true,
  });
  const commit = stdout.trim();
  if (commit !== item.commit)
    throw new Error(`${name} resolved to ${commit}, expected ${item.commit}`);
  return target;
}

const standalone = await checkout("standalone", expected.standalone);
await checkout("widget", {
  ...expected.widget,
  repository: expected.standalone.repository,
});

async function pack(name, item) {
  const output = await run(
    "npm",
    [
      "pack",
      item.package,
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      fileURLToPath(artifacts),
    ],
    { capture: true },
  );
  const records = JSON.parse(output.stdout);
  const record = records[0];
  if (!record || record.integrity !== item.integrity)
    throw new Error(`${item.package} registry integrity mismatch`);
  const tarball = new URL(record.filename, artifacts);
  const target = new URL(`${name}/`, extracted);
  await rm(target, { recursive: true, force: true });
  await mkdir(target, { recursive: true });
  await run("tar", [
    "-xzf",
    fileURLToPath(tarball),
    "-C",
    fileURLToPath(target),
  ]);
  return { filename: record.filename, integrity: record.integrity };
}

const widget = await pack("widget", expected.widget);
const wasm = await pack("wasm", expected.wasm);

if (process.argv.includes("--install-core")) {
  await run("bun", ["install", "--frozen-lockfile"], {
    cwd: new URL("core/", standalone),
  });
}

const provenance = {
  schema: "shar-cap-prepared-inputs-v1",
  prepared_at: new Date().toISOString(),
  standalone: expected.standalone,
  widget: { ...expected.widget, tarball: widget.filename },
  wasm: { ...expected.wasm, tarball: wasm.filename },
};
await writeFile(
  new URL("provenance.json", inputs),
  `${JSON.stringify(provenance, null, 2)}\n`,
);
console.log(
  `prepared pinned Cap inputs under ${dirname(fileURLToPath(new URL("provenance.json", inputs)))}`,
);
