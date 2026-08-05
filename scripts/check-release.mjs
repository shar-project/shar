import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const defaultRoot = new URL("../", import.meta.url);

export async function checkRelease(tag, root = defaultRoot) {
  if (!tag || !/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(tag)) {
    throw new Error("release tag must be a stable SemVer tag such as v1.2.3");
  }
  const version = tag.slice(1);

  async function json(path) {
    return JSON.parse(await readFile(new URL(path, root), "utf8"));
  }

  function requireEqual(actual, expected, message) {
    if (actual !== expected)
      throw new Error(
        `${message}: found ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`,
      );
  }

  const packageDefinitions = [
    { path: "packages/server/package.json", name: "@shar/server" },
    {
      path: "packages/widget/package.json",
      name: "@shar/widget",
      dependencies: { "@shar/server": version },
    },
    {
      path: "packages/cap-compat/package.json",
      name: "@shar/cap-compat",
      dependencies: { "@shar/widget": version },
    },
  ];

  const rootManifest = await json("package.json");
  requireEqual(rootManifest.name, "shar", "package.json name");
  requireEqual(rootManifest.version, version, "package.json version");
  requireEqual(rootManifest.license, "MIT", "package.json license");
  requireEqual(rootManifest.private, true, "package.json must remain private");

  for (const definition of packageDefinitions) {
    const manifest = await json(definition.path);
    requireEqual(manifest.name, definition.name, `${definition.path} name`);
    requireEqual(manifest.version, version, `${definition.path} version`);
    requireEqual(manifest.license, "MIT", `${definition.path} license`);
    requireEqual(
      manifest.publishConfig?.access,
      "public",
      `${definition.path} publish access`,
    );
    requireEqual(
      manifest.publishConfig?.provenance,
      true,
      `${definition.path} npm provenance`,
    );
    requireEqual(
      manifest.repository?.url,
      "git+https://github.com/shar-project/shar.git",
      `${definition.path} repository`,
    );
    requireEqual(
      manifest.repository?.directory,
      definition.path.replace(/\/package\.json$/, ""),
      `${definition.path} repository directory`,
    );
    for (const [dependency, expected] of Object.entries(
      definition.dependencies ?? {},
    ))
      requireEqual(
        manifest.dependencies?.[dependency],
        expected,
        `${definition.path} dependency ${dependency}`,
      );
  }

  const packageLock = await json("package-lock.json");
  requireEqual(packageLock.name, "shar", "package-lock.json name");
  requireEqual(packageLock.version, version, "package-lock.json version");
  requireEqual(
    packageLock.packages?.[""]?.version,
    version,
    "package-lock.json root package version",
  );
  requireEqual(
    packageLock.packages?.[""]?.license,
    "MIT",
    "package-lock.json root package license",
  );
  for (const definition of packageDefinitions) {
    const directory = definition.path.replace(/\/package\.json$/, "");
    const locked = packageLock.packages?.[directory];
    requireEqual(locked?.name, definition.name, `${directory} lockfile name`);
    requireEqual(locked?.version, version, `${directory} lockfile version`);
    requireEqual(locked?.license, "MIT", `${directory} lockfile license`);
    for (const [dependency, expected] of Object.entries(
      definition.dependencies ?? {},
    ))
      requireEqual(
        locked?.dependencies?.[dependency],
        expected,
        `${directory} lockfile dependency ${dependency}`,
      );
  }

  const cargo = await readFile(new URL("Cargo.toml", root), "utf8");
  const workspaceMarker = "[workspace.package]";
  const workspaceStart = cargo.indexOf(workspaceMarker);
  const afterWorkspace =
    workspaceStart < 0
      ? ""
      : cargo.slice(workspaceStart + workspaceMarker.length);
  const nextSection = afterWorkspace.search(/^\[/m);
  const workspacePackage =
    workspaceStart < 0
      ? ""
      : nextSection < 0
        ? afterWorkspace
        : afterWorkspace.slice(0, nextSection);
  if (!workspacePackage)
    throw new Error("Cargo.toml is missing [workspace.package]");
  if (
    !new RegExp(`^version = "${version.replaceAll(".", "\\.")}"$`, "m").test(
      workspacePackage,
    )
  )
    throw new Error("Cargo workspace version does not match the release");
  if (!/^license = "MIT"$/m.test(workspacePackage))
    throw new Error("Cargo workspace license must be MIT");

  for (const crate of ["shar-core", "shar-server", "shar-widget-wasm"]) {
    const manifest = await readFile(
      new URL(`crates/${crate}/Cargo.toml`, root),
      "utf8",
    );
    if (!new RegExp(`^name = "${crate}"$`, "m").test(manifest))
      throw new Error(`crates/${crate}/Cargo.toml has the wrong package name`);
    for (const inherited of ["version", "edition", "license", "repository"])
      if (!new RegExp(`^${inherited}\\.workspace = true$`, "m").test(manifest))
        throw new Error(`crates/${crate}/Cargo.toml must inherit ${inherited}`);
  }

  const cargoLock = await readFile(new URL("Cargo.lock", root), "utf8");
  for (const crate of ["shar-core", "shar-server", "shar-widget-wasm"]) {
    const escaped = crate.replaceAll("-", "\\-");
    if (
      !new RegExp(
        `^name = "${escaped}"\\nversion = "${version.replaceAll(".", "\\.")}"$`,
        "m",
      ).test(cargoLock)
    )
      throw new Error(`Cargo.lock ${crate} version does not match the release`);
  }

  return `release metadata and lockfiles are consistent for ${tag}`;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url)
  console.log(await checkRelease(process.argv[2]));
