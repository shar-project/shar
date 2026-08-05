import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, workspace } from "./lib.mjs";

const ENTRY_NAME = "shar.js";

/** Build the production widget as one eager graph plus optional lazy chunks. */
export async function buildWidgetBundle() {
  const directory = await mkdtemp(join(tmpdir(), "shar-widget-bundle-"));
  try {
    await run(
      "npx",
      [
        "rolldown",
        "packages/widget/dist/index.js",
        "--dir",
        directory,
        "--format",
        "esm",
        "--minify",
        "--entryFileNames",
        ENTRY_NAME,
        "--chunkFileNames",
        "[name]-[hash].js",
      ],
      { cwd: workspace, capture: true },
    );
    const names = (await readdir(directory))
      .filter((name) => name.endsWith(".js"))
      .sort();
    if (!names.includes(ENTRY_NAME))
      throw new Error("widget bundle entry is missing");
    const sources = new Map(
      await Promise.all(
        names.map(async (name) => [
          name,
          await readFile(join(directory, name)),
        ]),
      ),
    );
    const eager = new Set([ENTRY_NAME]);
    const visit = (name) => {
      const source = sources.get(name)?.toString("utf8");
      if (source === undefined)
        throw new Error(`missing widget chunk: ${name}`);
      for (const match of source.matchAll(
        /(?:^|\n)import(?:[^"'\n]*?from\s*)?["']\.\/([^"']+)["'];?/g,
      )) {
        const dependency = match[1];
        if (!sources.has(dependency))
          throw new Error(`missing static widget dependency: ${dependency}`);
        if (!eager.has(dependency)) {
          eager.add(dependency);
          visit(dependency);
        }
      }
    };
    visit(ENTRY_NAME);
    const resources = (selected) =>
      [...selected].sort().map((name) => ({ name, bytes: sources.get(name) }));
    return {
      eager: resources(eager),
      lazy: resources(names.filter((name) => !eager.has(name))),
      async dispose() {
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
