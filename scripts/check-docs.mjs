import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const ignoredDirectories = new Set([
  ".bench",
  ".git",
  "dist",
  "node_modules",
  "target",
]);

async function markdownFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await markdownFiles(absolute)));
    else if (entry.isFile() && entry.name.endsWith(".md")) files.push(absolute);
  }
  return files;
}

function destinations(markdown) {
  const links = [];
  const pattern = /!?(?:\[[^\]]*\])\((?:<([^>]+)>|([^\s)]+))(?:\s+"[^"]*")?\)/g;
  for (const match of markdown.matchAll(pattern))
    links.push(match[1] ?? match[2]);
  return links;
}

function localPath(destination) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(destination)) return undefined;
  const withoutFragment = destination.split("#", 1)[0].split("?", 1)[0];
  if (!withoutFragment) return undefined;
  try {
    return decodeURIComponent(withoutFragment);
  } catch {
    return withoutFragment;
  }
}

const failures = [];
for (const file of await markdownFiles(root)) {
  const markdown = await readFile(file, "utf8");
  for (const destination of destinations(markdown)) {
    const local = localPath(destination);
    if (local === undefined) continue;
    const target = path.resolve(path.dirname(file), local);
    if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
      failures.push(
        `${path.relative(root, file)}: link escapes the repository: ${destination}`,
      );
      continue;
    }
    try {
      const metadata = await stat(target);
      if (!metadata.isFile() && !metadata.isDirectory()) throw new Error();
    } catch {
      failures.push(
        `${path.relative(root, file)}: missing link target: ${destination}`,
      );
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log("documentation link targets passed");
