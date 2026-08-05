import { realpathSync, statSync } from "node:fs";
import { parse, resolve, sep } from "node:path";

export function canonicalAdminRoot(configured) {
  let root;
  try {
    root = realpathSync(resolve(configured));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`cannot read SHAR_ADMIN_ASSETS ${configured}: ${message}`);
  }
  if (parse(root).root === root)
    throw new Error("SHAR_ADMIN_ASSETS must not be a filesystem root");
  if (!statSync(root).isDirectory())
    throw new Error("SHAR_ADMIN_ASSETS must name an existing directory");
  return root;
}

export function decodeAdminRelative(pathname) {
  try {
    return decodeURIComponent(pathname.slice(7)) || "index.html";
  } catch {
    return undefined;
  }
}

export function resolveAdminAsset(root, relative) {
  const candidate = resolve(root, relative);
  if (candidate !== root && !candidate.startsWith(`${root}${sep}`))
    return undefined;
  try {
    const canonical = realpathSync(candidate);
    if (canonical === root || !canonical.startsWith(`${root}${sep}`))
      return undefined;
    if (!statSync(canonical).isFile()) return undefined;
    return canonical;
  } catch {
    return undefined;
  }
}
