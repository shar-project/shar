import { readFile, stat } from "node:fs/promises";
import process from "node:process";
import {
  deriveSiteVerifySecret,
  fromBase64url,
} from "../../dist/packages/server/src/index.js";

const values = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const flag = process.argv[index];
  const value = process.argv[index + 1];
  if (!flag?.startsWith("--") || value === undefined) usage();
  values.set(flag, value);
}
const tenant = values.get("--tenant");
const siteKey = values.get("--site-key");
if (!tenant || !siteKey) usage();

let encodedMaster = process.env.SHAR_SITEVERIFY_MASTER_SECRET;
const keyFile = values.get("--key-file") ?? process.env.SHAR_KEY_FILE;
if (!encodedMaster && keyFile) {
  const metadata = await stat(keyFile);
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0)
    throw new Error("key file must not be accessible by group or other users");
  const document = JSON.parse(await readFile(keyFile, "utf8"));
  encodedMaster = document.SHAR_SITEVERIFY_MASTER_SECRET;
}
if (!encodedMaster)
  throw new Error(
    "set SHAR_SITEVERIFY_MASTER_SECRET or pass --key-file with a generated key bundle",
  );
const master = fromBase64url(encodedMaster);
if (master.length !== 32)
  throw new Error("SHAR_SITEVERIFY_MASTER_SECRET must decode to 32 bytes");
process.stdout.write(
  `${await deriveSiteVerifySecret(master, tenant, siteKey)}\n`,
);

function usage() {
  throw new Error(
    "usage: npm run site-secret -- --tenant TENANT --site-key SITE [--key-file PATH]",
  );
}
