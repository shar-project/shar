import { readFile, writeFile } from "node:fs/promises";
import {
  base64url,
  bytesToBigint,
  fromBase64url,
} from "../dist/packages/server/src/index.js";

const [input, output] = process.argv.slice(2);
if (!input || !output)
  throw new Error("usage: node test/corrupt-rsw-key.mjs INPUT OUTPUT");

const document = JSON.parse(await readFile(input, "utf8"));
const lambda = bytesToBigint(fromBase64url(document.SHAR_RSW_LAMBDA));
let corrupted = lambda + 1n;
const bytes = [];
while (corrupted > 0n) {
  bytes.push(Number(corrupted & 0xffn));
  corrupted >>= 8n;
}
document.SHAR_RSW_LAMBDA = base64url(new Uint8Array(bytes.reverse()));
await writeFile(output, `${JSON.stringify(document)}\n`, { mode: 0o600 });
