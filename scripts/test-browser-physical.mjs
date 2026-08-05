import { spawn } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(
  new URL("../node_modules/@playwright/test/cli.js", import.meta.url),
);
const child = spawn(
  process.execPath,
  [cli, "test", "--project=chromium-physical", ...process.argv.slice(2)],
  {
    stdio: "inherit",
    env: { ...process.env, SHAR_TEST_PHYSICAL_GPU: "1" },
  },
);
child.once("error", (error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
child.once("exit", (code, signal) => {
  if (signal) {
    console.error(`physical browser test exited after ${signal}`);
    process.exitCode = 1;
  } else {
    process.exitCode = code ?? 1;
  }
});
