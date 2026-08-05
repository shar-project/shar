import process from "node:process";

import { listenHealthcheckUrl } from "./listen.mjs";

try {
  const response = await fetch(
    listenHealthcheckUrl(process.env.SHAR_LISTEN ?? "127.0.0.1:8080"),
    { signal: AbortSignal.timeout(2_000) },
  );
  process.exit(response.ok ? 0 : 1);
} catch {
  process.exit(1);
}
