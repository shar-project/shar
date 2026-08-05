import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";

const root = resolve(process.cwd());
const adminSecret = "admin-test-secret-0000000000";
let policy = {
  tenant: "default",
  site_key: "production",
  action: "signup",
  policy: {
    version: "policy-v1",
    base_iterations: "1024",
    base_render_rounds: 1,
    quiet_window_seconds: 60,
    base_lifetime_seconds: 120,
    iteration_allowance: "100000",
    round_allowance_seconds: 2,
    max_lifetime_seconds: 86400,
  },
};
const types = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".map", "application/json"],
]);
const security = {
  "content-security-policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
};

function json(response, status, body) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(body));
}
async function requestBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/healthz") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
      return;
    }
    if (url.pathname === "/v1/admin/policy") {
      if (request.headers.authorization !== `Bearer ${adminSecret}`) {
        json(response, 401, {
          code: "admin_unauthorized",
          retryable: false,
          next_action: "none",
        });
        return;
      }
      if (request.method === "GET") {
        json(response, 200, {
          ...policy,
          tenant: url.searchParams.get("tenant"),
          site_key: url.searchParams.get("site_key"),
          action: url.searchParams.get("action"),
        });
        return;
      }
      if (request.method === "PUT") {
        policy = JSON.parse(await requestBody(request));
        json(response, 200, policy);
        return;
      }
    }
    if (url.pathname === "/v1/admin/audit") {
      if (request.headers.authorization !== `Bearer ${adminSecret}`) {
        json(response, 401, {
          code: "admin_unauthorized",
          retryable: false,
          next_action: "none",
        });
        return;
      }
      json(response, 200, {
        tenant: url.searchParams.get("tenant"),
        site_key: url.searchParams.get("site_key"),
        action: url.searchParams.get("action"),
        events: [
          {
            version: "audit-v1",
            kind: "challenge_issued",
            occurred_at: 1_800_000_000,
            tenant: url.searchParams.get("tenant"),
            site_key: url.searchParams.get("site_key"),
            action: url.searchParams.get("action"),
            tier: 0,
          },
        ],
      });
      return;
    }
    if (url.pathname === "/metrics") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(
        "shar_challenges_issued_total 0\nshar_challenges_redeemed_total 0\nshar_site_verifications_total 0\nshar_fallback_completions_total 0\n",
      );
      return;
    }
    if (url.pathname === "/.well-known/shar/v1") {
      json(response, 200, { keys: [{ kid: "test" }], modulus_ids: ["test"] });
      return;
    }
    if (url.pathname === "/admin") {
      response.writeHead(308, { location: "/admin/" });
      response.end();
      return;
    }
    const pathname = url.pathname.startsWith("/admin/")
      ? `/dist/admin/${url.pathname.slice(7) || "index.html"}`
      : url.pathname;
    const relative = decodeURIComponent(pathname).replace(/^\/+/, "");
    const path = resolve(root, relative);
    if (path !== root && !path.startsWith(`${root}${sep}`))
      throw new Error("path");
    const bytes = await readFile(path);
    response.writeHead(200, {
      "content-type": types.get(extname(path)) ?? "application/octet-stream",
      "cache-control": "no-store",
      ...(url.pathname.startsWith("/admin/") ? security : {}),
    });
    response.end(bytes);
  } catch {
    response.writeHead(404, { "content-type": "text/plain" });
    response.end("not found");
  }
}).listen(4173, "127.0.0.1");
