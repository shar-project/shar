# Source quickstart

This guide runs the current unreleased source tree. It starts with a complete
in-memory protocol lifecycle, then shows either standalone server and the
browser/backend integration boundary.

## Requirements

- Node.js 22 or 24 and npm;
- Rust 1.94.0 for the native server path;
- a browser with JavaScript enabled.

The `@shar/*` packages are not published yet. Use a repository checkout until a
release is listed in this project.

## 1. Build and run the full lifecycle

```sh
git clone https://github.com/shar-project/shar.git
cd shar
npm ci
npm run build
node test/runtime-smoke.mjs
```

Expected final line:

```text
pure TypeScript restricted-runtime lifecycle passed
```

That program issues two quotes, proves that later pressure does not alter the
first quote, solves and redeems the first challenge, rejects its replay, verifies
the resulting token through authenticated `siteverify`, and rejects the final
token replay.

## 2. Start a local standalone

The shortest local evaluation uses an intentionally insecure ephemeral signing
key and tiny time-lock modulus. It is fast and must never be deployed.

Build once:

```sh
npm run build
```

Run the JavaScript standalone:

```sh
SHAR_INSECURE_DEVELOPMENT=1 \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
node standalone/js/server.mjs
```

Or run the independent Rust standalone:

```sh
SHAR_INSECURE_DEVELOPMENT=1 \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
cargo run --bin shar-server
```

Both listen on `127.0.0.1:8080`. In another terminal:

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

`healthz` reports process liveness. `readyz` probes the state required to issue
and redeem work. Do not use liveness as a traffic-readiness check.

## 3. Add the widget to a form

In an application that can resolve this checkout's `@shar/widget` workspace,
import the package once and use the form-associated custom element:

```js
import "@shar/widget";
```

```html
<form method="post" action="/signup">
  <label>
    Email
    <input name="email" type="email" required />
  </label>

  <shar-challenge
    endpoint="http://127.0.0.1:8080"
    tenant="example"
    sitekey="signup-form"
    action="signup"
    name="shar-token"
  ></shar-challenge>

  <button>Sign up</button>
</form>
```

Serve the page from `http://localhost:3000`, matching the exact origin allowed
when the standalone started. The element requests finite work when executed,
shows progress and controls, then adds the short-lived verification token to
`FormData` under `shar-token`.

Never trust that browser field directly. Verification belongs in the backend.

## 4. Verify from the backend

Production startup requires a protected key bundle and a private, tenant/site-
scoped site credential. Generate both with either implementation:

```sh
npm run keygen:js -- --output shar-keys.json
chmod 600 shar-keys.json
npm run site-secret -- \
  --key-file shar-keys.json \
  --tenant example \
  --site-key signup-form
```

The Rust equivalents are:

```sh
cargo run --release --bin shar-keygen -- --output shar-keys.json
cargo run --release --bin shar-keygen -- site-secret \
  --key-file shar-keys.json \
  --tenant example \
  --site-key signup-form
```

Store the printed `shrs1_...` credential in the application backend. Do not put
it in HTML, browser JavaScript, logs, or a public environment variable. Start
Shar with the protected bundle:

```sh
SHAR_KEY_FILE="$PWD/shar-keys.json" \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
node standalone/js/server.mjs
```

On form submission, the backend sends the browser token and private site
credential to Shar:

```js
const formData = await request.formData();
const response = await fetch("http://127.0.0.1:8080/v1/siteverify", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    secret: process.env.SHAR_SITE_SECRET,
    response: formData.get("shar-token"),
    action: "signup",
    origin: "http://localhost:3000",
  }),
});

const result = await response.json();
if (
  !response.ok ||
  !result.success ||
  result.action !== "signup" ||
  result.origin !== "http://localhost:3000"
) {
  // Ask the browser to obtain new work; do not permanently ban the client.
  throw new Error(result.code ?? "verification_failed");
}
```

Act only after checking success and the expected action/origin bindings. Final
tokens are single-use and expire after five minutes.

## 5. Before any real deployment

- use HTTPS for the application and Shar endpoint;
- store `shar-keys.json` in a real secret manager and back it up securely;
- configure PostgreSQL/Redis only after reading their TLS and failure semantics;
- put `/admin/` behind an operator-only access boundary;
- implement a host-owned fallback method if your application requires one;
- review the explicit [open release gates](roadmap.md)—Shar is not GA.

Continue with [operations](operations.md), the [widget guide](../packages/widget/README.md),
or the [architecture overview](architecture.md).
