# @shar/widget

Browser client and form-associated `<shar-challenge>` custom element for Shar.
It solves one canonical rendering challenge through WebGPU, WebGL2, or the CSS
layout engine, and always retains the CPU-capable fallback path.

The package exports `Shar.render()`, `Shar.execute()`, pause/resume/reset
controls, and reCAPTCHA/hCaptcha-shaped browser adapters. The adapters retain
the provider-style `ready`, `render`, `execute`, `reset`, `getResponse`, and
`remove` methods, callback names, and form response field names while executing
the exact same signed Shar quote.

## Localization

English is built into the widget. Optional catalogs for Arabic, German,
Spanish, French, Hebrew, Hindi, Japanese, Brazilian Portuguese, and Simplified
Chinese are separate entry points, so applications only ship the languages
they select:

```js
import { Shar } from "@shar/widget";
import { esTranslations } from "@shar/widget/locales/es";

Shar.registerTranslations("es", esTranslations);
```

The other entry points are `ar`, `de`, `fr`, `he`, `hi`, `ja`, `pt-br`, and
`zh-cn`. Register region or script aliases explicitly when the application
needs them; for example, the Simplified Chinese catalog can be registered for
both `zh-CN` and `zh-Hans`. Changing a connected element's `lang` attribute
updates its live status, work estimate, accessible labels, controls, number
formatting, and text direction without restarting or changing its signed quote.

Custom catalogs implement the exported `SharTranslations` interface. Shar
rejects invalid language tags, missing or empty messages, control characters,
oversized values, and missing or repeated interpolation placeholders. The
bundled translations still require professional linguistic review for each
deployment's audience before GA.

Each rendered element owns its execution controls. Multiple forms can solve in
parallel; pausing, resuming, resetting, replacing, or removing one widget does
not cancel another. The global `Shar.pause()`, `Shar.resume()`, and
`Shar.reset()` conveniences target the most recently started programmatic or
rendered execution.

## Accessibility and host styling

The custom element exposes a labelled status region, progress element, and
keyboard-operable verify, pause/resume, and fallback controls. Controls retain
44 CSS-pixel minimum targets, visible keyboard focus, narrow-screen reflow, and
system forced-color behavior. Motion is removed when
`prefers-reduced-motion: reduce` is active. The solving surface remains hidden
from the accessibility tree and cannot intercept host-page interaction.

Default presentation comes from one reviewed static constructed stylesheet in
the shadow root. It does not depend on inline `style` attributes, generated
rules, or a relaxed `style-src` CSP. Hosts can customize the documented parts
without reaching into the shadow tree: `container`, `status`, `expected-work`,
`progress`, `button`, `verify-button`, `pause-button`, and `fallback-button`.
For example:

```css
shar-challenge::part(button) {
  font: inherit;
}
```

```js
import { createRecaptchaAdapter, installHcaptchaAdapter } from "@shar/widget";

const grecaptcha = createRecaptchaAdapter({
  endpoint: "https://shar.example",
  tenant: "public",
});
const widgetId = grecaptcha.render("#challenge", {
  sitekey: "site-a",
  action: "signup",
  callback: (token) => submitWith(token),
});
await grecaptcha.execute(widgetId);

// Installation on globalThis is explicit and refuses to replace an existing
// hCaptcha SDK global.
installHcaptchaAdapter({
  endpoint: "https://shar.example",
  sitekey: "site-a",
});
```

`execute("site-key", { action: "checkout" })` provides the common invisible/
v3-shaped flow and returns the Shar verification token. Compatibility changes
only the integration surface: it never bypasses rendering, time-lock work,
expiry, or replay protection.

## Host fallback plans

The fallback control is hidden until an issued challenge advertises an
available `FallbackPlan` with at least one method. Selecting it emits a
`fallback` event whose detail contains the exact method list and the advertised
presence plan; the host can then open its passkey, email, authenticated-session,
support, or equivalent flow. `getFallbackMethods()` returns a defensive copy of
the same list.

The widget never calls the privileged completion endpoint or receives its
bearer secret. A host backend verifies the selected method, submits a unique
assertion id to `/v1/fallback/complete`, and handles the direct bound result.
Fallback does not create a work receipt and does not make an incomplete proof
valid. A server without fallback configuration advertises an empty plan, so the
widget does not offer a dead-end control.

The complete server-side stored-assertion pattern, exact binding requirements,
and Rust/TypeScript examples are in
[`docs/fallback.md`](../../docs/fallback.md). The browser must never receive the
fallback bearer secret or permission to create a successful assertion record.

## Optional Rust/WASM time-lock acceleration

The default sequential solver is pure JavaScript `BigInt` and is always
available. Hosts may opt into the packaged Rust/WASM chunk accelerator without
changing the signed plan, proof output, checkpoint format, or server behavior:

```js
await Shar.execute("site-a", {
  action: "signup",
  endpoint: "https://shar.example",
  timeLockWasm: true,
});
```

The equivalent custom-element opt-in is `<shar-challenge timelock-wasm>`. A
string or URL passed as `timeLockWasm`, or used as the attribute value, selects
a host-controlled static asset URL. The packaged asset is also exported as
`@shar/widget/timelock.wasm` for bundlers and static-copy steps.

Each WASM call is capped at 65,536 squarings over an integer no larger than 512
bytes. Progress, pause, navigation checkpoints, and fallback remain bounded at
the same chunk boundary. Fetch, compilation, allocation, or execution failure
restores the pre-chunk value and continues through JavaScript, so enabling the
accelerator never creates a correctness dependency on WebAssembly. It uses no
worker, blob URL, generated function, filesystem, native addon, or Node API.

An opt-in strict CSP must allow the asset through `connect-src` and WASM
compilation through `script-src 'wasm-unsafe-eval'`. Hosts that omit that token
continue through JavaScript. The default cold path does not fetch the optional
68 KiB artifact. Its SHA-256 is
`bf27c58d78885cb6b80d38fae2a605c18b1130b25d3fcc62fdc5c55f5058e4ce`.
Rebuild or verify the committed artifact with pinned Rust 1.94.0 and the
`wasm32-unknown-unknown` target:

```sh
scripts/build-widget-wasm.sh
scripts/build-widget-wasm.sh --check
```

## Navigation resume

An in-progress execution is checkpointed between bounded work chunks and
rendering rounds in same-tab `sessionStorage`. Reloading or navigating back and
calling `execute()` again resumes the exact unexpired signed quote; it does not
request easier work. The record is scoped to endpoint, tenant, site key, action,
and origin, capped at 4 MiB, and contains no cookie or stable device identifier.
Successful verification and `reset()` remove it. Expired, malformed,
non-canonical, or wrong-scope state is removed and a fresh quote can be
requested. If storage is unavailable or full, execution remains correct and
recomputes work instead.

The checkpoint is not trusted proof. The server still verifies the signed
quote, sequential output, canonical rendering digest, expiry, and single-use
nonce. Same-origin scripts can read `sessionStorage`, so apply the same script
integrity and CSP controls used for any in-flight verification token.

Because storage is intentionally capped to one same-tab record, concurrent
widgets all continue correctly in memory but only the most recently persisted
execution is navigation-resumable. Ownership checks prevent an older execution
or a differently scoped widget reset from overwriting or deleting that record.

A successful response is automatically cleared just after its inclusive signed
expiry second. The widget removes the stale form value, announces
“Verification expired,” and emits one `expired` event; `getResponse()` also
checks the absolute deadline synchronously so background-tab timer throttling
cannot return an expired token. Starting new work or calling `reset()` clears
the previous response and timer.

## Blinded trust credits

Trust-credit helpers are available from the optional subpath so applications
that do not use trust credits do not carry the VOPRF implementation in their
default cold path:

```js
import {
  issueWithTrustCredit,
  prepareTrustCreditIssuance,
} from "@shar/widget/trust-credits";
```

When the server advertises an optional VOPRF trust plan, the widget generates a
fresh secret token nonce and browser-side blind, sends only the blinded point
with its completed work, verifies the issuer proof, and keeps one finalized
`shrtrust1_` credit for the next quote. The nonce and VOPRF input are never
provided by or disclosed to the issuer during issuance, preventing a later
spend from being matched to the blinded transcript by protocol values alone.
Credits use a separate, bounded same-tab `sessionStorage` wallet;
there are no cookies, cross-tab identifiers, or device-derived inputs. Each
entry is bound to the normalized endpoint, tenant, site key, action, and origin,
and the cryptographic token repeats the tenant/site/action/origin binding.

The wallet retains at most one credit per scope and 16 scopes total. An issued
quote consumes the offered credit locally. If the server explicitly reports a
stale, replayed, unknown-key, or otherwise invalid credit, the widget removes it
and retries issuance once without a credit. Operational errors retain it for a
later attempt. Concurrent executions in the same page cannot offer the same
local token. Expired, malformed, wrong-scope, oversized, or corrupted records
are discarded; disabled or full storage merely disables this pricing
optimization. Blinding, proof verification, finalization, and storage failures
never invalidate completed work or suppress a successful verification token.
The main widget loads this module only when a stored credit exists or an issued
challenge advertises trust-credit issuance.

## Native forms

`<shar-challenge>` participates in `FormData` through `ElementInternals` and
uses a hidden-input fallback where form-associated custom elements are not
available:

```html
<form method="post" action="/signup">
  <shar-challenge
    endpoint="https://shar.example"
    sitekey="site-a"
    action="signup"
    name="shar-token"
  ></shar-challenge>
  <button>Sign up</button>
</form>
```

Native form and fieldset behavior is preserved: `form.reset()` clears the
response and in-flight checkpoint, a disabled element or fieldset cannot execute, and
changing `name` updates the submitted field. Browser history/autocomplete state
never restores a short-lived verification token; it clears the form value while
leaving an exact unexpired work checkpoint available to resume. `Shar.render()`
forwards its optional `AbortSignal` and event callback to the element's eventual
execution.
