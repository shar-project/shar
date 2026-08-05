# @shar/cap-compat

Compatibility custom element for migrating `<cap-widget>` integrations to a
Shar endpoint while retaining common attributes, events, and form behavior.

Import the package once, then point the existing widget at a Shar deployment:

```html
<script type="module" src="/dist/index.js"></script>
<cap-widget
  data-cap-api-endpoint="https://verify.example"
  data-cap-hidden-field-name="cap-token"
></cap-widget>
```

The adapter preserves `solve()`, `reset()`, `token`, `tokenValue`, the
`solve`/`progress`/`error`/`reset` events, custom hidden-field names, and the
usual `data-cap-*` endpoint, locale, worker-count, and label attributes. It
does not execute inline JavaScript attribute values; use event listeners (or
the safe global callback names supported by Cap) instead.

For constructor-style integrations, `new Cap({ apiEndpoint })` creates a
hidden compatible widget and exposes the same `solve`, `reset`, and token
surface.

Successful Shar responses retain their native expiry. When the inclusive
expiry second ends, the response and `cap-token` compatibility field are
cleared and the widget emits `expired`; an expired token is never restored from
browser form history.

The compatibility element owns exactly one hidden submission field. It opts out
of Shar's separate `ElementInternals` value, follows
`data-cap-hidden-field-name`, and mirrors disabled fieldset/element state, so a
form never submits duplicate `shar-token` and `cap-token` values.
