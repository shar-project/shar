# Shar admin design system

Reference: `admin-work-policies-concept.png` at 1536×1024. The image is a
layout and visual specification; all visible UI remains code-native.

## Screen inventory

- App shell: 222 px cool-gray navigation rail, flexible white main editor,
  298 px white change-summary rail, and a full-width operational footer.
- Navigation: Shar wordmark; Overview, Work policies, Operations, Key rotation.
  Only Work policies is active in v1; inactive destinations explain that their
  dedicated view is not yet available instead of pretending to navigate.
- Header: “Work policies” and “Price abuse without rejecting valid work.” No
  eyebrow, badge, search, avatar, or notification control.
- Scope row: Tenant, Site, Action. Values are editable scope identifiers because
  v1 stores do not expose a privacy-sensitive enumeration endpoint.
- Policy editor: the eight fields in `WorkPolicy`, each with one helper line.
- Quote preview: exact tiers 0, 8, 16, 24, and 32. Time-lock iterations are
  `base × 2^tier`; rendering rounds are `base × 2^min(tier,8)`.
- Invariant band, Save changes, Discard, Policy JSON, change summary, four
  unlabeled aggregate counters, storage connectivity, and signing-key overlap.
- Authentication state: a focused unlock dialog precedes the accepted primary
  screen. The bearer secret remains in memory and is never persisted.

## Tokens

- Canvas `#ffffff`; navigation `#f6f8fb`; subtle surface `#f9fbfd`.
- Primary text `#0b1736`; body text `#26334f`; muted text `#66728a`.
- Border `#d8deea`; strong border `#aeb9cb`.
- Accent `#1457e6`; accent hover `#0d47c9`; accent soft `#eaf1ff`.
- Healthy/invariant `#008681`; healthy soft `#effaf8`; attention `#a45b00`.
- Error `#b42318`; error soft `#fff3f2`.
- Font: Inter-like system stack (`Inter`, `ui-sans-serif`, system fallbacks).
  Title 44/48 730; section 17/24 680; body 14/21 430; controls 14/20 520;
  labels 13/18 650; captions 12/18 450.
- Spacing scale: 4, 8, 12, 16, 20, 24, 32, 40 px.
- Radius: controls 4 px, selected navigation 5 px, invariant/dialog 7 px.
  No decorative rounded cards and no gradients.
- Motion: 120–180 ms color/border transitions; none when reduced motion is
  requested.

## Component families

- `NavItem`: icon, label, selected/hover/focus states.
- `ScopeField` and `PolicyField`: shared label/control/error/helper anatomy.
- `Button`: primary and secondary only.
- `QuotePreview`: semantic table with tabular numbers and responsive horizontal
  scroll rather than a fabricated chart.
- `InvariantBand`: static policy guarantee with shield/check icon.
- `ChangeSummary`: selected scope and only values changed from the loaded policy.
- `MetricItem`: label, live value or em dash, and connection note.
- `UnlockDialog`: endpoint and bearer secret, accessible error/status handling.

## Responsive rules

- ≥1280 px: three-column shell matching the concept.
- 840–1279 px: compact rail, main editor, summary below actions; operational
  footer wraps to three columns.
- <840 px: top brand/navigation bar, single-column fields, horizontally
  scrollable quote table, summary after the invariant, and two-column metrics.
- <520 px: one-column metrics and full-width actions. No primary content clips
  at 400% zoom.

## Implementation fidelity review

The 1536×1024 Playwright capture was compared directly with the accepted
concept after the production bundle was rendered under its deployed CSP:

- the 222 px navigation rail, flexible editor, 298 px summary rail, and bottom
  operations strip preserve the reference hierarchy and proportions;
- the navy system typography, cobalt active/action treatment, teal invariant,
  cool-gray navigation, square controls, fine borders, and absence of gradients
  match the token sheet;
- the eight policy controls keep the reference's label/control/helper rows and
  the preview uses the same five exact tier values and tabular-number treatment;
- the invariant band, save/discard actions, summary, policy-JSON action, and six
  operations cells retain their reference position and relative emphasis;
- the implementation preserves the intentionally open white canvas and avoids
  decorative cards, fabricated charts, badges, or generated-image UI assets.

Two deliberate functional differences remain. Scope identifiers are editable
text plus an explicit **Load scope** action because v1 intentionally has no
tenant/site enumeration API; the concept's select affordances would imply one.
The operations strip renders real zero counters and connected key/store state
when those endpoints answer, while the static concept shows empty states. The
concept's tiny “lPolicy” image-generation typo is corrected to “Policy”.
