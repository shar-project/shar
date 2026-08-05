import { expect, test } from "@playwright/test";

const secret = "admin-test-secret-0000000000";
const defaultPolicy = {
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

test.beforeEach(async ({ request }) => {
  const response = await request.put("/v1/admin/policy", {
    headers: { authorization: `Bearer ${secret}` },
    data: defaultPolicy,
  });
  expect(response.ok()).toBe(true);
});

function captureErrors(page) {
  const errors = [];
  page.on("console", (message) => {
    if (["warning", "error"].includes(message.type()))
      errors.push(`${message.type()}: ${message.text()}`);
  });
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  return errors;
}

async function unlock(page) {
  await page.goto("/admin/");
  await expect(
    page.getByRole("heading", { name: "Open Shar administration" }),
  ).toBeVisible();
  await page.getByLabel("Admin secret").fill("incorrect-secret-value");
  await page.getByRole("button", { name: "Open dashboard" }).click();
  await expect(page.getByRole("alert")).toHaveText(
    "That admin secret was not accepted.",
  );
  await page.getByLabel("Admin secret").fill(secret);
  await page.getByRole("button", { name: "Open dashboard" }).click();
  await expect(
    page.getByRole("heading", { name: "Work policies" }),
  ).toBeVisible();
}

test("admin policy editor authenticates, previews exact work, and persists changes", async ({
  page,
}) => {
  const errors = captureErrors(page);
  await page.setViewportSize({ width: 1536, height: 1024 });
  await unlock(page);
  errors.length = 0;

  await expect(page.getByText("Correct work always succeeds")).toBeVisible();
  await expect(page.getByRole("row", { name: /Tier 8/ })).toContainText(
    "262,144",
  );
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();
  await expect(page.getByText("1 signing key")).toBeVisible();
  expect(errors).toEqual([]);

  await page.screenshot({
    path: "/tmp/shar-admin-implementation.png",
    fullPage: false,
    caret: "initial",
  });
  // WebKit reports Playwright's capture-only stylesheet against the page CSP.
  // Application console health was asserted immediately before the capture.
  errors.length = 0;

  await page.getByLabel("Base iterations").fill("2048");
  await expect(page.getByRole("row", { name: /Tier 8/ })).toContainText(
    "524,288",
  );
  await expect(
    page.getByRole("definition").filter({ hasText: "2048" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("status")).toContainText(
    "Policy saved. New quotes now use this configuration.",
  );
  await expect(page.getByText("No unsaved changes.")).toBeVisible();

  await page.getByRole("button", { name: "Policy JSON" }).click();
  await expect(page.getByRole("dialog", { name: "Policy JSON" })).toContainText(
    '"base_iterations": "2048"',
  );
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "Policy JSON" })).toHaveCount(
    0,
  );
  await page.getByRole("button", { name: "Operations" }).click();
  await expect(page.getByRole("heading", { name: "Operations" })).toBeVisible();
  await expect(page.getByText("Challenges issued")).toBeVisible();
  await expect(page.getByText("Healthy", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Audit events" }).click();
  await expect(
    page.getByRole("heading", { name: "Audit events" }),
  ).toBeVisible();
  await expect(
    page.getByRole("row", { name: /challenge issued/ }),
  ).toBeVisible();

  expect(errors).toEqual([]);
});

test("admin editor remains usable at narrow and 400%-equivalent viewports", async ({
  page,
}) => {
  const errors = captureErrors(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/admin/");
  const secretInput = page.getByLabel("Admin secret");
  await expect(secretInput).toBeFocused();
  await page.keyboard.type(secret);
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Open dashboard" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("heading", { name: "Work policies" }),
  ).toBeVisible();
  errors.length = 0;
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    page: document.documentElement.scrollWidth,
  }));
  expect(dimensions.page).toBeLessThanOrEqual(dimensions.viewport);
  const menu = page.getByRole("button", { name: "Menu" });
  await expect(menu).toBeVisible();
  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await expect(
    page.getByRole("navigation", { name: "Administration" }),
  ).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.getByText("Correct work always succeeds")).toBeVisible();
  expect(errors).toEqual([]);
});

test("admin dialogs and mobile navigation retain keyboard focus", async ({
  page,
}) => {
  const errors = captureErrors(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await unlock(page);
  errors.length = 0;

  const jsonTrigger = page.getByRole("button", { name: "Policy JSON" });
  await jsonTrigger.focus();
  await page.keyboard.press("Enter");
  const close = page.getByRole("button", { name: "Close policy JSON" });
  const document = page.getByLabel("Policy JSON document");
  await expect(close).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(document).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(close).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(jsonTrigger).toBeFocused();

  const menu = page.getByRole("button", { name: "Menu" });
  await menu.focus();
  await page.keyboard.press("Enter");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Overview" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(menu).toBeFocused();
  await expect(menu).toHaveAttribute("aria-expanded", "false");

  await page.keyboard.press("Enter");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Work policies" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  expect(errors).toEqual([]);
});

test("admin honors reduced motion and forced color system settings", async ({
  page,
}) => {
  const errors = captureErrors(page);
  await page.emulateMedia({ reducedMotion: "reduce", forcedColors: "active" });
  await unlock(page);
  errors.length = 0;
  const result = await page.evaluate(() => {
    const milliseconds = (value) =>
      Math.max(
        ...value.split(",").map((part) => {
          const duration = part.trim();
          return duration.endsWith("ms")
            ? Number.parseFloat(duration)
            : Number.parseFloat(duration) * 1_000;
        }),
      );
    const active = document.querySelector(".nav-item.active");
    const dot = document.querySelector(".status-dot");
    const activeStyle = getComputedStyle(active);
    const dotStyle = getComputedStyle(dot);
    return {
      reduced: matchMedia("(prefers-reduced-motion: reduce)").matches,
      forced: matchMedia("(forced-colors: active)").matches,
      transitionMs: milliseconds(activeStyle.transitionDuration),
      animationMs: milliseconds(activeStyle.animationDuration),
      activeBorder: activeStyle.borderTopWidth,
      dotBorder: dotStyle.borderTopWidth,
    };
  });
  expect(result).toEqual({
    reduced: true,
    forced: true,
    transitionMs: 0.01,
    animationMs: 0.01,
    activeBorder: "2px",
    dotBorder: "2px",
  });
  expect(errors).toEqual([]);
});
