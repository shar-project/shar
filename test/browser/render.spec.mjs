import { expect, test } from "@playwright/test";
import {
  base64url,
  decodeTrustCreditToken,
  deriveTrustKeyPair,
  deriveScopedTrustKeyPair,
  equalTrustOutput,
  evaluateTrustDirect,
  evaluateTrustInput,
  fromBase64url,
  trustCreditChallengeDigest,
  trustInputForScope,
} from "../../packages/server/dist/index.js";

function capturePageErrors(page) {
  const messages = [];
  page.on("console", (message) => {
    if (["warning", "error"].includes(message.type())) {
      messages.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => messages.push(`pageerror: ${error.message}`));
  return messages;
}

function expectNoRelevantErrors(messages) {
  const relevant = messages.filter(
    (message) =>
      !message.includes("GPU stall due to ReadPixels") &&
      !message.includes("No available adapters") &&
      !message.includes("Failed to create WebGL context"),
  );
  expect(relevant).toEqual([]);
}

test("render-v1 CPU and browser executors produce one digest", async ({
  page,
  browserName,
}) => {
  const messages = capturePageErrors(page);
  await page.goto("/test/browser/render-harness.html");
  await expect(page).toHaveTitle("Shar render-v1 conformance");
  await expect(
    page.getByRole("heading", { name: "Shar render-v1 conformance" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Run conformance" }).click();
  await expect(page.getByRole("status")).toHaveText("Conformance complete", {
    timeout: 45_000,
  });
  for (const id of ["cpu", "css", "adaptive"]) {
    await expect(page.locator(`#${id}`)).toHaveClass("pass");
  }
  if (browserName === "chromium") {
    await expect(page.locator("#webgl2")).toHaveClass("pass");
    await expect(page.locator("#webgpu")).toHaveClass("pass");
  } else {
    await expect(page.locator("#webgl2")).toHaveClass(/^(pass|skip)$/);
    await expect(page.locator("#webgpu")).toHaveClass(/^(pass|skip)$/);
  }
  await expect(page.locator("[data-shar-render-surface]")).toHaveCount(0);
  expectNoRelevantErrors(messages);
  await page.screenshot({
    path: "/tmp/shar-render-conformance.png",
    fullPage: false,
    caret: "initial",
  });
});

test("render-v1 stays identical across deterministic geometry cases", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.goto("/test/browser/render-harness.html");
  const results = await page.evaluate(() => globalThis.runRenderMatrix());
  expect(results).toHaveLength(3);
  for (const result of results) {
    expect(result.webgl2).toMatch(/^(pass|skip)$/);
    expect(result.webgpu).toMatch(/^(pass|skip)$/);
  }
  await expect(page.locator("[data-shar-render-surface]")).toHaveCount(0);
  expectNoRelevantErrors(messages);
});

test("adaptive executor retains completed rounds when WebGL2 falls back to CSS", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "gpu", {
      configurable: true,
      get: () => undefined,
    });
    const canvasPrototype =
      globalThis.OffscreenCanvas?.prototype ?? HTMLCanvasElement.prototype;
    const original = canvasPrototype.getContext;
    let webglContexts = 0;
    canvasPrototype.getContext = function (type, options) {
      if (type === "webgl2" && ++webglContexts > 1) return null;
      return original.call(this, type, options);
    };
  });
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(() =>
    globalThis.runAdaptiveFallbackHarness(),
  );
  expect(result.backend).toBe("css");
  expect(result.changes).toEqual(["webgpu", "webgl2", "css"]);
  expect(result.completed).toEqual([1, 2]);
  await expect(page.locator("[data-shar-render-surface]")).toHaveCount(0);
  expectNoRelevantErrors(messages);
});

test("actual WebGPU and WebGL2 loss resumes the same work through CSS", async ({
  page,
  browserName,
}) => {
  test.skip(
    browserName !== "chromium",
    "WebGPU loss injection requires Chromium",
  );
  const messages = capturePageErrors(page);
  await page.addInitScript(() => {
    const losses = { webgpu: 0, webgl2: 0 };
    globalThis.__sharInjectedLosses = losses;
    const originalGpu = navigator.gpu;
    if (originalGpu) {
      let submissions = 0;
      const wrappedGpu = {
        requestAdapter: async (...adapterArguments) => {
          const adapter = await originalGpu.requestAdapter(...adapterArguments);
          if (!adapter) return adapter;
          return {
            requestDevice: async (...deviceArguments) => {
              const device = await adapter.requestDevice(...deviceArguments);
              const queue = device.queue;
              const wrappedQueue = new Proxy(queue, {
                get(target, property) {
                  if (property === "submit")
                    return (...arguments_) => {
                      const result = target.submit(...arguments_);
                      submissions++;
                      if (submissions === 2) {
                        losses.webgpu++;
                        device.destroy();
                      }
                      return result;
                    };
                  const value = Reflect.get(target, property, target);
                  return typeof value === "function"
                    ? value.bind(target)
                    : value;
                },
              });
              return new Proxy(device, {
                get(target, property) {
                  if (property === "queue") return wrappedQueue;
                  const value = Reflect.get(target, property, target);
                  return typeof value === "function"
                    ? value.bind(target)
                    : value;
                },
              });
            },
          };
        },
      };
      Object.defineProperty(Navigator.prototype, "gpu", {
        configurable: true,
        get: () => wrappedGpu,
      });
    }

    const patchedContexts = new WeakSet();
    for (const prototype of [
      globalThis.OffscreenCanvas?.prototype,
      HTMLCanvasElement.prototype,
    ]) {
      if (!prototype) continue;
      const originalGetContext = prototype.getContext;
      prototype.getContext = function (type, options) {
        const context = originalGetContext.call(this, type, options);
        if (type !== "webgl2" || !context || patchedContexts.has(context))
          return context;
        patchedContexts.add(context);
        const drawArrays = context.drawArrays.bind(context);
        context.drawArrays = (...arguments_) => {
          const result = drawArrays(...arguments_);
          const extension = context.getExtension("WEBGL_lose_context");
          if (extension) {
            losses.webgl2++;
            extension.loseContext();
          }
          return result;
        };
        return context;
      };
    }
  });
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(async () => ({
    result: await globalThis.runAdaptiveFallbackHarness(),
    losses: globalThis.__sharInjectedLosses,
  }));
  expect(result.losses).toEqual({ webgpu: 1, webgl2: 1 });
  expect(result.result.backend).toBe("css");
  expect(result.result.changes).toEqual(["webgpu", "webgl2", "css"]);
  expect(result.result.completed).toEqual([1, 2]);
  await expect(page.locator("[data-shar-render-surface]")).toHaveCount(0);
  expectNoRelevantErrors(messages);
});

test("connected widgets relocalize live state and late translation registration", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(async () => {
    const { Shar } = await import("/packages/widget/dist/index.js");
    const { arTranslations } =
      await import("/packages/widget/dist/locales/ar.js");
    Shar.registerTranslations("ar", arTranslations);
    const widget = document.createElement("shar-challenge");
    widget.lang = "en";
    document.querySelector("main").append(widget);
    widget.handleClientEvent({
      type: "quoted",
      detail: {
        quote: {
          time_lock_iterations: "4294967296",
          render_rounds: 256,
        },
      },
    });
    widget.handleClientEvent({
      type: "progress",
      detail: { phase: "time_lock", value: 0.5 },
    });
    widget.lang = " ar-EG ";
    const region = widget.shadowRoot.querySelector('[role="group"]');
    const status = widget.shadowRoot.querySelector('[role="status"]');
    const work = widget.shadowRoot.querySelector("[data-shar-expected-work]");
    const progress = widget.shadowRoot.querySelector("progress");
    const buttons = () =>
      [...widget.shadowRoot.querySelectorAll("button")].map(
        (button) => button.textContent,
      );
    const arabic = {
      direction: region.dir,
      label: region.getAttribute("aria-label"),
      progressLabel: progress.getAttribute("aria-label"),
      status: status.textContent,
      work: work.textContent,
      buttons: buttons(),
      expectedPercent: new Intl.NumberFormat("ar-EG", {
        maximumFractionDigits: 0,
      }).format(25),
      expectedIterations: new Intl.NumberFormat("ar-EG", {
        maximumFractionDigits: 0,
      }).format(4294967296n),
    };
    widget.pause();
    widget.lang = "en-x-shar-test";
    const beforeRegistration = status.textContent;
    const customTranslations = {
      ready: "T ready",
      verify: "T verify",
      pause: "T pause",
      resume: "T resume",
      fallback: "T fallback",
      preparing: "T preparing",
      paused: "T paused",
      resumed: "T resumed",
      verifying: "T verifying {percent}",
      verified: "T verified",
      expired: "T expired",
      failed: "T failed",
      expectedWork: "T work {iterations}/{rounds}",
      verificationLabel: "T verification",
      progressLabel: "T progress",
    };
    Shar.registerTranslations(" EN-X-SHAR-TEST ", customTranslations);
    const registered = {
      direction: region.dir,
      label: region.getAttribute("aria-label"),
      progressLabel: progress.getAttribute("aria-label"),
      status: status.textContent,
      work: work.textContent,
      buttons: buttons(),
    };
    const localeCatalogs = [
      ["de", "deTranslations"],
      ["es", "esTranslations"],
      ["fr", "frTranslations"],
      ["he", "heTranslations"],
      ["hi", "hiTranslations"],
      ["ja", "jaTranslations"],
      ["pt-br", "ptBrTranslations"],
      ["zh-cn", "zhCnTranslations"],
    ];
    const localeResults = [];
    for (const [locale, exportName] of localeCatalogs) {
      const module = await import(`/packages/widget/dist/locales/${locale}.js`);
      Shar.registerTranslations(locale, module[exportName]);
      widget.lang = locale;
      localeResults.push({
        locale,
        direction: region.dir,
        status: status.textContent,
        label: region.getAttribute("aria-label"),
      });
    }
    const invalidRegistrationErrors = [];
    for (const [locale, translations] of [
      ["not a locale!", customTranslations],
      ["en-x-missing", { ...customTranslations, pause: undefined }],
      ["en-x-control", { ...customTranslations, ready: "bad\u0000value" }],
      ["en-x-large", { ...customTranslations, ready: "x".repeat(2_049) }],
      [
        "en-x-holder",
        { ...customTranslations, verifying: "T {percent}/{percent}" },
      ],
    ]) {
      try {
        Shar.registerTranslations(locale, translations);
      } catch (error) {
        invalidRegistrationErrors.push(
          error instanceof Error ? error.message : String(error),
        );
      }
    }
    widget.remove();
    return {
      arabic,
      beforeRegistration,
      registered,
      localeResults,
      invalidRegistrationErrors,
    };
  });
  expect(result.arabic.direction).toBe("rtl");
  expect(result.arabic.label).toBe("التحقق");
  expect(result.arabic.progressLabel).toBe("تقدم التحقق");
  expect(result.arabic.status).toContain(result.arabic.expectedPercent);
  expect(result.arabic.work).toContain(result.arabic.expectedIterations);
  expect(result.arabic.buttons).toEqual([
    "تحقق",
    "إيقاف مؤقت",
    "استخدام طريقة تحقق أخرى",
  ]);
  expect(result.beforeRegistration).toBe("Paused");
  expect(result.registered).toEqual({
    direction: "ltr",
    label: "T verification",
    progressLabel: "T progress",
    status: "T paused",
    work: "T work 4,294,967,296/256",
    buttons: ["T verify", "T resume", "T fallback"],
  });
  expect(result.localeResults).toHaveLength(8);
  for (const localized of result.localeResults) {
    expect(localized.status).not.toBe("Paused");
    expect(localized.label).not.toBe("Verification");
    expect(localized.direction).toBe(localized.locale === "he" ? "rtl" : "ltr");
  }
  expect(result.invalidRegistrationErrors).toEqual([
    "locale must be a valid BCP 47 tag",
    "invalid translation: pause",
    "invalid translation: ready",
    "invalid translation: ready",
    "translation verifying must contain {percent} once",
  ]);
  expectNoRelevantErrors(messages);
});

test("widget resumes the same signed quote after navigation and clears it on success", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "gpu", {
      configurable: true,
      get: () => undefined,
    });
    for (const prototype of [
      globalThis.OffscreenCanvas?.prototype,
      HTMLCanvasElement.prototype,
    ]) {
      if (!prototype) continue;
      const original = prototype.getContext;
      prototype.getContext = function (type, options) {
        if (type === "webgl2") return null;
        return original.call(this, type, options);
      };
    }
  });
  const issuedAt = Math.floor(Date.now() / 1000);
  let challengeRequests = 0;
  let redemption;
  await page.route(/\/v1\/challenges(?:\/redeem)?$/, async (route) => {
    if (route.request().url().endsWith("/redeem")) {
      redemption = route.request().postDataJSON();
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          token: "shr1_verified_after_navigation",
          expires_at: issuedAt + 600,
          receipt: {
            version: "work-receipt-v1",
            tier: 0,
            time_lock_iterations: "16",
            render_rounds: 2,
            rendering_backend: "css",
            completed_at: issuedAt,
          },
        }),
      });
      return;
    }
    challengeRequests++;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        token: "shr1_navigation_challenge",
        quote: {
          version: "work-price-v1",
          tier: 0,
          time_lock_iterations: "16",
          render_rounds: 2,
          issued_at: issuedAt,
          expires_at: issuedAt + 300,
        },
        render: {
          version: "render-v1",
          seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          rounds: 2,
          triangles: 8,
          samples: 16,
        },
        time_lock: {
          version: "rsw-v1",
          modulus_id: "test",
          modulus: "EQ",
          input: "Ag",
          iterations: "16",
        },
      }),
    });
  });

  await page.goto("/test/browser/render-harness.html");
  await page.evaluate(() => {
    const widget = document.createElement("shar-challenge");
    widget.setAttribute("sitekey", "site-navigation");
    widget.setAttribute("action", "signup");
    widget.addEventListener("progress", (event) => {
      const detail = event.detail;
      if (detail.phase === "rendering" && detail.value === 0.5) {
        widget.pause();
        globalThis.__sharPausedAfterRound = true;
      }
    });
    document.querySelector("main").append(widget);
    void widget.execute().catch(() => {});
  });
  await page.waitForFunction(() => globalThis.__sharPausedAfterRound === true);
  await page.evaluate(() => dispatchEvent(new Event("pagehide")));
  const saved = await page.evaluate(() =>
    JSON.parse(sessionStorage.getItem("shar:widget:execution:v1")),
  );
  expect(saved.rendering.roundDigests).toHaveLength(1);
  expect(saved.timeLock.completed).toBe("16");
  expect(saved.challenge.token).toBe("shr1_navigation_challenge");

  await page.reload();
  const resumed = await page.evaluate(async () => {
    const widget = document.createElement("shar-challenge");
    widget.setAttribute("sitekey", "site-navigation");
    widget.setAttribute("action", "signup");
    let quoted;
    widget.addEventListener("quoted", (event) => {
      quoted = event.detail;
    });
    document.querySelector("main").append(widget);
    const token = await widget.execute();
    return { token, quoted };
  });
  expect(resumed.token).toBe("shr1_verified_after_navigation");
  expect(resumed.quoted.resumed).toBe(true);
  expect(challengeRequests).toBe(1);
  expect(redemption.token).toBe("shr1_navigation_challenge");
  expect(redemption.rendering.backend).toBe("css");
  expect(
    await page.evaluate(() =>
      sessionStorage.getItem("shar:widget:execution:v1"),
    ),
  ).toBeNull();
  expectNoRelevantErrors(messages);
});

test("concurrent widgets own pause and reset without cancelling each other", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "gpu", {
      configurable: true,
      get: () => undefined,
    });
    for (const prototype of [
      globalThis.OffscreenCanvas?.prototype,
      HTMLCanvasElement.prototype,
    ]) {
      if (!prototype) continue;
      const original = prototype.getContext;
      prototype.getContext = function (type, options) {
        if (type === "webgl2") return null;
        return original.call(this, type, options);
      };
    }
  });
  const issuedAt = Math.floor(Date.now() / 1000);
  let challengeRequests = 0;
  let redemptions = 0;
  await page.route(/\/v1\/challenges(?:\/redeem)?$/, async (route) => {
    if (route.request().url().endsWith("/redeem")) {
      redemptions++;
      const request = route.request().postDataJSON();
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          token: `shr1_verified_${request.token}`,
          expires_at: issuedAt + 600,
          receipt: {
            version: "work-receipt-v1",
            tier: 0,
            time_lock_iterations: "16",
            render_rounds: 2,
            rendering_backend: "css",
            completed_at: issuedAt,
          },
        }),
      });
      return;
    }
    const action = route.request().postDataJSON().action;
    challengeRequests++;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        token: `shr1_${action}_challenge`,
        quote: {
          version: "work-price-v1",
          tier: 0,
          time_lock_iterations: "16",
          render_rounds: 2,
          issued_at: issuedAt,
          expires_at: issuedAt + 300,
        },
        render: {
          version: "render-v1",
          seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          rounds: 2,
          triangles: 8,
          samples: 16,
        },
        time_lock: {
          version: "rsw-v1",
          modulus_id: "test",
          modulus: "EQ",
          input: "Ag",
          iterations: "16",
        },
      }),
    });
  });

  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(async () => {
    const makePausedWidget = (action) => {
      const widget = document.createElement("shar-challenge");
      widget.setAttribute("sitekey", "site-concurrent");
      widget.setAttribute("action", action);
      const paused = new Promise((resolve) => {
        widget.addEventListener("progress", (event) => {
          if (
            event.detail.phase === "rendering" &&
            event.detail.value === 0.5
          ) {
            widget.pause();
            resolve();
          }
        });
      });
      document.querySelector("main").append(widget);
      let settled = false;
      const outcome = widget.execute().then(
        (token) => {
          settled = true;
          return { token };
        },
        (error) => {
          settled = true;
          return { error: error instanceof Error ? error.name : String(error) };
        },
      );
      return { widget, paused, outcome, settled: () => settled };
    };

    const first = makePausedWidget("first");
    await first.paused;
    const second = makePausedWidget("second");
    await second.paused;
    await new Promise((resolve) => setTimeout(resolve, 0));
    const firstSurvivedSecondStart = !first.settled();
    first.widget.reset();
    const firstOutcome = await first.outcome;
    const secondSurvivedFirstReset = !second.settled();
    second.widget.resume();
    const secondOutcome = await second.outcome;
    return {
      firstSurvivedSecondStart,
      firstOutcome,
      secondSurvivedFirstReset,
      secondOutcome,
    };
  });
  expect(result).toEqual({
    firstSurvivedSecondStart: true,
    firstOutcome: { error: "AbortError" },
    secondSurvivedFirstReset: true,
    secondOutcome: {
      token: "shr1_verified_shr1_second_challenge",
    },
  });
  expect(challengeRequests).toBe(2);
  expect(redemptions).toBe(1);
  expectNoRelevantErrors(messages);
});

test("navigation checkpoints reject expiry and corruption and reset removes state", async ({
  page,
}) => {
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(async () => {
    const { NAVIGATION_CHECKPOINT_KEY, NavigationCheckpoint } =
      await import("/packages/widget/dist/checkpoint.js");
    const now = Math.floor(Date.now() / 1000);
    const scope = {
      endpoint: new URL("/v1/challenges", location.href).href,
      tenant: "default",
      sitekey: "site-checkpoint",
      action: "signup",
      origin: location.origin,
    };
    const challenge = {
      token: "shr1_checkpoint_validation",
      quote: {
        version: "work-price-v1",
        tier: 0,
        time_lock_iterations: "1",
        render_rounds: 1,
        issued_at: now - 20,
        expires_at: now - 1,
      },
      render: {
        version: "render-v1",
        seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        rounds: 1,
        triangles: 8,
        samples: 16,
      },
      time_lock: {
        version: "rsw-v1",
        modulus_id: "test",
        modulus: "EQ",
        input: "Ag",
        iterations: "1",
      },
    };
    const checkpoint = new NavigationCheckpoint(scope);
    checkpoint.start(challenge);
    const expired = checkpoint.load(now);
    const removedExpired = sessionStorage.getItem(NAVIGATION_CHECKPOINT_KEY);

    sessionStorage.setItem(NAVIGATION_CHECKPOINT_KEY, "{not-json");
    const corrupted = checkpoint.load(now);
    const removedCorrupted = sessionStorage.getItem(NAVIGATION_CHECKPOINT_KEY);

    challenge.quote.issued_at = now;
    challenge.quote.expires_at = now + 300;
    checkpoint.start(challenge);
    const successor = new NavigationCheckpoint(scope);
    const takenOver = successor.load(now);
    const successorOwner = JSON.parse(
      sessionStorage.getItem(NAVIGATION_CHECKPOINT_KEY),
    ).owner;
    checkpoint.setTimeLock(1n, "BA", true);
    checkpoint.clear();
    const ownershipProtected =
      takenOver !== undefined &&
      JSON.parse(sessionStorage.getItem(NAVIGATION_CHECKPOINT_KEY)).owner ===
        successorOwner;
    const widget = document.createElement("shar-challenge");
    widget.setAttribute("sitekey", scope.sitekey);
    widget.setAttribute("action", scope.action);
    document.body.append(widget);
    widget.reset();
    const removedByReset = sessionStorage.getItem(NAVIGATION_CHECKPOINT_KEY);
    return {
      expired: expired === undefined,
      removedExpired,
      corrupted: corrupted === undefined,
      removedCorrupted,
      ownershipProtected,
      removedByReset,
    };
  });
  expect(result).toEqual({
    expired: true,
    removedExpired: null,
    corrupted: true,
    removedCorrupted: null,
    ownershipProtected: true,
    removedByReset: null,
  });
});

test("widget binds CSS execution to its transcript commitment", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "gpu", {
      configurable: true,
      get: () => undefined,
    });
    for (const prototype of [
      globalThis.OffscreenCanvas?.prototype,
      HTMLCanvasElement.prototype,
    ]) {
      if (!prototype) continue;
      const original = prototype.getContext;
      prototype.getContext = function (type, options) {
        if (type === "webgl2") return null;
        return original.call(this, type, options);
      };
    }
  });
  let redemption;
  await page.route(/\/v1\/challenges(?:\/redeem)?$/, async (route) => {
    if (route.request().url().endsWith("/redeem")) {
      redemption = route.request().postDataJSON();
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          token: "shr1_verified",
          expires_at: 1_800_000_300,
          receipt: {
            version: "work-receipt-v1",
            tier: 0,
            time_lock_iterations: "1",
            render_rounds: 1,
            rendering_backend: "css",
            completed_at: 1_800_000_000,
          },
        }),
      });
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        token: "shr1_challenge",
        quote: { time_lock_iterations: "1", render_rounds: 1 },
        render: {
          version: "render-v1",
          seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          rounds: 1,
          triangles: 8,
          samples: 16,
        },
        time_lock: {
          version: "rsw-v1",
          modulus_id: "test",
          modulus: "EQ",
          input: "Ag",
          iterations: "1",
        },
      }),
    });
  });
  await page.goto("/test/browser/render-harness.html");
  await expect(page).toHaveTitle("Shar render-v1 conformance");
  await page.evaluate(() => {
    const widget = document.createElement("shar-challenge");
    widget.setAttribute("sitekey", "site-a");
    widget.setAttribute("action", "signup");
    document.querySelector("main").append(widget);
  });
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByText("Verified", { exact: true })).toBeVisible();
  expect(redemption).toMatchObject({
    token: "shr1_challenge",
    time_lock: { output: "BA" },
    rendering: {
      backend: "css",
      css_commitment: {
        version: "css-transcript-v1",
        digest: "VdTNymqhcSxjrQk77ADCrscKUNIGjYqLc8vKAekByS4",
      },
    },
  });
  expect(redemption.rendering.digest).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expectNoRelevantErrors(messages);
  await page.screenshot({
    path: "/tmp/shar-widget-css-verified.png",
    fullPage: false,
    caret: "initial",
  });
});

test("opt-in Rust/WASM time-lock is canonical and falls back to JavaScript", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  const now = Math.floor(Date.now() / 1000);
  let redemption;
  let wasmRequests = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/packages/widget/wasm/shar_timelock.wasm"))
      wasmRequests++;
  });
  await page.route(/\/v1\/challenges(?:\/redeem)?$/, async (route) => {
    if (route.request().url().endsWith("/redeem")) {
      redemption = route.request().postDataJSON();
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          token: "shr1_wasm_verified",
          expires_at: now + 600,
          receipt: {
            version: "work-receipt-v1",
            tier: 0,
            time_lock_iterations: "4097",
            render_rounds: 1,
            rendering_backend: "css",
            completed_at: now,
          },
        }),
      });
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        token: "shr1_wasm_challenge",
        quote: {
          version: "work-price-v1",
          tier: 0,
          time_lock_iterations: "4097",
          render_rounds: 1,
          issued_at: now,
          expires_at: now + 300,
        },
        render: {
          version: "render-v1",
          seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          rounds: 1,
          triangles: 8,
          samples: 16,
        },
        time_lock: {
          version: "rsw-v1",
          modulus_id: "test",
          modulus: "EQ",
          input: "Ag",
          iterations: "4097",
        },
        presence: { mode: "host" },
        fallback: {
          available: true,
          methods: ["passkey", "support"],
        },
      }),
    });
  });

  await page.goto("/test/browser/render-harness.html");
  const accelerated = await page.evaluate(async () => {
    const widget = document.createElement("shar-challenge");
    widget.setAttribute("sitekey", "site-wasm");
    widget.setAttribute("action", "signup");
    widget.setAttribute("timelock-wasm", "");
    let fallbackDetail;
    widget.addEventListener("fallback", (event) => {
      fallbackDetail = event.detail;
    });
    document.querySelector("main").append(widget);
    const token = await widget.execute();
    const fallback = [...widget.shadowRoot.querySelectorAll("button")].find(
      (button) => button.textContent === "Use another verification method",
    );
    const fallbackHidden = fallback.hidden;
    fallback.click();
    return {
      token,
      fallbackHidden,
      fallbackDetail,
      methods: widget.getFallbackMethods(),
    };
  });
  expect(accelerated).toEqual({
    token: "shr1_wasm_verified",
    fallbackHidden: false,
    fallbackDetail: {
      methods: ["passkey", "support"],
      presence: { mode: "host" },
    },
    methods: ["passkey", "support"],
  });
  expect(wasmRequests).toBe(1);
  expect(redemption.time_lock.output).toBe("AQ");

  let brokenRequests = 0;
  await page.route("**/broken-timelock.wasm", async (route) => {
    brokenRequests++;
    await route.fulfill({
      contentType: "application/wasm",
      body: "not a WebAssembly module",
    });
  });
  const fallbackToken = await page.evaluate(async () => {
    const widget = document.createElement("shar-challenge");
    widget.setAttribute("sitekey", "site-wasm-fallback");
    widget.setAttribute("action", "signup");
    widget.setAttribute("timelock-wasm", "/broken-timelock.wasm");
    document.querySelector("main").append(widget);
    return widget.execute();
  });
  expect(fallbackToken).toBe("shr1_wasm_verified");
  expect(brokenRequests).toBe(1);
  expect(redemption.time_lock.output).toBe("AQ");
  expectNoRelevantErrors(messages);
});

test("widget earns, stores, and spends one scoped blinded trust credit", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "gpu", {
      configurable: true,
      get: () => undefined,
    });
    for (const prototype of [
      globalThis.OffscreenCanvas?.prototype,
      HTMLCanvasElement.prototype,
    ]) {
      if (!prototype) continue;
      const original = prototype.getContext;
      prototype.getContext = function (type, options) {
        if (type === "webgl2") return null;
        return original.call(this, type, options);
      };
    }
  });
  const now = Math.floor(Date.now() / 1000);
  const scope = {
    tenant: "default",
    siteKey: "site-trust",
    action: "signup",
    origin: "http://127.0.0.1:4173",
  };
  const issuer = deriveTrustKeyPair(
    new Uint8Array(32).fill(21),
    new Uint8Array([4, 2]),
  );
  const scopedIssuer = deriveScopedTrustKeyPair(issuer, scope);
  const challengeDigest = trustCreditChallengeDigest(
    issuer.keyId,
    scope,
    now,
    now + 86_400,
  );
  const trustPlan = {
    mode: "voprf-v1",
    suite: "ristretto255-SHA512",
    token_type: "credit",
    key_id: base64url(issuer.keyId),
    public_key: base64url(scopedIssuer.publicKey),
    challenge_digest: base64url(challengeDigest),
    issued_at: now,
    expires_at: now + 86_400,
  };
  let issued = 0;
  let redeemed = 0;
  let offeredCredit;
  await page.route(/\/v1\/challenges(?:\/redeem)?$/, async (route) => {
    const body = route.request().postDataJSON();
    if (route.request().url().endsWith("/redeem")) {
      redeemed++;
      const response = {
        token: `shr1_trust_verified_${redeemed}`,
        expires_at: now + 600,
        receipt: {
          version: "work-receipt-v1",
          tier: 0,
          time_lock_iterations: "1",
          render_rounds: 1,
          rendering_backend: "css",
          completed_at: now,
        },
      };
      if (redeemed === 1) {
        expect(body.trust_blinded).toMatch(/^[A-Za-z0-9_-]{43}$/);
        const evaluation = evaluateTrustInput(
          scopedIssuer,
          fromBase64url(body.trust_blinded),
        );
        response.trust_evaluation = {
          version: "trust-evaluation-v1",
          suite: "ristretto255-SHA512",
          key_id: trustPlan.key_id,
          evaluated: base64url(evaluation.evaluated),
          proof: base64url(evaluation.proof),
          issued_at: now,
          expires_at: now + 86_400,
        };
      } else {
        expect(body.trust_blinded).toBeUndefined();
      }
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify(response),
      });
      return;
    }

    issued++;
    if (issued === 1) {
      expect(body.trust_token).toBeUndefined();
    } else {
      offeredCredit = body.trust_token;
      const decoded = decodeTrustCreditToken(offeredCredit);
      expect(decoded.tenant).toBe(scope.tenant);
      expect(decoded.siteKey).toBe(scope.siteKey);
      expect(decoded.action).toBe(scope.action);
      expect(decoded.origin).toBe(scope.origin);
      const trustInput = trustInputForScope(
        "credit",
        decoded.challengeNonce,
        decoded.challengeDigest,
        decoded.keyId,
        scope,
      );
      expect(
        equalTrustOutput(
          decoded.output,
          evaluateTrustDirect(scopedIssuer, trustInput),
        ),
      ).toBe(true);
    }
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        token: `shr1_trust_challenge_${issued}`,
        quote: {
          version: "work-price-v1",
          tier: 0,
          time_lock_iterations: "1",
          render_rounds: 1,
          issued_at: now,
          expires_at: now + 300,
        },
        render: {
          version: "render-v1",
          seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          rounds: 1,
          triangles: 8,
          samples: 16,
        },
        time_lock: {
          version: "rsw-v1",
          modulus_id: "test",
          modulus: "EQ",
          input: "Ag",
          iterations: "1",
        },
        ...(issued === 1 ? { trust: trustPlan } : {}),
      }),
    });
  });

  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(async () => {
    const widget = document.createElement("shar-challenge");
    widget.setAttribute("sitekey", "site-trust");
    widget.setAttribute("action", "signup");
    document.querySelector("main").append(widget);
    const first = await widget.execute();
    const stored = sessionStorage.getItem("shar:widget:trust-credits:v1");
    const second = await widget.execute();
    const spent = sessionStorage.getItem("shar:widget:trust-credits:v1");
    return { first, second, stored: stored !== null, spent };
  });
  expect(result).toEqual({
    first: "shr1_trust_verified_1",
    second: "shr1_trust_verified_2",
    stored: true,
    spent: null,
  });
  expect(offeredCredit).toMatch(/^shrtrust1_/);
  expect(issued).toBe(2);
  expect(redeemed).toBe(2);
  expectNoRelevantErrors(messages);
});

test("widget controls and Cap compatibility preserve browser contracts", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(async () => {
    const { Shar } = await import("/packages/widget/dist/index.js");
    const { arTranslations } =
      await import("/packages/widget/dist/locales/ar.js");
    Shar.registerTranslations("ar", arTranslations);
    const shar = document.createElement("shar-challenge");
    document.body.append(shar);
    const buttons = [...shar.shadowRoot.querySelectorAll("button")];
    const pause = buttons.find((button) => button.textContent === "Pause");
    const fallback = buttons.find(
      (button) => button.textContent === "Use another verification method",
    );
    let fallbackEvents = 0;
    let fallbackDetail;
    shar.addEventListener("fallback", (event) => {
      fallbackEvents++;
      fallbackDetail = event.detail;
    });
    const fallbackInitiallyHidden = fallback.hidden;
    shar.handleClientEvent({
      type: "quoted",
      detail: {
        quote: { time_lock_iterations: "4294967296", render_rounds: 256 },
        presence: { mode: "host" },
        fallback: {
          available: true,
          methods: ["passkey", "email"],
        },
      },
    });
    const fallbackAfterQuotedHidden = fallback.hidden;
    pause.click();
    const pausedLabel = pause.textContent;
    pause.click();
    const resumedLabel = pause.textContent;
    fallback.click();

    const cap = document.createElement("cap-widget");
    cap.setAttribute("api-endpoint", "https://shar.example");
    cap.setAttribute("data-sitekey", "site-a");
    let solved;
    cap.addEventListener("solve", (event) => {
      solved = event.detail.token;
    });
    let capProgress;
    let capError;
    let capResets = 0;
    cap.addEventListener("progress", (event) => {
      capProgress = event.detail.progress;
    });
    cap.addEventListener("error", (event) => {
      capError = { code: event.detail.code, message: event.detail.message };
    });
    cap.addEventListener("reset", () => capResets++);
    document.body.append(cap);
    const hidden = cap.querySelector('input[type="hidden"][name="cap-token"]');
    cap.dispatchEvent(
      new CustomEvent("progress", {
        detail: { phase: "time_lock", value: 0.42 },
        bubbles: true,
      }),
    );
    const capFailure = Object.assign(new Error("nope"), {
      code: "test_error",
    });
    cap.dispatchEvent(
      new CustomEvent("error", { detail: { error: capFailure } }),
    );
    cap.dispatchEvent(new CustomEvent("verified"));
    cap.reset();
    const capCustom = document.createElement("cap-widget");
    capCustom.setAttribute("data-cap-api-endpoint", "https://shar.example");
    capCustom.setAttribute("data-cap-hidden-field-name", "legacy-token");
    document.body.append(capCustom);
    const customHidden = capCustom.querySelector(
      'input[type="hidden"][name="legacy-token"]',
    );
    const arabic = document.createElement("shar-challenge");
    arabic.lang = "ar";
    document.body.append(arabic);
    const arabicRegion = arabic.shadowRoot.querySelector('[role="group"]');
    return {
      pausedLabel,
      resumedLabel,
      fallbackEvents,
      fallbackDetail,
      fallbackInitiallyHidden,
      fallbackAfterQuotedHidden,
      fallbackMethods: shar.getFallbackMethods(),
      endpoint: cap.endpoint,
      sitekey: cap.sitekey,
      hidden: Boolean(hidden),
      hiddenValue: hidden?.value,
      customHidden: Boolean(customHidden),
      solved,
      expectedWork: shar.shadowRoot.querySelector("[data-shar-expected-work]")
        .textContent,
      verificationLabel: shar.shadowRoot
        .querySelector('[role="group"]')
        .getAttribute("aria-label"),
      progressLabel: shar.shadowRoot
        .querySelector("progress")
        .getAttribute("aria-label"),
      arabicDirection: arabicRegion.dir,
      arabicStatus: arabic.shadowRoot.querySelector('[aria-live="polite"]')
        .textContent,
      arabicButtons: [...arabic.shadowRoot.querySelectorAll("button")].map(
        (button) => button.textContent,
      ),
      capProgress,
      capError,
      capResets,
    };
  });
  expect(result).toEqual({
    pausedLabel: "Resume",
    resumedLabel: "Pause",
    fallbackEvents: 1,
    fallbackDetail: {
      methods: ["passkey", "email"],
      presence: { mode: "host" },
    },
    fallbackInitiallyHidden: true,
    fallbackAfterQuotedHidden: false,
    fallbackMethods: ["passkey", "email"],
    endpoint: "https://shar.example",
    sitekey: "site-a",
    hidden: true,
    hiddenValue: "",
    customHidden: true,
    solved: "",
    expectedWork:
      "Expected work: 4,294,967,296 sequential steps and 256 rendering rounds",
    verificationLabel: "Verification",
    progressLabel: "Verification progress",
    arabicDirection: "rtl",
    arabicStatus: "جاهز للتحقق",
    arabicButtons: ["تحقق", "إيقاف مؤقت", "استخدام طريقة تحقق أخرى"],
    capProgress: 42,
    capError: { code: "test_error", message: "nope" },
    capResets: 1,
  });
  expectNoRelevantErrors(messages);
});

test("widget remains keyboard operable at 400% reflow and system contrast settings", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.setViewportSize({ width: 320, height: 720 });
  await page.emulateMedia({ reducedMotion: "reduce", forcedColors: "active" });
  await page.goto("/test/browser/render-harness.html");
  await page.evaluate(() => {
    const widget = document.createElement("shar-challenge");
    widget.id = "accessible-widget";
    widget.addEventListener("fallback", () => {
      globalThis.accessibleFallbackEvents =
        (globalThis.accessibleFallbackEvents ?? 0) + 1;
    });
    document.querySelector("main").append(widget);
    widget.handleClientEvent({
      type: "quoted",
      detail: {
        quote: { time_lock_iterations: "1024", render_rounds: 1 },
        presence: { mode: "host" },
        fallback: { available: true, methods: ["passkey"] },
      },
    });
    widget.shadowRoot.querySelector('[part~="verify-button"]').focus();
  });

  await page.keyboard.press("Tab");
  let state = await page.evaluate(() => {
    const widget = document.querySelector("#accessible-widget");
    const root = widget.shadowRoot;
    const active = root.activeElement;
    const status = root.querySelector('[part="status"]');
    const buttons = [...root.querySelectorAll("button:not([hidden])")];
    return {
      active: active?.textContent,
      outline: getComputedStyle(active).outlineWidth,
      targets: buttons.map((button) => button.getBoundingClientRect().height),
      statusRole: status.getAttribute("role"),
      statusAtomic: status.getAttribute("aria-atomic"),
      busy: root.querySelector('[part="container"]').getAttribute("aria-busy"),
      reduced: matchMedia("(prefers-reduced-motion: reduce)").matches,
      forced: matchMedia("(forced-colors: active)").matches,
      styleSheets: root.adoptedStyleSheets.length,
      overflow:
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
    };
  });
  expect(state.active).toBe("Pause");
  expect(Number.parseFloat(state.outline)).toBeGreaterThanOrEqual(3);
  expect(Math.min(...state.targets)).toBeGreaterThanOrEqual(44);
  expect(state).toMatchObject({
    statusRole: "status",
    statusAtomic: "true",
    busy: "false",
    reduced: true,
    forced: true,
    styleSheets: 1,
  });
  expect(state.overflow).toBeLessThanOrEqual(0);

  await page.keyboard.press("Enter");
  state = await page.evaluate(() => {
    const root = document.querySelector("#accessible-widget").shadowRoot;
    return {
      active: root.activeElement?.textContent,
      pressed: root.activeElement?.getAttribute("aria-pressed"),
      status: root.querySelector('[part="status"]').textContent,
    };
  });
  expect(state).toEqual({
    active: "Resume",
    pressed: "true",
    status: "Paused",
  });

  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  const fallback = await page.evaluate(() => {
    const root = document.querySelector("#accessible-widget").shadowRoot;
    return {
      active: root.activeElement?.textContent,
      events: globalThis.accessibleFallbackEvents,
    };
  });
  expect(fallback).toEqual({
    active: "Use another verification method",
    events: 1,
  });
  expectNoRelevantErrors(messages);
});

test("form association honors native lifecycle and Shar.render options", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(() =>
    globalThis.runFormAssociationHarness(),
  );
  expect(result).toEqual({
    token: "native-form-token",
    initialEntry: "native-form-token",
    renamedEntry: "native-form-token",
    signalForwarded: true,
    externalEvents: ["quoted", "quoted"],
    disabledControls: true,
    disabledError: "InvalidStateError",
    resetResponse: "",
    resetEntry: null,
    restoredResponse: "",
    restoredEntry: null,
    retainedCheckpoint: "retain-exact-quote",
  });
  expectNoRelevantErrors(messages);
});

test("successful verification expires once and leaves no stale form value", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(() =>
    globalThis.runSuccessfulExpiryHarness(),
  );
  expect(result).toEqual({
    returned: "short-lived-token",
    response: "",
    formValue: null,
    status: "Verification expired",
    expiredEvents: 1,
    expiredAt: 1_800_000_499,
  });
  expectNoRelevantErrors(messages);
});

test("Cap compatibility owns exactly one disabled-aware form field", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(() => globalThis.runCapFormHarness());
  expect(result).toEqual({
    initialValues: ["cap-form-token"],
    initialHiddenCount: 1,
    renamedValues: ["cap-form-token"],
    disabledValues: [],
    disabledControls: true,
    resetValues: [""],
  });
  expectNoRelevantErrors(messages);
});

test("reCAPTCHA and hCaptcha browser adapters preserve canonical Shar execution", async ({
  page,
}) => {
  const messages = capturePageErrors(page);
  await page.goto("/test/browser/render-harness.html");
  const result = await page.evaluate(() =>
    globalThis.runBrowserCompatibilityAdapterHarness(),
  );
  expect(result).toEqual({
    ready: true,
    widgetId: 0,
    renderedToken: "rendered-token",
    renderedResponse: "rendered-token",
    resetResponse: "",
    callbackToken: "rendered-token",
    expiredCallbacks: 1,
    errorCallback: "adapter-error",
    widget: {
      endpoint: "/shar",
      sitekey: "site-a",
      action: "signup",
      tenant: "tenant-a",
      name: "g-recaptcha-response",
    },
    invisibleToken: "invisible-token",
    invisibleOptions: {
      endpoint: "/shar",
      sitekey: "site-v3",
      action: "checkout",
      tenant: "tenant-a",
    },
    hcaptchaId: 0,
    hcaptchaName: "h-captcha-response",
    globals: { recaptcha: true, hcaptcha: true },
    collisionError: "grecaptcha is already installed",
    remainingWidgets: 0,
  });
  expectNoRelevantErrors(messages);
});
