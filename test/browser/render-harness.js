import { base64url } from "/dist/packages/server/src/bytes.js";
import { solveRendering } from "/dist/packages/server/src/rendering.js";
import "/packages/cap-compat/dist/index.js";
import {
  Shar,
  createHcaptchaAdapter,
  createRecaptchaAdapter,
  installHcaptchaAdapter,
  installRecaptchaAdapter,
} from "/packages/widget/dist/index.js";
import {
  RenderBackendUnavailable,
  solveRenderingAdaptive,
  solveRenderingCss,
  solveRenderingWebGl2,
  solveRenderingWebGpu,
} from "/dist/packages/widget/src/render-executors.js";

const plan = {
  version: "render-v1",
  seed: base64url(new Uint8Array(32)),
  rounds: 2,
  triangles: 8,
  samples: 16,
};
const expected = "XBnikgSO8AzOfMrpg1EDZH46vjjovkkGRA9MmiQv7_A";
const status = document.querySelector("#status");
const button = document.querySelector("#run");

async function runBackend(name, solve, required) {
  const output = document.querySelector(`#${name}`);
  const started = performance.now();
  try {
    const result = await solve(plan);
    const digest = typeof result === "string" ? result : result.digest;
    if (digest !== expected) throw new Error(`digest mismatch: ${digest}`);
    output.textContent = `PASS ${digest} (${(performance.now() - started).toFixed(1)} ms)`;
    output.className = "pass";
    return { status: "pass", digest };
  } catch (error) {
    if (!required && error instanceof RenderBackendUnavailable) {
      output.textContent = `SKIP ${error.message}`;
      output.className = "skip";
      return { status: "skip", reason: error.message };
    }
    output.textContent = `FAIL ${error instanceof Error ? error.message : String(error)}`;
    output.className = "fail";
    throw error;
  }
}

export async function runRenderHarness() {
  button.disabled = true;
  status.textContent = "Running…";
  try {
    const cpu = await runBackend("cpu", solveRendering, true);
    const webgl2 = await runBackend("webgl2", solveRenderingWebGl2, false);
    const webgpu = await runBackend("webgpu", solveRenderingWebGpu, false);
    const css = await runBackend("css", solveRenderingCss, true);
    const adaptive = await runBackend("adaptive", solveRenderingAdaptive, true);
    status.textContent = "Conformance complete";
    return { cpu, webgl2, webgpu, css, adaptive };
  } catch (error) {
    status.textContent = "Conformance failed";
    throw error;
  } finally {
    button.disabled = false;
  }
}

export async function runRenderMatrix() {
  const cases = [
    { fill: 1, triangles: 8, samples: 31 },
    { fill: 127, triangles: 17, samples: 63 },
    { fill: 255, triangles: 32, samples: 96 },
  ];
  const results = [];
  for (const testCase of cases) {
    const matrixPlan = {
      ...plan,
      seed: base64url(new Uint8Array(32).fill(testCase.fill)),
      rounds: 1,
      triangles: testCase.triangles,
      samples: testCase.samples,
    };
    const cpu = await solveRendering(matrixPlan);
    const css = await solveRenderingCss(matrixPlan);
    let webgl2 = "skip";
    try {
      webgl2 = await solveRenderingWebGl2(matrixPlan);
    } catch (error) {
      if (!(error instanceof RenderBackendUnavailable)) throw error;
    }
    let webgpu = "skip";
    try {
      webgpu = await solveRenderingWebGpu(matrixPlan);
    } catch (error) {
      if (!(error instanceof RenderBackendUnavailable)) throw error;
    }
    const digests = [cpu, css];
    if (webgl2 !== "skip") digests.push(webgl2);
    if (webgpu !== "skip") digests.push(webgpu);
    if (new Set(digests).size !== 1) {
      throw new Error(`matrix mismatch for fill ${testCase.fill}`);
    }
    results.push({
      ...testCase,
      digest: cpu,
      webgl2: webgl2 === "skip" ? "skip" : "pass",
      webgpu: webgpu === "skip" ? "skip" : "pass",
    });
  }
  return results;
}

export async function runAdaptiveFallbackHarness() {
  const cpu = await solveRendering(plan);
  const changes = [];
  const completed = [];
  const result = await solveRenderingAdaptive(plan, {
    onBackendChange: (backend) => changes.push(backend),
    onRound: (round) => completed.push(round),
  });
  if (result.digest !== cpu)
    throw new Error("adaptive fallback digest mismatch");
  return { ...result, changes, completed };
}

export async function runBrowserCompatibilityAdapterHarness() {
  const container = document.createElement("div");
  container.id = "compatibility-adapter-container";
  document.body.append(container);
  let callbackToken;
  let expiredCallbacks = 0;
  let errorCallback;
  const recaptcha = createRecaptchaAdapter({
    endpoint: "/shar/",
    tenant: "tenant-a",
    action: "default-action",
  });
  let ready = false;
  recaptcha.ready(() => {
    ready = true;
  });
  await Promise.resolve();
  const widgetId = recaptcha.render(container, {
    sitekey: "site-a",
    action: "signup",
    callback: (token) => {
      callbackToken = token;
    },
    "expired-callback": () => expiredCallbacks++,
    "error-callback": (error) => {
      errorCallback = error instanceof Error ? error.message : String(error);
    },
  });
  const widget = container.querySelector("shar-challenge");
  widget.execute = async () => {
    widget.response = "rendered-token";
    widget.dispatchEvent(
      new CustomEvent("verified", {
        detail: { response: "rendered-token" },
      }),
    );
    return "rendered-token";
  };
  const renderedToken = await recaptcha.execute(widgetId);
  const renderedResponse = recaptcha.getResponse(widgetId);
  widget.dispatchEvent(
    new CustomEvent("expired", { detail: { error: new Error("expired") } }),
  );
  widget.dispatchEvent(
    new CustomEvent("error", { detail: { error: new Error("adapter-error") } }),
  );
  recaptcha.reset(widgetId);
  const resetResponse = recaptcha.getResponse(widgetId);

  const originalExecute = Shar.execute;
  let invisibleOptions;
  Shar.execute = async (options) => {
    invisibleOptions = options;
    return "invisible-token";
  };
  let invisibleToken;
  try {
    invisibleToken = await recaptcha.execute("site-v3", {
      action: "checkout",
    });
  } finally {
    Shar.execute = originalExecute;
  }

  const hcaptcha = createHcaptchaAdapter({
    endpoint: "/shar",
    sitekey: "site-h",
  });
  const hcaptchaId = hcaptcha.render(container);
  const hcaptchaWidget = [...container.querySelectorAll("shar-challenge")].at(
    -1,
  );

  const globals = {};
  const installedRecaptcha = installRecaptchaAdapter(
    { endpoint: "/shar", sitekey: "site-global" },
    globals,
  );
  const installedHcaptcha = installHcaptchaAdapter(
    { endpoint: "/shar", sitekey: "site-global" },
    globals,
  );
  let collisionError;
  try {
    installRecaptchaAdapter(
      { endpoint: "/shar", sitekey: "site-global" },
      globals,
    );
  } catch (error) {
    collisionError = error instanceof Error ? error.message : String(error);
  }

  const result = {
    ready,
    widgetId,
    renderedToken,
    renderedResponse,
    resetResponse,
    callbackToken,
    expiredCallbacks,
    errorCallback,
    widget: {
      endpoint: widget.endpoint,
      sitekey: widget.sitekey,
      action: widget.action,
      tenant: widget.tenant,
      name: widget.getAttribute("name"),
    },
    invisibleToken,
    invisibleOptions: {
      endpoint: invisibleOptions.endpoint,
      sitekey: invisibleOptions.sitekey,
      action: invisibleOptions.action,
      tenant: invisibleOptions.tenant,
    },
    hcaptchaId,
    hcaptchaName: hcaptchaWidget.getAttribute("name"),
    globals: {
      recaptcha: globals.grecaptcha === installedRecaptcha,
      hcaptcha: globals.hcaptcha === installedHcaptcha,
    },
    collisionError,
  };
  recaptcha.remove(widgetId);
  hcaptcha.remove(hcaptchaId);
  result.remainingWidgets = container.querySelectorAll("shar-challenge").length;
  container.remove();
  return result;
}

export async function runFormAssociationHarness() {
  const form = document.createElement("form");
  const fieldset = document.createElement("fieldset");
  const mount = document.createElement("div");
  fieldset.append(mount);
  form.append(fieldset);
  document.body.append(form);

  const controller = new AbortController();
  const externalEvents = [];
  let receivedSignal;
  const originalExecute = Shar.execute;
  Shar.execute = async (options) => {
    receivedSignal = options.signal;
    options.onEvent?.({
      type: "quoted",
      detail: {
        quote: {
          time_lock_iterations: "8",
          render_rounds: 1,
        },
      },
    });
    return "native-form-token";
  };

  try {
    const widget = Shar.render(mount, {
      endpoint: "/shar",
      sitekey: "site-form",
      action: "signup",
      signal: controller.signal,
      onEvent: (event) => externalEvents.push(event.type),
    });
    widget.setAttribute("name", "first-response");
    const token = await widget.execute();
    const initialEntry = new FormData(form).get("first-response");
    widget.setAttribute("name", "renamed-response");
    const renamedEntry = new FormData(form).get("renamed-response");

    fieldset.disabled = true;
    await Promise.resolve();
    const disabledControls = [
      ...widget.shadowRoot.querySelectorAll("button"),
    ].every((button) => button.disabled);
    let disabledError;
    try {
      await widget.execute();
    } catch (error) {
      disabledError =
        error instanceof DOMException ? error.name : String(error);
    }

    fieldset.disabled = false;
    form.reset();
    const resetResponse = widget.getResponse();
    const resetEntry = new FormData(form).get("renamed-response");

    sessionStorage.setItem("shar:widget:execution:v1", "retain-exact-quote");
    await widget.execute();
    widget.formStateRestoreCallback("cached-token", "restore");
    const restoredResponse = widget.getResponse();
    const restoredEntry = new FormData(form).get("renamed-response");
    const retainedCheckpoint = sessionStorage.getItem(
      "shar:widget:execution:v1",
    );

    return {
      token,
      initialEntry,
      renamedEntry,
      signalForwarded: receivedSignal === controller.signal,
      externalEvents,
      disabledControls,
      disabledError,
      resetResponse,
      resetEntry,
      restoredResponse,
      restoredEntry,
      retainedCheckpoint,
    };
  } finally {
    Shar.execute = originalExecute;
    sessionStorage.removeItem("shar:widget:execution:v1");
    form.remove();
  }
}

export async function runSuccessfulExpiryHarness() {
  const form = document.createElement("form");
  const widget = document.createElement("shar-challenge");
  widget.setAttribute("name", "shar-token");
  form.append(widget);
  document.body.append(form);
  const originalExecute = Shar.execute;
  const originalNow = Date.now;
  let expiredEvents = 0;
  let expiredAt;
  widget.addEventListener("expired", (event) => {
    expiredEvents++;
    expiredAt = event.detail.expires_at;
  });
  Date.now = () => 1_800_000_500_250;
  Shar.execute = async (options) => {
    options.onEvent?.({
      type: "verified",
      detail: { expires_at: 1_800_000_499 },
    });
    return "short-lived-token";
  };
  try {
    const returned = await widget.execute();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const response = widget.getResponse();
    const formValue = new FormData(form).get("shar-token");
    const status = widget.shadowRoot.querySelector(
      '[aria-live="polite"]',
    ).textContent;
    widget.getResponse();
    return {
      returned,
      response,
      formValue,
      status,
      expiredEvents,
      expiredAt,
    };
  } finally {
    Date.now = originalNow;
    Shar.execute = originalExecute;
    widget.reset();
    form.remove();
  }
}

export async function runCapFormHarness() {
  const form = document.createElement("form");
  const cap = document.createElement("cap-widget");
  form.append(cap);
  document.body.append(form);
  const originalExecute = Shar.execute;
  Shar.execute = async (options) => {
    options.onEvent?.({
      type: "verified",
      detail: { expires_at: Math.floor(Date.now() / 1000) + 300 },
    });
    return "cap-form-token";
  };
  try {
    await cap.execute();
    const initialValues = new FormData(form).getAll("cap-token");
    const initialHiddenCount = form.querySelectorAll(
      'input[type="hidden"][name="cap-token"]',
    ).length;
    cap.setAttribute("data-cap-hidden-field-name", "captcha-response");
    const renamedValues = new FormData(form).getAll("captcha-response");

    cap.disabled = true;
    await Promise.resolve();
    const disabledValues = new FormData(form).getAll("captcha-response");
    const disabledControls = [
      ...cap.shadowRoot.querySelectorAll("button"),
    ].every((button) => button.disabled);

    cap.disabled = false;
    cap.reset();
    const resetValues = new FormData(form).getAll("captcha-response");
    return {
      initialValues,
      initialHiddenCount,
      renamedValues,
      disabledValues,
      disabledControls,
      resetValues,
    };
  } finally {
    Shar.execute = originalExecute;
    cap.reset();
    form.remove();
  }
}

button.addEventListener("click", () => void runRenderHarness());
globalThis.runRenderHarness = runRenderHarness;
globalThis.runRenderMatrix = runRenderMatrix;
globalThis.runAdaptiveFallbackHarness = runAdaptiveFallbackHarness;
globalThis.runBrowserCompatibilityAdapterHarness =
  runBrowserCompatibilityAdapterHarness;
globalThis.runFormAssociationHarness = runFormAssociationHarness;
globalThis.runSuccessfulExpiryHarness = runSuccessfulExpiryHarness;
globalThis.runCapFormHarness = runCapFormHarness;
