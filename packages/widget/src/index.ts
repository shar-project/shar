import {
  base64url,
  bigintToBytes,
  bytesToBigint,
  cssTranscriptCommitment,
  fromBase64url,
  type ChallengeResponse,
  type RedeemResponse,
  type TimeLockPlan,
} from "@shar/server/browser";
import {
  NavigationCheckpoint,
  clearNavigationCheckpoint,
  clearNavigationCheckpointForScope,
  type NavigationCheckpointScope,
  type TimeLockExecutionCheckpoint,
} from "./checkpoint.js";
import { solveRenderingAdaptive } from "./render-executors.js";
import {
  loadTimeLockWasm,
  type TimeLockWasmAccelerator,
  type TimeLockWasmOption,
} from "./time-lock-wasm.js";

// Kept local so the optional trust-credit graph does not create a shared eager
// chunk solely for this internal wallet lookup. The optional public helper
// exports the same stable key from trust-credit-storage.ts.
const TRUST_CREDIT_STORAGE_KEY = "shar:widget:trust-credits:v1";

type TrustCreditModule = typeof import("./trust-credits.js");
let trustCreditModule: Promise<TrustCreditModule> | undefined;

function loadTrustCredits(): Promise<TrustCreditModule> {
  return (trustCreditModule ??= import("./trust-credits.js").catch((error) => {
    trustCreditModule = undefined;
    throw error;
  }));
}

function hasStoredTrustCredits(): boolean {
  try {
    return sessionStorage.getItem(TRUST_CREDIT_STORAGE_KEY) !== null;
  } catch {
    return false;
  }
}

export interface ExecuteOptions {
  endpoint: string;
  sitekey: string;
  action: string;
  tenant?: string;
  signal?: AbortSignal;
  onEvent?: (event: SharClientEvent) => void;
  /** Opt in to the packaged Rust/WASM accelerator or provide a static URL. */
  timeLockWasm?: TimeLockWasmOption;
}

export interface SharClientEvent {
  type: "quoted" | "progress" | "backendchange" | "verified";
  detail: Record<string, unknown>;
}

export interface SharTranslations {
  ready: string;
  verify: string;
  pause: string;
  resume: string;
  fallback: string;
  preparing: string;
  paused: string;
  resumed: string;
  verifying: string;
  verified: string;
  expired: string;
  failed: string;
  expectedWork: string;
  verificationLabel: string;
  progressLabel: string;
}

type StatusMessage =
  | "ready"
  | "preparing"
  | "paused"
  | "resumed"
  | "verifying"
  | "verified"
  | "expired"
  | "failed";

const TRANSLATION_KEYS = [
  "ready",
  "verify",
  "pause",
  "resume",
  "fallback",
  "preparing",
  "paused",
  "resumed",
  "verifying",
  "verified",
  "expired",
  "failed",
  "expectedWork",
  "verificationLabel",
  "progressLabel",
] as const satisfies readonly (keyof SharTranslations)[];
const MAX_TRANSLATION_BYTES = 2_048;

const translations = new Map<string, SharTranslations>([
  [
    "en",
    {
      ready: "Ready to verify",
      verify: "Verify",
      pause: "Pause",
      resume: "Resume",
      fallback: "Use another verification method",
      preparing: "Preparing work…",
      paused: "Paused",
      resumed: "Verification resumed",
      verifying: "Verifying {percent}%",
      verified: "Verified",
      expired: "Verification expired",
      failed: "Verification could not complete",
      expectedWork:
        "Expected work: {iterations} sequential steps and {rounds} rendering rounds",
      verificationLabel: "Verification",
      progressLabel: "Verification progress",
    },
  ],
]);

function localeFor(element: Element): string {
  return normalizeLocale(
    element.getAttribute("lang") ??
      element.closest("[lang]")?.getAttribute("lang") ??
      navigator.language ??
      "en",
  );
}
function normalizeLocale(locale: string): string {
  try {
    return registeredLocale(locale);
  } catch {
    return locale.trim().toLowerCase() || "en";
  }
}
function registeredLocale(locale: string): string {
  const trimmed = locale.trim();
  if (!trimmed) throw new Error("locale is required");
  try {
    return new Intl.Locale(trimmed).toString().toLowerCase();
  } catch {
    throw new Error("locale must be a valid BCP 47 tag");
  }
}
function validatedTranslations(messages: SharTranslations): SharTranslations {
  if (!messages || typeof messages !== "object")
    throw new Error("translations are required");
  const validated = {} as SharTranslations;
  for (const key of TRANSLATION_KEYS) {
    const value = messages[key];
    if (
      typeof value !== "string" ||
      value.trim().length === 0 ||
      new TextEncoder().encode(value).byteLength > MAX_TRANSLATION_BYTES ||
      /\p{Cc}/u.test(value)
    )
      throw new Error(`invalid translation: ${key}`);
    validated[key] = value;
  }
  for (const [key, placeholders] of [
    ["verifying", ["{percent}"]],
    ["expectedWork", ["{iterations}", "{rounds}"]],
  ] as const)
    for (const placeholder of placeholders)
      if (validated[key].split(placeholder).length !== 2)
        throw new Error(`translation ${key} must contain ${placeholder} once`);
  return validated;
}
function messagesFor(element: Element): SharTranslations {
  const locale = localeFor(element);
  return (
    translations.get(locale) ??
    translations.get(locale.split("-")[0] ?? "") ??
    translations.get("en")!
  );
}
function directionFor(locale: string): "ltr" | "rtl" {
  try {
    const value = (
      new Intl.Locale(locale) as Intl.Locale & {
        textInfo?: { direction?: string };
      }
    ).textInfo?.direction;
    if (value === "rtl" || value === "ltr") return value;
  } catch {}
  return /^(ar|fa|he|ur)(-|$)/i.test(locale) ? "rtl" : "ltr";
}

const WIDGET_STYLES = `
:host{display:inline-block;max-inline-size:100%;contain:content;color-scheme:light dark;font:1rem/1.5 system-ui,sans-serif}
[part="container"]{display:grid;gap:.5rem;inline-size:min(32rem,100%);max-inline-size:100%}
[part="status"],[part="expected-work"]{overflow-wrap:anywhere}
[part="progress"]{inline-size:100%;min-block-size:1rem}
[part~="button"]{box-sizing:border-box;max-inline-size:100%;min-block-size:2.75rem;padding:.5rem .75rem;font:inherit;line-height:1.25;white-space:normal;touch-action:manipulation}
[part~="button"]:focus-visible{outline:3px solid Highlight;outline-offset:2px}
[hidden]{display:none!important}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;scroll-behavior:auto!important;transition:none!important}}
@media(forced-colors:active){[part="progress"],[part~="button"]{border:1px solid ButtonText}}
`;

function installWidgetStyles(root: ShadowRoot): void {
  try {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(WIDGET_STYLES);
    root.adoptedStyleSheets = [...root.adoptedStyleSheets, sheet];
  } catch {
    // Semantic controls remain usable in engines without constructed sheets.
  }
}

class ExecutionControl {
  paused = false;
  cancelled = false;
  private readonly abortController = new AbortController();
  private waiters: Array<() => void> = [];
  private navigationCheckpoint: NavigationCheckpoint | undefined;

  get signal(): AbortSignal {
    return this.abortController.signal;
  }

  pause(): void {
    this.paused = true;
  }

  resume(): void {
    this.paused = false;
    for (const wake of this.waiters.splice(0)) wake();
  }

  cancel(): void {
    if (this.cancelled) return;
    this.cancelled = true;
    this.abortController.abort(
      new DOMException("Execution cancelled", "AbortError"),
    );
    this.resume();
  }

  setNavigationCheckpoint(checkpoint: NavigationCheckpoint): void {
    this.navigationCheckpoint = checkpoint;
  }

  clearNavigationCheckpoint(): void {
    this.navigationCheckpoint?.clear();
  }

  async checkpoint(): Promise<void> {
    if (this.cancelled)
      throw new DOMException("Execution cancelled", "AbortError");
    if (this.paused)
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    if (this.cancelled)
      throw new DOMException("Execution cancelled", "AbortError");
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
}

let activeControl: ExecutionControl | undefined;
const activeControls: ExecutionControl[] = [];
const EXECUTION_CONTROL = Symbol("shar.execution-control");
type InternalExecuteOptions = ExecuteOptions & {
  [EXECUTION_CONTROL]?: ExecutionControl;
};

function activateControl(control: ExecutionControl): void {
  const previous = activeControls.indexOf(control);
  if (previous >= 0) activeControls.splice(previous, 1);
  activeControls.push(control);
  activeControl = control;
}

function deactivateControl(control: ExecutionControl): void {
  const index = activeControls.indexOf(control);
  if (index >= 0) activeControls.splice(index, 1);
  activeControl = activeControls.at(-1);
}

async function solveTimeLockChunked(
  plan: TimeLockPlan,
  control: ExecutionControl,
  progress: (fraction: number) => void,
  initial?: TimeLockExecutionCheckpoint,
  save?: (completed: bigint, value: string, force: boolean) => void,
  wasm?: TimeLockWasmAccelerator,
): Promise<string> {
  const modulusBytes = fromBase64url(plan.modulus);
  const modulus = bytesToBigint(modulusBytes);
  let value = bytesToBigint(fromBase64url(initial?.value ?? plan.input));
  const total = BigInt(plan.iterations);
  if (modulus <= 1n || total < 1n) throw new Error("time_lock_plan");
  let completed = initial === undefined ? 0n : BigInt(initial.completed);
  if (completed < 0n || completed > total || value >= modulus)
    throw new Error("time_lock_checkpoint");
  if (completed > 0n) progress(Number((completed * 10_000n) / total) / 10_000);

  const chunk = 2048n;
  while (completed < total) {
    const end = completed + chunk < total ? completed + chunk : total;
    const iterations = Number(end - completed);
    if (wasm) {
      const before = value;
      try {
        value = wasm.squareChunk(modulusBytes, value, iterations);
        completed = end;
      } catch {
        value = before;
        wasm = undefined;
      }
    }
    if (!wasm && completed < end) {
      while (completed < end) {
        value = (value * value) % modulus;
        completed++;
      }
    }
    progress(Number((completed * 10_000n) / total) / 10_000);
    save?.(completed, base64url(bigintToBytes(value)), completed === total);
    await control.checkpoint();
  }
  return base64url(bigintToBytes(value));
}

async function executeWithControl(
  options: ExecuteOptions,
  control: ExecutionControl,
): Promise<string> {
  activateControl(control);
  const endpoint = options.endpoint.trim().replace(/\/+$/, "");
  const scope = checkpointScope(options);
  const checkpoint = new NavigationCheckpoint(scope);
  let trust: TrustCreditModule | undefined;
  let trustWallet: import("./trust-credits.js").TrustCreditWallet | undefined;
  control.setNavigationCheckpoint(checkpoint);
  const cancel = (): void => control.cancel();
  const saveForNavigation = (): void => checkpoint.flush(true);
  if (options.signal?.aborted) control.cancel();
  else options.signal?.addEventListener("abort", cancel, { once: true });
  addEventListener("pagehide", saveForNavigation);

  try {
    const request: Record<string, unknown> = {
      tenant: options.tenant ?? "default",
      site_key: options.sitekey,
      action: options.action,
      origin: location.origin,
    };
    const resumed = checkpoint.load();
    let challenge: ChallengeResponse;
    if (resumed) {
      challenge = resumed.challenge;
    } else {
      const issue = async (trustToken?: string): Promise<ChallengeResponse> => {
        const issued = await fetch(`${endpoint}/v1/challenges`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            ...request,
            ...(trustToken === undefined ? {} : { trust_token: trustToken }),
          }),
          signal: control.signal,
        });
        if (!issued.ok) throw await responseError(issued);
        return (await issued.json()) as ChallengeResponse;
      };
      if (hasStoredTrustCredits()) {
        try {
          trust = await loadTrustCredits();
          trustWallet = new trust.TrustCreditWallet(scope);
        } catch {
          // A code-loading or storage failure only disables the optional
          // credit optimization. Ordinary issuance remains available.
        }
      }
      challenge = trustWallet
        ? await trust!.issueWithTrustCredit(trustWallet, issue)
        : await issue();
      checkpoint.start(challenge);
    }
    options.onEvent?.({
      type: "quoted",
      detail: {
        quote: challenge.quote,
        presence: challenge.presence,
        fallback: challenge.fallback,
        resumed: resumed !== undefined,
      },
    });

    const timeLockWasm = loadTimeLockWasm(options.timeLockWasm);
    const timePromise = timeLockWasm.then((wasm) =>
      solveTimeLockChunked(
        challenge.time_lock,
        control,
        (value) => {
          options.onEvent?.({
            type: "progress",
            detail: { phase: "time_lock", value },
          });
        },
        resumed?.timeLock,
        (completed, value, force) =>
          checkpoint.setTimeLock(completed, value, force),
        wasm,
      ),
    );
    const renderPromise = solveRenderingAdaptive(challenge.render, {
      signal: control.signal,
      checkpoint: () => control.checkpoint(),
      ...(resumed === undefined
        ? {}
        : { completedRoundDigests: resumed.rendering.roundDigests }),
      ...(resumed?.rendering.backend === undefined
        ? {}
        : { resumeBackend: resumed.rendering.backend }),
      onBackendChange: (backend) => {
        options.onEvent?.({ type: "backendchange", detail: { backend } });
      },
      onRoundDigest: (completed, digest, backend) => {
        checkpoint.addRenderingRound(completed, digest, backend);
      },
      onRound: (completed, total) => {
        options.onEvent?.({
          type: "progress",
          detail: { phase: "rendering", value: completed / total },
        });
      },
    });
    const [output, rendering] = await Promise.all([timePromise, renderPromise]);
    const cssCommitment =
      rendering.backend === "css"
        ? {
            version: "css-transcript-v1" as const,
            digest: await cssTranscriptCommitment(challenge.render),
          }
        : undefined;
    let trustIssuance;
    if (challenge.trust?.mode === "voprf-v1") {
      try {
        trust ??= await loadTrustCredits();
        trustWallet ??= new trust.TrustCreditWallet(scope);
        trustIssuance = trust.prepareTrustCreditIssuance(
          challenge.trust,
          scope,
        );
      } catch {
        // Trust is optional. A malformed/unavailable credit path must never
        // prevent ordinary proof redemption.
      }
    }

    const redeemed = await fetch(`${endpoint}/v1/challenges/redeem`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: challenge.token,
        time_lock: { output },
        rendering: {
          digest: rendering.digest,
          backend: rendering.backend,
          ...(cssCommitment === undefined
            ? {}
            : { css_commitment: cssCommitment }),
        },
        ...(trustIssuance === undefined
          ? {}
          : { trust_blinded: trustIssuance.blinded }),
      }),
      signal: control.signal,
    });
    if (!redeemed.ok) throw await responseError(redeemed);
    const result = (await redeemed.json()) as RedeemResponse;
    checkpoint.clear();
    if (trustIssuance && result.trust_evaluation && trustWallet) {
      try {
        trustWallet.store(trustIssuance.finalize(result.trust_evaluation));
      } catch {
        // The verification token is authoritative; optional credit
        // finalization/storage failure cannot turn success into failure.
      }
    }
    options.onEvent?.({
      type: "verified",
      detail: { receipt: result.receipt, expires_at: result.expires_at },
    });
    return result.token;
  } catch (error) {
    control.cancel();
    if (shouldDiscardCheckpoint(error)) checkpoint.clear();
    throw error;
  } finally {
    options.signal?.removeEventListener("abort", cancel);
    removeEventListener("pagehide", saveForNavigation);
    deactivateControl(control);
  }
}

function checkpointScope(options: ExecuteOptions): NavigationCheckpointScope {
  const endpoint = options.endpoint.trim().replace(/\/+$/, "");
  return {
    endpoint: new URL(`${endpoint}/v1/challenges`, location.href).href,
    tenant: options.tenant ?? "default",
    sitekey: options.sitekey,
    action: options.action,
    origin: location.origin,
  };
}

export const Shar = {
  registerTranslations(locale: string, messages: SharTranslations): void {
    translations.set(registeredLocale(locale), validatedTranslations(messages));
    if (typeof document !== "undefined")
      for (const element of document.querySelectorAll<SharChallenge>(
        "shar-challenge",
      ))
        element.refreshTranslations();
  },
  async execute(options: ExecuteOptions): Promise<string> {
    const internal = options as InternalExecuteOptions;
    return executeWithControl(
      options,
      internal[EXECUTION_CONTROL] ?? new ExecutionControl(),
    );
  },

  render(
    container: Element | string,
    options: Omit<ExecuteOptions, "endpoint" | "sitekey" | "action"> & {
      endpoint: string;
      sitekey: string;
      action: string;
    },
  ): SharChallenge {
    const parent =
      typeof container === "string"
        ? document.querySelector(container)
        : container;
    if (!parent) throw new Error("Shar render container not found");
    const element = document.createElement("shar-challenge") as SharChallenge;
    element.endpoint = options.endpoint;
    element.sitekey = options.sitekey;
    element.action = options.action;
    if (options.tenant) element.tenant = options.tenant;
    element.configureExecution({
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      ...(options.onEvent === undefined ? {} : { onEvent: options.onEvent }),
      ...(options.timeLockWasm === undefined
        ? {}
        : { timeLockWasm: options.timeLockWasm }),
    });
    parent.append(element);
    return element;
  },

  pause(): void {
    activeControl?.pause();
  },
  resume(): void {
    activeControl?.resume();
  },
  reset(): void {
    const control = activeControl;
    control?.cancel();
    control?.clearNavigationCheckpoint();
    if (!control) clearNavigationCheckpoint();
    if (control) deactivateControl(control);
  },
  getResponse(): string {
    return (
      document.querySelector<SharChallenge>("shar-challenge")?.getResponse() ??
      ""
    );
  },
};

interface ErrorResponse {
  code?: string;
  retryable?: boolean;
  next_action?: string;
  retry_after?: number;
}

async function responseError(response: Response): Promise<Error> {
  const body = (await response
    .json()
    .catch(() => ({ code: `http_${response.status}` }))) as ErrorResponse;
  const error = new Error(body.code ?? `http_${response.status}`) as Error &
    ErrorResponse;
  error.name = "SharError";
  if (body.code !== undefined) error.code = body.code;
  if (body.retryable !== undefined) error.retryable = body.retryable;
  if (body.next_action !== undefined) error.next_action = body.next_action;
  if (body.retry_after !== undefined) error.retry_after = body.retry_after;
  return error;
}

function shouldDiscardCheckpoint(error: unknown): boolean {
  if (error instanceof DOMException && error.name === "AbortError")
    return false;
  if (!(error instanceof Error)) return false;
  const details = error as Error & ErrorResponse;
  if (details.name === "SharError") return details.retryable !== true;
  return [
    "time_lock_plan",
    "time_lock_checkpoint",
    "render_checkpoint",
    "render_bounds",
    "render_seed",
  ].includes(details.message);
}

export class SharChallenge extends HTMLElement {
  static formAssociated = true;
  static observedAttributes = ["disabled", "lang", "name"];
  private readonly internals: ElementInternals | undefined;
  private response = "";
  private fallbackInput?: HTMLInputElement;
  private paused = false;
  private regionElement?: HTMLElement;
  private statusElement?: HTMLElement;
  private progressElement?: HTMLProgressElement;
  private workElement?: HTMLOutputElement;
  private verifyButton?: HTMLButtonElement;
  private pauseButton?: HTMLButtonElement;
  private fallbackButton?: HTMLButtonElement;
  private fallbackMethods: string[] = [];
  private presenceMode: "none" | "host" = "none";
  private controls: HTMLButtonElement[] = [];
  private executionOptions: Pick<
    ExecuteOptions,
    "signal" | "onEvent" | "timeLockWasm"
  > = {};
  private executionControl: ExecutionControl | undefined;
  private executionScope: NavigationCheckpointScope | undefined;
  private verificationExpiresAt: number | undefined;
  private expiryTimer: number | undefined;
  private phaseProgress = { time_lock: 0, rendering: 0 };
  private statusMessage: StatusMessage = "ready";
  private quotedWork: { iterations: unknown; rounds: unknown } | undefined;

  constructor() {
    super();
    try {
      this.internals =
        typeof this.attachInternals === "function"
          ? this.attachInternals()
          : undefined;
    } catch {
      this.internals = undefined;
    }
  }

  get endpoint(): string {
    return this.getAttribute("endpoint") ?? "";
  }
  set endpoint(value: string) {
    this.setAttribute("endpoint", value);
  }
  get sitekey(): string {
    return this.getAttribute("sitekey") ?? "";
  }
  set sitekey(value: string) {
    this.setAttribute("sitekey", value);
  }
  get action(): string {
    return this.getAttribute("action") ?? "submit";
  }
  set action(value: string) {
    this.setAttribute("action", value);
  }
  get tenant(): string {
    return this.getAttribute("tenant") ?? "default";
  }
  set tenant(value: string) {
    this.setAttribute("tenant", value);
  }
  get disabled(): boolean {
    return this.hasAttribute("disabled");
  }
  set disabled(value: boolean) {
    this.toggleAttribute("disabled", value);
  }

  /** Compatibility subclasses that own a provider-specific hidden field can
   * opt out of Shar's ElementInternals/hidden-input submission path. */
  protected get managesFormValue(): boolean {
    return true;
  }

  configureExecution(
    options: Pick<ExecuteOptions, "signal" | "onEvent" | "timeLockWasm">,
  ): void {
    this.executionOptions = { ...options };
  }

  attributeChangedCallback(
    name: string,
    _oldValue: string | null,
    _newValue: string | null,
  ): void {
    if (name === "name" && this.fallbackInput)
      this.fallbackInput.name = this.getAttribute("name") ?? "shar-token";
    if (name === "disabled") this.applyDisabledState(this.disabled);
    if (name === "lang") this.refreshTranslations();
  }

  connectedCallback(): void {
    if (this.shadowRoot) {
      if (!this.expireIfNecessary()) this.scheduleExpiry();
      return;
    }
    if (this.managesFormValue && !this.internals && !this.fallbackInput) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = this.getAttribute("name") ?? "shar-token";
      this.append(input);
      this.fallbackInput = input;
    }
    const root = this.attachShadow({ mode: "open" });
    installWidgetStyles(root);
    const region = document.createElement("div");
    region.setAttribute("role", "group");
    region.setAttribute("part", "container");
    region.setAttribute("aria-busy", "false");
    const messages = messagesFor(this);
    region.dir = directionFor(localeFor(this));
    region.setAttribute("aria-label", messages.verificationLabel);

    const status = document.createElement("span");
    status.setAttribute("part", "status");
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.setAttribute("aria-atomic", "true");
    status.textContent = messages.ready;
    const work = document.createElement("output");
    work.setAttribute("part", "expected-work");
    work.dataset.sharExpectedWork = "";
    const progress = document.createElement("progress");
    progress.max = 1;
    progress.value = 0;
    progress.setAttribute("part", "progress");
    progress.setAttribute("aria-label", messages.progressLabel);
    const verify = document.createElement("button");
    verify.type = "button";
    verify.setAttribute("part", "button verify-button");
    verify.textContent = messages.verify;
    verify.addEventListener("click", () => void this.execute());
    const pause = document.createElement("button");
    pause.type = "button";
    pause.setAttribute("part", "button pause-button");
    pause.setAttribute("aria-pressed", "false");
    pause.textContent = messages.pause;
    pause.addEventListener("click", () =>
      this.paused ? this.resume() : this.pause(),
    );
    const fallback = document.createElement("button");
    fallback.type = "button";
    fallback.setAttribute("part", "button fallback-button");
    fallback.textContent = messages.fallback;
    fallback.hidden = true;
    fallback.addEventListener("click", () =>
      this.emit("fallback", {
        methods: [...this.fallbackMethods],
        presence: { mode: this.presenceMode },
      }),
    );

    region.append(status, work, progress, verify, pause, fallback);
    root.append(region);
    this.regionElement = region;
    this.statusElement = status;
    this.progressElement = progress;
    this.workElement = work;
    this.verifyButton = verify;
    this.pauseButton = pause;
    this.fallbackButton = fallback;
    this.controls = [verify, pause, fallback];
    this.applyDisabledState(this.disabled);
    queueMicrotask(() => this.emit("ready", {}));
  }

  disconnectedCallback(): void {
    this.clearExpiryTimer();
  }

  async execute(): Promise<string> {
    if (this.matches(":disabled") || this.disabled)
      throw new DOMException("Challenge is disabled", "InvalidStateError");
    this.clearVerifiedResponse();
    this.phaseProgress = { time_lock: 0, rendering: 0 };
    this.paused = false;
    this.executionControl?.cancel();
    const control = new ExecutionControl();
    this.executionControl = control;
    if (this.pauseButton)
      this.pauseButton.textContent = messagesFor(this).pause;
    if (this.pauseButton)
      this.pauseButton.setAttribute("aria-pressed", "false");
    if (this.regionElement)
      this.regionElement.setAttribute("aria-busy", "true");
    this.setStatusMessage("preparing");
    try {
      const options: InternalExecuteOptions = {
        endpoint: this.endpoint,
        sitekey: this.sitekey,
        action: this.action,
        tenant: this.tenant,
        ...(this.executionOptions.signal === undefined
          ? {}
          : { signal: this.executionOptions.signal }),
        ...(this.executionOptions.timeLockWasm === undefined
          ? this.hasAttribute("timelock-wasm")
            ? {
                timeLockWasm: this.getAttribute("timelock-wasm") || true,
              }
            : {}
          : { timeLockWasm: this.executionOptions.timeLockWasm }),
        onEvent: (event) => {
          this.handleClientEvent(event);
          this.executionOptions.onEvent?.(event);
        },
        [EXECUTION_CONTROL]: control,
      };
      this.executionScope = checkpointScope(options);
      const response = await Shar.execute(options);
      if (this.executionControl !== control)
        throw new DOMException("Execution superseded", "AbortError");
      this.response = response;
      this.setFormValue(this.response);
      this.scheduleExpiry();
      this.setStatusMessage("verified");
      this.emit("verified", { response: this.response });
      return this.response;
    } catch (error) {
      if (this.executionControl === control) {
        this.setStatusMessage("failed");
        if (
          error instanceof Error &&
          ["expired_challenge", "expired_verification"].includes(error.message)
        ) {
          this.emit("expired", { error });
        }
        this.emit("error", { error });
      }
      throw error;
    } finally {
      if (this.executionControl === control && this.regionElement)
        this.regionElement.setAttribute("aria-busy", "false");
    }
  }

  pause(): void {
    this.paused = true;
    this.executionControl?.pause();
    if (this.pauseButton)
      this.pauseButton.textContent = messagesFor(this).resume;
    if (this.pauseButton) this.pauseButton.setAttribute("aria-pressed", "true");
    this.setStatusMessage("paused");
  }

  resume(): void {
    this.paused = false;
    this.executionControl?.resume();
    if (this.pauseButton)
      this.pauseButton.textContent = messagesFor(this).pause;
    if (this.pauseButton)
      this.pauseButton.setAttribute("aria-pressed", "false");
    this.setStatusMessage("resumed");
  }

  reset(): void {
    const control = this.executionControl;
    control?.cancel();
    control?.clearNavigationCheckpoint();
    if (control) deactivateControl(control);
    this.executionControl = undefined;
    if (!control && !activeControl) {
      const scope =
        this.executionScope ??
        checkpointScope({
          endpoint: this.endpoint,
          sitekey: this.sitekey,
          action: this.action,
          tenant: this.tenant,
        });
      clearNavigationCheckpointForScope(scope);
    }
    this.resetView();
  }

  formResetCallback(): void {
    this.reset();
  }

  formDisabledCallback(disabled: boolean): void {
    this.applyDisabledState(disabled);
  }

  formStateRestoreCallback(
    _state: string | File | FormData | null,
    _mode: "restore" | "autocomplete",
  ): void {
    // Verification tokens are short-lived and single-use. Never restore a
    // browser-cached token, but retain any exact-quote navigation checkpoint.
    this.resetView();
  }

  private resetView(): void {
    this.clearVerifiedResponse();
    this.paused = false;
    this.phaseProgress = { time_lock: 0, rendering: 0 };
    this.quotedWork = undefined;
    if (this.progressElement) this.progressElement.value = 0;
    if (this.workElement) this.workElement.textContent = "";
    if (this.pauseButton)
      this.pauseButton.textContent = messagesFor(this).pause;
    if (this.pauseButton)
      this.pauseButton.setAttribute("aria-pressed", "false");
    if (this.regionElement)
      this.regionElement.setAttribute("aria-busy", "false");
    this.setStatusMessage("ready");
  }

  getResponse(): string {
    this.expireIfNecessary();
    return this.response;
  }

  getFallbackMethods(): readonly string[] {
    return [...this.fallbackMethods];
  }

  private setFormValue(value: string): void {
    if (this.managesFormValue) {
      this.internals?.setFormValue(value || null, null);
      if (this.fallbackInput) this.fallbackInput.value = value;
    }
  }

  private applyDisabledState(disabled: boolean): void {
    for (const control of this.controls) control.disabled = disabled;
    if (this.managesFormValue && this.fallbackInput)
      this.fallbackInput.disabled = disabled;
  }

  refreshTranslations(): void {
    const messages = messagesFor(this);
    if (this.regionElement) {
      this.regionElement.dir = directionFor(localeFor(this));
      this.regionElement.setAttribute("aria-label", messages.verificationLabel);
    }
    if (this.progressElement)
      this.progressElement.setAttribute("aria-label", messages.progressLabel);
    if (this.verifyButton) this.verifyButton.textContent = messages.verify;
    if (this.pauseButton)
      this.pauseButton.textContent = this.paused
        ? messages.resume
        : messages.pause;
    if (this.fallbackButton)
      this.fallbackButton.textContent = messages.fallback;
    this.renderExpectedWork();
    this.renderStatusMessage();
  }

  private setStatusMessage(message: StatusMessage): void {
    this.statusMessage = message;
    this.renderStatusMessage();
  }

  private renderStatusMessage(): void {
    if (!this.statusElement) return;
    const messages = messagesFor(this);
    if (this.statusMessage === "verifying") {
      const total =
        (this.phaseProgress.time_lock + this.phaseProgress.rendering) / 2;
      this.statusElement.textContent = messages.verifying.replace(
        "{percent}",
        formatProgressPercent(total, localeFor(this)),
      );
      return;
    }
    this.statusElement.textContent = messages[this.statusMessage];
  }

  private renderExpectedWork(): void {
    if (!this.workElement || !this.quotedWork) return;
    const iterations = formatWorkInteger(
      this.quotedWork.iterations,
      localeFor(this),
    );
    const rounds = formatWorkInteger(this.quotedWork.rounds, localeFor(this));
    this.workElement.textContent = messagesFor(this)
      .expectedWork.replace("{iterations}", iterations)
      .replace("{rounds}", rounds);
  }

  private handleClientEvent(event: SharClientEvent): void {
    if (event.type === "quoted") {
      const quote = event.detail.quote;
      if (this.workElement && quote && typeof quote === "object") {
        const values = quote as Record<string, unknown>;
        this.quotedWork = {
          iterations: values.time_lock_iterations,
          rounds: values.render_rounds,
        };
        this.renderExpectedWork();
      }
      const presence = event.detail.presence;
      this.presenceMode =
        presence &&
        typeof presence === "object" &&
        (presence as Record<string, unknown>).mode === "host"
          ? "host"
          : "none";
      const fallback = event.detail.fallback;
      const fallbackValues =
        fallback && typeof fallback === "object"
          ? (fallback as Record<string, unknown>)
          : undefined;
      const methods = fallbackValues?.methods;
      this.fallbackMethods =
        fallbackValues?.available === true &&
        Array.isArray(methods) &&
        methods.length > 0 &&
        methods.every((method) => typeof method === "string")
          ? [...methods]
          : [];
      if (this.fallbackButton)
        this.fallbackButton.hidden = this.fallbackMethods.length === 0;
      this.emit(event.type, event.detail);
      return;
    }
    if (event.type === "backendchange") {
      this.emit(event.type, event.detail);
      return;
    }
    if (event.type === "verified") {
      const expiresAt = Number(event.detail.expires_at);
      this.verificationExpiresAt =
        Number.isSafeInteger(expiresAt) && expiresAt >= 0
          ? expiresAt
          : undefined;
      return;
    }
    if (event.type !== "progress") return;
    const phase = event.detail.phase;
    const value = Number(event.detail.value ?? 0);
    if (
      (phase === "time_lock" || phase === "rendering") &&
      Number.isFinite(value)
    ) {
      this.phaseProgress[phase] = Math.max(0, Math.min(1, value));
      const total =
        (this.phaseProgress.time_lock + this.phaseProgress.rendering) / 2;
      if (this.progressElement) this.progressElement.value = total;
      this.setStatusMessage("verifying");
    }
    this.emit("progress", event.detail);
  }

  private clearVerifiedResponse(): void {
    this.clearExpiryTimer();
    this.verificationExpiresAt = undefined;
    this.response = "";
    this.setFormValue("");
  }

  private clearExpiryTimer(): void {
    if (this.expiryTimer !== undefined) clearTimeout(this.expiryTimer);
    this.expiryTimer = undefined;
  }

  private scheduleExpiry(): void {
    this.clearExpiryTimer();
    const expiresAt = this.verificationExpiresAt;
    if (expiresAt === undefined || !this.response) return;
    const delay = Math.max(
      0,
      Math.min(0x7fff_ffff, (expiresAt + 1) * 1000 - Date.now()),
    );
    this.expiryTimer = setTimeout(() => {
      this.expiryTimer = undefined;
      if (!this.expireIfNecessary()) this.scheduleExpiry();
    }, delay);
  }

  private expireIfNecessary(): boolean {
    const expiresAt = this.verificationExpiresAt;
    if (expiresAt === undefined || Math.floor(Date.now() / 1000) <= expiresAt)
      return false;
    this.clearVerifiedResponse();
    this.setStatusMessage("expired");
    this.emit("expired", { expires_at: expiresAt });
    return true;
  }

  private emit(type: string, detail: unknown): void {
    this.dispatchEvent(
      new CustomEvent(type, { detail, bubbles: true, composed: true }),
    );
  }
}

export interface BrowserCompatibilityAdapterConfig {
  endpoint: string;
  tenant?: string;
  sitekey?: string;
  action?: string;
}

export interface BrowserCompatibilityRenderParameters {
  sitekey?: string;
  action?: string;
  callback?: (token: string) => void;
  "expired-callback"?: () => void;
  "error-callback"?: (error: unknown) => void;
}

export interface BrowserCompatibilityExecuteOptions {
  action?: string;
}

/**
 * The common programmatic subset shared by the reCAPTCHA and hCaptcha browser
 * APIs. It intentionally delegates every execution to the canonical Shar
 * challenge; compatibility never creates an easier proof path.
 */
export interface BrowserCompatibilityAdapter {
  ready(callback: () => void): void;
  render(
    container: Element | string,
    parameters?: BrowserCompatibilityRenderParameters,
  ): number;
  execute(
    widgetIdOrSitekey?: number | string,
    options?: BrowserCompatibilityExecuteOptions,
  ): Promise<string>;
  reset(widgetId?: number): void;
  getResponse(widgetId?: number): string;
  remove(widgetId?: number): void;
}

type CompatibilityProvider = "recaptcha" | "hcaptcha";

interface CompatibilityWidget {
  element: SharChallenge;
}

function createBrowserCompatibilityAdapter(
  provider: CompatibilityProvider,
  config: BrowserCompatibilityAdapterConfig,
): BrowserCompatibilityAdapter {
  const endpoint = config.endpoint.trim().replace(/\/$/, "");
  if (!endpoint) throw new Error("compatibility endpoint is required");
  const widgets = new Map<number, CompatibilityWidget>();
  let nextWidgetId = 0;

  const firstWidget = (): CompatibilityWidget | undefined =>
    widgets.values().next().value as CompatibilityWidget | undefined;
  const widgetFor = (widgetId?: number): CompatibilityWidget | undefined =>
    widgetId === undefined ? firstWidget() : widgets.get(widgetId);

  return {
    ready(callback): void {
      queueMicrotask(callback);
    },

    render(container, parameters = {}): number {
      const parent =
        typeof container === "string"
          ? document.querySelector(container)
          : container;
      if (!parent) throw new Error("compatibility render container not found");
      const sitekey = parameters.sitekey ?? config.sitekey;
      if (!sitekey?.trim())
        throw new Error("compatibility sitekey is required");

      const element = document.createElement("shar-challenge") as SharChallenge;
      element.endpoint = endpoint;
      element.sitekey = sitekey;
      element.action = parameters.action ?? config.action ?? "submit";
      element.tenant = config.tenant ?? "default";
      element.setAttribute(
        "name",
        provider === "recaptcha"
          ? "g-recaptcha-response"
          : "h-captcha-response",
      );
      if (parameters.callback) {
        element.addEventListener("verified", (event) => {
          const detail = (event as CustomEvent<{ response?: unknown }>).detail;
          const response = detail?.response;
          if (typeof response === "string") parameters.callback?.(response);
        });
      }
      if (parameters["expired-callback"]) {
        element.addEventListener("expired", () =>
          parameters["expired-callback"]?.(),
        );
      }
      if (parameters["error-callback"]) {
        element.addEventListener("error", (event) => {
          const detail = (event as unknown as CustomEvent<{ error?: unknown }>)
            .detail;
          parameters["error-callback"]?.(detail?.error);
        });
      }
      parent.append(element);
      const widgetId = nextWidgetId++;
      widgets.set(widgetId, { element });
      return widgetId;
    },

    async execute(widgetIdOrSitekey, options = {}): Promise<string> {
      if (typeof widgetIdOrSitekey === "number") {
        const widget = widgets.get(widgetIdOrSitekey);
        if (!widget) throw new Error("compatibility widget not found");
        return widget.element.execute();
      }
      if (typeof widgetIdOrSitekey === "string") {
        if (!widgetIdOrSitekey.trim())
          throw new Error("compatibility sitekey is required");
        return Shar.execute({
          endpoint,
          sitekey: widgetIdOrSitekey,
          action: options.action ?? config.action ?? "submit",
          ...(config.tenant === undefined ? {} : { tenant: config.tenant }),
        });
      }
      const widget = firstWidget();
      if (widget) return widget.element.execute();
      if (!config.sitekey?.trim())
        throw new Error("compatibility sitekey is required");
      return Shar.execute({
        endpoint,
        sitekey: config.sitekey,
        action: options.action ?? config.action ?? "submit",
        ...(config.tenant === undefined ? {} : { tenant: config.tenant }),
      });
    },

    reset(widgetId): void {
      widgetFor(widgetId)?.element.reset();
    },

    getResponse(widgetId): string {
      return widgetFor(widgetId)?.element.getResponse() ?? "";
    },

    remove(widgetId): void {
      const widget = widgetFor(widgetId);
      if (!widget) return;
      widget.element.reset();
      widget.element.remove();
      for (const [id, candidate] of widgets) {
        if (candidate === widget) {
          widgets.delete(id);
          break;
        }
      }
    },
  };
}

export function createRecaptchaAdapter(
  config: BrowserCompatibilityAdapterConfig,
): BrowserCompatibilityAdapter {
  return createBrowserCompatibilityAdapter("recaptcha", config);
}

export function createHcaptchaAdapter(
  config: BrowserCompatibilityAdapterConfig,
): BrowserCompatibilityAdapter {
  return createBrowserCompatibilityAdapter("hcaptcha", config);
}

function installCompatibilityAdapter(
  name: "grecaptcha" | "hcaptcha",
  adapter: BrowserCompatibilityAdapter,
  target: Record<string, unknown>,
): BrowserCompatibilityAdapter {
  if (name in target) throw new Error(`${name} is already installed`);
  Object.defineProperty(target, name, {
    configurable: true,
    enumerable: true,
    value: adapter,
    writable: false,
  });
  return adapter;
}

/** Opt-in installation; Shar never overwrites a provider SDK already present. */
export function installRecaptchaAdapter(
  config: BrowserCompatibilityAdapterConfig,
  target: Record<string, unknown> = globalThis as unknown as Record<
    string,
    unknown
  >,
): BrowserCompatibilityAdapter {
  return installCompatibilityAdapter(
    "grecaptcha",
    createRecaptchaAdapter(config),
    target,
  );
}

/** Opt-in installation; Shar never overwrites a provider SDK already present. */
export function installHcaptchaAdapter(
  config: BrowserCompatibilityAdapterConfig,
  target: Record<string, unknown> = globalThis as unknown as Record<
    string,
    unknown
  >,
): BrowserCompatibilityAdapter {
  return installCompatibilityAdapter(
    "hcaptcha",
    createHcaptchaAdapter(config),
    target,
  );
}

function formatWorkInteger(value: unknown, locale: string): string {
  try {
    const integer = typeof value === "bigint" ? value : BigInt(String(value));
    if (integer < 0n) throw new Error("negative");
    return new Intl.NumberFormat(locale, { maximumFractionDigits: 0 }).format(
      integer,
    );
  } catch {
    return String(value ?? "");
  }
}

function formatProgressPercent(value: number, locale: string): string {
  try {
    return new Intl.NumberFormat(locale, { maximumFractionDigits: 0 }).format(
      Math.round(value * 100),
    );
  } catch {
    return String(Math.round(value * 100));
  }
}

if (
  typeof customElements !== "undefined" &&
  !customElements.get("shar-challenge")
) {
  customElements.define("shar-challenge", SharChallenge);
}

export * from "./render-executors.js";
export * from "./time-lock-wasm.js";
