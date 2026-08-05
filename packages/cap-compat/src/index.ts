import { SharChallenge } from "@shar/widget";

export class CapWidgetCompatibility extends SharChallenge {
  private initialized = false;
  private tokenInput?: HTMLInputElement;
  private workerCount = 1;
  private readonly eventHandlers = new Map<string, EventListener>();

  protected override get managesFormValue(): boolean {
    return false;
  }

  static get observedAttributes(): string[] {
    return [
      ...SharChallenge.observedAttributes,
      "data-cap-worker-count",
      "data-cap-hidden-field-name",
      "data-cap-lang",
      "onsolve",
      "onprogress",
      "onerror",
      "onreset",
    ];
  }

  /** Cap exposes the current token as both `token` and `tokenValue`. */
  get token(): string | null {
    return this.getResponse() || null;
  }

  get tokenValue(): string | null {
    return this.token;
  }

  connectedCallback(): void {
    if (!this.hasAttribute("endpoint")) {
      const endpoint =
        this.getAttribute("api-endpoint") ??
        this.getAttribute("data-cap-api-endpoint");
      if (endpoint) this.endpoint = endpoint;
    }
    if (!this.hasAttribute("sitekey")) {
      this.sitekey =
        this.getAttribute("data-sitekey") ??
        this.getAttribute("data-cap-sitekey") ??
        "default";
    }
    if (!this.hasAttribute("lang")) {
      const language = this.getAttribute("data-cap-lang");
      if (language) this.setAttribute("lang", language);
    }
    super.connectedCallback();
    if (this.initialized) return;
    this.initialized = true;

    const input =
      [...this.querySelectorAll<HTMLInputElement>("input[type='hidden']")].find(
        (candidate) => candidate.name === this.fieldName,
      ) ?? document.createElement("input");
    input.type = "hidden";
    input.name = this.fieldName;
    input.value = this.getResponse();
    input.disabled = this.matches(":disabled") || this.disabled;
    if (!input.isConnected) this.append(input);
    this.tokenInput = input;
    this.addEventListener("verified", () => {
      const token = this.getResponse();
      input.value = token;
      this.dispatchEvent(
        new CustomEvent("solve", {
          detail: { token },
          bubbles: true,
          composed: true,
        }),
      );
    });
    this.addEventListener("expired", () => {
      input.value = "";
    });

    const workers = Number.parseInt(
      this.getAttribute("data-cap-worker-count") ?? "",
      10,
    );
    if (Number.isFinite(workers) && workers > 0)
      this.workerCount = Math.floor(workers);
    this.applyInitialLabels();
  }

  attributeChangedCallback(
    name: string,
    oldValue: string | null,
    value: string | null,
  ): void {
    super.attributeChangedCallback(name, oldValue, value);
    if (name === "data-cap-worker-count" && value !== null) {
      const workers = Number.parseInt(value, 10);
      if (Number.isFinite(workers) && workers > 0)
        this.setWorkersCount(workers);
    }
    if (name === "data-cap-hidden-field-name" && this.tokenInput) {
      this.tokenInput.name = this.fieldName;
    }
    if (name.startsWith("on")) {
      const eventName = name.slice(2);
      const previous = this.eventHandlers.get(name);
      if (previous) this.removeEventListener(eventName, previous);
      this.eventHandlers.delete(name);
      if (value) {
        const handler: EventListener = (event) => {
          const callback = (globalThis as Record<string, unknown>)[value];
          if (typeof callback === "function")
            (callback as (event: Event) => void).call(this, event);
        };
        this.eventHandlers.set(name, handler);
        this.addEventListener(eventName, handler);
      }
    }
  }

  /** Preserve Cap's imperative API. Shar's executor chooses its own safe parallelism. */
  async solve(): Promise<{ success: boolean; token: string }> {
    const token = await this.execute();
    return { success: true, token };
  }

  setWorkersCount(workers: number): void {
    if (Number.isFinite(workers) && workers > 0)
      this.workerCount = Math.floor(workers);
  }

  reset(): void {
    super.reset();
    if (this.tokenInput) this.tokenInput.value = "";
    this.dispatchEvent(
      new CustomEvent("reset", { detail: {}, bubbles: true, composed: true }),
    );
  }

  override formDisabledCallback(disabled: boolean): void {
    super.formDisabledCallback(disabled);
    if (this.tokenInput) this.tokenInput.disabled = disabled;
  }

  /** Convert Shar's richer event details to the stable Cap event contract. */
  override dispatchEvent(event: Event): boolean {
    if (event instanceof CustomEvent && event.type === "progress") {
      const detail = event.detail as Record<string, unknown> | null;
      if (detail && "value" in detail) {
        const value = Number(detail.value);
        const progress = Number.isFinite(value)
          ? Math.max(0, Math.min(100, Math.round(value * 100)))
          : 0;
        return super.dispatchEvent(
          new CustomEvent("progress", {
            detail: { progress },
            bubbles: event.bubbles,
            cancelable: event.cancelable,
            composed: event.composed,
          }),
        );
      }
    }
    if (event instanceof CustomEvent && event.type === "error") {
      const detail = event.detail as { error?: unknown } | null;
      const error = detail?.error;
      const message =
        error instanceof Error
          ? error.message
          : String(error ?? "Verification failed");
      const code =
        error && typeof error === "object" && "code" in error
          ? String((error as { code?: unknown }).code ?? "unknown")
          : "unknown";
      return super.dispatchEvent(
        new CustomEvent("error", {
          detail: { isCap: true, code, message },
          bubbles: event.bubbles,
          cancelable: event.cancelable,
          composed: event.composed,
        }),
      );
    }
    return super.dispatchEvent(event);
  }

  private get fieldName(): string {
    return this.getAttribute("data-cap-hidden-field-name") || "cap-token";
  }

  private applyInitialLabels(): void {
    const initial = this.getAttribute("data-cap-i18n-initial-state");
    if (initial) {
      const status = this.shadowRoot?.querySelector<HTMLElement>(
        '[aria-live="polite"]',
      );
      if (status) status.textContent = initial;
    }
  }
}

export interface CapConfig {
  apiEndpoint?: string;
  "data-cap-api-endpoint"?: string;
  "data-cap-hidden-field-name"?: string;
  "data-cap-sitekey"?: string;
  "data-cap-worker-count"?: string;
  "data-cap-lang"?: string;
  sitekey?: string;
  action?: string;
  tenant?: string;
  required?: boolean | "";
}

/** Small constructor-compatible facade for integrations that use `new Cap(...)`. */
export class Cap {
  readonly widget: CapWidgetCompatibility;

  constructor(config: CapConfig = {}, element?: CapWidgetCompatibility) {
    const widget =
      element ??
      (document.createElement("cap-widget") as CapWidgetCompatibility);
    for (const [name, value] of Object.entries(config)) {
      if (value !== undefined) widget.setAttribute(name, String(value));
    }
    if (config.apiEndpoint) {
      widget.setAttribute("data-cap-api-endpoint", config.apiEndpoint);
      widget.endpoint = config.apiEndpoint;
    }
    if (
      !widget.hasAttribute("data-cap-api-endpoint") &&
      !widget.hasAttribute("endpoint")
    ) {
      widget.remove();
      throw new Error(
        "Missing API endpoint. Provide apiEndpoint or data-cap-api-endpoint.",
      );
    }
    this.widget = widget;
    if (!element) {
      widget.style.display = "none";
      document.documentElement.append(widget);
    }
  }

  get token(): string | null {
    return this.widget.token;
  }

  get tokenValue(): string | null {
    return this.widget.tokenValue;
  }

  solve(): Promise<{ success: boolean; token: string }> {
    return this.widget.solve();
  }

  reset(): void {
    this.widget.reset();
  }

  addEventListener(...args: Parameters<HTMLElement["addEventListener"]>): void {
    this.widget.addEventListener(...args);
  }
}

if (
  typeof customElements !== "undefined" &&
  !customElements.get("cap-widget")
) {
  customElements.define("cap-widget", CapWidgetCompatibility);
}

if (typeof window !== "undefined") {
  const globalWindow = window as Window & { Cap?: typeof Cap };
  if (!globalWindow.Cap) globalWindow.Cap = Cap;
}
