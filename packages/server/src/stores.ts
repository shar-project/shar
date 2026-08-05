import { base64url } from "./bytes.js";
import { decayTier, priceWork } from "./pricing.js";
import {
  AuditEvent,
  AuditStore,
  ChallengeRequest,
  ConfigStore,
  NonceStore,
  PressureInput,
  PressureStore,
  WorkPolicy,
  WorkQuote,
} from "./types.js";

const AUDIT_RETENTION_SECONDS = 86_400;

export class MemoryAuditStore implements AuditStore {
  private readonly values: AuditEvent[] = [];

  constructor(private readonly retentionSeconds = AUDIT_RETENTION_SECONDS) {
    if (!Number.isSafeInteger(retentionSeconds) || retentionSeconds <= 0)
      throw new Error("invalid_audit_retention");
  }

  async record(event: AuditEvent): Promise<void> {
    validateAuditEvent(event);
    const before = event.occurred_at - this.retentionSeconds;
    this.values.push(sanitizeAuditEvent(event));
    await this.purge(before);
  }

  async purge(before: number): Promise<void> {
    if (!Number.isSafeInteger(before)) throw new Error("invalid_audit_cutoff");
    const retained = this.values.filter((event) => event.occurred_at >= before);
    this.values.splice(0, this.values.length, ...retained);
  }

  snapshot(): readonly AuditEvent[] {
    return this.values.map((event) => ({ ...event }));
  }

  async list(
    tenant: string,
    siteKey: string,
    action: string,
    limit: number,
  ): Promise<AuditEvent[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("invalid_audit_limit");
    return this.values
      .filter(
        (event) =>
          event.tenant === tenant &&
          event.site_key === siteKey &&
          event.action === action,
      )
      .slice(-limit)
      .reverse()
      .map((event) => ({ ...event }));
  }
}

export class MemoryNonceStore implements NonceStore {
  private readonly used = new Map<string, number>();

  constructor(
    private readonly clock: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  async consume(
    namespace: "challenge" | "verification" | "fallback" | "trust",
    nonce: Uint8Array,
    expiresAt: number,
  ): Promise<boolean> {
    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error("invalid_clock");
    if (!Number.isSafeInteger(expiresAt) || expiresAt < 0)
      throw new Error("invalid_expiry");
    this.sweep(now);
    const key = `${namespace}:${base64url(nonce)}`;
    if (this.used.has(key)) return false;
    this.used.set(key, expiresAt);
    return true;
  }
  sweep(now: number): void {
    for (const [key, expiry] of this.used)
      if (expiry < now) this.used.delete(key);
  }
}

export const DEFAULT_POLICY: WorkPolicy = {
  version: "policy-v1",
  baseIterations: 1024n,
  baseRenderRounds: 1,
  quietWindowSeconds: 60,
  baseLifetimeSeconds: 120,
  iterationAllowance: 100_000n,
  roundAllowanceSeconds: 15,
  maxLifetimeSeconds: 63_072_000,
};

export class StaticConfigStore implements ConfigStore {
  constructor(private value: WorkPolicy = DEFAULT_POLICY) {}
  async policy(
    _tenant: string,
    _siteKey: string,
    _action: string,
  ): Promise<WorkPolicy> {
    return this.value;
  }
  async setPolicy(
    _tenant: string,
    _siteKey: string,
    _action: string,
    policy: WorkPolicy,
  ): Promise<void> {
    this.value = { ...policy };
  }
}

export class MemoryPressureStore implements PressureStore {
  private readonly values = new Map<string, PressureState>();
  private readonly overrides = new Map<string, PressureInput>();
  constructor(
    private readonly quietWindowSeconds = DEFAULT_POLICY.quietWindowSeconds,
  ) {
    if (!Number.isSafeInteger(quietWindowSeconds) || quietWindowSeconds <= 0)
      throw new Error("invalid_quiet_window");
  }
  private baseKey(input: ChallengeRequest): string {
    return `${input.tenant}\0${input.site_key}\0${input.action}`;
  }
  private actionKey(input: ChallengeRequest): string {
    return `action\0${this.baseKey(input)}`;
  }
  private clientKey(input: ChallengeRequest): string {
    return `client\0${this.baseKey(input)}\0${input.session_binding ?? ""}`;
  }
  private networkKey(input: ChallengeRequest): string | undefined {
    return input.network_pseudonym
      ? `network\0${this.baseKey(input)}\0${input.network_pseudonym}`
      : undefined;
  }
  private failureKey(input: ChallengeRequest): string {
    return input.session_binding || !input.network_pseudonym
      ? this.clientKey(input)
      : this.networkKey(input)!;
  }
  set(input: ChallengeRequest, pressure: PressureInput, now = 0): void {
    nonNegativeInteger(now, "invalid_time");
    this.overrides.set(this.clientKey(input), { ...pressure });
    this.values.set(this.clientKey(input), {
      ...pressure,
      lastActivity: now,
      windowStart: now,
      requestCount: 0,
      outstanding: [],
    });
  }
  private readNow(
    input: ChallengeRequest,
    now: number,
    quietWindowSeconds = this.quietWindowSeconds,
  ): PressureInput {
    nonNegativeInteger(now, "invalid_time");
    if (!Number.isSafeInteger(quietWindowSeconds) || quietWindowSeconds <= 0)
      throw new Error("invalid_quiet_window");
    const override = this.overrides.get(this.clientKey(input));
    if (override)
      return {
        ...override,
        assuranceDebt: Math.max(
          override.assuranceDebt,
          input.assurance_tier ?? 0,
        ),
      };
    const actionKey = this.actionKey(input),
      clientKey = this.clientKey(input),
      networkKey = this.networkKey(input);
    const action = this.values.get(actionKey) ?? initialState(now);
    // Signed expiries are inclusive: an outstanding quote at `now === expiry`
    // is still live for this pricing read.
    action.outstanding = action.outstanding.filter((expiry) => expiry >= now);
    rollWindow(action, now, quietWindowSeconds);
    action.requestCount++;
    action.lastActivity = now;
    this.values.set(actionKey, action);
    const client = this.values.get(clientKey) ?? initialState(now);
    decay(client, now, quietWindowSeconds);
    const assurance = Math.max(client.assuranceDebt, input.assurance_tier ?? 0);
    if (input.session_binding) client.assuranceDebt = assurance;
    client.lastActivity = now;
    this.values.set(clientKey, client);
    let networkTier = 0;
    if (networkKey) {
      const network = this.values.get(networkKey) ?? initialState(now);
      decay(network, now, quietWindowSeconds);
      rollWindow(network, now, quietWindowSeconds);
      network.requestCount++;
      networkTier = Math.max(
        network.networkTier,
        network.failureDebt,
        logarithmicTier(network.requestCount),
      );
      network.lastActivity = now;
      this.values.set(networkKey, network);
    }
    return {
      baseTier: client.baseTier,
      velocityTier: logarithmicTier(action.requestCount),
      outstandingTier: logarithmicTier(action.outstanding.length + 1),
      networkTier,
      failureDebt: client.failureDebt,
      assuranceDebt: assurance,
      trustCredits: client.trustCredits,
    };
  }
  async read(
    input: ChallengeRequest,
    now: number,
    quietWindowSeconds = this.quietWindowSeconds,
  ): Promise<PressureInput> {
    return this.readNow(input, now, quietWindowSeconds);
  }
  async priceAndRecord(
    input: ChallengeRequest,
    policy: WorkPolicy,
    now: number,
  ): Promise<WorkQuote> {
    const pressure = this.readNow(input, now, policy.quietWindowSeconds);
    const quote = priceWork(pressure, policy, now);
    const key = this.actionKey(input);
    const state = this.values.get(key) ?? initialState(now);
    state.outstanding.push(quote.expires_at);
    state.lastActivity = now;
    this.values.set(key, state);
    return quote;
  }
  async recordIssued(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
  ): Promise<void> {
    nonNegativeInteger(now, "invalid_time");
    nonNegativeInteger(expiresAt, "invalid_expiry");
    const key = this.actionKey(input);
    const state = this.values.get(key) ?? initialState(now);
    state.outstanding = state.outstanding.filter((expiry) => expiry >= now);
    state.outstanding.push(expiresAt);
    state.lastActivity = now;
    this.values.set(key, state);
  }
  async recordSuccess(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
  ): Promise<void> {
    nonNegativeInteger(now, "invalid_time");
    nonNegativeInteger(expiresAt, "invalid_expiry");
    const key = this.failureKey(input);
    const state = this.values.get(key) ?? initialState(now);
    state.failureDebt = Math.max(0, state.failureDebt - 1);
    state.lastActivity = now;
    this.values.set(key, state);
    const actionKey = this.actionKey(input),
      action = this.values.get(actionKey) ?? initialState(now);
    removeOutstanding(action.outstanding, expiresAt);
    this.values.set(actionKey, action);
  }
  async recordFailure(
    input: ChallengeRequest,
    kind: "invalid" | "replay" | "expired",
    expiresAt: number,
    now: number,
  ): Promise<void> {
    nonNegativeInteger(now, "invalid_time");
    nonNegativeInteger(expiresAt, "invalid_expiry");
    const key = this.failureKey(input);
    const state = this.values.get(key) ?? initialState(now);
    state.failureDebt = Math.min(32, state.failureDebt + 1);
    state.lastActivity = now;
    this.values.set(key, state);
    if (kind === "expired") {
      const actionKey = this.actionKey(input),
        action = this.values.get(actionKey) ?? initialState(now);
      removeOutstanding(action.outstanding, expiresAt);
      this.values.set(actionKey, action);
    }
  }

  async recordTrust(input: ChallengeRequest, now: number): Promise<void> {
    nonNegativeInteger(now, "invalid_time");
    // Trust credits may reduce client failure/assurance debt, never the
    // rotating network-pressure bucket shared by a NAT or proxy.
    const key = this.clientKey(input);
    const state = this.values.get(key) ?? initialState(now);
    // A credit is a one-time, unlinkable debt reduction. Prefer failure debt,
    // then assurance debt; network and current velocity are never changed.
    if (state.failureDebt > 0) state.failureDebt--;
    else if (state.assuranceDebt > 0) state.assuranceDebt--;
    state.lastActivity = now;
    this.values.set(key, state);
  }
}

interface PressureState extends PressureInput {
  lastActivity: number;
  windowStart: number;
  requestCount: number;
  outstanding: number[];
}
function initialState(now: number): PressureState {
  return {
    baseTier: 0,
    velocityTier: 0,
    outstandingTier: 0,
    networkTier: 0,
    failureDebt: 0,
    assuranceDebt: 0,
    trustCredits: 0,
    lastActivity: now,
    windowStart: now,
    requestCount: 0,
    outstanding: [],
  };
}
function logarithmicTier(count: number): number {
  if (!Number.isSafeInteger(count) || count < 0)
    throw new Error("invalid_pressure_count");
  let tier = 0;
  let threshold = 1;
  while (count > threshold && tier < 32) {
    threshold *= 2;
    tier += 1;
  }
  return tier;
}

function removeOutstanding(values: number[], expiresAt: number): void {
  const index = values.indexOf(expiresAt);
  if (index >= 0) values.splice(index, 1);
}

function nonNegativeInteger(value: number, code: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(code);
  return value;
}

function validateAuditEvent(event: AuditEvent): void {
  if (
    event.version !== "audit-v1" ||
    ![
      "challenge_issued",
      "proof_redeemed",
      "site_verified",
      "fallback_completed",
      "proof_failed",
      "verification_failed",
    ].includes(event.kind) ||
    !Number.isSafeInteger(event.occurred_at) ||
    event.occurred_at < 0 ||
    !Number.isSafeInteger(event.tier ?? 0) ||
    (event.tier !== undefined && (event.tier < 0 || event.tier > 32))
  )
    throw new Error("invalid_audit_event");
  for (const [value, maximum] of [
    [event.tenant, 128],
    [event.site_key, 256],
    [event.action, 128],
  ] as const) {
    if (
      typeof value !== "string" ||
      value.length < 1 ||
      value.length > maximum ||
      /[\0-\x1f\x7f]/.test(value)
    )
      throw new Error("invalid_audit_event");
  }
  if (
    (event.backend !== undefined &&
      !["webgpu", "webgl2", "css"].includes(event.backend)) ||
    (event.code !== undefined &&
      (event.code.length < 1 ||
        event.code.length > 128 ||
        /[^a-z0-9_]/.test(event.code)))
  )
    throw new Error("invalid_audit_event");
}

function sanitizeAuditEvent(event: AuditEvent): AuditEvent {
  const filtered: AuditEvent = {
    version: event.version,
    kind: event.kind,
    occurred_at: event.occurred_at,
    tenant: event.tenant,
    site_key: event.site_key,
    action: event.action,
  };
  if (event.tier !== undefined) filtered.tier = event.tier;
  if (event.backend !== undefined) filtered.backend = event.backend;
  if (event.code !== undefined) filtered.code = event.code;
  return filtered;
}
function decay(
  state: PressureState,
  now: number,
  quietWindowSeconds: number,
): void {
  state.failureDebt = decayTier(
    state.failureDebt,
    state.lastActivity,
    now,
    quietWindowSeconds,
  );
  state.assuranceDebt = decayTier(
    state.assuranceDebt,
    state.lastActivity,
    now,
    quietWindowSeconds,
  );
}
function rollWindow(
  state: PressureState,
  now: number,
  quietWindowSeconds: number,
): void {
  if (now - state.windowStart >= quietWindowSeconds) {
    state.windowStart = now;
    state.requestCount = 0;
  }
}
