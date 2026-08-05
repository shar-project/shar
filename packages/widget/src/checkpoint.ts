import {
  base64url,
  bytesToBigint,
  fromBase64url,
  type ChallengeResponse,
  type RenderingBackend,
} from "@shar/server/browser";

export const NAVIGATION_CHECKPOINT_KEY = "shar:widget:execution:v1";
const CHECKPOINT_VERSION = "shar-widget-checkpoint-v1";
const MAX_CHECKPOINT_BYTES = 4 * 1024 * 1024;
const FLUSH_INTERVAL_MS = 250;

export interface NavigationCheckpointScope {
  endpoint: string;
  tenant: string;
  sitekey: string;
  action: string;
  origin: string;
}

export interface TimeLockExecutionCheckpoint {
  completed: string;
  value: string;
}

export interface RenderingExecutionCheckpoint {
  roundDigests: string[];
  backend?: RenderingBackend;
}

export interface NavigationCheckpointState {
  challenge: ChallengeResponse;
  timeLock?: TimeLockExecutionCheckpoint;
  rendering: RenderingExecutionCheckpoint;
}

interface StoredNavigationCheckpoint extends NavigationCheckpointState {
  version: typeof CHECKPOINT_VERSION;
  owner: string;
  scope: NavigationCheckpointScope;
  updatedAt: number;
}

/**
 * Best-effort, same-tab persistence for already-issued work. Acceptance never
 * depends on this client-side state; the signed challenge and server verifier
 * remain authoritative.
 */
export class NavigationCheckpoint {
  private readonly owner = newCheckpointOwner();
  private stateValue: NavigationCheckpointState | undefined;
  private lastFlush = 0;
  private dirty = false;

  constructor(readonly scope: NavigationCheckpointScope) {}

  load(
    nowSeconds = Math.floor(Date.now() / 1000),
  ): NavigationCheckpointState | undefined {
    const storage = sessionStorageOrUndefined();
    if (!storage) return undefined;
    try {
      const raw = storage.getItem(NAVIGATION_CHECKPOINT_KEY);
      if (raw === null) return undefined;
      if (raw.length > MAX_CHECKPOINT_BYTES) throw new Error("checkpoint_size");
      const stored = JSON.parse(raw) as unknown;
      if (!validStoredCheckpoint(stored, this.scope, nowSeconds))
        throw new Error("checkpoint_invalid");
      this.stateValue = {
        challenge: stored.challenge,
        ...(stored.timeLock === undefined
          ? {}
          : { timeLock: { ...stored.timeLock } }),
        rendering: {
          roundDigests: [...stored.rendering.roundDigests],
          ...(stored.rendering.backend === undefined
            ? {}
            : { backend: stored.rendering.backend }),
        },
      };
      this.dirty = true;
      this.flush(true, true);
      return this.state;
    } catch {
      this.removeAny();
      return undefined;
    }
  }

  start(challenge: ChallengeResponse): void {
    this.stateValue = { challenge, rendering: { roundDigests: [] } };
    this.dirty = true;
    this.flush(true, true);
  }

  setTimeLock(completed: bigint, value: string, force = false): void {
    if (!this.stateValue) return;
    this.stateValue.timeLock = { completed: completed.toString(), value };
    this.dirty = true;
    this.flush(force);
  }

  addRenderingRound(
    completed: number,
    digest: string,
    backend: RenderingBackend,
  ): void {
    const rendering = this.stateValue?.rendering;
    if (!rendering || completed !== rendering.roundDigests.length + 1)
      throw new Error("render_checkpoint");
    rendering.roundDigests.push(digest);
    rendering.backend = backend;
    this.dirty = true;
    this.flush(completed === this.stateValue?.challenge.render.rounds);
  }

  flush(force = false, takeOwnership = false): void {
    if (!this.dirty || !this.stateValue) return;
    const now = Date.now();
    if (!force && now - this.lastFlush < FLUSH_INTERVAL_MS) return;
    const storage = sessionStorageOrUndefined();
    if (!storage) return;
    try {
      const current = storage.getItem(NAVIGATION_CHECKPOINT_KEY);
      if (
        !takeOwnership &&
        current !== null &&
        storedOwner(current) !== this.owner
      ) {
        this.dirty = false;
        return;
      }
      const stored: StoredNavigationCheckpoint = {
        version: CHECKPOINT_VERSION,
        owner: this.owner,
        scope: { ...this.scope },
        challenge: this.stateValue.challenge,
        ...(this.stateValue.timeLock === undefined
          ? {}
          : { timeLock: { ...this.stateValue.timeLock } }),
        rendering: {
          roundDigests: [...this.stateValue.rendering.roundDigests],
          ...(this.stateValue.rendering.backend === undefined
            ? {}
            : { backend: this.stateValue.rendering.backend }),
        },
        updatedAt: now,
      };
      const raw = JSON.stringify(stored);
      if (raw.length > MAX_CHECKPOINT_BYTES) throw new Error("checkpoint_size");
      storage.setItem(NAVIGATION_CHECKPOINT_KEY, raw);
      this.lastFlush = now;
      this.dirty = false;
    } catch {
      // Quota and disabled-storage failures only lose resume acceleration.
      try {
        storage.removeItem(NAVIGATION_CHECKPOINT_KEY);
      } catch {}
    }
  }

  clear(): void {
    this.stateValue = undefined;
    this.dirty = false;
    const storage = sessionStorageOrUndefined();
    try {
      const current = storage?.getItem(NAVIGATION_CHECKPOINT_KEY);
      if (typeof current === "string" && storedOwner(current) === this.owner)
        storage?.removeItem(NAVIGATION_CHECKPOINT_KEY);
    } catch {}
  }

  private removeAny(): void {
    this.stateValue = undefined;
    this.dirty = false;
    try {
      sessionStorageOrUndefined()?.removeItem(NAVIGATION_CHECKPOINT_KEY);
    } catch {}
  }

  get state(): NavigationCheckpointState | undefined {
    if (!this.stateValue) return undefined;
    return {
      challenge: this.stateValue.challenge,
      ...(this.stateValue.timeLock === undefined
        ? {}
        : { timeLock: { ...this.stateValue.timeLock } }),
      rendering: {
        roundDigests: [...this.stateValue.rendering.roundDigests],
        ...(this.stateValue.rendering.backend === undefined
          ? {}
          : { backend: this.stateValue.rendering.backend }),
      },
    };
  }
}

export function clearNavigationCheckpoint(): void {
  try {
    sessionStorageOrUndefined()?.removeItem(NAVIGATION_CHECKPOINT_KEY);
  } catch {}
}

export function clearNavigationCheckpointForScope(
  scope: NavigationCheckpointScope,
): void {
  const storage = sessionStorageOrUndefined();
  if (!storage) return;
  try {
    const raw = storage.getItem(NAVIGATION_CHECKPOINT_KEY);
    if (raw === null) return;
    const value = JSON.parse(raw) as unknown;
    if (
      !isRecord(value) ||
      !isRecord(value.scope) ||
      sameScope(value.scope, scope)
    )
      storage.removeItem(NAVIGATION_CHECKPOINT_KEY);
  } catch {
    try {
      storage.removeItem(NAVIGATION_CHECKPOINT_KEY);
    } catch {}
  }
}

function sessionStorageOrUndefined(): Storage | undefined {
  try {
    return typeof sessionStorage === "undefined" ? undefined : sessionStorage;
  } catch {
    return undefined;
  }
}

function validStoredCheckpoint(
  value: unknown,
  scope: NavigationCheckpointScope,
  nowSeconds: number,
): value is StoredNavigationCheckpoint {
  if (!isRecord(value) || value.version !== CHECKPOINT_VERSION) return false;
  if (typeof value.owner !== "string" || value.owner.length > 64) return false;
  if (!sameScope(value.scope, scope) || !validChallenge(value.challenge))
    return false;
  if (value.challenge.quote.expires_at < nowSeconds) return false;
  if (
    typeof value.updatedAt !== "number" ||
    !Number.isFinite(value.updatedAt) ||
    value.updatedAt < 0
  )
    return false;
  if (!validTimeLockCheckpoint(value.timeLock, value.challenge)) return false;
  return validRenderingCheckpoint(value.rendering, value.challenge);
}

function validChallenge(value: unknown): value is ChallengeResponse {
  if (!isRecord(value) || typeof value.token !== "string") return false;
  if (!value.token.startsWith("shr1_") || value.token.length > 131_072)
    return false;
  const quote = value.quote;
  const render = value.render;
  const timeLock = value.time_lock;
  if (
    (value.presence !== undefined && !validPresencePlan(value.presence)) ||
    (value.fallback !== undefined && !validFallbackPlan(value.fallback))
  )
    return false;
  if (!isRecord(quote) || quote.version !== "work-price-v1") return false;
  if (
    !safeIntegerIn(quote.tier, 0, 32) ||
    typeof quote.time_lock_iterations !== "string" ||
    !safeIntegerIn(quote.render_rounds, 1, 65_536) ||
    !safeIntegerIn(quote.issued_at, 0, Number.MAX_SAFE_INTEGER) ||
    !safeIntegerIn(quote.expires_at, 1, Number.MAX_SAFE_INTEGER) ||
    (quote.expires_at as number) <= (quote.issued_at as number)
  )
    return false;
  if (
    !isRecord(render) ||
    render.version !== "render-v1" ||
    typeof render.seed !== "string" ||
    render.rounds !== quote.render_rounds ||
    !safeIntegerIn(render.triangles, 1, 512) ||
    !safeIntegerIn(render.samples, 1, 4096)
  )
    return false;
  if (
    !isRecord(timeLock) ||
    timeLock.version !== "rsw-v1" ||
    typeof timeLock.modulus_id !== "string" ||
    typeof timeLock.modulus !== "string" ||
    typeof timeLock.input !== "string" ||
    timeLock.iterations !== quote.time_lock_iterations
  )
    return false;
  try {
    const seed = fromBase64url(render.seed);
    const modulus = fromBase64url(timeLock.modulus);
    const input = fromBase64url(timeLock.input);
    const iterations = BigInt(timeLock.iterations);
    return (
      seed.length === 32 &&
      base64url(seed) === render.seed &&
      modulus.length >= 1 &&
      base64url(modulus) === timeLock.modulus &&
      input.length >= 1 &&
      base64url(input) === timeLock.input &&
      bytesToBigint(modulus) > 1n &&
      iterations >= 1n &&
      iterations.toString() === timeLock.iterations
    );
  } catch {
    return false;
  }
}

function validPresencePlan(value: unknown): boolean {
  return (
    isRecord(value) &&
    Object.keys(value).length === 1 &&
    (value.mode === "none" || value.mode === "host")
  );
}

function validFallbackPlan(value: unknown): boolean {
  if (
    !isRecord(value) ||
    typeof value.available !== "boolean" ||
    !Array.isArray(value.methods) ||
    value.methods.length > 16 ||
    new Set(value.methods).size !== value.methods.length ||
    value.methods.some(
      (method) =>
        typeof method !== "string" ||
        method.length < 1 ||
        method.length > 64 ||
        /[^a-zA-Z0-9._-]/.test(method),
    )
  )
    return false;
  return value.available
    ? value.methods.length > 0
    : value.methods.length === 0;
}

function validTimeLockCheckpoint(
  value: unknown,
  challenge: ChallengeResponse,
): boolean {
  if (value === undefined) return true;
  if (
    !isRecord(value) ||
    typeof value.completed !== "string" ||
    typeof value.value !== "string"
  )
    return false;
  try {
    const completed = BigInt(value.completed);
    const total = BigInt(challenge.time_lock.iterations);
    const encoded = fromBase64url(value.value);
    const modulus = bytesToBigint(fromBase64url(challenge.time_lock.modulus));
    return (
      completed >= 0n &&
      completed <= total &&
      completed.toString() === value.completed &&
      encoded.length >= 1 &&
      encoded.length <= fromBase64url(challenge.time_lock.modulus).length &&
      base64url(encoded) === value.value &&
      bytesToBigint(encoded) < modulus
    );
  } catch {
    return false;
  }
}

function validRenderingCheckpoint(
  value: unknown,
  challenge: ChallengeResponse,
): boolean {
  if (!isRecord(value) || !Array.isArray(value.roundDigests)) return false;
  if (value.roundDigests.length > challenge.render.rounds) return false;
  if (
    value.roundDigests.length > 0 &&
    !["webgpu", "webgl2", "css"].includes(String(value.backend))
  )
    return false;
  if (value.roundDigests.length === 0 && value.backend !== undefined)
    return false;
  return value.roundDigests.every((encoded) => {
    if (typeof encoded !== "string") return false;
    try {
      const digest = fromBase64url(encoded);
      return digest.length === 32 && base64url(digest) === encoded;
    } catch {
      return false;
    }
  });
}

function sameScope(
  value: unknown,
  expected: NavigationCheckpointScope,
): boolean {
  if (!isRecord(value)) return false;
  return (
    Object.keys(expected) as Array<keyof NavigationCheckpointScope>
  ).every((key) => value[key] === expected[key]);
}

function safeIntegerIn(
  value: unknown,
  minimum: number,
  maximum: number,
): boolean {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

let checkpointOwnerSequence = 0;
function newCheckpointOwner(): string {
  const random = new Uint8Array(16);
  try {
    crypto.getRandomValues(random);
    return base64url(random);
  } catch {
    checkpointOwnerSequence++;
    return `${Date.now().toString(36)}-${checkpointOwnerSequence.toString(36)}`;
  }
}

function storedOwner(raw: string): string | undefined {
  try {
    const value = JSON.parse(raw) as unknown;
    return isRecord(value) && typeof value.owner === "string"
      ? value.owner
      : undefined;
  } catch {
    return undefined;
  }
}
