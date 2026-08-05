import type {
  Clock,
  FallbackCompletionRequest,
  FallbackVerifier,
} from "./types.js";

export const MAX_STORED_FALLBACK_LIFETIME_SECONDS = 300;

/**
 * A short-lived result written by the host only after its alternative
 * verification method succeeds. Reads must be idempotent: Shar owns replay
 * consumption after verification.
 */
export interface StoredFallbackAssertion {
  version: "fallback-assertion-v1";
  tenant: string;
  site_key: string;
  action: string;
  origin: string;
  region?: string;
  method: string;
  assertion_id: string;
  session_binding?: string;
  verified_at: number;
  expires_at: number;
}

export interface FallbackAssertionStore {
  /** Optional read-only dependency probe used by `/readyz`. */
  health?(): Promise<void>;
  /** Return a defensive copy or immutable record; never consume it here. */
  find(assertionId: string): Promise<StoredFallbackAssertion | undefined>;
}

/**
 * Verifies a host-owned stored result against every fallback request binding.
 * A missing, expired, future-dated, overlong, or mismatched assertion rejects
 * without consumption. Store/clock corruption throws so Shar returns the
 * retryable `fallback_unavailable` operational error.
 */
export class StoredFallbackVerifier implements FallbackVerifier {
  constructor(
    private readonly store: FallbackAssertionStore,
    private readonly clock: Clock,
  ) {}

  async health(): Promise<void> {
    await this.store.health?.();
  }

  async verify(method: string, payload: unknown): Promise<boolean> {
    const request = fallbackRequest(payload);
    if (!request || request.method !== method) return false;
    const assertion = await this.store.find(request.assertion_id);
    if (assertion === undefined) return false;
    if (!validAssertionRecord(assertion)) throw new Error("fallback_assertion");
    const now = this.clock.now();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error("clock");
    if (
      assertion.verified_at > now ||
      assertion.expires_at < now ||
      assertion.expires_at - assertion.verified_at >
        MAX_STORED_FALLBACK_LIFETIME_SECONDS
    )
      return false;
    return (
      assertion.tenant === request.tenant &&
      assertion.site_key === request.site_key &&
      assertion.action === request.action &&
      assertion.origin === request.origin &&
      assertion.region === request.region &&
      assertion.method === request.method &&
      assertion.assertion_id === request.assertion_id &&
      assertion.session_binding === request.session_binding
    );
  }
}

function fallbackRequest(
  value: unknown,
): FallbackCompletionRequest | undefined {
  if (!value || typeof value !== "object") return undefined;
  const request = value as Record<string, unknown>;
  for (const key of [
    "tenant",
    "site_key",
    "action",
    "origin",
    "method",
    "assertion_id",
  ])
    if (typeof request[key] !== "string") return undefined;
  if (
    (request.region !== undefined && typeof request.region !== "string") ||
    (request.session_binding !== undefined &&
      typeof request.session_binding !== "string")
  )
    return undefined;
  return request as unknown as FallbackCompletionRequest;
}

function validAssertionRecord(
  value: StoredFallbackAssertion,
): value is StoredFallbackAssertion {
  if (!value || typeof value !== "object") return false;
  if (value.version !== "fallback-assertion-v1") return false;
  for (const key of [
    "tenant",
    "site_key",
    "action",
    "origin",
    "method",
    "assertion_id",
  ] as const)
    if (typeof value[key] !== "string") return false;
  if (
    (value.region !== undefined && typeof value.region !== "string") ||
    (value.session_binding !== undefined &&
      typeof value.session_binding !== "string")
  )
    return false;
  return (
    Number.isSafeInteger(value.verified_at) &&
    value.verified_at >= 0 &&
    Number.isSafeInteger(value.expires_at) &&
    value.expires_at >= value.verified_at
  );
}
