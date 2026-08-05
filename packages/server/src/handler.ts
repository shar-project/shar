import { SharService } from "./service.js";
import { base64url } from "./bytes.js";
import { verifySiteVerifySecret } from "./crypto.js";
import {
  AdminPolicyDocument,
  ChallengeRequest,
  FallbackCompletionRequest,
  FallbackPlan,
  PresencePlan,
  RedeemRequest,
  SharError,
  SiteVerifyRequest,
} from "./types.js";

export interface HandlerOptions {
  maxBodyBytes?: number;
  /** Maximum in-flight protocol/admin requests per handler instance. */
  maxConcurrentRequests?: number;
  allowedOrigins?: readonly string[];
  networkPseudonym?: (
    request: Request,
    challenge: Readonly<ChallengeRequest>,
  ) => string | undefined | Promise<string | undefined>;
  /** Selects a deployment region from trusted server context. */
  region?: (
    request: Request,
  ) => string | undefined | Promise<string | undefined>;
  assuranceTier?: (
    request: Request,
  ) => number | undefined | Promise<number | undefined>;
  /** Selects an optional host-generated session binding from trusted context. */
  sessionBinding?: (
    request: Request,
  ) => string | undefined | Promise<string | undefined>;
  fallbackSecret?: Uint8Array;
  /** Methods the authenticated host fallback endpoint can complete. */
  fallbackMethods?: readonly string[];
  /** Trusted host-presence capability advertised to browser clients. */
  presence?: PresencePlan;
  adminSecret?: Uint8Array;
  siteVerifyMasterSecret?: Uint8Array;
  /**
   * Receives privacy-safe request completion metadata. Observer failures are
   * ignored and can never affect protocol responses.
   */
  observeRequest?: (
    observation: Readonly<RequestObservation>,
  ) => void | Promise<void>;
  /** Returns the deployment's bounded-audit drop count for Prometheus. */
  auditEventsDropped?: () => number;
}

export interface RequestObservation {
  version: "request-observation-v1";
  request_id: string;
  method: string;
  route: string;
  status: number;
  duration_ms: number;
}

export function createSharHandler(
  service: SharService,
  options: HandlerOptions = {},
): (request: Request) => Promise<Response> {
  const max = options.maxBodyBytes ?? 16_384;
  if (!Number.isSafeInteger(max) || max < 1)
    throw new Error("invalid_body_limit");
  const maxConcurrent = options.maxConcurrentRequests ?? 256;
  if (
    !Number.isSafeInteger(maxConcurrent) ||
    maxConcurrent < 1 ||
    maxConcurrent > 65_536
  )
    throw new Error("invalid_concurrency_limit");
  const advertisedPresence = normalizePresence(options.presence);
  const advertisedFallback = normalizeFallback(
    options.fallbackSecret,
    options.fallbackMethods,
  );
  const servicePlans = service.browserPlans();
  if (
    servicePlans.presence.mode !== advertisedPresence.mode ||
    servicePlans.fallback.available !== advertisedFallback.available ||
    servicePlans.fallback.methods.length !==
      advertisedFallback.methods.length ||
    servicePlans.fallback.methods.some(
      (method, index) => method !== advertisedFallback.methods[index],
    )
  )
    throw new Error("handler_browser_plan_mismatch");
  // Browser issuance is only enabled for explicitly configured exact origins.
  // An omitted allowlist must not silently become a permissive CORS policy.
  const configuredOrigins = options.allowedOrigins ?? [];
  if (
    (options.allowedOrigins !== undefined && configuredOrigins.length === 0) ||
    new Set(configuredOrigins).size !== configuredOrigins.length ||
    configuredOrigins.some((origin) => !isCanonicalBrowserOrigin(origin))
  )
    throw new Error("invalid_allowed_origins");
  const allowed = new Set(configuredOrigins);
  const metrics = {
    issued: 0,
    issueEngineMilliseconds: 0,
    issueHandlerMilliseconds: 0,
    redeemed: 0,
    verified: 0,
    fallback: 0,
  };
  let activeRequests = 0;
  const route = async (request: Request): Promise<Response> => {
    const handlerStarted = performance.now();
    const requestOrigin = request.headers.get("origin") ?? undefined;
    const corsOrigin =
      requestOrigin && allowed.has(requestOrigin) ? requestOrigin : undefined;
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/healthz")
        return json({ status: "ok" }, 200);
      if (request.method === "GET" && url.pathname === "/readyz") {
        await service.ready();
        return json({ status: "ready" }, 200);
      }
      if (url.pathname === "/readyz")
        throw new SharError(405, "method_not_allowed", false, "none");
      if (request.method === "GET" && url.pathname === "/metrics")
        return metricsResponse(metrics, options.auditEventsDropped?.() ?? 0);
      if (
        request.method === "OPTIONS" &&
        ["/v1/challenges", "/v1/challenges/redeem"].includes(url.pathname)
      ) {
        if (!requestOrigin)
          throw new SharError(400, "origin_required", false, "none");
        if (!corsOrigin)
          throw new SharError(400, "origin_not_configured", false, "none");
        if (request.headers.get("access-control-request-method") !== "POST")
          throw new SharError(400, "invalid_preflight", false, "none");
        return preflight(corsOrigin);
      }
      if (request.method === "GET" && url.pathname === "/.well-known/shar/v1")
        return json(await service.wellKnown(), 200);
      if (request.method === "GET" && url.pathname === "/v1/admin/audit") {
        authorizeAdmin(request, options.adminSecret);
        const rawLimit = url.searchParams.get("limit");
        const limit = rawLimit === null ? 100 : Number(rawLimit);
        return json(
          await service.adminAudit(
            url.searchParams.get("tenant") ?? "",
            url.searchParams.get("site_key") ?? "",
            url.searchParams.get("action") ?? "",
            limit,
          ),
          200,
        );
      }
      if (request.method === "GET" && url.pathname === "/v1/admin/policy") {
        authorizeAdmin(request, options.adminSecret);
        return json(
          await service.adminPolicy(
            url.searchParams.get("tenant") ?? "",
            url.searchParams.get("site_key") ?? "",
            url.searchParams.get("action") ?? "",
          ),
          200,
        );
      }
      if (
        request.method !== "POST" &&
        !(request.method === "PUT" && url.pathname === "/v1/admin/policy")
      ) {
        if (
          [
            "/v1/challenges",
            "/v1/challenges/redeem",
            "/v1/siteverify",
            "/v1/fallback/complete",
            "/v1/admin/policy",
            "/v1/admin/audit",
          ].includes(url.pathname)
        )
          throw new SharError(405, "method_not_allowed", false, "none");
        throw new SharError(404, "not_found", false, "none");
      }
      const contentLength = request.headers.get("content-length");
      if (contentLength && Number(contentLength) > max)
        throw new SharError(413, "body_too_large", false, "none");
      const bytes = await readBody(request, max);
      const contentType = request.headers
        .get("content-type")
        ?.split(";", 1)[0]
        ?.trim();
      let body: unknown;
      if (contentType === "application/x-www-form-urlencoded")
        body = Object.fromEntries(
          new URLSearchParams(new TextDecoder().decode(bytes)),
        );
      else if (contentType === "application/json") {
        try {
          body = JSON.parse(new TextDecoder().decode(bytes));
        } catch {
          throw new SharError(400, "malformed_json", false, "none");
        }
      } else throw new SharError(415, "unsupported_media_type", false, "none");
      if (!body || typeof body !== "object" || Array.isArray(body))
        throw new SharError(400, "malformed_body", false, "none");
      if (url.pathname === "/v1/challenges") {
        const origin = requestOrigin;
        if (!origin) throw new SharError(400, "origin_required", false, "none");
        if (!corsOrigin)
          throw new SharError(400, "origin_not_configured", false, "none");
        const challenge: ChallengeRequest = { ...(body as ChallengeRequest) };
        delete challenge.region;
        // A browser must not choose its own debt scope. Hosts that have an
        // authenticated session may inject a binding through trusted server
        // context below; the request body is never accepted for this field.
        delete challenge.session_binding;
        delete challenge.network_pseudonym;
        delete challenge.assurance_tier;
        const region = await options.region?.(request);
        if (region !== undefined) challenge.region = region;
        const sessionBinding = await options.sessionBinding?.(request);
        if (sessionBinding !== undefined)
          challenge.session_binding = sessionBinding;
        const network = await options.networkPseudonym?.(request, challenge);
        if (network !== undefined) challenge.network_pseudonym = network;
        const assurance = await options.assuranceTier?.(request);
        if (assurance !== undefined) challenge.assurance_tier = assurance;
        if (challenge.origin !== origin)
          throw new SharError(400, "origin_mismatch", false, "none");
        const engineStarted = performance.now();
        const result = await service.challenge(challenge);
        result.presence = advertisedPresence;
        result.fallback = advertisedFallback;
        metrics.issueEngineMilliseconds += performance.now() - engineStarted;
        metrics.issued++;
        const response = json(result, 200, origin);
        metrics.issueHandlerMilliseconds += performance.now() - handlerStarted;
        return response;
      }
      if (url.pathname === "/v1/challenges/redeem") {
        const result = await service.redeem(parseRedeemBody(body));
        metrics.redeemed++;
        return json(result, 200, corsOrigin);
      }
      if (url.pathname === "/v1/siteverify") {
        if (!options.siteVerifyMasterSecret)
          throw new SharError(501, "siteverify_not_configured", false, "none");
        if (options.siteVerifyMasterSecret.length !== 32)
          throw new SharError(500, "siteverify_misconfigured", false, "none");
        const normalized = normalizeVerify(body as Record<string, unknown>);
        const scope = await verifySiteVerifySecret(
          options.siteVerifyMasterSecret,
          normalized.secret,
        );
        if (!scope)
          throw new SharError(401, "siteverify_unauthorized", false, "none");
        if (
          (normalized.request.tenant !== undefined &&
            normalized.request.tenant !== scope.tenant) ||
          (normalized.request.site_key !== undefined &&
            normalized.request.site_key !== scope.site_key)
        )
          throw new SharError(401, "siteverify_unauthorized", false, "none");
        normalized.request.tenant = scope.tenant;
        normalized.request.site_key = scope.site_key;
        const result = await service.siteverify(normalized.request);
        metrics.verified++;
        return json(
          contentType === "application/x-www-form-urlencoded"
            ? { ...result, score: 1 }
            : result,
          200,
        );
      }
      if (url.pathname === "/v1/fallback/complete") {
        if (!options.fallbackSecret)
          throw new SharError(
            501,
            "fallback_not_configured",
            false,
            "fallback",
          );
        if (options.fallbackSecret.length !== 32)
          throw new SharError(500, "fallback_misconfigured", false, "none");
        const authorization = request.headers.get("authorization") ?? "";
        const expected = `Bearer ${base64url(options.fallbackSecret)}`;
        if (!constantTimeEqual(authorization, expected))
          throw new SharError(401, "fallback_unauthorized", false, "none");
        const fallbackMethod = (body as { method?: unknown }).method;
        if (
          typeof fallbackMethod !== "string" ||
          !advertisedFallback.methods.includes(fallbackMethod)
        )
          throw new SharError(400, "invalid_fallback_method", false, "none");
        const result = await service.completeFallback(
          body as FallbackCompletionRequest,
        );
        metrics.fallback++;
        return json(result, 200);
      }
      if (url.pathname === "/v1/admin/policy") {
        authorizeAdmin(request, options.adminSecret);
        if (request.method !== "PUT")
          throw new SharError(405, "method_not_allowed", false, "none");
        return json(
          await service.setAdminPolicy(body as AdminPolicyDocument),
          200,
        );
      }
      throw new SharError(404, "not_found", false, "none");
    } catch (error) {
      const shar =
        error instanceof SharError
          ? error
          : new SharError(500, "internal_error", true, "retry");
      const headers: Record<string, string> = {};
      if (shar.retry_after !== undefined)
        headers["retry-after"] = String(shar.retry_after);
      return json(shar.toJSON(), shar.status, corsOrigin, headers);
    }
  };
  return async (request: Request): Promise<Response> => {
    const started = monotonicMilliseconds();
    const requestId = createRequestId();
    const bypassAdmission = admissionBypass(request);
    let response: Response;
    if (!bypassAdmission && activeRequests >= maxConcurrent) {
      const origin = request.headers.get("origin") ?? undefined;
      response = json(
        {
          code: "capacity_unavailable",
          retryable: true,
          next_action: "retry",
          retry_after: 1,
        },
        503,
        origin && allowed.has(origin) ? origin : undefined,
        { "retry-after": "1" },
      );
    } else {
      if (!bypassAdmission) activeRequests++;
      try {
        response = await route(request);
      } finally {
        if (!bypassAdmission) activeRequests--;
      }
    }
    if (!response.headers.has("cache-control"))
      response.headers.set("cache-control", "no-store");
    if (!response.headers.has("x-content-type-options"))
      response.headers.set("x-content-type-options", "nosniff");
    response.headers.set("x-shar-request-id", requestId);
    if (response.headers.has("access-control-allow-origin"))
      response.headers.set(
        "access-control-expose-headers",
        "X-Shar-Request-Id",
      );
    const observation: RequestObservation = {
      version: "request-observation-v1",
      request_id: requestId,
      method: observedMethod(request.method),
      route: observedRoute(request.url),
      status: response.status,
      duration_ms: Math.max(0, Math.round(monotonicMilliseconds() - started)),
    };
    try {
      const pending = options.observeRequest?.(observation);
      if (pending && typeof pending.then === "function")
        void pending.catch(() => {});
    } catch {
      // Observability is best-effort and cannot affect protocol behavior.
    }
    return response;
  };
}

function isCanonicalBrowserOrigin(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    new TextEncoder().encode(value).length < 1 ||
    new TextEncoder().encode(value).length > 512 ||
    /\p{Cc}/u.test(value)
  )
    return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  const localHttp =
    parsed.protocol === "http:" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  return parsed.origin === value && (parsed.protocol === "https:" || localHttp);
}

const DEFAULT_FALLBACK_METHODS = [
  "passkey",
  "email",
  "authenticated-session",
  "support",
] as const;

function normalizePresence(plan: PresencePlan | undefined): PresencePlan {
  const mode = plan?.mode ?? "none";
  if (mode !== "none" && mode !== "host")
    throw new Error("invalid_presence_plan");
  return { mode };
}

function normalizeFallback(
  secret: Uint8Array | undefined,
  configuredMethods: readonly string[] | undefined,
): FallbackPlan {
  if (secret !== undefined && secret.length !== 32)
    throw new Error("invalid_fallback_secret");
  if (secret === undefined) {
    if (configuredMethods !== undefined)
      throw new Error("fallback_methods_without_secret");
    return { available: false, methods: [] };
  }
  const methods = [...(configuredMethods ?? DEFAULT_FALLBACK_METHODS)];
  if (
    methods.length < 1 ||
    methods.length > 16 ||
    methods.some(
      (method) =>
        method.length < 1 ||
        method.length > 64 ||
        /[^a-zA-Z0-9._-]/.test(method),
    ) ||
    new Set(methods).size !== methods.length
  )
    throw new Error("invalid_fallback_methods");
  return { available: true, methods };
}

function parseRedeemBody(value: unknown): RedeemRequest {
  if (!isRecord(value)) malformedRedeem();
  const timeLock = value.time_lock;
  const rendering = value.rendering;
  if (
    typeof value.token !== "string" ||
    !isRecord(timeLock) ||
    typeof timeLock.output !== "string" ||
    !isRecord(rendering) ||
    typeof rendering.digest !== "string" ||
    typeof rendering.backend !== "string" ||
    (value.trust_blinded !== undefined &&
      typeof value.trust_blinded !== "string")
  )
    malformedRedeem();
  const commitment = rendering.css_commitment;
  if (
    commitment !== undefined &&
    (!isRecord(commitment) ||
      typeof commitment.version !== "string" ||
      typeof commitment.digest !== "string")
  )
    malformedRedeem();
  return value as unknown as RedeemRequest;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function malformedRedeem(): never {
  throw new SharError(400, "malformed_json", false, "none");
}

function admissionBypass(request: Request): boolean {
  if (request.method !== "GET") return false;
  try {
    return ["/healthz", "/readyz", "/metrics"].includes(
      new URL(request.url).pathname,
    );
  } catch {
    return false;
  }
}

const observableRoutes = new Set([
  "/.well-known/shar/v1",
  "/healthz",
  "/readyz",
  "/metrics",
  "/v1/challenges",
  "/v1/challenges/redeem",
  "/v1/siteverify",
  "/v1/fallback/complete",
  "/v1/admin/policy",
  "/v1/admin/audit",
]);
let requestIdCounter = 0n;

function createRequestId(): string {
  const bytes = new Uint8Array(16);
  try {
    globalThis.crypto.getRandomValues(bytes);
  } catch {
    // Request correlation must remain available without making entropy an
    // operational dependency. This fallback is unique only within a runtime.
    requestIdCounter = (requestIdCounter + 1n) & 0xffff_ffff_ffff_ffffn;
    const time = BigInt(Math.max(0, Math.floor(Date.now())));
    for (let index = 0; index < 8; index++) {
      bytes[index] = Number((time >> BigInt((7 - index) * 8)) & 255n);
      bytes[index + 8] = Number(
        (requestIdCounter >> BigInt((7 - index) * 8)) & 255n,
      );
    }
  }
  return base64url(bytes);
}

function monotonicMilliseconds(): number {
  return typeof globalThis.performance?.now === "function"
    ? globalThis.performance.now()
    : Date.now();
}

function observedMethod(method: string): string {
  return ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"].includes(
    method,
  )
    ? method
    : "OTHER";
}

function observedRoute(rawUrl: string): string {
  try {
    const pathname = new URL(rawUrl).pathname;
    return observableRoutes.has(pathname) ? pathname : "unmatched";
  } catch {
    return "unmatched";
  }
}

function authorizeAdmin(
  request: Request,
  secret: Uint8Array | undefined,
): void {
  if (!secret) throw new SharError(404, "not_found", false, "none");
  if (secret.length !== 32)
    throw new SharError(500, "admin_misconfigured", false, "none");
  const expected = `Bearer ${base64url(secret)}`;
  if (!constantTimeEqual(request.headers.get("authorization") ?? "", expected))
    throw new SharError(401, "admin_unauthorized", false, "none");
}

function metricsResponse(
  metrics: {
    issued: number;
    issueEngineMilliseconds: number;
    issueHandlerMilliseconds: number;
    redeemed: number;
    verified: number;
    fallback: number;
  },
  auditEventsDropped: number,
): Response {
  const dropped =
    Number.isSafeInteger(auditEventsDropped) && auditEventsDropped >= 0
      ? auditEventsDropped
      : 0;
  const engineSeconds = (metrics.issueEngineMilliseconds / 1_000).toFixed(6);
  const handlerSeconds = (metrics.issueHandlerMilliseconds / 1_000).toFixed(6);
  const body = `# HELP shar_challenges_issued_total Successfully issued work quotes.\n# TYPE shar_challenges_issued_total counter\nshar_challenges_issued_total ${metrics.issued}\n# HELP shar_challenge_engine_duration_seconds_total Cumulative successful challenge pricing and construction time.\n# TYPE shar_challenge_engine_duration_seconds_total counter\nshar_challenge_engine_duration_seconds_total ${engineSeconds}\n# HELP shar_challenge_handler_duration_seconds_total Cumulative successful challenge HTTP handler time through response serialization.\n# TYPE shar_challenge_handler_duration_seconds_total counter\nshar_challenge_handler_duration_seconds_total ${handlerSeconds}\n# HELP shar_challenges_redeemed_total Successfully redeemed work quotes.\n# TYPE shar_challenges_redeemed_total counter\nshar_challenges_redeemed_total ${metrics.redeemed}\n# HELP shar_site_verifications_total Successfully consumed verification tokens.\n# TYPE shar_site_verifications_total counter\nshar_site_verifications_total ${metrics.verified}\n# HELP shar_fallback_completions_total Successfully consumed privileged fallback assertions.\n# TYPE shar_fallback_completions_total counter\nshar_fallback_completions_total ${metrics.fallback}\n# HELP shar_audit_events_dropped_total Privacy-filtered audit events dropped because the bounded queue was full or storage failed.\n# TYPE shar_audit_events_dropped_total counter\nshar_audit_events_dropped_total ${dropped}\n`;
  return new Response(new TextEncoder().encode(body), {
    status: 200,
    headers: {
      "content-type": "text/plain; version=0.0.4; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function constantTimeEqual(left: string, right: string): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++)
    difference |=
      (left.charCodeAt(index % Math.max(1, left.length)) || 0) ^
      (right.charCodeAt(index % Math.max(1, right.length)) || 0);
  return difference === 0;
}

async function readBody(
  request: Request,
  maximum: number,
): Promise<Uint8Array> {
  const stream = request.body;
  if (!stream || typeof stream.getReader !== "function") {
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.length > maximum)
      throw new SharError(413, "body_too_large", false, "none");
    return bytes;
  }

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      const value: unknown = result.value;
      const chunk =
        value instanceof Uint8Array
          ? value
          : ArrayBuffer.isView(value)
            ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
            : undefined;
      if (!chunk) throw new Error("invalid_body_chunk");
      length += chunk.byteLength;
      if (length > maximum) {
        try {
          await reader.cancel("body_too_large");
        } catch {
          // The bounded error is the useful result even if cancellation races
          // with a runtime's stream teardown.
        }
        throw new SharError(413, "body_too_large", false, "none");
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function preflight(origin: string): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "POST",
      "access-control-allow-headers": "Content-Type",
      "access-control-max-age": "600",
      vary: "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    },
  });
}

function normalizeVerify(body: Record<string, unknown>): {
  request: SiteVerifyRequest;
  secret: string;
} {
  const token =
    body.token ??
    body.response ??
    body["h-captcha-response"] ??
    body["g-recaptcha-response"];
  if (typeof token !== "string")
    throw new SharError(400, "token_required", false, "new_challenge");
  if (typeof body.secret !== "string")
    throw new SharError(401, "siteverify_unauthorized", false, "none");
  const out: SiteVerifyRequest = { token };
  for (const key of [
    "tenant",
    "site_key",
    "action",
    "origin",
    "region",
    "session_binding",
  ] as const)
    if (typeof body[key] === "string") out[key] = body[key] as never;
  return { request: out, secret: body.secret };
}

function json(
  body: unknown,
  status: number,
  origin?: string,
  extra: Record<string, string> = {},
): Response {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...extra,
  });
  if (origin) {
    headers.set("access-control-allow-origin", origin);
    headers.set("vary", "Origin");
  }
  return new Response(new TextEncoder().encode(JSON.stringify(body)), {
    status,
    headers,
  });
}
