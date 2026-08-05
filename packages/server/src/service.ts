import { base64url, bytesToBigint, fromBase64url, utf8 } from "./bytes.js";
import { Cbor, decodeCbor, encodeCbor } from "./cbor.js";
import {
  CoseSigner,
  SigningMaterial,
  VerificationMaterial,
  coseVerify,
  publicFromSeed,
  sha256,
} from "./crypto.js";
import { MAX_RENDER_ROUNDS, priceWork } from "./pricing.js";
import {
  DEFAULT_RENDER_SAMPLES,
  DEFAULT_RENDER_TRIANGLES,
  cssTranscriptCommitment,
  solveRendering,
} from "./rendering.js";
import {
  TRUST_VOPRF_SUITE,
  TrustKeyPair,
  TrustScope,
  decodeTrustCreditToken,
  deriveScopedTrustKeyPair,
  deterministicTrustRandom,
  equalTrustOutput,
  evaluateTrustDirect,
  evaluateTrustInput,
  trustCreditChallengeDigest,
  trustCreditLifetime,
  trustCreditReplayId,
  trustInputForScope,
} from "./trust.js";
import {
  TimeLockKey,
  deriveTimeLockInput,
  validateTimeLockKey,
  verifyTimeLock,
} from "./timelock.js";
import {
  AdminPolicyDocument,
  AdminAuditResponse,
  ChallengeRequest,
  ChallengeResponse,
  Clock,
  ConfigStore,
  FallbackCompletionRequest,
  FallbackCompletionResponse,
  FallbackPlan,
  FallbackVerifier,
  JsonWorkQuote,
  NonceStore,
  PressureStore,
  PresencePlan,
  RandomSource,
  RedeemRequest,
  RedeemResponse,
  RenderingBackend,
  RenderingProofPlan,
  SharError,
  SignalProvider,
  SiteVerifyRequest,
  SiteVerifyResponse,
  WorkReceipt,
  AuditEvent,
  AuditStore,
  TrustEvaluationEnvelope,
} from "./types.js";

interface ChallengeClaims {
  tenant: string;
  siteKey: string;
  action: string;
  origin: string;
  region?: string;
  issuedAt: number;
  expiresAt: number;
  policyVersion: string;
  tier: number;
  iterations: bigint;
  rounds: number;
  nonce: Uint8Array;
  renderSeed: Uint8Array;
  modulusId: string;
  sessionBinding?: string;
  triangles: number;
  samples: number;
  networkPseudonym?: string;
  trustKeyId?: Uint8Array;
}

interface VerificationClaims {
  tenant: string;
  siteKey: string;
  action: string;
  origin: string;
  region?: string;
  issuedAt: number;
  expiresAt: number;
  nonce: Uint8Array;
  sessionBinding?: string;
  receipt: WorkReceipt;
}

function normalizePresencePlan(plan: PresencePlan | undefined): PresencePlan {
  const mode = plan?.mode ?? "none";
  if (mode !== "none" && mode !== "host") throw new Error("presence_plan");
  return { mode };
}

function invalidBoundedText(
  value: unknown,
  minimumBytes: number,
  maximumBytes: number,
  rejectControls = true,
): boolean {
  if (typeof value !== "string") return true;
  const length = utf8(value).length;
  return (
    length < minimumBytes ||
    length > maximumBytes ||
    (rejectControls && /\p{Cc}/u.test(value))
  );
}

function normalizeFallbackPlan(plan: FallbackPlan | undefined): FallbackPlan {
  const candidate = plan ?? { available: false, methods: [] };
  if (
    typeof candidate.available !== "boolean" ||
    !Array.isArray(candidate.methods) ||
    candidate.methods.length > 16 ||
    (candidate.available && candidate.methods.length === 0) ||
    (!candidate.available && candidate.methods.length !== 0) ||
    candidate.methods.some(
      (method) =>
        typeof method !== "string" ||
        method.length < 1 ||
        method.length > 64 ||
        /[^a-zA-Z0-9._-]/.test(method),
    ) ||
    new Set(candidate.methods).size !== candidate.methods.length
  )
    throw new Error("fallback_plan");
  return { available: candidate.available, methods: [...candidate.methods] };
}

export interface SharServiceOptions {
  signing: SigningMaterial;
  verificationKeys?: readonly VerificationMaterial[];
  timeLock: TimeLockKey;
  previousTimeLocks?: readonly TimeLockKey[];
  nonces: NonceStore;
  pressure: PressureStore;
  config: ConfigStore;
  clock: Clock;
  random: RandomSource;
  audit?: AuditStore;
  renderTriangles?: number;
  renderSamples?: number;
  /** Browser-visible host-presence capability. It never changes proof validity. */
  presence?: PresencePlan;
  /** Browser-visible alternative methods verified by the host backend. */
  fallback?: FallbackPlan;
  /** Trusted assurance input used only while pricing a newly issued quote. */
  signals?: SignalProvider;
  /** Optional host assertion verifier invoked before fallback nonce use. */
  fallbackVerifier?: FallbackVerifier;
  /** Optional first-party VOPRF issuer. The first key is current; the rest
   * overlap rotation so credits issued before rotation remain redeemable. */
  trust?: {
    keys: readonly TrustKeyPair[];
    retentionSeconds?: number;
  };
}

export class SharService {
  private verificationKeys: readonly VerificationMaterial[] | undefined;
  private readonly renderTriangles: number;
  private readonly renderSamples: number;
  private readonly timeLocks: readonly TimeLockKey[];
  private readonly trustKeys: readonly TrustKeyPair[];
  private readonly trustRetentionSeconds: number;
  private readonly timeLockModulus: string;
  private readonly signer: CoseSigner;
  private readonly presencePlan: PresencePlan;
  private readonly fallbackPlan: FallbackPlan;

  constructor(private readonly options: SharServiceOptions) {
    if (typeof options.pressure.priceAndRecord !== "function")
      throw new Error("atomic_pressure_store_required");
    this.signer = new CoseSigner(options.signing);
    this.verificationKeys = options.verificationKeys;
    if (!validateTimeLockKey(options.timeLock))
      throw new Error("time_lock_key");
    const timeLocks = [options.timeLock];
    for (const key of options.previousTimeLocks ?? []) {
      if (!validateTimeLockKey(key)) throw new Error("time_lock_key");
      const existing = timeLocks.find((candidate) => candidate.id === key.id);
      if (
        existing &&
        (existing.modulus !== key.modulus || existing.lambda !== key.lambda)
      )
        throw new Error("time_lock_key_id_collision");
      if (!existing) timeLocks.push(key);
    }
    this.timeLocks = timeLocks;
    this.timeLockModulus = base64url(bigintBytes(options.timeLock.modulus));
    this.trustKeys = options.trust?.keys ?? [];
    this.trustRetentionSeconds = options.trust?.retentionSeconds ?? 86_400;
    if (
      this.trustKeys.length > 0 &&
      (!Number.isSafeInteger(this.trustRetentionSeconds) ||
        this.trustRetentionSeconds < 60 ||
        this.trustRetentionSeconds > 2_592_000)
    )
      throw new Error("trust_retention");
    if (
      this.trustKeys.some(
        (key) =>
          key.keyId.length < 1 ||
          key.keyId.length > 32 ||
          key.secretKey.length !== 32 ||
          key.publicKey.length !== 32,
      )
    )
      throw new Error("trust_key");
    this.renderTriangles = options.renderTriangles ?? DEFAULT_RENDER_TRIANGLES;
    this.renderSamples = options.renderSamples ?? DEFAULT_RENDER_SAMPLES;
    if (
      this.renderTriangles < 1 ||
      this.renderTriangles > 512 ||
      this.renderSamples < 1 ||
      this.renderSamples > 4096
    )
      throw new Error("render_bounds");
    this.presencePlan = normalizePresencePlan(options.presence);
    this.fallbackPlan = normalizeFallbackPlan(options.fallback);
  }

  browserPlans(): { presence: PresencePlan; fallback: FallbackPlan } {
    return {
      presence: { ...this.presencePlan },
      fallback: {
        available: this.fallbackPlan.available,
        methods: [...this.fallbackPlan.methods],
      },
    };
  }

  /** Audit failures are intentionally non-fatal: proof validity is never
   * coupled to observability storage. */
  private recordAudit(event: AuditEvent): void {
    const audit = this.options.audit;
    if (!audit) return;
    try {
      void Promise.resolve(audit.record(event)).catch(() => undefined);
    } catch {
      // A synchronous adapter failure is just as non-fatal as a rejected write.
    }
  }

  private async keys(): Promise<readonly VerificationMaterial[]> {
    if (!this.verificationKeys)
      this.verificationKeys = [
        {
          keyId: this.options.signing.keyId,
          publicKey: await publicFromSeed(this.options.signing.privateSeed),
        },
      ];
    return this.verificationKeys;
  }

  async wellKnown(): Promise<Record<string, unknown>> {
    const keys = await this.keys();
    const result: Record<string, unknown> = {
      version: "shar-v1",
      algorithms: ["Ed25519", "RSW-2048", "render-v1"],
      keys: keys.map((key) => ({
        kid: base64url(key.keyId),
        kty: "OKP",
        crv: "Ed25519",
        x: base64url(key.publicKey),
        use: "sig",
      })),
      modulus_id: this.options.timeLock.id,
      modulus_ids: this.timeLocks.map((key) => key.id),
    };
    if (this.trustKeys.length > 0)
      result.trust = this.trustKeys.map((key) => ({
        suite: TRUST_VOPRF_SUITE,
        kid: base64url(key.keyId),
        kty: "OKP",
        crv: "Ristretto255",
        x: base64url(key.publicKey),
        use: "trust",
      }));
    return result;
  }

  /**
   * Verify that every state dependency required to issue and redeem work is
   * reachable. Audit storage is intentionally excluded because its contract is
   * best-effort and an audit outage must never reject a valid proof.
   */
  async ready(): Promise<void> {
    try {
      await this.options.config.health?.();
      await this.options.pressure.health?.();
      await this.options.nonces.health?.();
      await this.options.signals?.health?.();
      await this.options.fallbackVerifier?.health?.();
    } catch {
      throw new SharError(503, "readiness_unavailable", true, "retry", 1);
    }
  }

  async adminPolicy(
    tenant: string,
    siteKey: string,
    action: string,
  ): Promise<AdminPolicyDocument> {
    validateScope(tenant, siteKey, action);
    let policy;
    try {
      policy = await this.options.config.policy(tenant, siteKey, action);
    } catch {
      throw new SharError(503, "config_store_unavailable", true, "retry", 1);
    }
    return policyDocument(tenant, siteKey, action, policy);
  }

  async setAdminPolicy(
    document: AdminPolicyDocument,
  ): Promise<AdminPolicyDocument> {
    validateScope(document.tenant, document.site_key, document.action);
    if (!this.options.config.setPolicy)
      throw new SharError(501, "config_store_read_only", false, "none");
    const policy = parsePolicyDocument(document);
    try {
      await this.options.config.setPolicy(
        document.tenant,
        document.site_key,
        document.action,
        policy,
      );
    } catch {
      throw new SharError(503, "config_store_unavailable", true, "retry", 1);
    }
    return policyDocument(
      document.tenant,
      document.site_key,
      document.action,
      policy,
    );
  }

  private trustScope(request: ChallengeRequest): TrustScope {
    return {
      tenant: request.tenant,
      siteKey: request.site_key,
      action: request.action,
      origin: request.origin,
    };
  }

  /** Validate and atomically consume one client-held trust credit. */
  private async consumeTrustCredit(
    request: ChallengeRequest,
    now: number,
  ): Promise<void> {
    if (request.trust_token === undefined) return;
    if (this.trustKeys.length === 0)
      throw new SharError(400, "trust_not_configured", false, "new_challenge");
    let token;
    try {
      token = decodeTrustCreditToken(request.trust_token);
    } catch {
      throw new SharError(400, "invalid_trust_token", false, "new_challenge");
    }
    if (
      token.issuedAt > safeFutureBound(now, 60) ||
      now > token.expiresAt ||
      token.expiresAt - token.issuedAt > this.trustRetentionSeconds
    )
      throw new SharError(400, "expired_trust_token", false, "new_challenge");
    if (
      token.tenant !== request.tenant ||
      token.siteKey !== request.site_key ||
      token.action !== request.action ||
      token.origin !== request.origin
    )
      throw new SharError(
        400,
        "trust_binding_mismatch",
        false,
        "new_challenge",
      );
    const key = this.trustKeys.find((candidate) =>
      equalTrustOutput(candidate.keyId, token.keyId),
    );
    if (!key)
      throw new SharError(400, "unknown_trust_key", false, "new_challenge");
    const scope = this.trustScope(request);
    const expectedDigest = trustCreditChallengeDigest(
      token.keyId,
      scope,
      token.issuedAt,
      token.expiresAt,
    );
    if (!equalTrustOutput(expectedDigest, token.challengeDigest))
      throw new SharError(400, "invalid_trust_token", false, "new_challenge");
    const scopedKey = deriveScopedTrustKeyPair(key, scope);
    const expected = evaluateTrustDirect(
      scopedKey,
      trustInputForScope(
        "credit",
        token.challengeNonce,
        token.challengeDigest,
        token.keyId,
        scope,
      ),
    );
    if (!equalTrustOutput(expected, token.output))
      throw new SharError(400, "invalid_trust_token", false, "new_challenge");
    let fresh: boolean;
    try {
      fresh = await this.options.nonces.consume(
        "trust",
        trustCreditReplayId(token.keyId, token.output),
        token.expiresAt,
      );
    } catch {
      throw new SharError(503, "nonce_store_unavailable", true, "retry", 1);
    }
    if (!fresh)
      throw new SharError(409, "replayed_trust_token", false, "new_challenge");
    // The nonce consumption is the durable one-shot boundary.  Trust debt is
    // only a future pricing hint, so a telemetry/pressure adapter failure
    // must not turn an already-consumed credit into a retryable loss.
    try {
      await this.options.pressure.recordTrust?.(request, now);
    } catch {
      // Continue with the ordinary quote; the credit still remains valid for
      // this request and no proof validity depends on pressure bookkeeping.
    }
  }

  private async trustPlan(
    claims: ChallengeClaims,
  ): Promise<import("./types.js").TrustTokenPlan | undefined> {
    const key = this.trustKeys[0];
    if (!key) return undefined;
    let lifetime;
    try {
      lifetime = trustCreditLifetime(
        claims.issuedAt,
        this.trustRetentionSeconds,
      );
    } catch {
      return undefined;
    }
    const scope = {
      tenant: claims.tenant,
      siteKey: claims.siteKey,
      action: claims.action,
      origin: claims.origin,
    };
    const scopedKey = deriveScopedTrustKeyPair(key, scope);
    return {
      mode: "voprf-v1",
      suite: TRUST_VOPRF_SUITE,
      token_type: "credit",
      key_id: base64url(key.keyId),
      public_key: base64url(scopedKey.publicKey),
      challenge_digest: base64url(
        trustCreditChallengeDigest(
          key.keyId,
          scope,
          lifetime.issuedAt,
          lifetime.expiresAt,
        ),
      ),
      issued_at: lifetime.issuedAt,
      expires_at: lifetime.expiresAt,
    };
  }

  async adminAudit(
    tenant: string,
    siteKey: string,
    action: string,
    limit = 100,
  ): Promise<AdminAuditResponse> {
    validateScope(tenant, siteKey, action);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new SharError(400, "invalid_audit_limit", false, "none");
    const audit = this.options.audit;
    const list = audit?.list;
    if (!list) throw new SharError(501, "audit_not_configured", false, "none");
    let events: import("./types.js").AuditEvent[];
    try {
      events = await list.call(audit, tenant, siteKey, action, limit);
    } catch {
      throw new SharError(503, "audit_unavailable", true, "retry", 1);
    }
    return { tenant, site_key: siteKey, action, events };
  }

  async challenge(request: ChallengeRequest): Promise<ChallengeResponse> {
    validateRequest(request);
    let pricedRequest = request;
    if (this.options.signals) {
      let tier: number;
      try {
        tier = await this.options.signals.assuranceTier({ ...request });
      } catch {
        throw new SharError(503, "pricing_unavailable", true, "retry", 1);
      }
      if (!Number.isSafeInteger(tier) || tier < 0 || tier > 32)
        throw new SharError(503, "pricing_unavailable", true, "retry", 1);
      pricedRequest = {
        ...request,
        assurance_tier: Math.max(request.assurance_tier ?? 0, tier),
      };
    }
    const now = this.options.clock.now();
    ensureClock(now);
    let policy;
    try {
      policy = await this.options.config.policy(
        request.tenant,
        request.site_key,
        request.action,
      );
    } catch {
      throw new SharError(503, "pricing_unavailable", true, "retry", 1);
    }
    let quote;
    try {
      quote = await this.options.pressure.priceAndRecord(
        pricedRequest,
        policy,
        now,
      );
    } catch {
      throw new SharError(503, "pricing_unavailable", true, "retry", 1);
    }
    const nonce = this.options.random.bytes(16);
    const renderSeed = this.options.random.bytes(32);
    if (nonce.length !== 16 || renderSeed.length !== 32)
      throw new Error("random_source_length");
    const input = await deriveTimeLockInput(
      nonce,
      this.options.timeLock.modulus,
    );
    const claims: ChallengeClaims = {
      tenant: pricedRequest.tenant,
      siteKey: pricedRequest.site_key,
      action: pricedRequest.action,
      origin: pricedRequest.origin,
      issuedAt: quote.issued_at,
      expiresAt: quote.expires_at,
      policyVersion: policy.version,
      tier: quote.tier,
      iterations: quote.time_lock_iterations,
      rounds: quote.render_rounds,
      nonce,
      renderSeed,
      modulusId: this.options.timeLock.id,
      triangles: this.renderTriangles,
      samples: this.renderSamples,
    };
    if (pricedRequest.region !== undefined)
      claims.region = pricedRequest.region;
    if (pricedRequest.session_binding !== undefined)
      claims.sessionBinding = pricedRequest.session_binding;
    if (pricedRequest.network_pseudonym !== undefined)
      claims.networkPseudonym = pricedRequest.network_pseudonym;
    if (this.trustKeys.length > 0)
      claims.trustKeyId = this.trustKeys[0]!.keyId.slice();
    const challengePayload = encodeChallenge(claims);
    const token = await this.signer.sign(challengePayload);
    // Consume an optional credit only after every quote-producing operation
    // has succeeded. This preserves a client's one-shot credit when config,
    // pricing, randomness, signing, or outstanding-work storage is down.
    await this.consumeTrustCredit(pricedRequest, now);
    this.recordAudit({
      version: "audit-v1",
      kind: "challenge_issued",
      occurred_at: now,
      tenant: pricedRequest.tenant,
      site_key: pricedRequest.site_key,
      action: pricedRequest.action,
      tier: quote.tier,
    });
    const render: RenderingProofPlan = {
      version: "render-v1",
      seed: base64url(renderSeed),
      rounds: quote.render_rounds,
      triangles: this.renderTriangles,
      samples: this.renderSamples,
    };
    const response: ChallengeResponse = {
      token,
      quote: jsonQuote(quote),
      render,
      presence: { ...this.presencePlan },
      fallback: {
        available: this.fallbackPlan.available,
        methods: [...this.fallbackPlan.methods],
      },
      time_lock: {
        version: "rsw-v1",
        modulus_id: this.options.timeLock.id,
        modulus: this.timeLockModulus,
        input: base64url(bigintBytes(input)),
        iterations: quote.time_lock_iterations.toString(),
      },
    };
    if (pricedRequest.region !== undefined)
      response.region = pricedRequest.region;
    const trust = await this.trustPlan(claims);
    if (trust !== undefined) response.trust = trust;
    return response;
  }

  async redeem(request: RedeemRequest): Promise<RedeemResponse> {
    let claims: ChallengeClaims;
    let payload: Uint8Array;
    try {
      payload = await coseVerify(request.token, await this.keys());
      claims = decodeChallenge(payload);
    } catch {
      throw new SharError(400, "invalid_challenge", false, "new_challenge");
    }
    const pressureRequest = claimsRequest(claims);
    const now = this.options.clock.now();
    ensureClock(now);
    if (now > claims.expiresAt) {
      await this.options.pressure
        .recordFailure(pressureRequest, "expired", claims.expiresAt, now)
        .catch(() => undefined);
      this.recordAudit({
        version: "audit-v1",
        kind: "proof_failed",
        occurred_at: now,
        tenant: claims.tenant,
        site_key: claims.siteKey,
        action: claims.action,
        tier: claims.tier,
        code: "expired_challenge",
      });
      throw new SharError(400, "expired_challenge", false, "new_challenge");
    }
    const timeLock = this.timeLocks.find((key) => key.id === claims.modulusId);
    if (!timeLock) {
      await this.options.pressure
        .recordFailure(pressureRequest, "invalid", claims.expiresAt, now)
        .catch(() => undefined);
      this.recordAudit({
        version: "audit-v1",
        kind: "proof_failed",
        occurred_at: now,
        tenant: claims.tenant,
        site_key: claims.siteKey,
        action: claims.action,
        tier: claims.tier,
        code: "unsupported_modulus",
      });
      throw new SharError(400, "unsupported_modulus", false, "new_challenge");
    }
    const input = await deriveTimeLockInput(claims.nonce, timeLock.modulus);
    if (
      !verifyTimeLock(timeLock, input, claims.iterations, request.time_lock)
    ) {
      await this.options.pressure
        .recordFailure(pressureRequest, "invalid", claims.expiresAt, now)
        .catch(() => undefined);
      this.recordAudit({
        version: "audit-v1",
        kind: "proof_failed",
        occurred_at: now,
        tenant: claims.tenant,
        site_key: claims.siteKey,
        action: claims.action,
        tier: claims.tier,
        code: "invalid_work",
      });
      throw new SharError(400, "invalid_work", false, "new_challenge");
    }
    const plan: RenderingProofPlan = {
      version: "render-v1",
      seed: base64url(claims.renderSeed),
      rounds: claims.rounds,
      triangles: claims.triangles,
      samples: claims.samples,
    };
    const presentedCssCommitment = request.rendering.css_commitment;
    const cssCommitmentIsValid = validCssCommitment(presentedCssCommitment);
    let cssCommitmentMatches = true;
    if (cssCommitmentIsValid && presentedCssCommitment !== undefined)
      cssCommitmentMatches =
        presentedCssCommitment.digest === (await cssTranscriptCommitment(plan));
    if (
      !validBackend(request.rendering.backend) ||
      !cssCommitmentIsValid ||
      !cssCommitmentMatches ||
      request.rendering.digest !== (await solveRendering(plan))
    ) {
      await this.options.pressure
        .recordFailure(pressureRequest, "invalid", claims.expiresAt, now)
        .catch(() => undefined);
      this.recordAudit({
        version: "audit-v1",
        kind: "proof_failed",
        occurred_at: now,
        tenant: claims.tenant,
        site_key: claims.siteKey,
        action: claims.action,
        tier: claims.tier,
        code: "invalid_work",
      });
      throw new SharError(400, "invalid_work", false, "new_challenge");
    }
    const verificationNonce = this.options.random.bytes(16);
    if (verificationNonce.length !== 16)
      throw new Error("random_source_length");
    let trustEvaluation: TrustEvaluationEnvelope | undefined;
    if (request.trust_blinded !== undefined) {
      try {
        if (claims.trustKeyId === undefined) throw new Error("trust_key");
        const key = this.trustKeys.find((candidate) =>
          equalTrustOutput(candidate.keyId, claims.trustKeyId!),
        );
        if (!key) throw new Error("trust_key");
        const scopedKey = deriveScopedTrustKeyPair(key, {
          tenant: claims.tenant,
          siteKey: claims.siteKey,
          action: claims.action,
          origin: claims.origin,
        });
        const blinded = fromBase64url(request.trust_blinded);
        if (blinded.length !== 32) throw new Error("length");
        const proofSeed = await sha256(
          new TextEncoder().encode("shar/trust/proof/v1\0"),
          verificationNonce,
          claims.nonce,
        );
        const evaluation = evaluateTrustInput(
          scopedKey,
          blinded,
          deterministicTrustRandom(proofSeed),
        );
        const lifetime = trustCreditLifetime(
          claims.issuedAt,
          this.trustRetentionSeconds,
        );
        trustEvaluation = {
          version: "trust-evaluation-v1",
          suite: TRUST_VOPRF_SUITE,
          key_id: base64url(key.keyId),
          evaluated: base64url(evaluation.evaluated),
          proof: base64url(evaluation.proof),
          issued_at: lifetime.issuedAt,
          expires_at: lifetime.expiresAt,
        };
      } catch {
        // Credit issuance is optional metadata. Correct ordinary work remains
        // honored even when the blinded point/key/lifetime is unusable.
      }
    }
    const receipt: WorkReceipt = {
      version: "work-receipt-v1",
      tier: claims.tier,
      time_lock_iterations: claims.iterations.toString(),
      render_rounds: claims.rounds,
      rendering_backend: request.rendering.backend,
      completed_at: now,
    };
    const verification: VerificationClaims = {
      tenant: claims.tenant,
      siteKey: claims.siteKey,
      action: claims.action,
      origin: claims.origin,
      issuedAt: now,
      expiresAt: checkedTimeAdd(now, 300),
      nonce: verificationNonce,
      receipt,
    };
    if (claims.sessionBinding !== undefined)
      verification.sessionBinding = claims.sessionBinding;
    if (claims.region !== undefined) verification.region = claims.region;
    // Prepare every response-producing operation before consuming the
    // challenge nonce. A signing/randomness failure must leave a correct
    // proof retryable rather than consuming it without returning a receipt.
    const verificationToken = await this.signer.sign(
      encodeVerification(verification),
    );
    let fresh: boolean;
    try {
      fresh = await this.options.nonces.consume(
        "challenge",
        claims.nonce,
        claims.expiresAt,
      );
    } catch {
      throw new SharError(503, "nonce_store_unavailable", true, "retry", 1);
    }
    if (!fresh) {
      await this.options.pressure
        .recordFailure(pressureRequest, "replay", claims.expiresAt, now)
        .catch(() => undefined);
      this.recordAudit({
        version: "audit-v1",
        kind: "proof_failed",
        occurred_at: now,
        tenant: claims.tenant,
        site_key: claims.siteKey,
        action: claims.action,
        tier: claims.tier,
        code: "replayed_challenge",
      });
      throw new SharError(409, "replayed_challenge", false, "new_challenge");
    }
    await this.options.pressure
      .recordSuccess(pressureRequest, claims.expiresAt, now)
      .catch(() => undefined);
    this.recordAudit({
      version: "audit-v1",
      kind: "proof_redeemed",
      occurred_at: now,
      tenant: claims.tenant,
      site_key: claims.siteKey,
      action: claims.action,
      tier: claims.tier,
      backend: request.rendering.backend,
    });
    const result: RedeemResponse = {
      token: verificationToken,
      expires_at: verification.expiresAt,
      receipt,
    };
    if (trustEvaluation !== undefined)
      result.trust_evaluation = trustEvaluation;
    return result;
  }

  async siteverify(request: SiteVerifyRequest): Promise<SiteVerifyResponse> {
    let claims: VerificationClaims;
    try {
      claims = decodeVerification(
        await coseVerify(request.token, await this.keys()),
      );
    } catch {
      throw new SharError(400, "invalid_verification", false, "new_challenge");
    }
    const now = this.options.clock.now();
    ensureClock(now);
    if (now > claims.expiresAt) {
      this.recordAudit({
        version: "audit-v1",
        kind: "verification_failed",
        occurred_at: now,
        tenant: claims.tenant,
        site_key: claims.siteKey,
        action: claims.action,
        tier: claims.receipt.tier,
        code: "expired_verification",
      });
      throw new SharError(400, "expired_verification", false, "new_challenge");
    }
    if (
      (request.tenant !== undefined && request.tenant !== claims.tenant) ||
      (request.site_key !== undefined && request.site_key !== claims.siteKey) ||
      (request.action !== undefined && request.action !== claims.action) ||
      (request.origin !== undefined && request.origin !== claims.origin) ||
      (request.region !== undefined && request.region !== claims.region) ||
      (request.session_binding !== undefined &&
        request.session_binding !== claims.sessionBinding)
    ) {
      this.recordAudit({
        version: "audit-v1",
        kind: "verification_failed",
        occurred_at: now,
        tenant: claims.tenant,
        site_key: claims.siteKey,
        action: claims.action,
        tier: claims.receipt.tier,
        code: "binding_mismatch",
      });
      throw new SharError(400, "binding_mismatch", false, "new_challenge");
    }
    let fresh: boolean;
    try {
      fresh = await this.options.nonces.consume(
        "verification",
        claims.nonce,
        claims.expiresAt,
      );
    } catch {
      throw new SharError(503, "nonce_store_unavailable", true, "retry", 1);
    }
    if (!fresh) {
      this.recordAudit({
        version: "audit-v1",
        kind: "verification_failed",
        occurred_at: now,
        tenant: claims.tenant,
        site_key: claims.siteKey,
        action: claims.action,
        tier: claims.receipt.tier,
        code: "replayed_verification",
      });
      throw new SharError(409, "replayed_verification", false, "new_challenge");
    }
    this.recordAudit({
      version: "audit-v1",
      kind: "site_verified",
      occurred_at: now,
      tenant: claims.tenant,
      site_key: claims.siteKey,
      action: claims.action,
      tier: claims.receipt.tier,
    });
    const result: SiteVerifyResponse = {
      success: true,
      tenant: claims.tenant,
      site_key: claims.siteKey,
      action: claims.action,
      origin: claims.origin,
      receipt: claims.receipt,
    };
    if (claims.region !== undefined) result.region = claims.region;
    return result;
  }

  async completeFallback(
    request: FallbackCompletionRequest,
  ): Promise<FallbackCompletionResponse> {
    validateRequest(request);
    if (
      typeof request.method !== "string" ||
      request.method.length < 1 ||
      request.method.length > 64 ||
      /[^a-zA-Z0-9._-]/.test(request.method)
    )
      throw new SharError(400, "invalid_fallback_method", false, "none");
    if (
      this.fallbackPlan.available &&
      !this.fallbackPlan.methods.includes(request.method)
    )
      throw new SharError(400, "invalid_fallback_method", false, "none");
    if (invalidBoundedText(request.assertion_id, 16, 256, false))
      throw new SharError(400, "invalid_assertion_id", false, "none");
    if (!this.fallbackPlan.available)
      throw new SharError(501, "fallback_not_configured", false, "fallback");
    const now = this.options.clock.now();
    ensureClock(now);
    if (this.options.fallbackVerifier) {
      let verified: boolean;
      try {
        verified = await this.options.fallbackVerifier.verify(request.method, {
          ...request,
        });
      } catch {
        throw new SharError(503, "fallback_unavailable", true, "retry", 1);
      }
      if (verified !== true) {
        this.recordAudit({
          version: "audit-v1",
          kind: "verification_failed",
          occurred_at: now,
          tenant: request.tenant,
          site_key: request.site_key,
          action: request.action,
          code: "fallback_not_verified",
        });
        throw new SharError(400, "fallback_not_verified", false, "fallback");
      }
    }
    const fallbackExpiry = checkedTimeAdd(now, 300);
    const nonce = await sha256(
      new TextEncoder().encode("shar/fallback-assertion/v1\0"),
      new TextEncoder().encode(request.assertion_id),
    );
    let fresh: boolean;
    try {
      fresh = await this.options.nonces.consume(
        "fallback",
        nonce,
        fallbackExpiry,
      );
    } catch {
      throw new SharError(503, "nonce_store_unavailable", true, "retry", 1);
    }
    if (!fresh)
      throw new SharError(409, "replayed_fallback_assertion", false, "none");
    this.recordAudit({
      version: "audit-v1",
      kind: "fallback_completed",
      occurred_at: now,
      tenant: request.tenant,
      site_key: request.site_key,
      action: request.action,
    });
    const result: FallbackCompletionResponse = {
      success: true,
      tenant: request.tenant,
      site_key: request.site_key,
      action: request.action,
      origin: request.origin,
      verification_method: "fallback",
      method: request.method,
    };
    if (request.region !== undefined) result.region = request.region;
    return result;
  }
}

function validateRequest(request: ChallengeRequest): void {
  for (const [name, value, limit] of [
    ["tenant", request.tenant, 128],
    ["site_key", request.site_key, 256],
    ["action", request.action, 128],
    ["origin", request.origin, 512],
  ] as const) {
    if (invalidBoundedText(value, 1, limit))
      throw new SharError(400, `invalid_${name}`, false, "none");
  }
  if (request.region !== undefined && invalidBoundedText(request.region, 1, 64))
    throw new SharError(400, "invalid_region", false, "none");
  let origin: URL;
  try {
    origin = new URL(request.origin);
  } catch {
    throw new SharError(400, "invalid_origin", false, "none");
  }
  if (
    origin.origin !== request.origin ||
    (origin.protocol !== "https:" &&
      !(
        origin.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname)
      ))
  )
    throw new SharError(400, "invalid_origin", false, "none");
  if (
    request.assurance_tier !== undefined &&
    (!Number.isSafeInteger(request.assurance_tier) ||
      request.assurance_tier < 0 ||
      request.assurance_tier > 32)
  )
    throw new SharError(400, "invalid_assurance_tier", false, "none");
  if (
    request.session_binding !== undefined &&
    invalidBoundedText(request.session_binding, 1, 256)
  )
    throw new SharError(400, "invalid_session_binding", false, "none");
  if (
    request.network_pseudonym !== undefined &&
    invalidBoundedText(request.network_pseudonym, 1, 128)
  )
    throw new SharError(400, "invalid_network_pseudonym", false, "none");
  if (
    request.trust_token !== undefined &&
    invalidBoundedText(request.trust_token, 1, 4096, false)
  )
    throw new SharError(400, "invalid_trust_token", false, "none");
}

function validateScope(tenant: string, siteKey: string, action: string): void {
  for (const [name, value, limit] of [
    ["tenant", tenant, 128],
    ["site_key", siteKey, 256],
    ["action", action, 128],
  ] as const) {
    if (invalidBoundedText(value, 1, limit))
      throw new SharError(400, `invalid_${name}`, false, "none");
  }
}

function policyDocument(
  tenant: string,
  siteKey: string,
  action: string,
  policy: import("./types.js").WorkPolicy,
): AdminPolicyDocument {
  return {
    tenant,
    site_key: siteKey,
    action,
    policy: {
      version: policy.version,
      base_iterations: policy.baseIterations.toString(),
      base_render_rounds: policy.baseRenderRounds,
      quiet_window_seconds: policy.quietWindowSeconds,
      base_lifetime_seconds: policy.baseLifetimeSeconds,
      iteration_allowance: policy.iterationAllowance.toString(),
      round_allowance_seconds: policy.roundAllowanceSeconds,
      max_lifetime_seconds: policy.maxLifetimeSeconds,
    },
  };
}

function parsePolicyDocument(
  document: AdminPolicyDocument,
): import("./types.js").WorkPolicy {
  const value = document?.policy;
  if (!value || typeof value !== "object")
    throw new SharError(400, "invalid_policy", false, "none");
  let baseIterations: bigint, iterationAllowance: bigint;
  try {
    if (
      !/^(?:0|[1-9]\d*)$/.test(value.base_iterations) ||
      !/^(?:0|[1-9]\d*)$/.test(value.iteration_allowance)
    )
      throw new Error();
    baseIterations = BigInt(value.base_iterations);
    iterationAllowance = BigInt(value.iteration_allowance);
  } catch {
    throw new SharError(400, "invalid_policy", false, "none");
  }
  const policy = {
    version: value.version,
    baseIterations,
    baseRenderRounds: value.base_render_rounds,
    quietWindowSeconds: value.quiet_window_seconds,
    baseLifetimeSeconds: value.base_lifetime_seconds,
    iterationAllowance,
    roundAllowanceSeconds: value.round_allowance_seconds,
    maxLifetimeSeconds: value.max_lifetime_seconds,
  };
  if (invalidBoundedText(policy.version, 1, 128))
    throw new SharError(400, "invalid_policy", false, "none");
  try {
    priceWork(
      {
        baseTier: 32,
        velocityTier: 0,
        outstandingTier: 0,
        networkTier: 0,
        failureDebt: 0,
        assuranceDebt: 0,
        trustCredits: 0,
      },
      policy,
      0,
    );
  } catch {
    throw new SharError(400, "invalid_policy", false, "none");
  }
  return policy;
}

function claimsRequest(claims: ChallengeClaims): ChallengeRequest {
  const out: ChallengeRequest = {
    tenant: claims.tenant,
    site_key: claims.siteKey,
    action: claims.action,
    origin: claims.origin,
  };
  if (claims.region !== undefined) out.region = claims.region;
  if (claims.sessionBinding !== undefined)
    out.session_binding = claims.sessionBinding;
  if (claims.networkPseudonym !== undefined)
    out.network_pseudonym = claims.networkPseudonym;
  return out;
}

function validBackend(value: string): value is RenderingBackend {
  return ["webgpu", "webgl2", "css"].includes(value);
}

function validCssCommitment(
  value: unknown,
): value is RedeemRequest["rendering"]["css_commitment"] {
  if (value === undefined) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const commitment = value as Record<string, unknown>;
  if (
    commitment.version !== "css-transcript-v1" ||
    typeof commitment.digest !== "string"
  )
    return false;
  try {
    return fromBase64url(commitment.digest).length === 32;
  } catch {
    return false;
  }
}

function ensureClock(now: number): void {
  if (!Number.isSafeInteger(now) || now < 0)
    throw new SharError(503, "clock_unavailable", true, "retry", 1);
}

function safeFutureBound(now: number, seconds: number): number {
  ensureClock(now);
  if (!Number.isSafeInteger(seconds) || seconds < 0)
    throw new SharError(503, "clock_unavailable", true, "retry", 1);
  return now > Number.MAX_SAFE_INTEGER - seconds
    ? Number.MAX_SAFE_INTEGER
    : now + seconds;
}

function checkedTimeAdd(now: number, seconds: number): number {
  const bound = safeFutureBound(now, seconds);
  if (now > Number.MAX_SAFE_INTEGER - seconds)
    throw new SharError(503, "clock_unavailable", true, "retry", 1);
  return bound;
}

function bigintBytes(value: bigint): Uint8Array {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return new Uint8Array(
    hex.match(/../g)?.map((x) => Number.parseInt(x, 16)) ?? [0],
  );
}
function jsonQuote(q: {
  version: "work-price-v1";
  tier: number;
  time_lock_iterations: bigint;
  render_rounds: number;
  issued_at: number;
  expires_at: number;
}): JsonWorkQuote {
  return { ...q, time_lock_iterations: q.time_lock_iterations.toString() };
}

function encodeChallenge(c: ChallengeClaims): Uint8Array {
  const map = new Map<Cbor, Cbor>([
    [0, "challenge"],
    [1, "shar-v1"],
    [2, c.tenant],
    [3, c.siteKey],
    [4, c.action],
    [5, c.origin],
    [6, c.issuedAt],
    [7, c.expiresAt],
    [8, c.policyVersion],
    [9, c.tier],
    [10, c.iterations],
    [11, c.rounds],
    [12, c.nonce],
    [13, c.renderSeed],
    [14, c.modulusId],
    [16, c.triangles],
    [17, c.samples],
  ]);
  if (c.region !== undefined) map.set(20, c.region);
  if (c.sessionBinding !== undefined) map.set(15, c.sessionBinding);
  if (c.networkPseudonym !== undefined) map.set(19, c.networkPseudonym);
  if (c.trustKeyId !== undefined) map.set(21, c.trustKeyId);
  return encodeCbor(map);
}

function decodeChallenge(bytes: Uint8Array): ChallengeClaims {
  const m = map(bytes);
  if (m.get(0) !== "challenge" || m.get(1) !== "shar-v1")
    throw new Error("claim_type");
  const result: ChallengeClaims = {
    tenant: str(m, 2),
    siteKey: str(m, 3),
    action: str(m, 4),
    origin: str(m, 5),
    issuedAt: num(m, 6),
    expiresAt: num(m, 7),
    policyVersion: str(m, 8),
    tier: num(m, 9),
    iterations: big(m, 10),
    rounds: num(m, 11),
    nonce: bin(m, 12),
    renderSeed: bin(m, 13),
    modulusId: str(m, 14),
    triangles: num(m, 16),
    samples: num(m, 17),
  };
  const region = m.get(20);
  if (region !== undefined) {
    if (typeof region !== "string") throw new Error("claim_shape");
    result.region = region;
  }
  const session = m.get(15);
  if (session !== undefined) {
    if (typeof session !== "string") throw new Error("claim_shape");
    result.sessionBinding = session;
  }
  const network = m.get(19);
  if (network !== undefined) {
    if (typeof network !== "string") throw new Error("claim_shape");
    result.networkPseudonym = network;
  }
  const trustKeyId = m.get(21);
  if (trustKeyId !== undefined) {
    if (
      !(trustKeyId instanceof Uint8Array) ||
      trustKeyId.length < 1 ||
      trustKeyId.length > 32
    )
      throw new Error("claim_shape");
    result.trustKeyId = trustKeyId;
  }
  if (
    result.nonce.length !== 16 ||
    result.renderSeed.length !== 32 ||
    result.tier > 32 ||
    result.iterations < 1n ||
    result.rounds < 1 ||
    result.rounds > MAX_RENDER_ROUNDS ||
    result.triangles < 1 ||
    result.triangles > 512 ||
    result.samples < 1 ||
    result.samples > 4096 ||
    result.expiresAt < result.issuedAt ||
    (result.region !== undefined && invalidBoundedText(result.region, 1, 64)) ||
    (result.sessionBinding !== undefined &&
      invalidBoundedText(result.sessionBinding, 1, 256)) ||
    (result.networkPseudonym !== undefined &&
      invalidBoundedText(result.networkPseudonym, 1, 128))
  )
    throw new Error("claim_bounds");
  return result;
}

function encodeVerification(c: VerificationClaims): Uint8Array {
  const r = c.receipt;
  const receipt = new Map<Cbor, Cbor>([
    [0, r.version],
    [1, r.tier],
    [2, r.time_lock_iterations],
    [3, r.render_rounds],
    [4, r.rendering_backend],
    [5, r.completed_at],
  ]);
  const map = new Map<Cbor, Cbor>([
    [0, "verification"],
    [1, "shar-v1"],
    [2, c.tenant],
    [3, c.siteKey],
    [4, c.action],
    [5, c.origin],
    [6, c.issuedAt],
    [7, c.expiresAt],
    [12, c.nonce],
    [18, receipt],
  ]);
  if (c.region !== undefined) map.set(20, c.region);
  if (c.sessionBinding !== undefined) map.set(15, c.sessionBinding);
  return encodeCbor(map);
}

function decodeVerification(bytes: Uint8Array): VerificationClaims {
  const m = map(bytes);
  if (m.get(0) !== "verification" || m.get(1) !== "shar-v1")
    throw new Error("claim_type");
  const rm = m.get(18);
  if (!(rm instanceof Map)) throw new Error("claim_shape");
  const backend = str(rm, 4);
  if (!validBackend(backend)) throw new Error("claim_shape");
  const iterations = str(rm, 2);
  const result: VerificationClaims = {
    tenant: str(m, 2),
    siteKey: str(m, 3),
    action: str(m, 4),
    origin: str(m, 5),
    issuedAt: num(m, 6),
    expiresAt: num(m, 7),
    nonce: bin(m, 12),
    receipt: {
      version: "work-receipt-v1",
      tier: num(rm, 1),
      time_lock_iterations: iterations,
      render_rounds: num(rm, 3),
      rendering_backend: backend,
      completed_at: num(rm, 5),
    },
  };
  const region = m.get(20);
  if (region !== undefined) {
    if (typeof region !== "string") throw new Error("claim_shape");
    result.region = region;
  }
  if (
    rm.get(0) !== "work-receipt-v1" ||
    result.nonce.length !== 16 ||
    result.expiresAt < result.issuedAt ||
    result.receipt.tier > 32 ||
    result.receipt.render_rounds < 1 ||
    result.receipt.render_rounds > MAX_RENDER_ROUNDS ||
    !/^[1-9][0-9]*$/.test(iterations) ||
    (result.region !== undefined && invalidBoundedText(result.region, 1, 64))
  )
    throw new Error("claim_bounds");
  const session = m.get(15);
  if (session !== undefined) {
    if (typeof session !== "string") throw new Error("claim_shape");
    result.sessionBinding = session;
  }
  return result;
}

function map(bytes: Uint8Array): Map<Cbor, Cbor> {
  const value = decodeCbor(bytes);
  if (!(value instanceof Map)) throw new Error("claim_shape");
  return value;
}
function str(m: Map<Cbor, Cbor>, k: number): string {
  const v = m.get(k);
  if (typeof v !== "string") throw new Error("claim_shape");
  return v;
}
function num(m: Map<Cbor, Cbor>, k: number): number {
  const v = m.get(k);
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0)
    throw new Error("claim_shape");
  return v;
}
function big(m: Map<Cbor, Cbor>, k: number): bigint {
  const v = m.get(k);
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0)
    return BigInt(v);
  if (typeof v === "bigint" && v >= 0n) return v;
  throw new Error("claim_shape");
}
function bin(m: Map<Cbor, Cbor>, k: number): Uint8Array {
  const v = m.get(k);
  if (!(v instanceof Uint8Array)) throw new Error("claim_shape");
  return v;
}
