export type RenderingBackend = "webgpu" | "webgl2" | "css";

export interface WorkQuote {
  version: "work-price-v1";
  tier: number;
  time_lock_iterations: bigint;
  render_rounds: number;
  issued_at: number;
  expires_at: number;
}

export interface PressureInput {
  baseTier: number;
  velocityTier: number;
  outstandingTier: number;
  networkTier: number;
  failureDebt: number;
  assuranceDebt: number;
  trustCredits: number;
}

export interface WorkPolicy {
  version: string;
  baseIterations: bigint;
  baseRenderRounds: number;
  quietWindowSeconds: number;
  baseLifetimeSeconds: number;
  iterationAllowance: bigint;
  roundAllowanceSeconds: number;
  maxLifetimeSeconds: number;
}

export interface AdminPolicyDocument {
  tenant: string;
  site_key: string;
  action: string;
  policy: {
    version: string;
    base_iterations: string;
    base_render_rounds: number;
    quiet_window_seconds: number;
    base_lifetime_seconds: number;
    iteration_allowance: string;
    round_allowance_seconds: number;
    max_lifetime_seconds: number;
  };
}

export interface ChallengeRequest {
  tenant: string;
  site_key: string;
  action: string;
  origin: string;
  /** Optional deployment region selected by the trusted server boundary. */
  region?: string;
  session_binding?: string;
  network_pseudonym?: string;
  assurance_tier?: number;
  /** Optional single-use blinded trust credit to offset failure/assurance debt. */
  trust_token?: string;
}

export interface ChallengeResponse {
  token: string;
  quote: JsonWorkQuote;
  render: RenderingProofPlan;
  time_lock: TimeLockPlan;
  presence: PresencePlan;
  fallback: FallbackPlan;
  region?: string;
  trust?: TrustTokenPlan;
}

export interface JsonWorkQuote {
  version: "work-price-v1";
  tier: number;
  time_lock_iterations: string;
  render_rounds: number;
  issued_at: number;
  expires_at: number;
}

export interface TimeLockPlan {
  version: "rsw-v1";
  modulus_id: string;
  modulus: string;
  input: string;
  iterations: string;
}

export interface TimeLockProof {
  output: string;
}

export interface RenderingProofPlan {
  version: "render-v1";
  seed: string;
  rounds: number;
  triangles: number;
  samples: number;
}

export interface CssTranscriptCommitment {
  version: "css-transcript-v1";
  digest: string;
}

export interface Triangle {
  id: number;
  z: number;
  ax: number;
  ay: number;
  bx: number;
  by: number;
  cx: number;
  cy: number;
}

export interface TriangleProgram {
  version: "render-v1";
  triangles: Triangle[];
  samples: Array<readonly [number, number]>;
}

export interface RenderingProof {
  digest: string;
  backend: RenderingBackend;
  css_commitment?: CssTranscriptCommitment;
}

export interface RedeemRequest {
  token: string;
  time_lock: TimeLockProof;
  rendering: RenderingProof;
  /** Serialized VOPRF point; evaluated only after the work proof passes. */
  trust_blinded?: string;
}

export interface WorkReceipt {
  version: "work-receipt-v1";
  tier: number;
  time_lock_iterations: string;
  render_rounds: number;
  rendering_backend: RenderingBackend;
  completed_at: number;
}

export interface RedeemResponse {
  token: string;
  expires_at: number;
  receipt: WorkReceipt;
  trust_evaluation?: TrustEvaluationEnvelope;
}

export interface TrustEvaluationEnvelope {
  version: "trust-evaluation-v1";
  suite: "ristretto255-SHA512";
  key_id: string;
  evaluated: string;
  proof: string;
  issued_at: number;
  expires_at: number;
}

export interface SiteVerifyRequest {
  token: string;
  tenant?: string;
  site_key?: string;
  action?: string;
  origin?: string;
  region?: string;
  session_binding?: string;
}

export interface SiteVerifyResponse {
  success: true;
  tenant: string;
  site_key: string;
  action: string;
  origin: string;
  region?: string;
  receipt: WorkReceipt;
}

export interface AdminAuditResponse {
  tenant: string;
  site_key: string;
  action: string;
  events: AuditEvent[];
}

export type NextAction = "new_challenge" | "retry" | "fallback" | "none";

export class SharError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;
  readonly next_action: NextAction;
  readonly retry_after?: number;

  constructor(
    status: number,
    code: string,
    retryable: boolean,
    nextAction: NextAction,
    retryAfter?: number,
  ) {
    super(code);
    this.name = "SharError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.next_action = nextAction;
    if (retryAfter !== undefined) this.retry_after = retryAfter;
  }

  toJSON(): Record<string, string | boolean | number> {
    const body: Record<string, string | boolean | number> = {
      code: this.code,
      retryable: this.retryable,
      next_action: this.next_action,
    };
    if (this.retry_after !== undefined) body.retry_after = this.retry_after;
    return body;
  }
}

export interface PresencePlan {
  mode: "none" | "host";
}
export type TrustTokenPlan =
  | { mode: "disabled" }
  | {
      mode: "voprf-v1";
      suite: "ristretto255-SHA512";
      token_type: "credit";
      key_id: string;
      public_key: string;
      challenge_digest: string;
      issued_at: number;
      expires_at: number;
    };
export interface FallbackPlan {
  available: boolean;
  methods: string[];
}

export interface NonceStore {
  /** Read-only dependency probe used by `/readyz`; it must not consume state. */
  health?(): Promise<void>;
  consume(
    namespace: "challenge" | "verification" | "fallback" | "trust",
    nonce: Uint8Array,
    expiresAt: number,
  ): Promise<boolean>;
}

export interface PressureStore {
  /** Read-only dependency probe used by `/readyz`; it must not mutate pressure. */
  health?(): Promise<void>;
  read(
    input: ChallengeRequest,
    now: number,
    quietWindowSeconds: number,
  ): Promise<PressureInput>;
  /** Atomically price and reserve one outstanding quote. */
  priceAndRecord(
    input: ChallengeRequest,
    policy: WorkPolicy,
    now: number,
  ): Promise<WorkQuote>;
  recordIssued(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
  ): Promise<void>;
  recordSuccess(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
  ): Promise<void>;
  recordFailure(
    input: ChallengeRequest,
    kind: "invalid" | "replay" | "expired",
    expiresAt: number,
    now: number,
  ): Promise<void>;
  /** Apply one already-consumed, unlinkable trust credit to debt. */
  recordTrust?(input: ChallengeRequest, now: number): Promise<void>;
}

export interface ConfigStore {
  /** Read-only dependency probe used by `/readyz`. */
  health?(): Promise<void>;
  policy(tenant: string, siteKey: string, action: string): Promise<WorkPolicy>;
  setPolicy?(
    tenant: string,
    siteKey: string,
    action: string,
    policy: WorkPolicy,
  ): Promise<void>;
}

export interface SignalProvider {
  /** Optional dependency probe used by `/readyz`. */
  health?(): Promise<void>;
  assuranceTier(request: ChallengeRequest): Promise<number>;
}

export interface FallbackVerifier {
  /** Optional dependency probe used by `/readyz`. */
  health?(): Promise<void>;
  verify(method: string, payload: unknown): Promise<boolean>;
}

/**
 * Privacy-filtered operational events.  Deliberately excludes origins,
 * session bindings, network pseudonyms, user agents, and addresses.
 */
export type AuditEventKind =
  | "challenge_issued"
  | "proof_redeemed"
  | "site_verified"
  | "fallback_completed"
  | "proof_failed"
  | "verification_failed";

export interface AuditEvent {
  version: "audit-v1";
  kind: AuditEventKind;
  occurred_at: number;
  tenant: string;
  site_key: string;
  action: string;
  tier?: number;
  backend?: RenderingBackend;
  code?: string;
}

export interface AuditStore {
  record(event: AuditEvent): Promise<void>;
  recordBatch?(events: readonly AuditEvent[]): Promise<void>;
  purge?(before: number): Promise<void>;
  /** Return only the requested tenant/site/action scope, newest first. */
  list?(
    tenant: string,
    siteKey: string,
    action: string,
    limit: number,
  ): Promise<AuditEvent[]>;
}

export interface FallbackCompletionRequest {
  tenant: string;
  site_key: string;
  action: string;
  origin: string;
  region?: string;
  method: string;
  assertion_id: string;
  session_binding?: string;
}

export interface FallbackCompletionResponse {
  success: true;
  tenant: string;
  site_key: string;
  action: string;
  origin: string;
  region?: string;
  verification_method: "fallback";
  method: string;
}

export interface Clock {
  now(): number;
}
export interface RandomSource {
  bytes(length: number): Uint8Array;
}
