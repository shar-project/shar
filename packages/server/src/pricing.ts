import { PressureInput, WorkPolicy, WorkQuote } from "./types.js";

const U64_MAX = (1n << 64n) - 1n;
const U32_MAX = (1 << 30) * 4 - 1;
export const MAX_RENDER_ROUNDS = 65_536;

function tier(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error("invalid_pressure_tier");
  return Math.min(32, value);
}

function addTier(a: number, b: number): number {
  return Math.min(32, a + b);
}

export function priceWork(
  input: PressureInput,
  policy: WorkPolicy,
  now: number,
): WorkQuote {
  if (
    !Number.isSafeInteger(now) ||
    now < 0 ||
    policy.baseIterations <= 0n ||
    policy.baseIterations > U64_MAX ||
    policy.iterationAllowance <= 0n ||
    policy.iterationAllowance > U64_MAX ||
    ![
      policy.baseRenderRounds,
      policy.quietWindowSeconds,
      policy.baseLifetimeSeconds,
      policy.roundAllowanceSeconds,
      policy.maxLifetimeSeconds,
    ].every(Number.isSafeInteger) ||
    policy.baseRenderRounds <= 0 ||
    policy.baseRenderRounds > U32_MAX ||
    policy.quietWindowSeconds <= 0 ||
    policy.baseLifetimeSeconds <= 0 ||
    policy.roundAllowanceSeconds < 0 ||
    policy.maxLifetimeSeconds <= 0
  )
    throw new Error("invalid_policy");
  const debt = Math.max(
    0,
    tier(input.failureDebt) +
      tier(input.assuranceDebt) -
      tier(input.trustCredits),
  );
  let total = 0;
  total = addTier(total, tier(input.baseTier));
  total = addTier(total, tier(input.velocityTier));
  total = addTier(total, tier(input.outstandingTier));
  total = addTier(total, Math.min(4, tier(input.networkTier)));
  total = addTier(total, debt);
  const iterations = policy.baseIterations << BigInt(total);
  if (iterations > U64_MAX) throw new Error("work_overflow");
  const rounds = policy.baseRenderRounds * 2 ** Math.min(total, 8);
  if (
    !Number.isSafeInteger(rounds) ||
    rounds > U32_MAX ||
    rounds > MAX_RENDER_ROUNDS
  )
    throw new Error("work_overflow");
  const additionalIterations = iterations - policy.baseIterations;
  const iterationSecondsBig =
    additionalIterations / policy.iterationAllowance +
    (additionalIterations % policy.iterationAllowance === 0n ? 0n : 1n);
  if (iterationSecondsBig > BigInt(Number.MAX_SAFE_INTEGER))
    throw new Error("work_overflow");
  const iterationSeconds = Number(iterationSecondsBig);
  const additionalRounds = rounds - policy.baseRenderRounds;
  const roundSeconds = additionalRounds * policy.roundAllowanceSeconds;
  if (!Number.isSafeInteger(roundSeconds)) throw new Error("work_overflow");
  const uncappedLifetime =
    policy.baseLifetimeSeconds + iterationSeconds + roundSeconds;
  if (!Number.isSafeInteger(uncappedLifetime)) throw new Error("work_overflow");
  const lifetime = Math.min(policy.maxLifetimeSeconds, uncappedLifetime);
  const expiresAt = now + lifetime;
  if (
    !Number.isSafeInteger(lifetime) ||
    lifetime <= 0 ||
    !Number.isSafeInteger(expiresAt)
  )
    throw new Error("work_overflow");
  return {
    version: "work-price-v1",
    tier: total,
    time_lock_iterations: iterations,
    render_rounds: rounds,
    issued_at: now,
    expires_at: expiresAt,
  };
}

export function decayTier(
  value: number,
  lastActivity: number,
  now: number,
  quietWindowSeconds: number,
): number {
  if (
    ![value, lastActivity, now, quietWindowSeconds].every(
      Number.isSafeInteger,
    ) ||
    value < 0 ||
    lastActivity < 0 ||
    now < lastActivity ||
    quietWindowSeconds <= 0
  )
    throw new Error("invalid_decay_input");
  return Math.max(
    0,
    value - Math.floor((now - lastActivity) / quietWindowSeconds),
  );
}
