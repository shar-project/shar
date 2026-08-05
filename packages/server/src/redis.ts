import { base64url, utf8 } from "./bytes.js";
import { sha256 } from "./crypto.js";
import { priceWork } from "./pricing.js";
import type {
  AuditEvent,
  AuditStore,
  ChallengeRequest,
  NonceStore,
  PressureInput,
  PressureStore,
  WorkPolicy,
  WorkQuote,
} from "./types.js";

// Audit events live in a sorted set so pruning is based on the event timestamp,
// rather than on list length or a sliding key TTL.  The sequence key makes
// identical events distinct members while sharing the action hash slot.
const RECORD_AUDIT =
  "local cutoff=tonumber(ARGV[1]);local count=(#ARGV-1)/2;if count<1 then return 0 end;local last=redis.call('INCRBY',KEYS[2],count);local first=last-count+1;local entries={};local item=0;for index=2,#ARGV,2 do item=item+1;local occurred=tonumber(ARGV[index]);local payload=ARGV[index+1];local member=tostring(occurred)..':'..tostring(first+item-1)..':'..payload;entries[#entries+1]=occurred;entries[#entries+1]=member end;redis.call('ZADD',KEYS[1],unpack(entries));redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf','('..tostring(cutoff));redis.call('EXPIRE',KEYS[1],86400);redis.call('EXPIRE',KEYS[2],86400);return count";
const MAX_AUDIT_BATCH_SIZE = 128;

export interface RedisCommandClient {
  sendCommand(arguments_: readonly string[]): Promise<unknown>;
}

const READ_PRESSURE = `
local now=tonumber(ARGV[1]);local quiet=tonumber(ARGV[2]);local assurance=tonumber(ARGV[3]);local has_session=ARGV[4]=='1';local retention=tonumber(ARGV[5]);local has_network=ARGV[6]=='1'
local function tier(count) local result=0;local threshold=1;while count>threshold and result<32 do threshold=threshold*2;result=result+1 end;return result end
redis.call('ZREMRANGEBYSCORE',KEYS[4],'-inf','('..tostring(now))
local av=redis.call('HMGET',KEYS[1],'window','count');local aw=tonumber(av[1]) or now;local ac=tonumber(av[2]) or 0;if now-aw>=quiet then aw=now;ac=0 end;ac=ac+1;redis.call('HSET',KEYS[1],'last',now,'window',aw,'count',ac)
local cv=redis.call('HMGET',KEYS[2],'last','failure','assurance','base','trust');local cl=tonumber(cv[1]) or now;local decay=math.floor(math.max(0,now-cl)/quiet);local failure=math.max(0,(tonumber(cv[2]) or 0)-decay);local stored=math.max(0,(tonumber(cv[3]) or 0)-decay);local current=math.max(stored,assurance);redis.call('HSET',KEYS[2],'failure',failure,'assurance',has_session and current or stored,'last',now)
local network_tier=0;if has_network then local nv=redis.call('HMGET',KEYS[3],'last','failure','window','count','network');local nl=tonumber(nv[1]) or now;local nd=math.floor(math.max(0,now-nl)/quiet);local nf=math.max(0,(tonumber(nv[2]) or 0)-nd);local nw=tonumber(nv[3]) or now;local nc=tonumber(nv[4]) or 0;if now-nw>=quiet then nw=now;nc=0 end;nc=nc+1;network_tier=math.max(tonumber(nv[5]) or 0,nf,tier(nc));redis.call('HSET',KEYS[3],'failure',nf,'last',now,'window',nw,'count',nc) end
local base=tonumber(cv[4]) or 0;local velocity=tier(ac);local outstanding=tier(redis.call('ZCARD',KEYS[4])+1);local trust=tonumber(cv[5]) or 0
if ARGV[7]=='1' then redis.call('EXPIRE',KEYS[2],retention);if has_network then redis.call('EXPIRE',KEYS[3],retention) end;local debt=math.max(0,failure+current-trust);local total=math.min(32,base+velocity+outstanding+math.min(4,network_tier)+debt);local expires=tonumber(ARGV[8+total]);local sequence=redis.call('INCR',KEYS[5]);redis.call('ZADD',KEYS[4],expires,tostring(now)..':'..tostring(sequence));local deadline=math.max(expires+3600,now+retention);redis.call('EXPIREAT',KEYS[4],deadline);redis.call('EXPIREAT',KEYS[5],deadline);redis.call('EXPIREAT',KEYS[1],deadline) else redis.call('EXPIRE',KEYS[1],retention);redis.call('EXPIRE',KEYS[2],retention);redis.call('EXPIRE',KEYS[4],retention);if has_network then redis.call('EXPIRE',KEYS[3],retention) end end
return {base,velocity,outstanding,network_tier,failure,current,trust}`;

const RECORD_ISSUED = `
local now=tonumber(ARGV[1]);local expires=tonumber(ARGV[2]);local retention=tonumber(ARGV[3]);local sequence=redis.call('INCR',KEYS[3]);redis.call('ZADD',KEYS[2],expires,tostring(now)..':'..tostring(sequence));redis.call('HSETNX',KEYS[1],'last',now);redis.call('HSET',KEYS[1],'last',now);local deadline=math.max(expires+3600,now+retention);redis.call('EXPIREAT',KEYS[2],deadline);redis.call('EXPIREAT',KEYS[3],deadline);redis.call('EXPIREAT',KEYS[1],deadline);return 1`;

const RECORD_OUTCOME = `
local now=tonumber(ARGV[1]);local delta=tonumber(ARGV[2]);local remove=ARGV[3]=='1';local retention=tonumber(ARGV[4]);local expires=tonumber(ARGV[5]);redis.call('HSETNX',KEYS[1],'failure',0);local debt=tonumber(redis.call('HGET',KEYS[1],'failure'));if delta>0 then debt=math.min(32,debt+1) else debt=math.max(0,debt-1) end;redis.call('HSET',KEYS[1],'failure',debt,'last',now);redis.call('EXPIRE',KEYS[1],retention);if remove then local matching=redis.call('ZRANGEBYSCORE',KEYS[2],tostring(expires),tostring(expires),'LIMIT',0,1);if #matching>0 then redis.call('ZREM',KEYS[2],matching[1]) end end;return debt`;

const RECORD_TRUST = `
local now=tonumber(ARGV[1]);local retention=tonumber(ARGV[2]);redis.call('HSETNX',KEYS[1],'failure',0);redis.call('HSETNX',KEYS[1],'assurance',0);local failure=tonumber(redis.call('HGET',KEYS[1],'failure'));local assurance=tonumber(redis.call('HGET',KEYS[1],'assurance'));if failure>0 then failure=failure-1 else assurance=math.max(0,assurance-1) end;redis.call('HSET',KEYS[1],'failure',failure,'assurance',assurance,'last',now);redis.call('EXPIRE',KEYS[1],retention);return 1`;

// Redis Lua numbers are IEEE-754 doubles. Keep every timestamp and deadline
// inside the exact integer range so pressure windows and expiry retention do
// not silently round at the upper bound of JavaScript's safe integer range.
const LUA_MAX_INTEGER = Number.MAX_SAFE_INTEGER;

function samePolicy(left: WorkPolicy, right: WorkPolicy): boolean {
  return (
    left.version === right.version &&
    left.baseIterations === right.baseIterations &&
    left.baseRenderRounds === right.baseRenderRounds &&
    left.quietWindowSeconds === right.quietWindowSeconds &&
    left.baseLifetimeSeconds === right.baseLifetimeSeconds &&
    left.iterationAllowance === right.iterationAllowance &&
    left.roundAllowanceSeconds === right.roundAllowanceSeconds &&
    left.maxLifetimeSeconds === right.maxLifetimeSeconds
  );
}

export class RedisStore implements NonceStore, PressureStore, AuditStore {
  private expiryCache?: {
    policy: WorkPolicy;
    now: number;
    expiries: readonly number[];
  };
  private readonly pressureKeyCache = new Map<string, PressureKeys>();

  constructor(
    private readonly client: RedisCommandClient,
    private readonly retentionSeconds = 172_800,
  ) {
    if (
      !Number.isSafeInteger(retentionSeconds) ||
      retentionSeconds < 3600 ||
      retentionSeconds > LUA_MAX_INTEGER - 3600
    )
      throw new Error("invalid_redis_retention");
  }

  async health(): Promise<void> {
    const response = await this.client.sendCommand(["PING"]);
    if (response !== "PONG") throw new Error("redis_health_reply");
  }

  async consume(
    namespace: "challenge" | "verification" | "fallback" | "trust",
    nonce: Uint8Array,
    expiresAt: number,
  ): Promise<boolean> {
    nonNegativeInteger(expiresAt, "invalid_expiry");
    // Shar treats the signed expiry as inclusive: a proof at exactly
    // `expiresAt` is still valid. Redis removes EXAT keys at the boundary,
    // so retain the one-shot marker for one additional second to match the
    // SQL and in-memory stores. Reject the unrepresentable upper bound rather
    // than wrapping or silently weakening replay protection.
    if (expiresAt === Number.MAX_SAFE_INTEGER)
      throw new Error("invalid_expiry");
    const key = `shar:nonce:${namespace}:${base64url(nonce)}`;
    const result = await this.client.sendCommand([
      "SET",
      key,
      "1",
      "EXAT",
      String(expiresAt + 1),
      "NX",
    ]);
    return result === "OK";
  }

  async read(
    input: ChallengeRequest,
    now: number,
    quietWindowSeconds: number,
  ): Promise<PressureInput> {
    nonNegativeInteger(now, "invalid_time");
    integer(quietWindowSeconds, "invalid_quiet_window", true);
    const keys = await this.pressureKeys(input);
    const reply = await this.eval(
      READ_PRESSURE,
      [keys.action, keys.client, keys.network ?? keys.client, keys.outstanding],
      [
        now,
        quietWindowSeconds,
        input.assurance_tier ?? 0,
        input.session_binding ? 1 : 0,
        this.retentionSeconds,
        keys.network ? 1 : 0,
      ],
    );
    return pressureFromReply(reply);
  }

  async priceAndRecord(
    input: ChallengeRequest,
    policy: WorkPolicy,
    now: number,
  ): Promise<WorkQuote> {
    nonNegativeInteger(now, "invalid_time");
    integer(policy.quietWindowSeconds, "invalid_quiet_window", true);
    const keys = await this.pressureKeys(input);
    const expiries = this.expiryArguments(policy, now);
    const reply = await this.eval(
      READ_PRESSURE,
      [
        keys.action,
        keys.client,
        keys.network ?? keys.client,
        keys.outstanding,
        keys.sequence,
      ],
      [
        now,
        policy.quietWindowSeconds,
        input.assurance_tier ?? 0,
        input.session_binding ? 1 : 0,
        this.retentionSeconds,
        keys.network ? 1 : 0,
        1,
        ...expiries,
      ],
    );
    return priceWork(pressureFromReply(reply), policy, now);
  }

  private expiryArguments(policy: WorkPolicy, now: number): readonly number[] {
    const cached = this.expiryCache;
    if (cached && cached.now === now && samePolicy(cached.policy, policy))
      return cached.expiries;
    const expiries: number[] = [];
    for (let totalTier = 0; totalTier <= 32; totalTier++) {
      const quote = priceWork(
        {
          baseTier: totalTier,
          velocityTier: 0,
          outstandingTier: 0,
          networkTier: 0,
          failureDebt: 0,
          assuranceDebt: 0,
          trustCredits: 0,
        },
        policy,
        now,
      );
      validateLuaDeadline(now, quote.expires_at, this.retentionSeconds);
      expiries.push(quote.expires_at);
    }
    this.expiryCache = { policy: { ...policy }, now, expiries };
    return expiries;
  }

  private async pressureKeys(input: ChallengeRequest): Promise<PressureKeys> {
    const scope = pressureKeyScope(input);
    const cacheKey = pressureKeyCacheKey(scope);
    const cached = this.pressureKeyCache.get(cacheKey);
    if (cached) return cached;
    const keys = await pressureKeys(scope);
    const concurrent = this.pressureKeyCache.get(cacheKey);
    if (concurrent) return concurrent;
    if (this.pressureKeyCache.size >= 1_024) {
      const oldest = this.pressureKeyCache.keys().next().value;
      if (oldest !== undefined) this.pressureKeyCache.delete(oldest);
    }
    this.pressureKeyCache.set(cacheKey, keys);
    return keys;
  }

  async recordIssued(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
  ): Promise<void> {
    validateLuaDeadline(now, expiresAt, this.retentionSeconds);
    const keys = await this.pressureKeys(input);
    await this.eval(
      RECORD_ISSUED,
      [keys.action, keys.outstanding, keys.sequence],
      [now, expiresAt, this.retentionSeconds],
    );
  }

  async recordSuccess(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
  ): Promise<void> {
    await this.outcome(input, expiresAt, now, -1, true);
  }

  async recordFailure(
    input: ChallengeRequest,
    kind: "invalid" | "replay" | "expired",
    expiresAt: number,
    now: number,
  ): Promise<void> {
    await this.outcome(input, expiresAt, now, 1, kind === "expired");
  }

  async recordTrust(input: ChallengeRequest, now: number): Promise<void> {
    nonNegativeInteger(now, "invalid_time");
    const keys = await this.pressureKeys(input);
    // Keep trust reductions out of the network-pressure scope.
    await this.eval(RECORD_TRUST, [keys.client], [now, this.retentionSeconds]);
  }

  async record(event: AuditEvent): Promise<void> {
    await this.recordBatch([event]);
  }

  async recordBatch(events: readonly AuditEvent[]): Promise<void> {
    const groups = new Map<string, { occurredAt: number; encoded: string }[]>();
    const keys = new Map<string, Promise<string>>();
    for (const event of events) {
      validateAuditEvent(event);
      const scope = `${event.tenant}\0${event.site_key}\0${event.action}`;
      let key = keys.get(scope);
      if (!key) {
        key = auditKey(event.tenant, event.site_key, event.action);
        keys.set(scope, key);
      }
      const resolved = await key;
      const group = groups.get(resolved) ?? [];
      group.push({
        occurredAt: event.occurred_at,
        encoded: JSON.stringify(sanitizeAuditEvent(event)),
      });
      groups.set(resolved, group);
    }
    for (const [key, group] of groups) {
      const tag = key.slice("shar:{".length, key.indexOf("}:audit"));
      const latest = Math.max(...group.map((event) => event.occurredAt));
      for (
        let offset = 0;
        offset < group.length;
        offset += MAX_AUDIT_BATCH_SIZE
      ) {
        const chunk = group.slice(offset, offset + MAX_AUDIT_BATCH_SIZE);
        const values: (number | string)[] = [Math.max(0, latest - 86_400)];
        for (const event of chunk) values.push(event.occurredAt, event.encoded);
        const written = await this.eval(
          RECORD_AUDIT,
          [key, `shar:{${tag}}:audit-seq`],
          values,
        );
        if (Number(written) !== chunk.length)
          throw new Error("redis_audit_batch_reply");
      }
    }
  }

  async list(
    tenant: string,
    siteKey: string,
    action: string,
    limit = 100,
  ): Promise<AuditEvent[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("invalid_audit_limit");
    const key = await auditKey(tenant, siteKey, action);
    const reply = await this.client.sendCommand([
      "ZREVRANGEBYSCORE",
      key,
      "+inf",
      "-inf",
      "LIMIT",
      "0",
      String(limit),
    ]);
    if (!Array.isArray(reply)) throw new Error("redis_audit_reply");
    return reply.map((value) => {
      if (typeof value !== "string") throw new Error("redis_audit_member");
      const first = value.indexOf(":");
      const second = value.indexOf(":", first + 1);
      if (first < 1 || second < first + 2)
        throw new Error("redis_audit_member");
      let event: AuditEvent;
      try {
        event = JSON.parse(value.slice(second + 1)) as AuditEvent;
      } catch {
        throw new Error("redis_audit_event");
      }
      validateAuditEvent(event);
      if (
        event.tenant !== tenant ||
        event.site_key !== siteKey ||
        event.action !== action
      )
        throw new Error("redis_audit_scope");
      return sanitizeAuditEvent(event);
    });
  }

  private async outcome(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
    delta: -1 | 1,
    remove: boolean,
  ): Promise<void> {
    validateLuaDeadline(now, expiresAt, this.retentionSeconds);
    const keys = await this.pressureKeys(input);
    await this.eval(
      RECORD_OUTCOME,
      [failureKey(input, keys), keys.outstanding],
      [now, delta, remove ? 1 : 0, this.retentionSeconds, expiresAt],
    );
  }

  private eval(
    script: string,
    keys: readonly string[],
    values: readonly (string | number)[],
  ): Promise<unknown> {
    return this.client.sendCommand([
      "EVAL",
      script,
      String(keys.length),
      ...keys,
      ...values.map(String),
    ]);
  }
}

interface PressureKeys {
  action: string;
  client: string;
  network?: string;
  outstanding: string;
  sequence: string;
}

interface PressureKeyScope {
  tenant: string;
  siteKey: string;
  action: string;
  sessionBinding: string | undefined;
  networkPseudonym: string | undefined;
}

function pressureKeyScope(input: ChallengeRequest): PressureKeyScope {
  return {
    tenant: input.tenant,
    siteKey: input.site_key,
    action: input.action,
    sessionBinding: input.session_binding,
    networkPseudonym: input.network_pseudonym,
  };
}

function pressureKeyCacheKey(scope: PressureKeyScope): string {
  // Request validation excludes controls from every field, but JSON encoding
  // also makes this cache identity unambiguous if that validation evolves.
  return JSON.stringify([
    scope.tenant,
    scope.siteKey,
    scope.action,
    scope.sessionBinding ?? null,
    scope.networkPseudonym ?? null,
  ]);
}

async function auditKey(
  tenant: string,
  siteKey: string,
  action: string,
): Promise<string> {
  const tag = base64url(
    (
      await sha256(
        utf8("shar/redis/audit/v1\0"),
        utf8(tenant + "\0" + siteKey + "\0" + action),
      )
    ).slice(0, 16),
  );
  return `shar:{${tag}}:audit`;
}
async function pressureKeys(input: PressureKeyScope): Promise<PressureKeys> {
  const base = `${input.tenant}\0${input.siteKey}\0${input.action}`;
  const tag = base64url(
    (await sha256(utf8("shar/redis/action/v1\0"), utf8(base))).slice(0, 16),
  );
  const prefix = `shar:{${tag}}`;
  const client = base64url(
    (
      await sha256(
        utf8("shar/redis/client/v1\0"),
        utf8(input.sessionBinding ?? ""),
      )
    ).slice(0, 16),
  );
  const result: PressureKeys = {
    action: `${prefix}:action`,
    client: `${prefix}:client:${client}`,
    outstanding: `${prefix}:outstanding`,
    sequence: `${prefix}:sequence`,
  };
  if (input.networkPseudonym) {
    const network = base64url(
      (
        await sha256(
          utf8("shar/redis/network/v1\0"),
          utf8(input.networkPseudonym),
        )
      ).slice(0, 16),
    );
    result.network = `${prefix}:network:${network}`;
  }
  return result;
}
function failureKey(input: ChallengeRequest, keys: PressureKeys): string {
  return input.session_binding || !keys.network ? keys.client : keys.network;
}
function tier(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 32)
    throw new Error("redis_tier");
  return parsed;
}

function pressureFromReply(reply: unknown): PressureInput {
  if (!Array.isArray(reply) || reply.length !== 7)
    throw new Error("redis_pressure_reply");
  return {
    baseTier: tier(reply[0]),
    velocityTier: tier(reply[1]),
    outstandingTier: tier(reply[2]),
    networkTier: tier(reply[3]),
    failureDebt: tier(reply[4]),
    assuranceDebt: tier(reply[5]),
    trustCredits: tier(reply[6]),
  };
}
function integer(value: number, code: string, positive = false): number {
  if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0))
    throw new Error(code);
  return value;
}

function nonNegativeInteger(value: number, code: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(code);
  return value;
}

function validateLuaDeadline(
  now: number,
  expiresAt: number,
  retentionSeconds: number,
): void {
  nonNegativeInteger(now, "invalid_time");
  nonNegativeInteger(expiresAt, "invalid_expiry");
  if (now > LUA_MAX_INTEGER - retentionSeconds) throw new Error("invalid_time");
  if (expiresAt > LUA_MAX_INTEGER - 3600) throw new Error("invalid_expiry");
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
    (event.tier !== undefined &&
      (!Number.isSafeInteger(event.tier) || event.tier < 0 || event.tier > 32))
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
    !/^[a-z_]{1,64}$/.test(event.kind) ||
    (event.backend !== undefined &&
      !["webgpu", "webgl2", "css"].includes(event.backend)) ||
    (event.code !== undefined && !/^[a-z0-9_]{1,128}$/.test(event.code))
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
