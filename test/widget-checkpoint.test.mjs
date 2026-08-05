import assert from "node:assert/strict";
import test from "node:test";
import { base64url } from "../packages/server/dist/index.js";
import {
  NAVIGATION_CHECKPOINT_KEY,
  NavigationCheckpoint,
  clearNavigationCheckpoint,
  clearNavigationCheckpointForScope,
} from "../packages/widget/dist/checkpoint.js";

class MemorySessionStorage {
  values = new Map();
  failWrites = false;

  get length() {
    return this.values.size;
  }
  clear() {
    this.values.clear();
  }
  getItem(key) {
    return this.values.get(String(key)) ?? null;
  }
  key(index) {
    return [...this.values.keys()][index] ?? null;
  }
  removeItem(key) {
    this.values.delete(String(key));
  }
  setItem(key, value) {
    if (this.failWrites) throw new DOMException("quota", "QuotaExceededError");
    this.values.set(String(key), String(value));
  }
}

const originalStorage = Object.getOwnPropertyDescriptor(
  globalThis,
  "sessionStorage",
);
const storage = new MemorySessionStorage();
Object.defineProperty(globalThis, "sessionStorage", {
  configurable: true,
  value: storage,
});
test.after(() => {
  if (originalStorage)
    Object.defineProperty(globalThis, "sessionStorage", originalStorage);
  else delete globalThis.sessionStorage;
});
test.beforeEach(() => {
  storage.failWrites = false;
  storage.clear();
});

const scope = {
  endpoint: "https://app.example/v1/challenges",
  tenant: "public",
  sitekey: "site-a",
  action: "signup",
  origin: "https://app.example",
};

function challenge(now = 1_800_000_000) {
  return {
    token: "shr1_navigation_checkpoint",
    quote: {
      version: "work-price-v1",
      tier: 0,
      time_lock_iterations: "2",
      render_rounds: 2,
      issued_at: now,
      expires_at: now + 300,
    },
    render: {
      version: "render-v1",
      seed: base64url(new Uint8Array(32)),
      rounds: 2,
      triangles: 8,
      samples: 16,
    },
    time_lock: {
      version: "rsw-v1",
      modulus_id: "test",
      modulus: "EQ",
      input: "Ag",
      iterations: "2",
    },
    presence: { mode: "none" },
    fallback: { available: false, methods: [] },
  };
}

test("navigation checkpoint resumes exact validated intermediate state", () => {
  const first = new NavigationCheckpoint(scope);
  first.start(challenge());
  first.setTimeLock(1n, "BA", true);
  const roundDigest = base64url(new Uint8Array(32).fill(7));
  first.addRenderingRound(1, roundDigest, "webgl2");
  first.flush(true);

  const successor = new NavigationCheckpoint(scope);
  assert.deepEqual(successor.load(1_800_000_001), {
    challenge: challenge(),
    timeLock: { completed: "1", value: "BA" },
    rendering: { roundDigests: [roundDigest], backend: "webgl2" },
  });
});

test("a stale execution cannot overwrite or clear its successor", () => {
  const stale = new NavigationCheckpoint(scope);
  stale.start(challenge());
  const successor = new NavigationCheckpoint(scope);
  assert.ok(successor.load(1_800_000_001));
  const owner = JSON.parse(storage.getItem(NAVIGATION_CHECKPOINT_KEY)).owner;

  stale.setTimeLock(1n, "BA", true);
  stale.clear();
  const retained = JSON.parse(storage.getItem(NAVIGATION_CHECKPOINT_KEY));
  assert.equal(retained.owner, owner);
  assert.equal(retained.timeLock, undefined);

  successor.clear();
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);
});

test("expired, malformed, non-canonical, and wrong-scope records are removed", () => {
  const expired = new NavigationCheckpoint(scope);
  expired.start(challenge());
  assert.equal(expired.load(1_800_000_301), undefined);
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);

  storage.setItem(NAVIGATION_CHECKPOINT_KEY, "{not-json");
  assert.equal(new NavigationCheckpoint(scope).load(), undefined);
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);

  const invalid = new NavigationCheckpoint(scope);
  invalid.start(challenge());
  const value = JSON.parse(storage.getItem(NAVIGATION_CHECKPOINT_KEY));
  value.rendering.roundDigests = ["not-canonical"];
  storage.setItem(NAVIGATION_CHECKPOINT_KEY, JSON.stringify(value));
  assert.equal(new NavigationCheckpoint(scope).load(1_800_000_001), undefined);
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);

  const invalidPlan = new NavigationCheckpoint(scope);
  invalidPlan.start(challenge());
  const planValue = JSON.parse(storage.getItem(NAVIGATION_CHECKPOINT_KEY));
  planValue.challenge.fallback = {
    available: true,
    methods: ["email", "email"],
  };
  storage.setItem(NAVIGATION_CHECKPOINT_KEY, JSON.stringify(planValue));
  assert.equal(new NavigationCheckpoint(scope).load(1_800_000_001), undefined);
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);

  new NavigationCheckpoint(scope).start(challenge());
  assert.equal(
    new NavigationCheckpoint({ ...scope, action: "checkout" }).load(
      1_800_000_001,
    ),
    undefined,
  );
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);
});

test("navigation resume honors the inclusive challenge expiry second", () => {
  const value = challenge();
  const checkpoint = new NavigationCheckpoint(scope);
  checkpoint.start(value);
  assert.ok(checkpoint.load(value.quote.expires_at));
  assert.equal(
    new NavigationCheckpoint(scope).load(value.quote.expires_at + 1),
    undefined,
  );
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);
});

test("storage denial and oversized records only disable resume", () => {
  storage.failWrites = true;
  assert.doesNotThrow(() => new NavigationCheckpoint(scope).start(challenge()));
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);

  storage.failWrites = false;
  storage.setItem(NAVIGATION_CHECKPOINT_KEY, "x".repeat(4 * 1024 * 1024 + 1));
  assert.equal(new NavigationCheckpoint(scope).load(), undefined);
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);

  new NavigationCheckpoint(scope).start(challenge());
  clearNavigationCheckpoint();
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);
});

test("scoped reset cannot remove another widget's navigation record", () => {
  new NavigationCheckpoint(scope).start(challenge());
  clearNavigationCheckpointForScope({ ...scope, action: "checkout" });
  assert.notEqual(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);
  clearNavigationCheckpointForScope(scope);
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);

  storage.setItem(NAVIGATION_CHECKPOINT_KEY, "corrupt");
  clearNavigationCheckpointForScope(scope);
  assert.equal(storage.getItem(NAVIGATION_CHECKPOINT_KEY), null);
});
