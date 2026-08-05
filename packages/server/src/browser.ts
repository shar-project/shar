/**
 * Curated runtime-neutral primitives used by @shar/widget.
 *
 * Keeping this surface separate prevents browser bundlers from traversing the
 * server, durable-store, and HTTP-handler export graph.
 */
export {
  base64url,
  bigintToBytes,
  bytesToBigint,
  fromBase64url,
} from "./bytes.js";
export {
  RENDER_COORDINATE_LIMIT,
  cssTranscriptCommitment,
  deriveCanonicalCssTranscript,
  solveRenderingWithExecutor,
} from "./rendering.js";
export type { TriangleRoundExecutor, TriangleSelection } from "./rendering.js";
export type {
  ChallengeResponse,
  RedeemResponse,
  RenderingBackend,
  RenderingProofPlan,
  TimeLockPlan,
  TriangleProgram,
  TrustTokenPlan,
} from "./types.js";
