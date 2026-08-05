import { base64url, concatBytes, fromBase64url, utf8 } from "./bytes.js";
import { sha256 } from "./crypto.js";
import { MAX_RENDER_ROUNDS } from "./pricing.js";
import { RenderingProofPlan, Triangle, TriangleProgram } from "./types.js";

export const RENDER_COORDINATE_LIMIT = 1 << 20;
export const RENDER_COORDINATE_GUARD = 64;
export const DEFAULT_RENDER_TRIANGLES = 256;
export const DEFAULT_RENDER_SAMPLES = 4096;
export const DEFAULT_RENDER_PREDICATES =
  DEFAULT_RENDER_TRIANGLES * DEFAULT_RENDER_SAMPLES;
export type TriangleSelection = readonly [id: number, z: number];
export type TriangleRoundExecutor = (
  program: TriangleProgram,
  round: number,
) => Promise<readonly TriangleSelection[]>;

export interface CanonicalCssTranscript {
  version: "css-transcript-v1";
  chainWidth: number;
  layoutHeight: number;
  gridFirstWidth: number;
  gridSecondWidth: number;
  flexFirstWidth: number;
  flexSecondWidth: number;
  intrinsicWidth: number;
  queryBranch: number;
  styleBranch: number;
  nestedBranch: number;
  transformX: number;
  transformY: number;
  verticalWriting: number;
  hitId: number;
  topologyDepth: number;
}

function u32(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] ?? 0) |
      ((bytes[offset + 1] ?? 0) << 8) |
      ((bytes[offset + 2] ?? 0) << 16) |
      ((bytes[offset + 3] ?? 0) << 24)) >>>
    0
  );
}

function next(state: { value: number }): number {
  let x = state.value >>> 0;
  x ^= x << 13;
  x ^= x >>> 17;
  x ^= x << 5;
  state.value = x >>> 0;
  return state.value;
}

export async function createTriangleProgram(
  seed: Uint8Array,
  triangleCount: number,
  sampleCount: number,
): Promise<TriangleProgram> {
  if (
    !Number.isSafeInteger(triangleCount) ||
    triangleCount < 1 ||
    triangleCount > 512 ||
    !Number.isSafeInteger(sampleCount) ||
    sampleCount < 1 ||
    sampleCount > 4096
  )
    throw new Error("render_bounds");
  const material = await sha256(utf8("shar/render-v1/program\0"), seed);
  const state = { value: u32(material, 0) || 0x6d2b79f5 };
  const triangles: Triangle[] = [];
  for (let id = 1; id <= triangleCount; id++) {
    const cx =
      RENDER_COORDINATE_GUARD +
      (next(state) % (RENDER_COORDINATE_LIMIT - 2 * RENDER_COORDINATE_GUARD));
    const cy =
      RENDER_COORDINATE_GUARD +
      (next(state) % (RENDER_COORDINATE_LIMIT - 2 * RENDER_COORDINATE_GUARD));
    const rx = 4096 + (next(state) % (RENDER_COORDINATE_LIMIT >>> 2));
    const ry = 4096 + (next(state) % (RENDER_COORDINATE_LIMIT >>> 2));
    const ax = Math.max(RENDER_COORDINATE_GUARD, cx - rx),
      ay = Math.min(RENDER_COORDINATE_LIMIT - RENDER_COORDINATE_GUARD, cy + ry);
    const bx = Math.min(
        RENDER_COORDINATE_LIMIT - RENDER_COORDINATE_GUARD,
        cx + rx,
      ),
      by = Math.min(
        RENDER_COORDINATE_LIMIT - RENDER_COORDINATE_GUARD,
        cy + (ry >>> 1),
      );
    const tx = Math.max(
      RENDER_COORDINATE_GUARD,
      Math.min(
        RENDER_COORDINATE_LIMIT - RENDER_COORDINATE_GUARD,
        cx + Number(next(state) % (rx + 1)) - (rx >>> 1),
      ),
    );
    const ty = Math.max(RENDER_COORDINATE_GUARD, cy - ry);
    triangles.push({ id, z: next(state), ax, ay, bx, by, cx: tx, cy: ty });
  }
  const samples: Array<readonly [number, number]> = [];
  for (let i = 0; i < sampleCount; i++)
    samples.push([
      RENDER_COORDINATE_GUARD +
        (next(state) % (RENDER_COORDINATE_LIMIT - 2 * RENDER_COORDINATE_GUARD)),
      RENDER_COORDINATE_GUARD +
        (next(state) % (RENDER_COORDINATE_LIMIT - 2 * RENDER_COORDINATE_GUARD)),
    ]);
  return { version: "render-v1", triangles, samples };
}

function edge(
  ax: number,
  ay: number,
  bx: number,
  by: number,
  px: number,
  py: number,
): number {
  // All coordinates are guarded 20-bit protocol integers. Each product is
  // therefore below 2^40 and their difference below 2^41, so Number retains
  // exact integer semantics with more than twelve bits of safety margin.
  return (px - ax) * (by - ay) - (py - ay) * (bx - ax);
}

export function triangleContains(t: Triangle, x: number, y: number): boolean {
  const a = edge(t.ax, t.ay, t.bx, t.by, x, y);
  const b = edge(t.bx, t.by, t.cx, t.cy, x, y);
  const c = edge(t.cx, t.cy, t.ax, t.ay, x, y);
  return (a >= 0 && b >= 0 && c >= 0) || (a <= 0 && b <= 0 && c <= 0);
}

function word(value: number): Uint8Array {
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value]);
}

export function deriveCanonicalCssTranscript(
  seed: Uint8Array,
): CanonicalCssTranscript {
  if (seed.length !== 32) throw new Error("render_seed");
  const chainWidth = 64 + (seed[0]! % 64);
  const gridFirstWidth = 16 + (seed[2]! % 32);
  const flexFirstWidth = 4 + (seed[3]! % (gridFirstWidth - 8));
  return {
    version: "css-transcript-v1",
    chainWidth,
    layoutHeight: 48 + (seed[1]! % 48),
    gridFirstWidth,
    gridSecondWidth: chainWidth - gridFirstWidth,
    flexFirstWidth,
    flexSecondWidth: gridFirstWidth - flexFirstWidth,
    intrinsicWidth: 8 + (seed[11]! % 24),
    queryBranch: 12 + (seed[4]! % 32),
    styleBranch: 12 + (seed[5]! % 32),
    nestedBranch: 1,
    transformX: 4 + (seed[6]! % 24),
    transformY: 4 + (seed[7]! % 24),
    verticalWriting: seed[8]! & 1,
    hitId: 1 + (seed[9]! & 1),
    topologyDepth: 3 + (seed[10]! % 6),
  };
}

function encodeCanonicalCssTranscript(
  transcript: CanonicalCssTranscript,
): Uint8Array {
  if (transcript.version !== "css-transcript-v1")
    throw new Error("css_transcript_version");
  return concatBytes(
    word(transcript.chainWidth),
    word(transcript.layoutHeight),
    word(transcript.gridFirstWidth),
    word(transcript.gridSecondWidth),
    word(transcript.flexFirstWidth),
    word(transcript.flexSecondWidth),
    word(transcript.intrinsicWidth),
    word(transcript.queryBranch),
    word(transcript.styleBranch),
    word(transcript.nestedBranch),
    word(transcript.transformX),
    word(transcript.transformY),
    word(transcript.verticalWriting),
    word(transcript.hitId),
    word(transcript.topologyDepth),
  );
}

export function selectTriangles(program: TriangleProgram): TriangleSelection[] {
  const selections: TriangleSelection[] = [];
  for (const sample of program.samples) {
    let selected: Triangle | undefined;
    for (const triangle of program.triangles)
      if (
        triangleContains(triangle, sample[0], sample[1]) &&
        (!selected ||
          triangle.z > selected.z ||
          (triangle.z === selected.z && triangle.id > selected.id))
      )
        selected = triangle;
    selections.push([selected?.id ?? 0, selected?.z ?? 0]);
  }
  return selections;
}

export async function reduceTriangleSelections(
  selections: readonly TriangleSelection[],
): Promise<Uint8Array> {
  if (selections.length < 1 || selections.length > 4096)
    throw new Error("render_bounds");
  const chunks: Uint8Array[] = [utf8("shar/render-v1/output\0")];
  for (let sampleId = 0; sampleId < selections.length; sampleId++) {
    const selection = selections[sampleId];
    if (
      !selection ||
      selection.length !== 2 ||
      !selection.every(
        (value) =>
          Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff,
      )
    )
      throw new Error("render_selection");
    chunks.push(word(sampleId), word(selection[0]), word(selection[1]));
  }
  return sha256(...chunks);
}

export async function evaluateTriangleProgram(
  program: TriangleProgram,
): Promise<Uint8Array> {
  return reduceTriangleSelections(selectTriangles(program));
}

export interface RenderingExecutionCheckpoint {
  /** Digests of the contiguous prefix of rounds that already completed. */
  completedRoundDigests?: readonly string[];
  /** Called only after a newly executed round has been reduced to its digest. */
  onRoundDigest?: (completed: number, digest: string) => void;
}

export async function solveRenderingWithExecutor(
  plan: RenderingProofPlan,
  executeRound: TriangleRoundExecutor,
  checkpoint: RenderingExecutionCheckpoint = {},
): Promise<string> {
  if (
    plan.version !== "render-v1" ||
    !Number.isSafeInteger(plan.rounds) ||
    plan.rounds < 1 ||
    plan.rounds > MAX_RENDER_ROUNDS
  )
    throw new Error("render_bounds");
  const root = fromBase64url(plan.seed);
  if (root.length !== 32) throw new Error("render_seed");
  const programRoot = await sha256(
    utf8("shar/render-v1/css-program\0"),
    root,
    encodeCanonicalCssTranscript(deriveCanonicalCssTranscript(root)),
  );
  const completed = checkpoint.completedRoundDigests ?? [];
  if (completed.length > plan.rounds) throw new Error("render_checkpoint");
  const digests: Uint8Array[] = [];
  for (const encoded of completed) {
    const digest = fromBase64url(encoded);
    if (digest.length !== 32 || base64url(digest) !== encoded)
      throw new Error("render_checkpoint");
    digests.push(digest);
  }
  for (let round = digests.length; round < plan.rounds; round++) {
    const roundSeed = await sha256(
      utf8("shar/render-v1/round\0"),
      programRoot,
      word(round),
    );
    const program = await createTriangleProgram(
      roundSeed,
      plan.triangles,
      plan.samples,
    );
    const selections = await executeRound(program, round);
    if (selections.length !== program.samples.length)
      throw new Error("render_selection_count");
    const digest = await reduceTriangleSelections(selections);
    digests.push(digest);
    checkpoint.onRoundDigest?.(round + 1, base64url(digest));
  }
  return base64url(await sha256(utf8("shar/render-v1/final\0"), ...digests));
}

export async function solveRendering(
  plan: RenderingProofPlan,
): Promise<string> {
  return solveRenderingWithExecutor(plan, async (program) =>
    selectTriangles(program),
  );
}

export async function cssTranscriptCommitment(
  plan: RenderingProofPlan,
): Promise<string> {
  if (
    plan.version !== "render-v1" ||
    !Number.isSafeInteger(plan.rounds) ||
    plan.rounds < 1 ||
    plan.rounds > MAX_RENDER_ROUNDS ||
    !Number.isSafeInteger(plan.triangles) ||
    plan.triangles < 1 ||
    plan.triangles > 512 ||
    !Number.isSafeInteger(plan.samples) ||
    plan.samples < 1 ||
    plan.samples > 4096
  )
    throw new Error("render_bounds");
  const seed = fromBase64url(plan.seed);
  if (seed.length !== 32) throw new Error("render_seed");
  const transcript = encodeCanonicalCssTranscript(
    deriveCanonicalCssTranscript(seed),
  );
  return base64url(
    await sha256(
      utf8("shar/css-transcript-v1\0"),
      concatBytes(
        seed,
        word(plan.rounds),
        word(plan.triangles),
        word(plan.samples),
        transcript,
      ),
    ),
  );
}
