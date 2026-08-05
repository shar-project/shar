import {
  RENDER_COORDINATE_LIMIT,
  deriveCanonicalCssTranscript,
  fromBase64url,
  solveRenderingWithExecutor,
  type RenderingProofPlan,
  type TriangleProgram,
  type TriangleRoundExecutor,
  type TriangleSelection,
} from "@shar/server/browser";

const GPU_BUFFER_USAGE = {
  MAP_READ: 0x0001,
  COPY_SRC: 0x0004,
  COPY_DST: 0x0008,
  UNIFORM: 0x0040,
  STORAGE: 0x0080,
} as const;
const GPU_MAP_READ = 0x0001;
const MAX_WORKING_BYTES = 16 * 1024 * 1024;

export class RenderBackendUnavailable extends Error {
  constructor(
    readonly backend: "webgpu" | "webgl2" | "css",
    message = `${backend}_unavailable`,
  ) {
    super(message);
    this.name = "RenderBackendUnavailable";
  }
}

export interface RenderExecutorOptions {
  signal?: AbortSignal;
  onRound?: (completed: number, total: number) => void;
}
export interface AdaptiveRenderOptions extends RenderExecutorOptions {
  checkpoint?: () => Promise<void>;
  onBackendChange?: (backend: "webgpu" | "webgl2" | "css") => void;
  completedRoundDigests?: readonly string[];
  resumeBackend?: "webgpu" | "webgl2" | "css";
  onRoundDigest?: (
    completed: number,
    digest: string,
    backend: "webgpu" | "webgl2" | "css",
  ) => void;
}
export interface AdaptiveRenderResult {
  digest: string;
  backend: "webgpu" | "webgl2" | "css";
}

// Challenge data is supplied only through buffers. This source is static.
export const RENDER_V1_WGSL = `
struct Params { triangle_count:u32, sample_count:u32, _pad0:u32, _pad1:u32 }
struct U64 { lo:u32, hi:u32 }
struct Signed64 { magnitude:U64, negative:u32 }
@group(0) @binding(0) var<storage,read> triangles:array<u32>;
@group(0) @binding(1) var<storage,read> samples:array<u32>;
@group(0) @binding(2) var<storage,read_write> output:array<u32>;
@group(0) @binding(3) var<uniform> params:Params;

fn multiply_u32(a:u32,b:u32)->U64 {
  let a0=a&0xffffu;let a1=a>>16u;let b0=b&0xffffu;let b1=b>>16u;
  let w0=a0*b0;let t=a1*b0+(w0>>16u);let w2=t>>16u;let low_mid=t&0xffffu;
  let w1=a0*b1+low_mid;
  return U64((w1<<16u)|(w0&0xffffu),a1*b1+w2+(w1>>16u));
}
fn magnitude_i32(value:i32)->u32 {var result=value;if(result<0){result=-result;}return u32(result);}
fn signed_product(a:i32,b:i32)->Signed64 {
  let magnitude=multiply_u32(magnitude_i32(a),magnitude_i32(b));
  var negative=select(0u,1u,(a<0)!=(b<0));if((magnitude.lo|magnitude.hi)==0u){negative=0u;}
  return Signed64(magnitude,negative);
}
fn compare_u64(a:U64,b:U64)->i32 {if(a.hi>b.hi){return 1;}if(a.hi<b.hi){return -1;}if(a.lo>b.lo){return 1;}if(a.lo<b.lo){return -1;}return 0;}
fn difference_sign(a:Signed64,b:Signed64)->i32 {
  if(a.negative!=b.negative){if(a.negative==1u){return -1;}return 1;}
  let compared=compare_u64(a.magnitude,b.magnitude);if(a.negative==1u){return -compared;}return compared;
}
fn edge_sign(ax:i32,ay:i32,bx:i32,by:i32,px:i32,py:i32)->i32 {
  return difference_sign(signed_product(px-ax,by-ay),signed_product(py-ay,bx-ax));
}
fn covers(base:u32,x:i32,y:i32)->bool {
  let ax=i32(triangles[base+2u]);let ay=i32(triangles[base+3u]);let bx=i32(triangles[base+4u]);let by=i32(triangles[base+5u]);let cx=i32(triangles[base+6u]);let cy=i32(triangles[base+7u]);
  let a=edge_sign(ax,ay,bx,by,x,y);let b=edge_sign(bx,by,cx,cy,x,y);let c=edge_sign(cx,cy,ax,ay,x,y);
  return (a>=0&&b>=0&&c>=0)||(a<=0&&b<=0&&c<=0);
}
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) invocation:vec3<u32>) {
  let sample_id=invocation.x;if(sample_id>=params.sample_count){return;}
  let x=i32(samples[sample_id*2u]);let y=i32(samples[sample_id*2u+1u]);var selected_id=0u;var selected_z=0u;
  for(var triangle_id=0u;triangle_id<params.triangle_count;triangle_id++) {let base=triangle_id*8u;let id=triangles[base];let z=triangles[base+1u];if(covers(base,x,y)&&(selected_id==0u||z>selected_z||(z==selected_z&&id>selected_id))){selected_id=id;selected_z=z;}}
  output[sample_id*2u]=selected_id;output[sample_id*2u+1u]=selected_z;
}`;

export const RENDER_V1_WEBGL_VERTEX = `#version 300 es
const vec2 positions[3]=vec2[3](vec2(-1.0,-1.0),vec2(3.0,-1.0),vec2(-1.0,3.0));
void main(){gl_Position=vec4(positions[gl_VertexID],0.0,1.0);}`;

export const RENDER_V1_WEBGL_FRAGMENT = `#version 300 es
precision highp float;precision highp int;
struct U64 {uint lo;uint hi;};struct Signed64 {U64 magnitude;bool negative;};
uniform highp usampler2D triangle_data;uniform highp usampler2D sample_data;uniform uint triangle_count;
layout(location=0) out highp uvec2 selected;
U64 multiply_u32(uint a,uint b){uint a0=a&0xffffu,a1=a>>16u,b0=b&0xffffu,b1=b>>16u;uint w0=a0*b0,t=a1*b0+(w0>>16u),w2=t>>16u,low_mid=t&0xffffu,w1=a0*b1+low_mid;return U64((w1<<16u)|(w0&0xffffu),a1*b1+w2+(w1>>16u));}
uint magnitude_i32(int value){return uint(value<0?-value:value);}
Signed64 signed_product(int a,int b){U64 magnitude=multiply_u32(magnitude_i32(a),magnitude_i32(b));bool negative=(a<0)!=(b<0);if((magnitude.lo|magnitude.hi)==0u)negative=false;return Signed64(magnitude,negative);}
int compare_u64(U64 a,U64 b){if(a.hi>b.hi)return 1;if(a.hi<b.hi)return -1;if(a.lo>b.lo)return 1;if(a.lo<b.lo)return -1;return 0;}
int difference_sign(Signed64 a,Signed64 b){if(a.negative!=b.negative)return a.negative?-1:1;int compared=compare_u64(a.magnitude,b.magnitude);return a.negative?-compared:compared;}
int edge_sign(int ax,int ay,int bx,int by,int px,int py){return difference_sign(signed_product(px-ax,by-ay),signed_product(py-ay,bx-ax));}
bool covers(uvec4 first,uvec4 second,int x,int y){int ax=int(first.z),ay=int(first.w),bx=int(second.x),by=int(second.y),cx=int(second.z),cy=int(second.w);int a=edge_sign(ax,ay,bx,by,x,y),b=edge_sign(bx,by,cx,cy,x,y),c=edge_sign(cx,cy,ax,ay,x,y);return (a>=0&&b>=0&&c>=0)||(a<=0&&b<=0&&c<=0);}
void main(){int sample_id=int(gl_FragCoord.x);uvec2 point=texelFetch(sample_data,ivec2(sample_id,0),0).xy;uint selected_id=0u,selected_z=0u;for(uint triangle_id=0u;triangle_id<512u;triangle_id++){if(triangle_id>=triangle_count)break;uvec4 first=texelFetch(triangle_data,ivec2(int(triangle_id*2u),0),0);uvec4 second=texelFetch(triangle_data,ivec2(int(triangle_id*2u+1u),0),0);if(covers(first,second,int(point.x),int(point.y))&&(selected_id==0u||first.y>selected_z||(first.y==selected_z&&first.x>selected_id))){selected_id=first.x;selected_z=first.y;}}selected=uvec2(selected_id,selected_z);}`;

export async function solveRenderingWebGpu(
  plan: RenderingProofPlan,
  options: RenderExecutorOptions = {},
): Promise<string> {
  const device = await requestWebGpuDevice();
  let completed = 0;
  const execute: TriangleRoundExecutor = async (program) => {
    throwIfAborted(options.signal);
    const selections = await executeWebGpuRound(
      device,
      program,
      options.signal,
    );
    completed++;
    options.onRound?.(completed, plan.rounds);
    return selections;
  };
  try {
    return await solveRenderingWithExecutor(plan, execute);
  } finally {
    try {
      device.destroy();
    } catch {}
  }
}

export async function solveRenderingAdaptive(
  plan: RenderingProofPlan,
  options: AdaptiveRenderOptions = {},
): Promise<AdaptiveRenderResult> {
  const backends = ["webgpu", "webgl2", "css"] as const;
  let backendIndex = 0;
  let active: (typeof backends)[number] | undefined = options.resumeBackend;
  let device: any;
  let cssTranscriptValidated = false;
  const completedRoundDigests = options.completedRoundDigests ?? [];
  if (completedRoundDigests.length > 0 && active === undefined)
    throw new Error("render_checkpoint");
  if (completedRoundDigests.length > 0)
    options.onRound?.(completedRoundDigests.length, plan.rounds);

  const execute: TriangleRoundExecutor = async (program, round) => {
    await options.checkpoint?.();
    throwIfAborted(options.signal);
    for (; backendIndex < backends.length; backendIndex++) {
      const backend = backends[backendIndex];
      if (!backend) break;
      if (active !== backend) {
        active = backend;
        options.onBackendChange?.(backend);
      }
      try {
        let selections: readonly TriangleSelection[];
        if (backend === "webgpu") {
          device ??= await requestWebGpuDevice();
          selections = await executeWebGpuRound(
            device,
            program,
            options.signal,
          );
        } else if (backend === "webgl2") {
          selections = executeWebGl2Round(program);
        } else {
          if (!cssTranscriptValidated) {
            await validateCssExecutionTranscript(plan, options.signal);
            cssTranscriptValidated = true;
          }
          selections = await executeCssRound(program, options.signal);
        }
        await options.checkpoint?.();
        return selections;
      } catch (error) {
        if (isAbort(error)) throw error;
        if (!(error instanceof RenderBackendUnavailable)) throw error;
        try {
          device?.destroy();
        } catch {}
        device = undefined;
      }
    }
    throw new RenderBackendUnavailable("css", "render_backends_exhausted");
  };

  try {
    const digest = await solveRenderingWithExecutor(plan, execute, {
      completedRoundDigests,
      onRoundDigest: (completed, roundDigest) => {
        const backend = active;
        if (!backend) throw new Error("render_checkpoint");
        options.onRoundDigest?.(completed, roundDigest, backend);
        options.onRound?.(completed, plan.rounds);
      },
    });
    const backend = active;
    if (!backend)
      throw new RenderBackendUnavailable("css", "render_backends_exhausted");
    return { digest, backend };
  } finally {
    try {
      device?.destroy();
    } catch {}
  }
}

export async function solveRenderingWebGl2(
  plan: RenderingProofPlan,
  options: RenderExecutorOptions = {},
): Promise<string> {
  let completed = 0;
  const execute: TriangleRoundExecutor = async (program) => {
    throwIfAborted(options.signal);
    const selections = executeWebGl2Round(program);
    completed++;
    options.onRound?.(completed, plan.rounds);
    await schedulerYield();
    return selections;
  };
  return solveRenderingWithExecutor(plan, execute);
}

export async function solveRenderingCss(
  plan: RenderingProofPlan,
  options: RenderExecutorOptions = {},
): Promise<string> {
  await validateCssExecutionTranscript(plan, options.signal);
  let completed = 0;
  const execute: TriangleRoundExecutor = async (program) => {
    const selections = await executeCssRound(program, options.signal);
    completed++;
    options.onRound?.(completed, plan.rounds);
    return selections;
  };
  return solveRenderingWithExecutor(plan, execute);
}

const CSS_TRANSCRIPT_V1_STYLES = `
:host{all:initial}
.probe-viewport{position:fixed;left:0;top:0;width:1px;height:1px;overflow:hidden;contain:strict;opacity:0;pointer-events:none;z-index:2147483647}
.probe-container{position:relative;width:256px;height:256px;container:outer / size;--style-ready:ready}
.chain-1{--chain-1:calc(var(--chain-0) + var(--chain-delta))}
.chain-2{--chain-2:calc(var(--chain-1) + 0px)}
.chain-3{--chain-3:calc(var(--chain-2) + 0px)}
.chain-4{--chain-4:calc(var(--chain-3) + 0px)}
.chain-5{--chain-5:calc(var(--chain-4) + 0px)}
.chain-6{--chain-6:calc(var(--chain-5) + 0px)}
.chain-7{--chain-7:calc(var(--chain-6) + 0px)}
.chain-8{--chain-8:calc(var(--chain-7) + 0px)}
.depth-3{--selected-width:var(--chain-3)}.depth-4{--selected-width:var(--chain-4)}
.depth-5{--selected-width:var(--chain-5)}.depth-6{--selected-width:var(--chain-6)}
.depth-7{--selected-width:var(--chain-7)}.depth-8{--selected-width:var(--chain-8)}
.query-host{width:100%;container-type:inline-size;--style-ready:ready}
.probe-layout{position:relative;box-sizing:border-box;width:clamp(1px,var(--selected-width),255px);height:max(1px,min(var(--layout-height),255px));display:grid;grid-template-columns:minmax(0,var(--grid-first)) minmax(0,var(--grid-second));grid-template-rows:1fr;--query-branch:0px;--style-branch:0px;--nested-branch:0px}
.grid-first,.grid-second{box-sizing:border-box;width:100%;min-width:0}.grid-first{display:flex;flex-flow:row nowrap}.flex-first{flex:0 0 var(--flex-first)}.flex-second{flex:0 0 var(--flex-second)}
.intrinsic-probe{position:absolute;left:0;bottom:0;width:max-content;height:1px}.intrinsic-child{display:block;width:var(--intrinsic-width);height:1px}
.transform-probe{position:absolute;left:0;top:0;width:1px;height:1px;transform:translate(var(--transform-x),var(--transform-y)) scale(1);transform-origin:0 0}
.writing-probe{position:absolute;width:1px;height:1px}.vertical-writing{writing-mode:vertical-rl}.horizontal-writing{writing-mode:horizontal-tb}
.hit-stack{position:absolute;left:0;top:0;width:1px;height:1px;isolation:isolate;transform:translateZ(0)}
.hit{position:absolute;inset:0;clip-path:polygon(-100% -100%,200% -100%,200% 200%,-100% 200%);pointer-events:auto}.hit-a{z-index:var(--hit-a-z)}.hit-b{z-index:var(--hit-b-z)}
@container outer (min-width:1px){.probe-layout{--query-branch:var(--query-value)}@container style(--style-ready:ready){.probe-layout{--style-branch:var(--style-value);--nested-branch:1px}}}`;

async function validateCssExecutionTranscript(
  plan: RenderingProofPlan,
  signal?: AbortSignal,
): Promise<void> {
  if (
    typeof document === "undefined" ||
    typeof CSSStyleSheet === "undefined" ||
    typeof document.createElement("div").attachShadow !== "function"
  )
    throw new RenderBackendUnavailable("css");
  throwIfAborted(signal);
  const expected = deriveCanonicalCssTranscript(fromBase64url(plan.seed));
  const host = document.createElement("div");
  host.setAttribute("aria-hidden", "true");
  const shadow = host.attachShadow({ mode: "closed" });
  if (typeof shadow.elementsFromPoint !== "function")
    throw new RenderBackendUnavailable("css", "css_hit_testing_unavailable");
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(CSS_TRANSCRIPT_V1_STYLES);
  shadow.adoptedStyleSheets = [sheet];
  const viewport = document.createElement("div");
  viewport.className = "probe-viewport";
  const container = document.createElement("div");
  container.className = "probe-container";
  const delta = 7;
  container.style.setProperty("--chain-0", `${expected.chainWidth - delta}px`);
  container.style.setProperty("--chain-delta", `${delta}px`);
  container.style.setProperty("--layout-height", `${expected.layoutHeight}px`);
  container.style.setProperty("--grid-first", `${expected.gridFirstWidth}px`);
  container.style.setProperty("--grid-second", `${expected.gridSecondWidth}px`);
  container.style.setProperty("--flex-first", `${expected.flexFirstWidth}px`);
  container.style.setProperty("--flex-second", `${expected.flexSecondWidth}px`);
  container.style.setProperty(
    "--intrinsic-width",
    `${expected.intrinsicWidth}px`,
  );
  container.style.setProperty("--query-value", `${expected.queryBranch}px`);
  container.style.setProperty("--style-value", `${expected.styleBranch}px`);
  container.style.setProperty("--transform-x", `${expected.transformX}px`);
  container.style.setProperty("--transform-y", `${expected.transformY}px`);
  container.style.setProperty("--hit-a-z", expected.hitId === 1 ? "2" : "1");
  container.style.setProperty("--hit-b-z", expected.hitId === 2 ? "2" : "1");
  let parent = container;
  for (let depth = 1; depth <= expected.topologyDepth; depth++) {
    const node = document.createElement("div");
    node.className = `chain-${depth}`;
    parent.append(node);
    parent = node;
  }
  const queryHost = document.createElement("div");
  queryHost.className = "query-host";
  const layout = document.createElement("div");
  layout.className = `probe-layout depth-${expected.topologyDepth}`;
  const gridFirst = document.createElement("div");
  gridFirst.className = "grid-first";
  const flexFirst = document.createElement("i");
  flexFirst.className = "flex-first";
  const flexSecond = document.createElement("i");
  flexSecond.className = "flex-second";
  gridFirst.append(flexFirst, flexSecond);
  const gridSecond = document.createElement("div");
  gridSecond.className = "grid-second";
  const transformProbe = document.createElement("i");
  transformProbe.className = "transform-probe";
  const intrinsicProbe = document.createElement("div");
  intrinsicProbe.className = "intrinsic-probe";
  const intrinsicChild = document.createElement("i");
  intrinsicChild.className = "intrinsic-child";
  intrinsicProbe.append(intrinsicChild);
  const writingProbe = document.createElement("i");
  writingProbe.className = `writing-probe ${expected.verticalWriting ? "vertical-writing" : "horizontal-writing"}`;
  const hitStack = document.createElement("div");
  hitStack.className = "hit-stack";
  for (const id of [1, 2]) {
    const hit = document.createElement("i");
    hit.className = `hit hit-${id === 1 ? "a" : "b"}`;
    hit.dataset.transcriptHit = String(id);
    hitStack.append(hit);
  }
  layout.append(
    gridFirst,
    gridSecond,
    intrinsicProbe,
    transformProbe,
    writingProbe,
    hitStack,
  );
  queryHost.append(layout);
  parent.append(queryHost);
  viewport.append(container);
  shadow.append(viewport);
  document.body.append(host);
  try {
    viewport.style.pointerEvents = "auto";
    const layoutRect = layout.getBoundingClientRect();
    const firstRect = gridFirst.getBoundingClientRect();
    const secondRect = gridSecond.getBoundingClientRect();
    const flexFirstRect = flexFirst.getBoundingClientRect();
    const flexSecondRect = flexSecond.getBoundingClientRect();
    const intrinsicRect = intrinsicProbe.getBoundingClientRect();
    const transformRect = transformProbe.getBoundingClientRect();
    const style = getComputedStyle(layout);
    const selected = shadow
      .elementsFromPoint(0.5, 0.5)
      .find((element) => (element as HTMLElement).dataset.transcriptHit) as
      HTMLElement | undefined;
    const actual = {
      version: "css-transcript-v1" as const,
      chainWidth: exactCssInteger(layoutRect.width),
      layoutHeight: exactCssInteger(layoutRect.height),
      gridFirstWidth: exactCssInteger(firstRect.width),
      gridSecondWidth: exactCssInteger(secondRect.width),
      flexFirstWidth: exactCssInteger(flexFirstRect.width),
      flexSecondWidth: exactCssInteger(flexSecondRect.width),
      intrinsicWidth: exactCssInteger(intrinsicRect.width),
      queryBranch: exactCssInteger(
        Number.parseFloat(style.getPropertyValue("--query-branch")),
      ),
      styleBranch: exactCssInteger(
        Number.parseFloat(style.getPropertyValue("--style-branch")),
      ),
      nestedBranch: exactCssInteger(
        Number.parseFloat(style.getPropertyValue("--nested-branch")),
      ),
      transformX: exactCssInteger(transformRect.left - layoutRect.left),
      transformY: exactCssInteger(transformRect.top - layoutRect.top),
      verticalWriting:
        getComputedStyle(writingProbe).writingMode === "vertical-rl" ? 1 : 0,
      hitId: Number(selected?.dataset.transcriptHit ?? 0),
      topologyDepth: countTranscriptDepth(layout, container),
    };
    for (const key of Object.keys(expected) as Array<keyof typeof expected>)
      if (actual[key] !== expected[key])
        throw new Error(`css_transcript_${key}`);
  } catch (error) {
    if (error instanceof RenderBackendUnavailable) throw error;
    throw new RenderBackendUnavailable(
      "css",
      error instanceof Error ? error.message : "css_transcript_failed",
    );
  } finally {
    viewport.style.pointerEvents = "none";
    host.remove();
  }
  await schedulerYield();
}

function exactCssInteger(value: number): number {
  const rounded = Math.round(value);
  if (!Number.isFinite(value) || Math.abs(value - rounded) > 0.01)
    throw new Error("css_transcript_quantization");
  return rounded;
}

function countTranscriptDepth(node: Element, root: Element): number {
  let depth = 0;
  for (let current = node.parentElement; current && current !== root;) {
    if (current.className.startsWith("chain-")) depth++;
    current = current.parentElement;
  }
  return depth;
}

export async function executeCssRound(
  program: TriangleProgram,
  signal?: AbortSignal,
): Promise<readonly TriangleSelection[]> {
  const workingBytes =
    program.triangles.length * 8 * 4 +
    program.samples.length * 2 * 4 +
    program.samples.length * 2 * 4;
  if (workingBytes > MAX_WORKING_BYTES) throw new Error("render_memory_bound");
  if (
    typeof document === "undefined" ||
    typeof CSSStyleSheet === "undefined" ||
    typeof document.createElement("div").attachShadow !== "function"
  )
    throw new RenderBackendUnavailable("css");
  throwIfAborted(signal);
  const host = document.createElement("div");
  host.setAttribute("aria-hidden", "true");
  host.dataset.sharRenderSurface = "render-v1";
  const shadow = host.attachShadow({ mode: "closed" });
  if (typeof shadow.elementsFromPoint !== "function")
    throw new RenderBackendUnavailable("css", "css_hit_testing_unavailable");
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(`
:host{all:initial}
.viewport{--surface-size:2048;--surface-ready:ready;position:fixed;left:0;top:0;width:1px;height:1px;overflow:hidden;contain:strict;container-type:size;display:grid;writing-mode:horizontal-tb;opacity:0;pointer-events:none;z-index:2147483647}
.surface{position:absolute;left:0;top:0;width:clamp(2048px,calc(var(--surface-size)*1px),2048px);height:max(2048px,calc(var(--surface-size)*1px));display:flex;flex:0 0 auto;container-type:inline-size;transform:translate3d(calc(.5px - var(--sample-x)*1px),calc(.5px - var(--sample-y)*1px),0) scale(1) rotate(0deg);transform-origin:0 0;transform-style:preserve-3d;isolation:isolate}
@container (min-width:1px){.surface{--query-branch:inline}}
@container style(--surface-ready:ready){.surface{--style-branch:ready}}
.triangle{position:absolute;inset:0;display:block;box-sizing:border-box;background:currentColor;color:transparent;writing-mode:horizontal-tb;transform:translate(0,0) scale(1);clip-path:polygon(var(--ax) var(--ay),var(--bx) var(--by),var(--cx) var(--cy));pointer-events:auto}`);
  shadow.adoptedStyleSheets = [sheet];
  const viewportRule = (sheet.cssRules[1] as CSSStyleRule).style,
    surfaceRule = (sheet.cssRules[2] as CSSStyleRule).style;
  const viewport = document.createElement("div"),
    surface = document.createElement("div");
  viewport.className = "viewport";
  surface.className = "surface";
  viewport.append(surface);
  shadow.append(viewport);
  const ranked = [...program.triangles].sort(
    (a, b) => a.z - b.z || a.id - b.id,
  );
  for (const [rank, triangle] of ranked.entries()) {
    const element = document.createElement("i");
    element.className = "triangle";
    const declaration = element.style;
    declaration.zIndex = String(rank + 1);
    declaration.setProperty("--ax", percent(triangle.ax));
    declaration.setProperty("--ay", percent(triangle.ay));
    declaration.setProperty("--bx", percent(triangle.bx));
    declaration.setProperty("--by", percent(triangle.by));
    declaration.setProperty("--cx", percent(triangle.cx));
    declaration.setProperty("--cy", percent(triangle.cy));
    element.dataset.triangleId = String(triangle.id);
    element.dataset.triangleZ = String(triangle.z);
    surface.append(element);
  }
  document.body.append(host);
  const selections: TriangleSelection[] = [];
  try {
    const chunkSize = 32;
    for (let start = 0; start < program.samples.length; start += chunkSize) {
      throwIfAborted(signal);
      viewportRule.pointerEvents = "auto";
      const end = Math.min(program.samples.length, start + chunkSize);
      for (let index = start; index < end; index++) {
        const sample = program.samples[index];
        if (!sample) throw new Error("missing_sample");
        surfaceRule.setProperty(
          "--sample-x",
          String((sample[0] * 2048) / RENDER_COORDINATE_LIMIT),
        );
        surfaceRule.setProperty(
          "--sample-y",
          String((sample[1] * 2048) / RENDER_COORDINATE_LIMIT),
        );
        const selected = shadow
          .elementsFromPoint(0.5, 0.5)
          .find((element) => (element as HTMLElement).dataset.triangleId) as
          HTMLElement | undefined;
        selections.push(
          selected
            ? [
                Number(selected.dataset.triangleId),
                Number(selected.dataset.triangleZ),
              ]
            : [0, 0],
        );
      }
      viewportRule.pointerEvents = "none";
      await schedulerYield();
    }
    return selections;
  } catch (error) {
    if (error instanceof RenderBackendUnavailable) throw error;
    throw new RenderBackendUnavailable(
      "css",
      error instanceof Error ? error.message : "css_failed",
    );
  } finally {
    viewportRule.pointerEvents = "none";
    host.remove();
  }
}

export function executeWebGl2Round(
  program: TriangleProgram,
): readonly TriangleSelection[] {
  const canvas = makeCanvas(program.samples.length, 1);
  const gl = canvas.getContext("webgl2", {
    alpha: false,
    antialias: false,
    depth: false,
    stencil: false,
    premultipliedAlpha: false,
    preserveDrawingBuffer: false,
    powerPreference: "high-performance",
  }) as WebGL2RenderingContext | null;
  if (!gl) throw new RenderBackendUnavailable("webgl2");
  const workingBytes =
    program.triangles.length * 8 * 4 + program.samples.length * 2 * 4 * 2;
  if (workingBytes > MAX_WORKING_BYTES) throw new Error("render_memory_bound");
  let lost = false;
  const element =
    typeof HTMLCanvasElement !== "undefined" &&
    canvas instanceof HTMLCanvasElement
      ? canvas
      : undefined;
  const onLost = (event: Event) => {
    event.preventDefault();
    lost = true;
  };
  element?.addEventListener("webglcontextlost", onLost, { once: true });
  const shaders: WebGLShader[] = [];
  const textures: WebGLTexture[] = [];
  let framebuffer: WebGLFramebuffer | null = null;
  let vertexArray: WebGLVertexArrayObject | null = null;
  let pipeline: WebGLProgram | null = null;
  try {
    const vertex = compileShader(gl, gl.VERTEX_SHADER, RENDER_V1_WEBGL_VERTEX),
      fragment = compileShader(
        gl,
        gl.FRAGMENT_SHADER,
        RENDER_V1_WEBGL_FRAGMENT,
      );
    shaders.push(vertex, fragment);
    pipeline = linkProgram(gl, vertex, fragment);
    vertexArray = gl.createVertexArray();
    if (!vertexArray) throw new Error("webgl_vertex_array");
    gl.bindVertexArray(vertexArray);
    const triangleTexture = createIntegerTexture(
      gl,
      gl.RGBA32UI,
      program.triangles.length * 2,
      gl.RGBA_INTEGER,
      packTriangles(program),
    );
    textures.push(triangleTexture);
    const sampleTexture = createIntegerTexture(
      gl,
      gl.RG32UI,
      program.samples.length,
      gl.RG_INTEGER,
      packSamples(program),
    );
    textures.push(sampleTexture);
    const outputTexture = createIntegerTexture(
      gl,
      gl.RG32UI,
      program.samples.length,
      gl.RG_INTEGER,
      null,
    );
    textures.push(outputTexture);
    framebuffer = gl.createFramebuffer();
    if (!framebuffer) throw new Error("webgl_framebuffer");
    gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
    gl.framebufferTexture2D(
      gl.FRAMEBUFFER,
      gl.COLOR_ATTACHMENT0,
      gl.TEXTURE_2D,
      outputTexture,
      0,
    );
    if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE)
      throw new Error("webgl_framebuffer_incomplete");
    gl.disable(gl.BLEND);
    gl.disable(gl.DITHER);
    gl.disable(gl.DEPTH_TEST);
    gl.disable(gl.STENCIL_TEST);
    gl.disable(gl.SCISSOR_TEST);
    gl.viewport(0, 0, program.samples.length, 1);
    gl.useProgram(pipeline);
    bindTexture(gl, pipeline, "triangle_data", triangleTexture, 0);
    bindTexture(gl, pipeline, "sample_data", sampleTexture, 1);
    const count = gl.getUniformLocation(pipeline, "triangle_count");
    if (count === null) throw new Error("webgl_uniform");
    gl.uniform1ui(count, program.triangles.length);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    const words = new Uint32Array(program.samples.length * 2);
    gl.readPixels(
      0,
      0,
      program.samples.length,
      1,
      gl.RG_INTEGER,
      gl.UNSIGNED_INT,
      words,
    );
    if (lost || gl.isContextLost())
      throw new RenderBackendUnavailable("webgl2", "webgl_context_lost");
    const error = gl.getError();
    if (error !== gl.NO_ERROR) throw new Error(`webgl_error_${error}`);
    return unpackSelections(words, program.samples.length);
  } catch (error) {
    if (error instanceof RenderBackendUnavailable) throw error;
    throw new RenderBackendUnavailable(
      "webgl2",
      error instanceof Error ? error.message : "webgl_failed",
    );
  } finally {
    element?.removeEventListener("webglcontextlost", onLost);
    if (framebuffer) gl.deleteFramebuffer(framebuffer);
    for (const texture of textures) gl.deleteTexture(texture);
    if (vertexArray) gl.deleteVertexArray(vertexArray);
    if (pipeline) gl.deleteProgram(pipeline);
    for (const shader of shaders) gl.deleteShader(shader);
  }
}

export async function executeWebGpuRound(
  device: any,
  program: TriangleProgram,
  signal?: AbortSignal,
): Promise<readonly TriangleSelection[]> {
  throwIfAborted(signal);
  const triangleWords = program.triangles.length * 8,
    sampleWords = program.samples.length * 2,
    outputBytes = sampleWords * 4;
  const workingBytes = triangleWords * 4 + sampleWords * 4 + outputBytes + 16;
  if (workingBytes > MAX_WORKING_BYTES) throw new Error("render_memory_bound");
  const resources: any[] = [];
  try {
    const triangleBuffer = createMappedBuffer(
      device,
      packTriangles(program),
      GPU_BUFFER_USAGE.STORAGE,
    );
    resources.push(triangleBuffer);
    const sampleBuffer = createMappedBuffer(
      device,
      packSamples(program),
      GPU_BUFFER_USAGE.STORAGE,
    );
    resources.push(sampleBuffer);
    const output = device.createBuffer({
      size: outputBytes,
      usage: GPU_BUFFER_USAGE.STORAGE | GPU_BUFFER_USAGE.COPY_SRC,
    });
    resources.push(output);
    const readback = device.createBuffer({
      size: outputBytes,
      usage: GPU_BUFFER_USAGE.COPY_DST | GPU_BUFFER_USAGE.MAP_READ,
    });
    resources.push(readback);
    const parameters = createMappedBuffer(
      device,
      new Uint32Array([program.triangles.length, program.samples.length, 0, 0]),
      GPU_BUFFER_USAGE.UNIFORM,
    );
    resources.push(parameters);
    const module = device.createShaderModule({ code: RENDER_V1_WGSL });
    const pipeline = device.createComputePipeline({
      layout: "auto",
      compute: { module, entryPoint: "main" },
    });
    const bindGroup = device.createBindGroup({
      layout: pipeline.getBindGroupLayout(0),
      entries: [
        { binding: 0, resource: { buffer: triangleBuffer } },
        { binding: 1, resource: { buffer: sampleBuffer } },
        { binding: 2, resource: { buffer: output } },
        { binding: 3, resource: { buffer: parameters } },
      ],
    });
    const encoder = device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    pass.setPipeline(pipeline);
    pass.setBindGroup(0, bindGroup);
    pass.dispatchWorkgroups(Math.ceil(program.samples.length / 64));
    pass.end();
    encoder.copyBufferToBuffer(output, 0, readback, 0, outputBytes);
    device.queue.submit([encoder.finish()]);
    await raceDeviceLoss(device, device.queue.onSubmittedWorkDone(), signal);
    await raceDeviceLoss(device, readback.mapAsync(GPU_MAP_READ), signal);
    const words = new Uint32Array(readback.getMappedRange().slice(0));
    readback.unmap();
    return unpackSelections(words, program.samples.length);
  } catch (error) {
    if (isAbort(error) || error instanceof RenderBackendUnavailable)
      throw error;
    throw new RenderBackendUnavailable(
      "webgpu",
      error instanceof Error ? error.message : "webgpu_failed",
    );
  } finally {
    for (const resource of resources)
      try {
        resource.destroy();
      } catch {}
  }
}

function createMappedBuffer(
  device: any,
  words: Uint32Array,
  usage: number,
): any {
  const buffer = device.createBuffer({
    size: Math.max(4, words.byteLength),
    usage,
    mappedAtCreation: true,
  });
  new Uint32Array(buffer.getMappedRange()).set(words);
  buffer.unmap();
  return buffer;
}
async function requestWebGpuDevice(): Promise<any> {
  try {
    const gpu = (
      globalThis.navigator as
        (Navigator & { gpu?: { requestAdapter(): Promise<any> } }) | undefined
    )?.gpu;
    if (!gpu) throw new RenderBackendUnavailable("webgpu");
    const adapter = await gpu.requestAdapter();
    if (!adapter) throw new RenderBackendUnavailable("webgpu");
    return await adapter.requestDevice();
  } catch (error) {
    if (error instanceof RenderBackendUnavailable) throw error;
    throw new RenderBackendUnavailable(
      "webgpu",
      error instanceof Error ? error.message : "webgpu_device_failed",
    );
  }
}
function packTriangles(program: TriangleProgram): Uint32Array {
  const words = new Uint32Array(program.triangles.length * 8);
  program.triangles.forEach((triangle, index) =>
    words.set(
      [
        triangle.id,
        triangle.z,
        triangle.ax,
        triangle.ay,
        triangle.bx,
        triangle.by,
        triangle.cx,
        triangle.cy,
      ],
      index * 8,
    ),
  );
  return words;
}
function packSamples(program: TriangleProgram): Uint32Array {
  const words = new Uint32Array(program.samples.length * 2);
  program.samples.forEach((sample, index) => words.set(sample, index * 2));
  return words;
}
function unpackSelections(
  words: Uint32Array,
  count: number,
): TriangleSelection[] {
  if (words.length !== count * 2) throw new Error("render_selection_count");
  const output: TriangleSelection[] = [];
  for (let index = 0; index < count; index++)
    output.push([words[index * 2] ?? 0, words[index * 2 + 1] ?? 0]);
  return output;
}
function makeCanvas(
  width: number,
  height: number,
): OffscreenCanvas | HTMLCanvasElement {
  if (typeof OffscreenCanvas !== "undefined")
    return new OffscreenCanvas(width, height);
  if (typeof document !== "undefined") {
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    return canvas;
  }
  throw new RenderBackendUnavailable("webgl2");
}
function compileShader(
  gl: WebGL2RenderingContext,
  type: number,
  source: string,
): WebGLShader {
  const shader = gl.createShader(type);
  if (!shader) throw new Error("webgl_shader");
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    const message = gl.getShaderInfoLog(shader) ?? "webgl_shader_compile";
    gl.deleteShader(shader);
    throw new Error(message);
  }
  return shader;
}
function linkProgram(
  gl: WebGL2RenderingContext,
  vertex: WebGLShader,
  fragment: WebGLShader,
): WebGLProgram {
  const program = gl.createProgram();
  if (!program) throw new Error("webgl_program");
  gl.attachShader(program, vertex);
  gl.attachShader(program, fragment);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    const message = gl.getProgramInfoLog(program) ?? "webgl_program_link";
    gl.deleteProgram(program);
    throw new Error(message);
  }
  return program;
}
function createIntegerTexture(
  gl: WebGL2RenderingContext,
  internalFormat: number,
  width: number,
  format: number,
  data: Uint32Array | null,
): WebGLTexture {
  const texture = gl.createTexture();
  if (!texture) throw new Error("webgl_texture");
  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  gl.texStorage2D(gl.TEXTURE_2D, 1, internalFormat, width, 1);
  if (data)
    gl.texSubImage2D(
      gl.TEXTURE_2D,
      0,
      0,
      0,
      width,
      1,
      format,
      gl.UNSIGNED_INT,
      data,
    );
  return texture;
}
function bindTexture(
  gl: WebGL2RenderingContext,
  program: WebGLProgram,
  name: string,
  texture: WebGLTexture,
  unit: number,
): void {
  const location = gl.getUniformLocation(program, name);
  if (location === null) throw new Error("webgl_uniform");
  gl.activeTexture(gl.TEXTURE0 + unit);
  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.uniform1i(location, unit);
}
function percent(value: number): string {
  return `${(value * 100) / RENDER_COORDINATE_LIMIT}%`;
}
async function raceDeviceLoss<T>(
  device: any,
  operation: Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const lost = Promise.resolve(device.lost).then((info: any) => {
    throw new RenderBackendUnavailable(
      "webgpu",
      `webgpu_device_lost:${String(info?.reason ?? "unknown")}`,
    );
  });
  const aborted = signal
    ? new Promise<never>((_, reject) => {
        if (signal.aborted)
          reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
        else
          signal.addEventListener(
            "abort",
            () =>
              reject(
                signal.reason ?? new DOMException("Aborted", "AbortError"),
              ),
            { once: true },
          );
      })
    : new Promise<never>(() => {});
  return Promise.race([operation, lost, aborted]);
}
function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted)
    throw signal.reason ?? new DOMException("Aborted", "AbortError");
}
function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
function schedulerYield(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}
