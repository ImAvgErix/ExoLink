import { useEffect, useRef } from "react";

/**
 * The renderer deliberately owns its backdrop. WebView2 cannot safely expose
 * arbitrary DOM pixels as a texture, so this is honest ambient refraction: the
 * same procedural field is sampled at displaced coordinates inside registered
 * GlassSurface planes. Message text and controls remain ordinary sharp DOM.
 */
export const REFRACTIVE_GLASS_MAX_PLANES = 5;
export const REFRACTIVE_GLASS_STORAGE_KEY = "exocord.refractive-glass";
export const REFRACTIVE_GLASS_PROOF_QUERY = "refractiveGlass";

export type RefractiveGlassMode = "system" | "refractive" | "solid";

export const DEFAULT_REFRACTIVE_GLASS_MODE: RefractiveGlassMode = "system";

/**
 * Keeps the appearance setting forwards-compatible while retaining the old
 * boolean storage contract. Older builds wrote `0` for the opt-out; treating
 * it as Solid means an upgrade never unexpectedly turns the shader back on.
 */
export function normalizeRefractiveGlassMode(
  value: string | null | undefined,
): RefractiveGlassMode {
  switch (value) {
    case "refractive":
      return "refractive";
    case "solid":
    case "0":
      return "solid";
    case "system":
      return "system";
    default:
      return DEFAULT_REFRACTIVE_GLASS_MODE;
  }
}

export function readRefractiveGlassMode(
  storage?: Pick<Storage, "getItem">,
): RefractiveGlassMode {
  if (storage) return normalizeRefractiveGlassMode(storage.getItem(REFRACTIVE_GLASS_STORAGE_KEY));
  if (typeof window === "undefined") return DEFAULT_REFRACTIVE_GLASS_MODE;
  try {
    return normalizeRefractiveGlassMode(
      window.localStorage.getItem(REFRACTIVE_GLASS_STORAGE_KEY),
    );
  } catch {
    return DEFAULT_REFRACTIVE_GLASS_MODE;
  }
}

export const REFRACTIVE_GLASS_VERTEX_SHADER = `#version 300 es
in vec2 aPosition;
out vec2 vUv;

void main() {
  vUv = aPosition * 0.5 + 0.5;
  gl_Position = vec4(aPosition, 0.0, 1.0);
}`;

export const REFRACTIVE_GLASS_FRAGMENT_SHADER = `#version 300 es
precision highp float;

in vec2 vUv;
uniform vec2 uResolution;
uniform float uTime;
uniform vec2 uPointer;
uniform float uProof;
uniform vec4 uRects[5];
uniform float uKinds[5];
out vec4 outColor;

float lineField(vec2 p) {
  vec2 cell = abs(fract(p) - 0.5);
  float x = 1.0 - smoothstep(0.015, 0.045, cell.x);
  float y = 1.0 - smoothstep(0.015, 0.045, cell.y);
  return max(x, y);
}

float proofLineField(vec2 p) {
  vec2 cell = abs(fract(p) - 0.5);
  float x = 1.0 - smoothstep(0.01, 0.06, cell.x);
  float y = 1.0 - smoothstep(0.01, 0.06, cell.y);
  return max(x, y);
}

vec3 ambientBackdrop(vec2 uv) {
  float time = uTime * 0.035;
  float aspect = uResolution.x / max(uResolution.y, 1.0);
  vec2 p = vec2((uv.x - 0.5) * aspect * 2.0, uv.y * 2.0 - 1.0);
  float drift = sin(p.x * 3.4 + time) * 0.5 + 0.5;
  float bloom = exp(-3.2 * dot(p - vec2(-0.42, 0.24), p - vec2(-0.42, 0.24)));
  float halo = exp(-4.4 * dot(p - vec2(0.48, -0.28), p - vec2(0.48, -0.28)));
  vec3 color = mix(vec3(0.025, 0.033, 0.055), vec3(0.13, 0.10, 0.25), drift * 0.42);
  color += vec3(0.20, 0.16, 0.48) * bloom;
  color += vec3(0.08, 0.30, 0.34) * halo;

  // A fine, straight-line field is always present at low contrast. Proof
  // mode raises it so a screenshot makes the coordinate displacement obvious.
  float fineGrid = lineField(uv * vec2(74.0, 42.0));
  float proofGrid = proofLineField(uv * vec2(72.0, 42.0));
  color += fineGrid * (uProof > 0.5 ? vec3(0.15, 0.19, 0.30) : vec3(0.025, 0.031, 0.055));
  color += proofGrid * (uProof > 0.5 ? vec3(0.76, 0.88, 1.0) : vec3(0.0));
  return color;
}

void main() {
  vec3 base = ambientBackdrop(vUv);
  vec3 refracted = base;
  float mask = 0.0;

  for (int i = 0; i < 5; i += 1) {
    vec4 rect = uRects[i];
    if (rect.z <= 0.0 || rect.w <= 0.0) continue;
    vec2 local = (vUv - rect.xy) / rect.zw;
    bool inside = all(greaterThanEqual(local, vec2(0.0))) &&
      all(lessThanEqual(local, vec2(1.0)));
    if (!inside) continue;

    float edge = min(min(local.x, 1.0 - local.x), min(local.y, 1.0 - local.y));
    float edgeBand = 1.0 - smoothstep(0.015, 0.18, edge);
    vec2 fromCenter = local - 0.5;
    float radius = max(length(fromCenter), 0.0001);
    vec2 normal = fromCenter / radius;
    float clearPlane = uKinds[i];

    // Approximate a shallow IOR bend. Crucially, the ambient field is sampled
    // again at this displaced UV; this is not a blur or a color-only overlay.
    float bendAmount = uProof > 0.5
      ? mix(0.045, 0.075, clearPlane)
      : mix(0.014, 0.024, clearPlane);
    vec2 bend = normal * bendAmount * (0.35 + edgeBand * 0.95);
    vec2 pointerDelta = (uPointer - vUv) / max(rect.zw, vec2(0.02));
    bend += pointerDelta * 0.0035 * (1.0 - smoothstep(0.20, 0.76, radius));
    vec2 displaced = clamp(vUv + bend, vec2(0.001), vec2(0.999));
    vec2 dispersion = normal * (uProof > 0.5
      ? 0.012 + edgeBand * 0.012
      : 0.0018 + edgeBand * 0.0042);

    vec3 redSample = ambientBackdrop(clamp(displaced + dispersion, vec2(0.001), vec2(0.999)));
    vec3 greenSample = ambientBackdrop(displaced);
    vec3 blueSample = ambientBackdrop(clamp(displaced - dispersion, vec2(0.001), vec2(0.999)));
    refracted = vec3(redSample.r, greenSample.g, blueSample.b);

    float fresnel = pow(1.0 - clamp(edge / 0.18, 0.0, 1.0), 2.0);
    vec3 specular = (uProof > 0.5 ? vec3(0.45, 0.75, 1.0) : vec3(0.48, 0.55, 0.78)) *
      (edgeBand * (uProof > 0.5 ? 0.24 : 0.12) + fresnel * (uProof > 0.5 ? 0.20 : 0.10));
    refracted += specular;
    mask = max(mask, uProof > 0.5 ? 0.94 + edgeBand * 0.05 : 0.72 + edgeBand * 0.20);
  }

  outColor = vec4(refracted, mask);
}`;

export type RendererStatus = "disabled" | "fallback" | "webgl2";

/** Stable, proof-visible codes for every path that prevents WebGL2 output. */
export type RefractiveFallbackReason =
  | "none"
  | "explicit-off"
  | "feature-flag"
  | "reduced-transparency"
  | "forced-colors"
  | "webgl2-unavailable"
  | "shader-compile"
  | "program-link"
  | "uniform-missing"
  | "pipeline-allocation"
  | "resize-observer-missing"
  | "plane-measurement"
  | "context-lost";

type RefractiveFailureReason = Exclude<RefractiveFallbackReason, "none">;

export function sanitizeRefractiveDiagnostic(value: string): string {
  return (
    value
      .replace(/\s+/g, " ")
      .replace(/[^a-zA-Z0-9 .,:;_+()\-]/g, "")
      .trim()
      .slice(0, 160) || "unknown"
  );
}

export function formatRefractiveProofStatus(
  renderer: RendererStatus,
  reason: RefractiveFallbackReason,
  planes: number,
): string {
  const count = Math.max(0, Math.floor(planes));
  if (renderer === "webgl2") return `WEBGL2 · ${count} PLANES`;
  return `FALLBACK:${reason === "none" ? "unknown" : reason} · ${count} PLANES`;
}

class RefractivePipelineError extends Error {
  readonly reason: RefractiveFailureReason;
  readonly diagnostic: string;

  constructor(reason: RefractiveFailureReason, diagnostic: string) {
    const detail = sanitizeRefractiveDiagnostic(diagnostic);
    super(`${reason}: ${detail}`);
    this.name = "RefractivePipelineError";
    this.reason = reason;
    this.diagnostic = detail;
  }
}

type RendererOptions = {
  mode: RefractiveGlassMode;
  enabled: boolean;
  proof: boolean;
  proofOverride: boolean;
  disabledReason: RefractiveFailureReason | null;
};

function readRendererOptions(mode?: RefractiveGlassMode): RendererOptions {
  if (typeof window === "undefined") {
    return {
      mode: mode ?? DEFAULT_REFRACTIVE_GLASS_MODE,
      enabled: false,
      proof: false,
      proofOverride: false,
      disabledReason: "explicit-off",
    };
  }
  const query = new URLSearchParams(window.location.search).get(
    REFRACTIVE_GLASS_PROOF_QUERY,
  );
  const envEnabled = import.meta.env.VITE_EXOCORD_REFRACTIVE_GLASS !== "0";
  let stored: string | null = null;
  try {
    stored = window.localStorage.getItem(REFRACTIVE_GLASS_STORAGE_KEY);
  } catch {
    // A storage-denied WebView still honors the live mode prop for this run.
  }
  const selectedMode = mode ?? normalizeRefractiveGlassMode(stored);
  // An explicit URL mode is a deterministic QA/dev override. In particular,
  // `?refractiveGlass=proof` must not be masked by a previous `=0` opt-out.
  const hasExplicitMode = query !== null;
  const proofOverride = query === "proof";
  const proof = query === "proof" || (!hasExplicitMode && stored === "proof");
  const enabled = envEnabled &&
    (proofOverride ||
      (hasExplicitMode ? query !== "0" : selectedMode !== "solid"));
  const disabledReason = !envEnabled
    ? "feature-flag"
    : enabled
      ? null
      : "explicit-off";
  return { mode: selectedMode, enabled, proof, proofOverride, disabledReason };
}

function hasReducedTransparency(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-reduced-transparency: reduce)").matches;
}

function hasForcedColors(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(forced-colors: active)").matches;
}

function hasReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function compileShader(
  gl: WebGL2RenderingContext,
  type: number,
  source: string,
): WebGLShader {
  const shader = gl.createShader(type);
  if (!shader) {
    throw new RefractivePipelineError(
      "shader-compile",
      "WebGL2 could not allocate a shader",
    );
  }
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    const message = sanitizeRefractiveDiagnostic(
      gl.getShaderInfoLog(shader) ?? "unknown shader error",
    );
    gl.deleteShader(shader);
    throw new RefractivePipelineError("shader-compile", message);
  }
  return shader;
}

function createProgram(gl: WebGL2RenderingContext): WebGLProgram {
  let vertex: WebGLShader | null = null;
  let fragment: WebGLShader | null = null;
  let program: WebGLProgram | null = null;
  try {
    vertex = compileShader(
      gl,
      gl.VERTEX_SHADER,
      REFRACTIVE_GLASS_VERTEX_SHADER,
    );
    fragment = compileShader(
      gl,
      gl.FRAGMENT_SHADER,
      REFRACTIVE_GLASS_FRAGMENT_SHADER,
    );
    program = gl.createProgram();
    if (!program) {
      throw new RefractivePipelineError(
        "program-link",
        "WebGL2 could not allocate a program",
      );
    }
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      const message = sanitizeRefractiveDiagnostic(
        gl.getProgramInfoLog(program) ?? "unknown link error",
      );
      throw new RefractivePipelineError("program-link", message);
    }
    return program;
  } catch (error) {
    if (program) gl.deleteProgram(program);
    throw error;
  } finally {
    if (vertex) gl.deleteShader(vertex);
    if (fragment) gl.deleteShader(fragment);
  }
}

type RefractivePipeline = {
  program: WebGLProgram;
  vertexBuffer: WebGLBuffer;
  position: number;
  resolution: WebGLUniformLocation;
  time: WebGLUniformLocation;
  pointer: WebGLUniformLocation;
  proof: WebGLUniformLocation;
  rects: WebGLUniformLocation;
  kinds: WebGLUniformLocation;
};

type PipelineResult =
  | { pipeline: RefractivePipeline; failure: null }
  | { pipeline: null; failure: { reason: RefractiveFailureReason; detail: string } };

function createPipeline(gl: WebGL2RenderingContext): PipelineResult {
  let program: WebGLProgram | null = null;
  let vertexBuffer: WebGLBuffer | null = null;
  try {
    program = createProgram(gl);
    vertexBuffer = gl.createBuffer();
    if (!vertexBuffer) {
      throw new RefractivePipelineError(
        "pipeline-allocation",
        "WebGL2 could not allocate a vertex buffer",
      );
    }

    const pipeline: RefractivePipeline = {
      program,
      vertexBuffer,
      position: gl.getAttribLocation(program, "aPosition"),
      resolution: gl.getUniformLocation(program, "uResolution")!,
      time: gl.getUniformLocation(program, "uTime")!,
      pointer: gl.getUniformLocation(program, "uPointer")!,
      proof: gl.getUniformLocation(program, "uProof")!,
      rects: gl.getUniformLocation(program, "uRects[0]")!,
      kinds: gl.getUniformLocation(program, "uKinds[0]")!,
    };
    if (
      pipeline.position < 0 ||
      !pipeline.resolution ||
      !pipeline.time ||
      !pipeline.pointer ||
      !pipeline.proof ||
      !pipeline.rects ||
      !pipeline.kinds
    ) {
      throw new RefractivePipelineError(
        "uniform-missing",
        "shader attribute or uniform was optimized out",
      );
    }

    gl.bindBuffer(gl.ARRAY_BUFFER, pipeline.vertexBuffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]),
      gl.STATIC_DRAW,
    );
    gl.useProgram(pipeline.program);
    gl.enableVertexAttribArray(pipeline.position);
    gl.vertexAttribPointer(pipeline.position, 2, gl.FLOAT, false, 0, 0);
    gl.disable(gl.DEPTH_TEST);
    gl.disable(gl.BLEND);
    return { pipeline, failure: null };
  } catch (error) {
    if (vertexBuffer) gl.deleteBuffer(vertexBuffer);
    if (program) gl.deleteProgram(program);
    if (error instanceof RefractivePipelineError) {
      return {
        pipeline: null,
        failure: { reason: error.reason, detail: error.diagnostic },
      };
    }
    const detail = error instanceof Error ? error.message : String(error);
    return {
      pipeline: null,
      failure: {
        reason: "pipeline-allocation",
        detail: sanitizeRefractiveDiagnostic(detail),
      },
    };
  }
}

function clamp(value: number, low: number, high: number): number {
  return Math.min(high, Math.max(low, value));
}

function setRendererStatus(
  status: RendererStatus,
  proof = false,
  reason: RefractiveFallbackReason = "none",
  detail = "",
  mode: RefractiveGlassMode = DEFAULT_REFRACTIVE_GLASS_MODE,
): void {
  const root = document.documentElement;
  const fallback =
    status === "fallback" ||
    (status === "disabled" && mode !== "solid");
  root.classList.toggle("refractive-glass-enabled", status === "webgl2");
  root.classList.toggle("refractive-glass-fallback", fallback);
  root.classList.toggle(
    "refractive-glass-solid",
    status === "disabled" && mode === "solid",
  );
  root.classList.toggle("refractive-glass-proof", status === "webgl2" && proof);
  root.classList.toggle("refractive-glass-opt-in", mode === "refractive");
  root.dataset.refractiveGlass = status;
  root.dataset.refractiveGlassMode = mode;
  root.dataset.refractiveGlassReason = reason;
  if (detail) root.dataset.refractiveGlassDetail = detail;
  else delete root.dataset.refractiveGlassDetail;
}

function measurePlanes(width: number, height: number) {
  // Portaled GlassSurface elements live under document.body, not the app shell.
  // Keep the global query explicit and bounded; primary shell planes win when
  // more than the five-plane GPU budget is visible.
  const rects = new Float32Array(REFRACTIVE_GLASS_MAX_PLANES * 4);
  const kinds = new Float32Array(REFRACTIVE_GLASS_MAX_PLANES);
  const surfaces = Array.from(
    document.querySelectorAll<HTMLElement>("[data-glass-surface='true']"),
  ).sort((left, right) => {
    const primary = (surface: HTMLElement) =>
      surface.matches(".top-navigation, .composer, .voice-panel, .voice-rail")
        ? 1
        : 0;
    return primary(right) - primary(left);
  });
  let plane = 0;
  for (const surface of surfaces) {
    if (plane >= REFRACTIVE_GLASS_MAX_PLANES) break;
    const bounds = surface.getBoundingClientRect();
    if (
      bounds.width < 1 ||
      bounds.height < 1 ||
      bounds.right < 0 ||
      bounds.bottom < 0 ||
      bounds.left > width ||
      bounds.top > height
    ) {
      continue;
    }
    const left = clamp(bounds.left / width, 0, 1);
    const bottom = clamp((height - bounds.bottom) / height, 0, 1);
    rects[plane * 4] = left;
    rects[plane * 4 + 1] = bottom;
    rects[plane * 4 + 2] = clamp(bounds.width / width, 0, 1);
    rects[plane * 4 + 3] = clamp(bounds.height / height, 0, 1);
    kinds[plane] = surface.dataset.glassVariant === "clear" ? 1 : 0;
    plane += 1;
  }
  return { rects, kinds, count: plane };
}

/** A single bounded GPU plane for all registered shell surfaces. */
export function RefractiveBackdrop({
  mode,
}: {
  mode?: RefractiveGlassMode;
} = {}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const proofStatusRef = useRef<HTMLOutputElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const host = canvas?.parentElement;
    if (!canvas || !host) return undefined;

    const options = readRendererOptions(mode);
    document.documentElement.classList.toggle(
      "refractive-glass-proof-requested",
      options.proof,
    );
    document.documentElement.classList.toggle(
      "refractive-glass-proof-override",
      options.proofOverride,
    );
    const clearProofRequest = () => {
      document.documentElement.classList.remove("refractive-glass-proof-requested");
      document.documentElement.classList.remove("refractive-glass-proof-override");
    };
    let proofStatusKey = "";
    const updateProofStatus = (
      renderer: RendererStatus,
      planes: number,
      reason: RefractiveFallbackReason = renderer === "webgl2" ? "none" : "pipeline-allocation",
      detail = "",
    ) => {
      const output = proofStatusRef.current;
      if (!output || !options.proof) return;
      const nextKey = `${renderer}:${reason}:${planes}:${detail}`;
      if (nextKey === proofStatusKey) return;
      proofStatusKey = nextKey;
      output.dataset.renderer = renderer;
      output.dataset.reason = reason;
      output.dataset.planes = String(planes);
      if (detail) output.dataset.detail = detail;
      else delete output.dataset.detail;
      output.textContent = formatRefractiveProofStatus(renderer, reason, planes);
    };
    const setStatus = (
      status: RendererStatus,
      reason: RefractiveFallbackReason,
      detail = "",
    ) => {
      setRendererStatus(status, options.proof, reason, detail, options.mode);
      canvas.dataset.renderer = status;
      canvas.dataset.refractiveGlassReason = reason;
      if (detail) canvas.dataset.refractiveGlassDetail = detail;
      else delete canvas.dataset.refractiveGlassDetail;
    };
    const reducedTransparency = hasReducedTransparency();
    const forcedColors = hasForcedColors();
    // `?refractiveGlass=proof` is an explicit developer/QA override for the
    // transparency preference only. Forced-colors always wins for legibility.
    if (
      !options.enabled ||
      forcedColors ||
      (reducedTransparency && options.mode !== "refractive" && !options.proofOverride)
    ) {
      const reason: RefractiveFailureReason = forcedColors
        ? "forced-colors"
        : !options.enabled
          ? options.disabledReason ?? "explicit-off"
          : "reduced-transparency";
      const detail = reason === "reduced-transparency"
        ? "OS transparency disabled; use refractiveGlass=proof for QA"
        : "";
      const status: RendererStatus = options.enabled ? "fallback" : "disabled";
      updateProofStatus(status, 0, reason, detail);
      setStatus(status, reason, detail);
      return clearProofRequest;
    }

    const gl = canvas.getContext("webgl2", {
      alpha: true,
      antialias: false,
      depth: false,
      premultipliedAlpha: false,
      preserveDrawingBuffer: false,
    });
    if (!gl) {
      updateProofStatus("fallback", 0, "webgl2-unavailable", "getContext(webgl2) returned null");
      setStatus("fallback", "webgl2-unavailable", "getContext(webgl2) returned null");
      return clearProofRequest;
    }

    const initialResult = createPipeline(gl);
    if (!initialResult.pipeline) {
      updateProofStatus("fallback", 0, initialResult.failure.reason, initialResult.failure.detail);
      setStatus("fallback", initialResult.failure.reason, initialResult.failure.detail);
      return clearProofRequest;
    }
    let pipeline: RefractivePipeline = initialResult.pipeline;

    setStatus("webgl2", "none");
    updateProofStatus("webgl2", 0, "none");
    canvas.dataset.proof = options.proof ? "high-frequency-grid" : "ambient";

    let frame: number | null = null;
    let destroyed = false;
    let contextLost = false;
    let lastFrame = -Infinity;
    let width = 1;
    let height = 1;
    let dpr = 1;
    let pointerX = 0.5;
    let pointerY = 0.5;
    const reducedMotion = hasReducedMotion();

    const resize = () => {
      const bounds = host.getBoundingClientRect();
      width = Math.max(1, bounds.width || window.innerWidth);
      height = Math.max(1, bounds.height || window.innerHeight);
      dpr = Math.min(1.5, Math.max(1, window.devicePixelRatio || 1));
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      gl.viewport(0, 0, canvas.width, canvas.height);
    };

    const render = (now: number) => {
      if (destroyed || contextLost || document.visibilityState === "hidden") {
        frame = null;
        return;
      }
      // Idle motion is capped to 30fps; reduced-motion receives one static
      // frame and never schedules another animation callback.
      if (!reducedMotion && now - lastFrame < 33) {
        frame = window.requestAnimationFrame(render);
        return;
      }
      lastFrame = now;
      try {
        resize();
      } catch (error) {
        const detail = sanitizeRefractiveDiagnostic(
          error instanceof Error ? error.message : String(error),
        );
        updateProofStatus("fallback", 0, "plane-measurement", detail);
        setStatus("fallback", "plane-measurement", detail);
        frame = reducedMotion ? null : window.requestAnimationFrame(render);
        return;
      }
      let measured: ReturnType<typeof measurePlanes>;
      try {
        measured = measurePlanes(width, height);
      } catch (error) {
        const detail = sanitizeRefractiveDiagnostic(
          error instanceof Error ? error.message : String(error),
        );
        updateProofStatus("fallback", 0, "plane-measurement", detail);
        setStatus("fallback", "plane-measurement", detail);
        frame = reducedMotion ? null : window.requestAnimationFrame(render);
        return;
      }
      canvas.dataset.planes = String(measured.count);
      const renderer: RendererStatus = measured.count > 0 ? "webgl2" : "fallback";
      const reason: RefractiveFallbackReason = measured.count > 0
        ? "none"
        : "plane-measurement";
      const detail = measured.count > 0 ? "" : "no visible data-glass-surface planes";
      setStatus(renderer, reason, detail);
      updateProofStatus(renderer, measured.count, reason, detail);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.useProgram(pipeline.program);
      gl.uniform2f(pipeline.resolution, width, height);
      gl.uniform1f(pipeline.time, reducedMotion ? 0 : now / 1000);
      gl.uniform2f(pipeline.pointer, pointerX, pointerY);
      gl.uniform1f(pipeline.proof, options.proof ? 1 : 0);
      gl.uniform4fv(pipeline.rects, measured.rects);
      gl.uniform1fv(pipeline.kinds, measured.kinds);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      frame = reducedMotion ? null : window.requestAnimationFrame(render);
    };

    const schedule = () => {
      if (!contextLost && frame === null) frame = window.requestAnimationFrame(render);
    };
    const onPointerMove = (event: PointerEvent) => {
      pointerX = clamp(event.clientX / Math.max(1, width), 0, 1);
      pointerY = clamp(1 - event.clientY / Math.max(1, height), 0, 1);
      schedule();
    };
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") schedule();
    };
    const onScroll = () => schedule();
    const onContextLost = (event: Event) => {
      event.preventDefault();
      contextLost = true;
      if (frame !== null) {
        window.cancelAnimationFrame(frame);
        frame = null;
      }
      updateProofStatus("fallback", 0, "context-lost", "webglcontextlost event");
      setStatus("fallback", "context-lost", "webglcontextlost event");
    };
    const onContextRestored = () => {
      if (destroyed) return;
      const restoredResult = createPipeline(gl);
      if (!restoredResult.pipeline) {
        contextLost = true;
        updateProofStatus(
          "fallback",
          0,
          restoredResult.failure.reason,
          restoredResult.failure.detail,
        );
        setStatus(
          "fallback",
          restoredResult.failure.reason,
          restoredResult.failure.detail,
        );
        return;
      }
      pipeline = restoredResult.pipeline;
      contextLost = false;
      setStatus("webgl2", "none");
      updateProofStatus("webgl2", 0, "none");
      lastFrame = -Infinity;
      resize();
      schedule();
    };
    if (typeof ResizeObserver === "undefined") {
      gl.deleteBuffer(pipeline.vertexBuffer);
      gl.deleteProgram(pipeline.program);
      updateProofStatus(
        "fallback",
        0,
        "resize-observer-missing",
        "ResizeObserver is unavailable",
      );
      setStatus(
        "fallback",
        "resize-observer-missing",
        "ResizeObserver is unavailable",
      );
      return clearProofRequest;
    }
    const resizeObserver = new ResizeObserver(schedule);
    resizeObserver.observe(host);
    const onMutations = (records: MutationRecord[]) => {
      const containsGlassSurface = (node: Node) =>
        node instanceof Element &&
        (node.matches("[data-glass-surface='true']") ||
          Boolean(node.querySelector("[data-glass-surface='true']")));
      const relevant = records.some((record) => {
        if (record.type === "childList") {
          if (record.target === canvas || record.target === proofStatusRef.current) {
            return false;
          }
          if (
            record.target instanceof Element &&
            Boolean(record.target.closest("[data-glass-surface='true']"))
          ) {
            return true;
          }
          return (
            Array.from(record.addedNodes).some(containsGlassSurface) ||
            Array.from(record.removedNodes).some(containsGlassSurface)
          );
        }
        const target = record.target;
        return (
          target !== canvas &&
          target !== proofStatusRef.current &&
          target instanceof Element &&
          (record.attributeName === "data-glass-surface" ||
            Boolean(target.closest("[data-glass-surface='true']")))
        );
      });
      if (relevant) schedule();
    };
    const mutationObserver = new MutationObserver(onMutations);
    // Observe body so portal-mounted GlassSurface planes trigger a redraw too.
    // The callback filters out canvas self-mutations and unrelated DOM churn.
    mutationObserver.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: [
        "class",
        "data-glass-surface",
        "data-glass-variant",
        "hidden",
        "style",
      ],
    });
    window.addEventListener("resize", schedule, { passive: true });
    window.addEventListener("scroll", onScroll, { passive: true, capture: true });
    document.addEventListener("scroll", onScroll, { passive: true, capture: true });
    window.addEventListener("pointermove", onPointerMove, { passive: true });
    document.addEventListener("visibilitychange", onVisibilityChange);
    canvas.addEventListener("webglcontextlost", onContextLost, { passive: false });
    canvas.addEventListener("webglcontextrestored", onContextRestored);
    resize();
    schedule();

    return () => {
      destroyed = true;
      if (frame !== null) window.cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      mutationObserver.disconnect();
      window.removeEventListener("resize", schedule);
      window.removeEventListener("scroll", onScroll, true);
      document.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("pointermove", onPointerMove);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      canvas.removeEventListener("webglcontextlost", onContextLost);
      canvas.removeEventListener("webglcontextrestored", onContextRestored);
      gl.deleteBuffer(pipeline.vertexBuffer);
      gl.deleteProgram(pipeline.program);
      clearProofRequest();
      setStatus("disabled", "none");
    };
  }, [mode]);

  return (
    <>
      <canvas
        ref={canvasRef}
        className="refractive-backdrop"
        aria-hidden="true"
        data-renderer="pending"
      />
      <output
        ref={proofStatusRef}
        className="refractive-proof-status"
        aria-hidden="true"
        aria-live="off"
      />
    </>
  );
}
