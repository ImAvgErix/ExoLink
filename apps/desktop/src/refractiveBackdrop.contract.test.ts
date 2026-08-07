import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_REFRACTIVE_GLASS_MODE,
  REFRACTIVE_GLASS_FRAGMENT_SHADER,
  REFRACTIVE_GLASS_MAX_PLANES,
  REFRACTIVE_GLASS_PROOF_QUERY,
  REFRACTIVE_GLASS_STORAGE_KEY,
  REFRACTIVE_GLASS_VERTEX_SHADER,
  formatRefractiveProofStatus,
  normalizeRefractiveGlassMode,
  readRefractiveGlassMode,
  sanitizeRefractiveDiagnostic,
} from "./RefractiveBackdrop";

const source = readFileSync(
  new URL("./RefractiveBackdrop.tsx", import.meta.url),
  "utf8",
);
const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
const glass = readFileSync(new URL("./LiquidGlass.tsx", import.meta.url), "utf8");
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

describe("WebGL2 refractive backdrop contract", () => {
  it("uses one bounded canvas and samples displaced ambient coordinates", () => {
    expect(REFRACTIVE_GLASS_MAX_PLANES).toBe(5);
    expect(source).toMatch(/className="refractive-backdrop"/);
    expect(source).toMatch(/getContext\("webgl2"/);
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/uniform vec4 uRects\[5\]/);
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/uniform float uKinds\[5\]/);
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/vec2 displaced = clamp\(vUv \+ bend/);
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/ambientBackdrop\(clamp\(displaced/);
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/dispersion/);
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/fresnel/);
    expect(REFRACTIVE_GLASS_VERTEX_SHADER).toMatch(/#version 300 es/);
  });

  it("keeps the sampling model explicit and gives QA a high-frequency proof mode", () => {
    expect(source).toMatch(/cannot safely expose[\s\S]*arbitrary DOM pixels/);
    expect(source).toMatch(/same procedural field is sampled at displaced coordinates/);
    expect(source).toMatch(/REFRACTIVE_GLASS_PROOF_QUERY/);
    expect(source).toMatch(/high-frequency-grid/);
    expect(REFRACTIVE_GLASS_PROOF_QUERY).toBe("refractiveGlass");
    expect(REFRACTIVE_GLASS_STORAGE_KEY).toBe("exocord.refractive-glass");
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/lineField/);
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/proofLineField/);
    expect(REFRACTIVE_GLASS_FRAGMENT_SHADER).toMatch(/72\.0, 42\.0/);
    expect(source).toMatch(/hasExplicitMode/);
    expect(source).toMatch(/hasExplicitMode \? query !== "0" : selectedMode !== "solid"/);
    expect(source).toMatch(/refractive-glass-proof-requested/);
    expect(source).toMatch(/refractive-proof-status/);
    expect(source).toMatch(/aria-hidden="true"/);
    expect(source).toMatch(/aria-live="off"/);
    expect(formatRefractiveProofStatus("fallback", "shader-compile", 0)).toBe(
      "FALLBACK:shader-compile · 0 PLANES",
    );
    expect(formatRefractiveProofStatus("webgl2", "none", 2)).toBe(
      "WEBGL2 · 2 PLANES",
    );
    expect(sanitizeRefractiveDiagnostic("ERROR: 0:4: bad\n<shader>"))
      .toBe("ERROR: 0:4: bad shader");
  });

  it("persists the three appearance modes without reviving the legacy opt-out", () => {
    expect(DEFAULT_REFRACTIVE_GLASS_MODE).toBe("system");
    expect(normalizeRefractiveGlassMode(null)).toBe("system");
    expect(normalizeRefractiveGlassMode("system")).toBe("system");
    expect(normalizeRefractiveGlassMode("refractive")).toBe("refractive");
    expect(normalizeRefractiveGlassMode("solid")).toBe("solid");
    expect(normalizeRefractiveGlassMode("0")).toBe("solid");
    expect(normalizeRefractiveGlassMode("unexpected")).toBe("system");
    expect(
      readRefractiveGlassMode({
        getItem: (key) => (key === REFRACTIVE_GLASS_STORAGE_KEY ? "0" : null),
      }),
    ).toBe("solid");
    expect(app).toMatch(/readRefractiveGlassMode\(\)/);
    expect(app).toMatch(/REFRACTIVE_GLASS_STORAGE_KEY/);
    expect(app).toMatch(/localStorage\.setItem\([\s\S]*refractiveGlassMode/);
  });

  it("applies mode changes live while preserving forced-colors and proof precedence", () => {
    expect(source).toMatch(/mode\?: RefractiveGlassMode/);
    expect(source).toMatch(/readRendererOptions\(mode\)/);
    expect(source).toMatch(/\}, \[mode\]\);/);
    expect(source).toMatch(/forcedColors/);
    expect(source).toMatch(/options\.mode !== "refractive"/);
    expect(source).toMatch(/query === "proof"/);
    expect(source).toMatch(/proofOverride/);
    expect(source).toMatch(/refractive-glass-opt-in/);
    expect(source).toMatch(/status === "disabled" && mode !== "solid"/);
    expect(styles).toMatch(/refractive-glass-solid \.refractive-backdrop/);
    expect(styles).toMatch(/refractive-glass-solid \.top-navigation[\s\S]*backdrop-filter: none !important/);
    expect(styles).toMatch(
      /@media not \(forced-colors: active\)[\s\S]*refractive-glass-opt-in\.refractive-glass-enabled[\s\S]*backdrop-filter: none !important/,
    );
    expect(
      styles.lastIndexOf("refractive-glass-opt-in.refractive-glass-enabled"),
    ).toBeGreaterThan(styles.lastIndexOf("@media (prefers-reduced-transparency: reduce)"));
  });

  it("propagates precise fallback reasons and sanitized diagnostics", () => {
    expect(source).toMatch(/reduced-transparency/);
    expect(source).toMatch(/forced-colors/);
    expect(source).toMatch(/webgl2-unavailable/);
    expect(source).toMatch(/shader-compile/);
    expect(source).toMatch(/program-link/);
    expect(source).toMatch(/uniform-missing/);
    expect(source).toMatch(/resize-observer-missing/);
    expect(source).toMatch(/plane-measurement/);
    expect(source).toMatch(/context-lost/);
    expect(source).toMatch(/refractiveGlassReason/);
    expect(source).toMatch(/dataset\.reason = reason/);
    expect(source).toMatch(/sanitizeRefractiveDiagnostic/);
    expect(source).toMatch(/proofOverride/);
    expect(source).toMatch(/refractiveGlass=proof for QA/);
  });

  it("registers semantic DOM planes while keeping blur fallback-only", () => {
    expect(glass).toMatch(/data-glass-surface/);
    expect(glass).toMatch(/data-glass-variant/);
    expect(styles).toMatch(/\.refractive-glass-fallback \.top-navigation/);
    expect(styles).toMatch(/\.refractive-glass-enabled \.glass-surface/);
    expect(styles).toMatch(/\.refractive-glass-fallback \.glass-surface-regular/);
    expect(styles).toMatch(/\.refractive-backdrop[\s\S]*pointer-events: none/);
    expect(styles).toMatch(/\.refractive-proof-status/);
    expect(styles).toMatch(/refractive-glass-proof-override[\s\S]*background: rgba\(17, 23, 32, 0\.08\) !important/);
    expect(styles.indexOf("refractive-glass-proof-override")).toBeGreaterThan(
      styles.lastIndexOf("@media (prefers-reduced-transparency: reduce)"),
    );
    expect(styles).toMatch(/@media not \(forced-colors: active\)/);
  });

  it("recovers from a WebGL context reset without leaving stale enabled state", () => {
    expect(source).toMatch(/webglcontextlost/);
    expect(source).toMatch(/event\.preventDefault\(\)/);
    expect(source).toMatch(/cancelAnimationFrame\(frame\)/);
    expect(source).toMatch(/setStatus\("fallback", "context-lost"/);
    expect(source).toMatch(/webglcontextrestored/);
    expect(source).toMatch(/const restoredResult = createPipeline\(gl\)/);
    expect(source).toMatch(/pipeline = restoredResult\.pipeline/);
    expect(source).toMatch(/setStatus\("webgl2", "none"/);
    expect(source).toMatch(/canvas\.removeEventListener\("webglcontextlost"/);
  });

  it("does not let canvas self-mutations keep scheduling the renderer", () => {
    expect(source).toMatch(/const onMutations = \(records: MutationRecord\[\]\)/);
    expect(source).toMatch(/target !== canvas/);
    expect(source).toMatch(/target === proofStatusRef\.current/);
    expect(source).toMatch(/containsGlassSurface/);
    expect(source).toMatch(/addedNodes/);
    expect(source).toMatch(/removedNodes/);
    expect(source).toMatch(/attributeFilter: \[/);
    expect(source).toMatch(/"data-glass-surface"/);
    expect(source).toMatch(/"data-glass-variant"/);
    expect(source).toMatch(/mutationObserver = new MutationObserver\(onMutations\)/);
    expect(source).toMatch(/mutationObserver\.observe\(document\.body/);
    expect(source).toMatch(/document\.querySelectorAll<HTMLElement>\("\[data-glass-surface='true'\]"\)/);
    expect(source).toMatch(/addEventListener\("scroll", onScroll, \{ passive: true, capture: true \}\)/);
    expect(source).toMatch(/removeEventListener\("scroll", onScroll, true\)/);
  });
});
