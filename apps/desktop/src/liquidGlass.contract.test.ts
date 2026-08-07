import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const defs = readFileSync(new URL("./LiquidGlass.tsx", import.meta.url), "utf8");
const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

describe("bounded Liquid Glass contract", () => {
  it("keeps stable hidden defs with low-amplitude bounded refraction", () => {
    expect(defs).toMatch(/aria-hidden=\"true\"/);
    expect(defs).toMatch(/focusable=\"false\"/);
    expect(defs).toMatch(/id=\{LIQUID_GLASS_REGULAR_FILTER_ID\}/);
    expect(defs).toMatch(/id=\{LIQUID_GLASS_CLEAR_FILTER_ID\}/);
    expect(defs).toMatch(/<feTurbulence/);
    expect(defs).toMatch(/<feDisplacementMap/);
    expect(defs).toMatch(/scale=\"6\"/);
    expect(defs).toMatch(/scale=\"8\"/);
    expect(defs).toMatch(/x=\"-14%\"[\s\S]*width=\"128%\"/);
    expect(defs).toMatch(/x=\"-16%\"[\s\S]*width=\"132%\"/);
    expect(defs).not.toMatch(/scale=\"(?:1[1-9]|[2-9]\d+)\"/);
  });

  it("applies one surface plane only to approved utility groups", () => {
    expect(app).toMatch(/<GlassSurface[\s\S]*className=\{`top-navigation/);
    expect(app).toMatch(/<GlassSurface[\s\S]*className=\"composer\"/);
    expect(app).toMatch(/<GlassSurface[\s\S]*className=\"voice-panel/);
    expect(app).toMatch(/<GlassSurface[\s\S]*variant=\"clear\"[\s\S]*attachment-lightbox-header/);
    expect(app).not.toMatch(/className=\"message-item[^\"]*glass-surface/);
    expect(styles).not.toMatch(/\.message-item[^{}]*backdrop-filter/);
    expect(styles).not.toMatch(/\.message-list[^{}]*backdrop-filter/);
    expect(styles).not.toMatch(/\.composer[^{}]*button[^{}]*backdrop-filter/);
  });

  it("feature-detects URL filters and keeps accessible fallbacks", () => {
    expect(styles).toMatch(/@supports \(backdrop-filter: url\(#exocord-liquid-glass-regular\)\)/);
    expect(styles).toMatch(/@supports \(-webkit-backdrop-filter: url\(#exocord-liquid-glass-regular\)\)/);
    expect(styles).toMatch(/@supports not \(backdrop-filter: url\(#exocord-liquid-glass-regular\)\)/);
    expect(styles).toMatch(/prefers-reduced-transparency:[\s\S]*\.glass-surface[\s\S]*backdrop-filter: none/);
    expect(styles).toMatch(/@media \(forced-colors: active\)[\s\S]*\.glass-surface[\s\S]*background: Canvas/);
  });

  it("anchors utility menus and keeps voice details out of the reading grid", () => {
    expect(styles).toMatch(
      /\.glass-surface\.chrome-popover,[\s\S]*?\.glass-surface\.member-popover\s*\{[\s\S]*?position:\s*absolute/,
    );
    expect(styles).toMatch(
      /\.app-content,[\s\S]*?\.app-content\.has-voice-dock[\s\S]*?grid-template-columns:\s*minmax\(0, 1fr\)/,
    );
    expect(app).toMatch(
      /const \[voiceCollapsed, setVoiceCollapsed\] = useState\(true\)/,
    );
    expect(app).toMatch(/className="voice-rail-summary"/);
  });

  it("keeps reduced-transparency and forced-colors overrides after shell tuning", () => {
    const tuningMarker = styles.lastIndexOf("/* Final shell tuning");
    const transparencyMarker = styles.lastIndexOf(
      "@media (prefers-reduced-transparency: reduce)",
    );
    const forcedColorsMarker = styles.lastIndexOf(
      "@media (forced-colors: active)",
    );
    expect(tuningMarker).toBeGreaterThan(-1);
    expect(transparencyMarker).toBeGreaterThan(tuningMarker);
    expect(forcedColorsMarker).toBeGreaterThan(transparencyMarker);
    const accessibilityTail = styles.slice(transparencyMarker);
    expect(accessibilityTail).toMatch(
      /\.glass-surface,[\s\S]*?background:\s*#171a1d !important;[\s\S]*?backdrop-filter:\s*none !important/,
    );
    expect(accessibilityTail).toMatch(
      /\.modal-backdrop,[\s\S]*?backdrop-filter:\s*none !important/,
    );
    expect(styles.slice(forcedColorsMarker)).toMatch(
      /\.glass-surface,[\s\S]*?background:\s*Canvas !important/,
    );
    expect(styles.slice(forcedColorsMarker)).toMatch(/\.modal-backdrop,/);
  });
});
