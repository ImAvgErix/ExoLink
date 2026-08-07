import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

describe("canonical shell CSS contract", () => {
  it("keeps the shell full width with one floating navigation plane", () => {
    expect(styles).toMatch(
      /\.app-shell\s*\{[\s\S]*grid-template-columns:\s*minmax\(0,\s*1fr\);[\s\S]*grid-template-areas:\s*"header"\s*"content";/,
    );
    expect(styles).toMatch(/\.top-navigation\s*\{[\s\S]*border-radius:\s*16px;/);
    expect(styles).not.toMatch(/workspace-rail|rail-collapsed|workspace-rail-width/);
    expect(styles).toMatch(/\.presence\.presence-online::after\s*\{/);
    expect(styles).not.toMatch(/^\s*\.presence-online::after\s*\{/m);
    expect(styles).toMatch(
      /\.presence,\s*\.profile-presence-dot,\s*\.member-profile-presence i\s*\{[\s\S]*pointer-events:\s*none;/,
    );
    expect(styles).toMatch(/@supports \(backdrop-filter:\s*blur\(1px\)\)/);
    expect(styles).toMatch(/@supports not \(backdrop-filter:\s*blur\(1px\)\)/);
    expect(styles).toMatch(/@media \(prefers-reduced-transparency:\s*reduce\)/);
    expect(styles).toMatch(
      /prefers-reduced-transparency:[\s\S]*backdrop-filter:\s*none;/,
    );
  });

  it("keeps reduced motion after the compact interaction layer", () => {
    const interactionMarker = styles.lastIndexOf(
      "/* Shared icon control affordances",
    );
    const motionMarker = styles.lastIndexOf(
      "/* This must remain the final motion rule",
    );
    expect(interactionMarker).toBeGreaterThan(-1);
    expect(motionMarker).toBeGreaterThan(interactionMarker);
    const motionTail = styles.slice(motionMarker);
    expect(motionTail).toMatch(
      /\.top-navigation,[\s\S]*?\.channel-tab,[\s\S]*?\.window-control,[\s\S]*?\.composer,[\s\S]*?\.voice-panel,[\s\S]*?\.attachment-lightbox,[\s\S]*?transition:\s*none !important;/,
    );
    expect(motionTail).toMatch(
      /\.message-actions button,[\s\S]*?\.composer > button,[\s\S]*?\.voice-controls button,[\s\S]*?transition:\s*none !important;/,
    );
  });
});
