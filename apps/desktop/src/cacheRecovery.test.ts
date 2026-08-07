import { describe, expect, it } from "vitest";
import {
  CACHE_RESET_CONFIRMATION,
  cacheResetConfirmed,
} from "./cacheRecovery";

describe("local cache reset confirmation", () => {
  it("requires the complete destructive-action phrase", () => {
    expect(cacheResetConfirmed("reset")).toBe(false);
    expect(cacheResetConfirmed("RESET LOCAL")).toBe(false);
    expect(cacheResetConfirmed(CACHE_RESET_CONFIRMATION)).toBe(true);
  });

  it("accepts harmless surrounding whitespace but remains case-sensitive", () => {
    expect(cacheResetConfirmed(`  ${CACHE_RESET_CONFIRMATION}\n`)).toBe(true);
    expect(cacheResetConfirmed("reset local cache")).toBe(false);
  });
});
