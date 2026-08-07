import { describe, expect, it } from "vitest";
import { EMOJI_CATALOG, searchEmojiCatalog } from "./emojiCatalog";

describe("emoji catalog", () => {
  it("contains a broad local catalogue", () => {
    const count = EMOJI_CATALOG.reduce((total, [, entries]) => total + entries.length, 0);
    expect(EMOJI_CATALOG.length).toBeGreaterThanOrEqual(8);
    expect(count).toBeGreaterThan(200);
  });

  it("searches names and preserves category grouping", () => {
    expect(searchEmojiCatalog("pizza")).toEqual([
      ["Food", [["🍕", "pizza"]]],
    ]);
    expect(searchEmojiCatalog("  ")).toBe(EMOJI_CATALOG);
  });
});

