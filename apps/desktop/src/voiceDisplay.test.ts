import { describe, expect, it } from "vitest";
import { isUnsafeVoiceLabel, resolveVoiceDisplayName } from "./voiceDisplay";

describe("resolveVoiceDisplayName", () => {
  it("prefers the member's display name over transport labels", () => {
    expect(
      resolveVoiceDisplayName(
        { memberId: "u-1", displayName: "morgan" },
        { name: "Morgan Lee", handle: "morgan" },
      ),
    ).toBe("Morgan Lee");
  });

  it("rejects member ids and handles", () => {
    expect(resolveVoiceDisplayName({ memberId: "user_42", displayName: "user_42" })).toBe("Member");
    expect(
      resolveVoiceDisplayName(
        { memberId: "u-42", displayName: "riley" },
        { name: "", handle: "riley" },
      ),
    ).toBe("Member");
  });

  it("accepts a safe participant display name when no member is loaded", () => {
    expect(
      resolveVoiceDisplayName({ memberId: "opaque-id", displayName: "Riley" }),
    ).toBe("Riley");
  });

  it("does not expose lowercase handles or the local marker", () => {
    expect(
      resolveVoiceDisplayName({ memberId: "opaque-id", displayName: "riley" }),
    ).toBe("Member");
    expect(
      resolveVoiceDisplayName({ memberId: "opaque-id", displayName: "you" }),
    ).toBe("Member");
  });
});

describe("isUnsafeVoiceLabel", () => {
  it("recognizes empty and id-like labels", () => {
    expect(isUnsafeVoiceLabel("", "user-1")).toBe(true);
    expect(isUnsafeVoiceLabel("7f4a2b0c", "user-1")).toBe(true);
    expect(isUnsafeVoiceLabel("friendly name", "user-1")).toBe(false);
  });
});
