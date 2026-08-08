import { describe, expect, it } from "vitest";
import {
  PUSH_TO_TALK_STORAGE_KEY,
  isTextEntryTarget,
  readPushToTalkEnabled,
  reducePushToTalk,
  writePushToTalkEnabled,
} from "./pushToTalk";

/** Minimal Element stand-in so tests do not need a full DOM environment. */
function fakeElement(
  tag: string,
  opts: { contentEditable?: boolean; role?: string } = {},
): EventTarget {
  return {
    tagName: tag,
    isContentEditable: opts.contentEditable === true,
    getAttribute: (name: string) =>
      name === "role" ? (opts.role ?? null) : null,
    closest: () => null,
  } as unknown as EventTarget;
}

describe("isTextEntryTarget", () => {
  it("treats inputs, textareas, and contenteditable as text entry", () => {
    expect(isTextEntryTarget(fakeElement("INPUT"))).toBe(true);
    expect(isTextEntryTarget(fakeElement("TEXTAREA"))).toBe(true);
    expect(isTextEntryTarget(fakeElement("DIV", { contentEditable: true }))).toBe(
      true,
    );
    expect(isTextEntryTarget(fakeElement("DIV"))).toBe(false);
    expect(isTextEntryTarget(null)).toBe(false);
  });
});

describe("reducePushToTalk", () => {
  const base = {
    enabled: true,
    holding: false,
    voiceConnected: true,
    deafened: false,
  };
  const body = fakeElement("DIV");

  it("starts force-muted when the preference is enabled", () => {
    const next = reducePushToTalk(
      { ...base, enabled: false },
      { type: "preference", enabled: true },
    );
    expect(next).toEqual({
      enabled: true,
      holding: false,
      decision: { action: "force_mute" },
    });
  });

  it("holds on Space outside text fields and releases on keyup", () => {
    const hold = reducePushToTalk(base, {
      type: "keydown",
      key: " ",
      target: body,
    });
    expect(hold.decision).toEqual({ action: "hold" });
    expect(hold.holding).toBe(true);

    const release = reducePushToTalk(
      { ...base, holding: true },
      { type: "keyup", key: " ", target: body },
    );
    expect(release.decision).toEqual({ action: "release" });
    expect(release.holding).toBe(false);
  });

  it("ignores Space while typing in a text field", () => {
    const next = reducePushToTalk(base, {
      type: "keydown",
      key: " ",
      target: fakeElement("INPUT"),
    });
    expect(next.decision).toEqual({ action: "none" });
    expect(next.holding).toBe(false);
  });

  it("fails closed on blur, leave, and deafen while holding", () => {
    const holding = { ...base, holding: true };
    expect(reducePushToTalk(holding, { type: "blur" }).decision).toEqual({
      action: "force_mute",
    });
    expect(reducePushToTalk(holding, { type: "leave" }).decision).toEqual({
      action: "force_mute",
    });
    expect(
      reducePushToTalk(holding, { type: "deafen", deafened: true }).decision,
    ).toEqual({ action: "force_mute" });
  });

  it("does nothing when disabled or voice is idle", () => {
    expect(
      reducePushToTalk(
        { ...base, enabled: false },
        { type: "keydown", key: " ", target: body },
      ).decision,
    ).toEqual({ action: "none" });
    expect(
      reducePushToTalk(
        { ...base, voiceConnected: false },
        { type: "keydown", key: " ", target: body },
      ).decision,
    ).toEqual({ action: "none" });
  });
});

describe("push-to-talk preference storage", () => {
  it("uses the shipped storage key and pure enable→force_mute path", () => {
    expect(PUSH_TO_TALK_STORAGE_KEY).toBe("exocord.push-to-talk");
    // Storage helpers are guarded for non-window environments.
    expect(readPushToTalkEnabled()).toBe(false);
    writePushToTalkEnabled(true);
    expect(readPushToTalkEnabled()).toBe(false);
  });
});
