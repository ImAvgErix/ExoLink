import { describe, expect, it } from "vitest";
import { mockBootstrap } from "./mockData";
import {
  NotificationDeduper,
  notificationIntent,
} from "./notificationPolicy";
import type {
  BootstrapViewModel,
  CoreDelta,
  NotificationMode,
} from "./models";

function model(): BootstrapViewModel {
  return structuredClone(mockBootstrap);
}

function incoming(
  overrides: Partial<Extract<CoreDelta, { type: "message_upsert" }>> = {},
): Extract<CoreDelta, { type: "message_upsert" }> {
  return {
    version: 1,
    revision: 1,
    type: "message_upsert",
    notify: true,
    message: {
      id: "incoming-1",
      channelId: "gateway",
      authorId: "marin",
      content: "This content must never reach Windows.",
      sentAt: "14:30",
      deliveryState: "sent",
    },
    ...overrides,
  };
}

function decide(
  mode: NotificationMode,
  delta = incoming(),
  windowFocused = false,
) {
  return notificationIntent({
    delta,
    mode,
    model: model(),
    windowFocused,
  });
}

describe("privacy-safe Windows notification policy", () => {
  it("uses content-free copy by default", () => {
    const intent = decide("private");
    expect(intent).toEqual({
      title: "New Exocord message",
      body: "Open Exocord to view it.",
    });
    expect(JSON.stringify(intent)).not.toContain("must never reach");
  });

  it("suppresses alerts while the Exocord window is focused", () => {
    expect(decide("private", incoming(), true)).toBeNull();
  });

  it("suppresses disabled, local, pending, edited, and reaction deltas", () => {
    expect(decide("off")).toBeNull();
    expect(
      decide(
        "private",
        incoming({
          message: {
            ...incoming().message,
            authorId: mockBootstrap.currentUserId,
          },
        }),
      ),
    ).toBeNull();
    expect(
      decide(
        "private",
        incoming({
          message: { ...incoming().message, deliveryState: "pending" },
        }),
      ),
    ).toBeNull();
    expect(decide("private", { ...incoming(), notify: undefined })).toBeNull();
  });

  it("shows names and conversation context only after explicit opt-in", () => {
    const channel = decide("names");
    expect(channel).toEqual({
      title: "New message from Marin",
      body: "gateway · Halcyon",
    });
    const direct = decide(
      "names",
      incoming({
        message: {
          ...incoming().message,
          id: "incoming-dm",
          channelId: "dm-marin",
        },
      }),
    );
    expect(direct).toEqual({
      title: "New message from Marin",
      body: "Direct message",
    });
  });

  it("removes control characters and bounds user-controlled labels", () => {
    const current = model();
    current.members.find((member) => member.id === "marin")!.name =
      `Marin\n${"x".repeat(100)}`;
    const intent = notificationIntent({
      delta: incoming(),
      mode: "names",
      model: current,
      windowFocused: false,
    });
    expect(intent?.title).not.toContain("\n");
    expect([...(intent?.title ?? "")].length).toBeLessThanOrEqual(
      "New message from ".length + 64,
    );
  });

  it("deduplicates resumed gateway events with bounded memory", () => {
    const deduper = new NotificationDeduper(2);
    expect(deduper.accept("one")).toBe(true);
    expect(deduper.accept("one")).toBe(false);
    expect(deduper.accept("two")).toBe(true);
    expect(deduper.accept("three")).toBe(true);
    expect(deduper.accept("one")).toBe(true);
  });
});
