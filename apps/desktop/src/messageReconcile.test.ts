import { describe, expect, it } from "vitest";
import type { ChatMessage } from "./models";
import { reconcileMessageResult } from "./messageReconcile";

const message = (deliveryState: ChatMessage["deliveryState"]): ChatMessage => ({
  id: "server-1",
  clientKey: "client-1",
  channelId: "channel-1",
  authorId: "member-1",
  content: "hello",
  sentAt: "2026-01-01T00:00:00.000Z",
  edited: false,
  deliveryState,
  reactions: [],
});

describe("reconcileMessageResult", () => {
  it("keeps a sent realtime ack when a late invoke result is still pending", () => {
    const current = [message("sent")];
    const result = reconcileMessageResult(current, message("pending"));
    expect(result[0].deliveryState).toBe("sent");
  });

  it("does not downgrade an authoritative failure either", () => {
    const result = reconcileMessageResult([message("failed")], message("pending"));
    expect(result[0].deliveryState).toBe("failed");
  });

  it("accepts an authoritative sent result over a local pending message", () => {
    const result = reconcileMessageResult([message("pending")], message("sent"));
    expect(result[0].deliveryState).toBe("sent");
  });

  it("preserves a newer reaction snapshot when an invoke response is stale", () => {
    const current = {
      ...message("sent"),
      reactions: [{ emoji: "👍", count: 4, me: true }],
    };
    const stale = {
      ...message("sent"),
      reactions: [{ emoji: "👍", count: 3, me: true }],
    };
    const result = reconcileMessageResult([current], stale, {
      preserveReactions: true,
    });
    expect(result[0].reactions).toEqual(current.reactions);
  });

  it("keeps reactions when a partial command result omits them", () => {
    const current = {
      ...message("sent"),
      reactions: [{ emoji: "✨", count: 2, me: false }],
    };
    const result = reconcileMessageResult([current], {
      ...message("sent"),
      reactions: undefined,
    });
    expect(result[0].reactions).toEqual(current.reactions);
  });
});
