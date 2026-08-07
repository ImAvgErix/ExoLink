import { describe, expect, it } from "vitest";
import { applyCoreDelta } from "./coreDelta";
import { mockBootstrap } from "./mockData";
import type { BootstrapViewModel, ChatMessage, CoreDelta } from "./models";

function model(): BootstrapViewModel {
  return structuredClone(mockBootstrap);
}

function message(index: number): ChatMessage {
  return {
    id: String(index),
    clientKey: `message-${index}`,
    channelId: "gateway",
    authorId: "marin",
    content: `message ${index}`,
    sentAt: "13:00",
  };
}

describe("native core deltas", () => {
  it("upserts by stable client key and advances the revision", () => {
    const current = model();
    current.messages = [message(1)];
    const replacement = { ...message(2), clientKey: "message-1" };
    const next = applyCoreDelta(current, {
      version: 1,
      revision: 7,
      type: "message_upsert",
      message: replacement,
    });
    expect(next.revision).toBe(7);
    expect(next.messages).toEqual([replacement]);
  });

  it("collapses a gateway echo when the HTTP acknowledgement keeps the optimistic key", () => {
    const current = model();
    current.pendingOutbox = 1;
    current.messages = [
      {
        ...message(1),
        id: "temporary",
        clientKey: "stable-nonce",
        deliveryState: "pending",
      },
      {
        ...message(2),
        id: "server-id",
        clientKey: "server-id",
      },
    ];
    const acknowledged = {
      ...message(3),
      id: "server-id",
      clientKey: "stable-nonce",
      deliveryState: "sent" as const,
    };
    const next = applyCoreDelta(current, {
      version: 1,
      revision: 1,
      type: "message_upsert",
      message: acknowledged,
    });
    expect(next.messages).toEqual([acknowledged]);
    expect(next.pendingOutbox).toBe(0);
  });

  it("does not downgrade an acknowledged message when a pending DTO arrives late", () => {
    const current = model();
    current.messages = [{ ...message(1), deliveryState: "sent" }];
    const next = applyCoreDelta(current, {
      version: 1,
      revision: 2,
      type: "message_upsert",
      message: { ...message(1), deliveryState: "pending" },
    });
    expect(next.messages[0]?.deliveryState).toBe("sent");
  });

  it("keeps only the newest one hundred messages per channel", () => {
    const current = model();
    current.messages = Array.from({ length: 100 }, (_, index) =>
      message(index),
    );
    const next = applyCoreDelta(current, {
      version: 1,
      revision: 1,
      type: "message_upsert",
      message: message(100),
    });
    expect(next.messages).toHaveLength(100);
    expect(next.messages[0]?.id).toBe("1");
    expect(next.messages.at(-1)?.id).toBe("100");
  });

  it("removes a deleted message without disturbing another channel", () => {
    const current = model();
    current.messages = [
      message(1),
      { ...message(2), channelId: "other-channel" },
    ];
    const next = applyCoreDelta(current, {
      version: 1,
      revision: 4,
      type: "message_delete",
      messageId: "1",
      channelId: "gateway",
    });
    expect(next.revision).toBe(4);
    expect(next.messages).toEqual([
      { ...message(2), channelId: "other-channel" },
    ]);
  });

  it("applies a ten-thousand-message burst without growing the render window", () => {
    let current = model();
    current.messages = [];
    for (let index = 1; index <= 10_000; index += 1) {
      current = applyCoreDelta(current, {
        version: 1,
        revision: index,
        type: "message_upsert",
        message: message(index),
      });
    }
    expect(current.revision).toBe(10_000);
    expect(current.messages).toHaveLength(100);
    expect(current.messages[0]?.id).toBe("9901");
  });

  it("updates presence, typing, and DM unread state without rebuilding peers", () => {
    let current = model();
    const untouchedWorkspace = current.workspaces.find(
      (workspace) => !workspace.directMessages,
    );
    const deltas: CoreDelta[] = [
      {
        version: 1,
        revision: 1,
        type: "presence",
        userId: "marin",
        presence: "offline",
      },
      {
        version: 1,
        revision: 2,
        type: "typing_upsert",
        typing: {
          channelId: "gateway",
          userId: "marin",
          expiresAt: "2026-07-29T13:00:08Z",
        },
      },
      {
        version: 1,
        revision: 3,
        type: "read_state",
        directUnread: {
          channelId: "dm-marin",
          unread: false,
          unreadCount: 0,
        },
      },
    ];
    for (const delta of deltas) current = applyCoreDelta(current, delta);
    expect(
      current.members.find((member) => member.id === "marin")?.presence,
    ).toBe("offline");
    expect(current.typing).toContainEqual({
      channelId: "gateway",
      userId: "marin",
      expiresAt: "2026-07-29T13:00:08Z",
    });
    expect(
      current.workspaces.find((workspace) => !workspace.directMessages),
    ).toBe(untouchedWorkspace);
  });
});
