import { describe, expect, it } from "vitest";
import { coreBridge } from "./coreBridge";
import type { MessageAttachment } from "./models";

describe("attachment and search bridge contracts", () => {
  it("keeps completed attachment metadata on the optimistic message", async () => {
    const attachment: MessageAttachment = {
      id: "attachment-1",
      filename: "profile.png",
      contentType: "image/png",
      size: 128,
      url: "blob:test",
      width: 1,
      height: 1,
      animated: false,
    };
    const message = await coreBridge.sendMessage({
      channelId: "gateway",
      content: "",
      attachments: [attachment],
    });
    expect(message.attachments).toEqual([attachment]);
    expect(message.deliveryState).toBe("sent");
  });

  it("scopes preview search to the selected server and channel set", async () => {
    const result = await coreBridge.searchMessages({
      workspaceId: "halcyon",
      query: "socket leak",
    });
    expect(result.hits.length).toBeGreaterThan(0);
    expect(result.hits.every((hit) => hit.workspaceId === "halcyon")).toBe(true);
    expect(result.hits[0]?.message.content).toContain("socket leak");
  });
});
