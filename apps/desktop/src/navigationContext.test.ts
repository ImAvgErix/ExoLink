import { describe, expect, it } from "vitest";
import type { BootstrapViewModel } from "./models";
import {
  preferredNavigationContext,
  resolveNavigationContext,
} from "./navigationContext";

function model(): BootstrapViewModel {
  return {
    revision: 1,
    currentUserId: "me",
    activeWorkspaceId: "messages",
    activeChannelId: "dm-coltrigga",
    activeVoiceRoomId: null,
    connectionState: "connected",
    pendingOutbox: 0,
    workspaces: [
      {
        id: "messages",
        name: "Messages",
        initials: "@",
        accent: "#3ecf8e",
        directMessages: true,
        localOnly: false,
        channels: [
          { id: "dm-coltrigga", name: "Coltrigga", kind: "text", unread: false },
        ],
        voiceRooms: [],
        memberIds: [],
        ownerId: "me",
        permissionKeys: [],
        unreadCount: 0,
      },
      {
        id: "aura",
        name: "Aura",
        initials: "AU",
        accent: "#69d7bd",
        directMessages: false,
        localOnly: false,
        channels: [
          { id: "general", name: "general", kind: "text", unread: false },
        ],
        voiceRooms: [],
        memberIds: [],
        ownerId: "me",
        permissionKeys: [],
        unreadCount: 0,
      },
    ],
    members: [],
    relationships: [],
    typing: [],
    messages: [],
    cacheProtection: {
      encrypted: true,
      cipher: "SQLCipher",
      keyStorage: "Operating-system credential vault",
    },
    cacheRecovery: null,
  };
}

describe("navigation context", () => {
  it("uses the model's active conversation for the initial renderer target", () => {
    expect(preferredNavigationContext(model())).toEqual({
      workspaceId: "messages",
      channelId: "dm-coltrigga",
    });
  });

  it("keeps DM home selected when a later snapshot reports the previous DM", () => {
    const selectedHome = { workspaceId: "messages", channelId: "" };
    const nextSnapshot = {
      ...model(),
      revision: 2,
      activeWorkspaceId: "messages",
      activeChannelId: "dm-coltrigga",
    };

    expect(resolveNavigationContext(nextSnapshot, selectedHome)).toEqual(
      selectedHome,
    );
  });

  it("falls back when an explicit conversation no longer exists", () => {
    const nextSnapshot = {
      ...model(),
      workspaces: model().workspaces.map((workspace) =>
        workspace.id === "messages"
          ? { ...workspace, channels: [] }
          : workspace,
      ),
      activeWorkspaceId: "aura",
      activeChannelId: "general",
    };

    expect(
      resolveNavigationContext(nextSnapshot, {
        workspaceId: "messages",
        channelId: "dm-coltrigga",
      }),
    ).toEqual({ workspaceId: "aura", channelId: "general" });
  });
});
