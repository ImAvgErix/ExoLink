import { describe, expect, it } from "vitest";
import { coreBridge } from "./coreBridge";

describe("web fallback bridge", () => {
  it("returns a fresh bootstrap snapshot", async () => {
    const first = await coreBridge.bootstrap();
    const second = await coreBridge.bootstrap();
    first.workspaces[0].name = "changed";
    expect(
      second.workspaces.find((workspace) => workspace.id === "halcyon")?.name,
    ).toBe("Halcyon");
    expect(second.workspaces[0].directMessages).toBe(true);
  });

  it("keeps preview context across refreshed relationship snapshots", async () => {
    await coreBridge.setActiveContext({
      workspaceId: "0",
      channelId: "dm-marin",
      voiceRoomId: null,
    });
    const refreshed = await coreBridge.bootstrap();
    expect(refreshed.activeWorkspaceId).toBe("0");
    expect(refreshed.activeChannelId).toBe("dm-marin");
    await coreBridge.setActiveContext({
      workspaceId: "halcyon",
      channelId: "gateway",
      voiceRoomId: "deploy-room",
    });
  });

  it("creates a server with a general channel", async () => {
    const workspace = await coreBridge.createWorkspace({ name: "Night Shift" });
    expect(workspace.initials).toBe("NI");
    expect(workspace.ownerId).toBe("erix");
    expect(workspace.channels[0].name).toBe("general");
  });

  it("previews invite links before joining", async () => {
    const preview = await coreBridge.previewServerInvite(
      "https://example.test/invite/demo-invite-code",
    );
    expect(preview.code).toBe("demo-invite-code");
    expect(preview.memberCount).toBeGreaterThan(0);
    const joined = await coreBridge.acceptServerInvite(preview.code);
    expect(joined.name).toBe(preview.name);
    expect(joined.channels[0].name).toBe("general");
  });

  it("signs out and clears the web preview session", async () => {
    await expect(coreBridge.logout()).resolves.toMatchObject({
      signedIn: false,
      email: null,
    });
  });

  it("creates, edits, assigns, and deletes a server role", async () => {
    const workspaceId = "role-test-workspace";
    const initial = await coreBridge.loadServerRoles(workspaceId);
    const member = initial.members[0];
    const created = await coreBridge.createServerRole({
      workspaceId,
      name: "Builder",
      color: "#69d7bd",
      permissionKeys: ["manage_channels", "view_channel"],
    });
    expect(created.permissionKeys).toContain("manage_channels");
    const updated = await coreBridge.updateServerRole({
      workspaceId,
      roleId: created.id,
      name: "Lead builder",
      color: "#3ecf8e",
      permissionKeys: ["manage_channels", "manage_roles", "view_channel"],
    });
    expect(updated.name).toBe("Lead builder");
    await coreBridge.setServerMemberRole(
      workspaceId,
      member.id,
      created.id,
      true,
    );
    expect(
      (await coreBridge.loadServerRoles(workspaceId)).members[0].roleIds,
    ).toContain(created.id);
    await coreBridge.deleteServerRole(workspaceId, created.id);
    expect(
      (await coreBridge.loadServerRoles(workspaceId)).roles.some(
        (role) => role.id === created.id,
      ),
    ).toBe(false);
  });

  it("creates, updates, audits, and deletes a safety rule", async () => {
    const workspaceId = "safety-test-workspace";
    const created = await coreBridge.createAutomodRule({
      workspaceId,
      name: "No leaked keys",
      enabled: true,
      triggerType: "keyword",
      terms: ["private-key"],
      action: "block",
      explanation: "Credentials must remain private.",
    });
    expect(created.enabled).toBe(true);
    const updated = await coreBridge.updateAutomodRule({
      workspaceId,
      ruleId: created.id,
      name: "No leaked credentials",
      enabled: false,
      triggerType: "keyword",
      terms: ["private-key", "recovery phrase"],
      action: "timeout",
      durationSeconds: 3600,
      explanation: "Credentials must remain private.",
    });
    expect(updated.action).toBe("timeout");
    expect(updated.enabled).toBe(false);
    const manager = await coreBridge.loadServerModeration(workspaceId);
    expect(manager.rules).toHaveLength(1);
    expect(manager.audit.map((entry) => entry.actionType)).toEqual(
      expect.arrayContaining([50, 51]),
    );
    await coreBridge.deleteAutomodRule(workspaceId, created.id);
    expect(
      (await coreBridge.loadServerModeration(workspaceId)).rules,
    ).toHaveLength(0);
  });

  it("manages exact-handle friends, direct messages, and blocks", async () => {
    const requested = await coreBridge.requestFriend("@otto");
    expect(
      requested.relationships.find(
        (relationship) => relationship.userId === "otto",
      )?.kind,
    ).toBe("outgoing");
    await coreBridge.removeRelationship("otto");

    const accepted = await coreBridge.acceptFriend("ines");
    expect(
      accepted.relationships.find(
        (relationship) => relationship.userId === "ines",
      )?.kind,
    ).toBe("friend");
    const opened = await coreBridge.openDirectMessage("ines");
    expect(opened.activeWorkspaceId).toBe("0");
    expect(
      opened.workspaces
        .find((workspace) => workspace.directMessages)
        ?.channels.some((channel) => channel.name === "Ines"),
    ).toBe(true);

    const blocked = await coreBridge.blockUser("ines");
    expect(
      blocked.relationships.find(
        (relationship) => relationship.userId === "ines",
      )?.kind,
    ).toBe("blocked");
    expect(
      blocked.workspaces
        .find((workspace) => workspace.directMessages)
        ?.channels.some((channel) => channel.name === "Ines"),
    ).toBe(true);
    const unblocked = await coreBridge.removeRelationship("ines");
    expect(
      unblocked.relationships.some(
        (relationship) => relationship.userId === "ines",
      ),
    ).toBe(false);
  });
});
