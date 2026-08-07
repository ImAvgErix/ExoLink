import type { BootstrapViewModel } from "./models";

/** The renderer-owned conversation target. An empty channel is the DM home. */
export interface NavigationContext {
  workspaceId: string;
  channelId: string;
}

/**
 * Pick the initial target from the core snapshot. This is only used before a
 * user has made a navigation choice in the current renderer session.
 */
export function preferredNavigationContext(
  model: BootstrapViewModel,
): NavigationContext {
  const active = model.workspaces.find(
    (workspace) => workspace.id === model.activeWorkspaceId,
  );
  if (active && !active.localOnly) {
    return {
      workspaceId: active.id,
      channelId: active.channels.some(
        (channel) => channel.id === model.activeChannelId,
      )
        ? model.activeChannelId
        : active.directMessages
          ? ""
          : (active.channels[0]?.id ?? ""),
    };
  }

  const messages = model.workspaces.find(
    (workspace) => workspace.directMessages && !workspace.localOnly,
  );
  if (messages) {
    return { workspaceId: messages.id, channelId: "" };
  }

  const first = model.workspaces.find((workspace) => !workspace.localOnly);
  return {
    workspaceId: first?.id ?? "",
    channelId: first?.channels[0]?.id ?? "",
  };
}

function hasChannel(
  model: BootstrapViewModel,
  context: NavigationContext,
): boolean {
  const workspace = model.workspaces.find(
    (candidate) => candidate.id === context.workspaceId,
  );
  if (!workspace) return false;

  // Direct-message home intentionally has no selected channel. A direct
  // conversation, when selected, still needs to resolve to an existing DM
  // channel so a stale snapshot cannot resurrect a removed conversation.
  if (workspace.directMessages && context.channelId === "") return true;
  return workspace.channels.some((channel) => channel.id === context.channelId);
}

/**
 * Keep an explicit renderer navigation choice across model snapshots. Core
 * snapshots describe synchronized data and may contain the last persisted
 * context; they must not silently replace a DM-home selection made by the
 * user. Invalid targets (for example after a server is removed) fall back to
 * the best target available in the new model.
 */
export function resolveNavigationContext(
  model: BootstrapViewModel,
  requested: NavigationContext | null,
): NavigationContext {
  if (requested && hasChannel(model, requested)) return requested;
  return preferredNavigationContext(model);
}
