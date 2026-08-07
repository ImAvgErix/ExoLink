import type {
  BootstrapViewModel,
  CoreDelta,
  DirectUnreadDelta,
} from "./models";

const MAX_MESSAGES_PER_CHANNEL = 100;

function applyDirectUnread(
  model: BootstrapViewModel,
  unread: DirectUnreadDelta,
): BootstrapViewModel["workspaces"] {
  return model.workspaces.map((workspace) => {
    if (!workspace.directMessages) return workspace;
    const channel = workspace.channels.find(
      (candidate) => candidate.id === unread.channelId,
    );
    if (!channel) return workspace;
    return {
      ...workspace,
      unreadCount: unread.unreadCount,
      channels: workspace.channels.map((candidate) =>
        candidate.id === unread.channelId
          ? { ...candidate, unread: unread.unread }
          : candidate,
      ),
    };
  });
}

function upsertBoundedMessage(
  model: BootstrapViewModel,
  delta: Extract<CoreDelta, { type: "message_upsert" }>,
): BootstrapViewModel {
  const key = delta.message.clientKey ?? delta.message.id;
  const byClientKey = model.messages.findIndex(
    (message) => (message.clientKey ?? message.id) === key,
  );
  const byMessageId = model.messages.findIndex(
    (message) => message.id === delta.message.id,
  );
  const existing = byClientKey >= 0 ? byClientKey : byMessageId;
  const existingMessage = existing >= 0 ? model.messages[existing] : undefined;
  // Delivery is monotonic in the renderer. A late pending DTO must never
  // downgrade a sent or failed message already acknowledged by the stream.
  const effectiveMessage =
    delta.message.deliveryState === "pending" &&
    (existingMessage?.deliveryState === "sent" ||
      existingMessage?.deliveryState === "failed")
      ? existingMessage
      : delta.message;
  const acknowledgedPending =
    model.messages.some(
      (message) =>
        ((message.clientKey ?? message.id) === key ||
          message.id === delta.message.id) &&
        message.deliveryState === "pending",
    ) &&
    delta.message.deliveryState !== "pending";
  const messages =
    existing >= 0
      ? model.messages.flatMap((message, index) => {
          if (index === existing) return [effectiveMessage];
          if (
            (message.clientKey ?? message.id) === key ||
            message.id === delta.message.id
          ) {
            return [];
          }
          return [message];
        })
      : [...model.messages, effectiveMessage];
  let overflow =
    messages.filter(
      (message) => message.channelId === delta.message.channelId,
    ).length - MAX_MESSAGES_PER_CHANNEL;
  const bounded =
    overflow > 0
      ? messages.filter((message) => {
          if (
            overflow > 0 &&
            message.channelId === delta.message.channelId
          ) {
            overflow -= 1;
            return false;
          }
          return true;
        })
      : messages;
  return {
    ...model,
    revision: delta.revision,
    messages: bounded,
    pendingOutbox: acknowledgedPending
      ? Math.max(0, model.pendingOutbox - 1)
      : model.pendingOutbox,
    workspaces: delta.directUnread
      ? applyDirectUnread(model, delta.directUnread)
      : model.workspaces,
  };
}

export function applyCoreDelta(
  model: BootstrapViewModel,
  delta: CoreDelta,
): BootstrapViewModel {
  switch (delta.type) {
    case "message_upsert":
      return upsertBoundedMessage(model, delta);
    case "message_delete":
      return {
        ...model,
        revision: delta.revision,
        messages: model.messages.filter(
          (message) =>
            message.id !== delta.messageId ||
            message.channelId !== delta.channelId,
        ),
      };
    case "presence":
      return {
        ...model,
        revision: delta.revision,
        members: model.members.map((member) =>
          member.id === delta.userId
            ? { ...member, presence: delta.presence }
            : member,
        ),
      };
    case "typing_upsert": {
      const exists = model.typing.some(
        (typing) =>
          typing.channelId === delta.typing.channelId &&
          typing.userId === delta.typing.userId,
      );
      return {
        ...model,
        revision: delta.revision,
        typing: exists
          ? model.typing.map((typing) =>
              typing.channelId === delta.typing.channelId &&
              typing.userId === delta.typing.userId
                ? delta.typing
                : typing,
            )
          : [...model.typing, delta.typing],
      };
    }
    case "typing_remove":
      return {
        ...model,
        revision: delta.revision,
        typing: model.typing.filter(
          (typing) =>
            typing.channelId !== delta.channelId ||
            typing.userId !== delta.userId,
        ),
      };
    case "read_state":
      return {
        ...model,
        revision: delta.revision,
        workspaces: applyDirectUnread(model, delta.directUnread),
      };
    case "connection":
      return {
        ...model,
        revision: delta.revision,
        connectionState: delta.connectionState,
      };
  }
}
