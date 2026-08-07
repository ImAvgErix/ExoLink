import type {
  BootstrapViewModel,
  CoreDelta,
  NotificationMode,
} from "./models";

export interface NotificationIntent {
  title: string;
  body: string;
}

export interface NotificationDecisionInput {
  delta: CoreDelta;
  mode: NotificationMode;
  model: BootstrapViewModel;
  windowFocused: boolean;
}

function safeLabel(value: string | undefined, fallback: string): string {
  const cleaned = value
    ?.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!cleaned) return fallback;
  return [...cleaned].slice(0, 64).join("");
}

export function notificationIntent({
  delta,
  mode,
  model,
  windowFocused,
}: NotificationDecisionInput): NotificationIntent | null {
  if (
    mode === "off" ||
    windowFocused ||
    delta.type !== "message_upsert" ||
    delta.notify !== true ||
    delta.message.deliveryState !== "sent" ||
    delta.message.authorId === model.currentUserId
  ) {
    return null;
  }

  if (mode === "private") {
    return {
      title: "New Exocord message",
      body: "Open Exocord to view it.",
    };
  }

  const sender = model.members.find(
    (member) => member.id === delta.message.authorId,
  );
  const workspace = model.workspaces.find((candidate) =>
    candidate.channels.some(
      (channel) => channel.id === delta.message.channelId,
    ),
  );
  const channel = workspace?.channels.find(
    (candidate) => candidate.id === delta.message.channelId,
  );

  return {
    title: `New message from ${safeLabel(sender?.name, "someone")}`,
    body: workspace?.directMessages
      ? "Direct message"
      : `${safeLabel(channel?.name, "a channel")} · ${safeLabel(
          workspace?.name,
          "Exocord",
        )}`,
  };
}

export class NotificationDeduper {
  readonly #ids = new Set<string>();
  readonly #limit: number;

  constructor(limit = 512) {
    this.#limit = Math.max(1, limit);
  }

  accept(messageId: string): boolean {
    if (this.#ids.has(messageId)) return false;
    this.#ids.add(messageId);
    if (this.#ids.size > this.#limit) {
      const oldest = this.#ids.values().next().value;
      if (oldest) this.#ids.delete(oldest);
    }
    return true;
  }
}
