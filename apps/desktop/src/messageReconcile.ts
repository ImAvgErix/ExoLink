import type { ChatMessage } from "./models";

export interface MessageReconcileOptions {
  /** Keep the current reaction snapshot when a command response is stale. */
  preserveReactions?: boolean;
}

function sameReactions(
  left: ChatMessage["reactions"],
  right: ChatMessage["reactions"],
): boolean {
  if (left === right) return true;
  if (!left || !right || left.length !== right.length) return false;
  const normalize = (reactions: NonNullable<ChatMessage["reactions"]>) =>
    [...reactions]
      .map((reaction) => `${reaction.emoji}\u0000${reaction.count}\u0000${reaction.me ? 1 : 0}`)
      .sort()
      .join("\u0001");
  return normalize(left) === normalize(right);
}

function messageKey(message: Pick<ChatMessage, "id" | "clientKey">): string {
  return message.clientKey ?? message.id;
}

/**
 * Merge a renderer command result without allowing a late pending DTO to undo
 * an authoritative sent/failed update delivered by the realtime stream.
 */
export function reconcileMessageResult(
  messages: readonly ChatMessage[],
  incoming: ChatMessage,
  options: MessageReconcileOptions = {},
): ChatMessage[] {
  const key = messageKey(incoming);
  const index = messages.findIndex((candidate) => messageKey(candidate) === key);
  if (index < 0) return [...messages, incoming];
  const existing = messages[index];
  if (
    incoming.deliveryState === "pending" &&
    (existing.deliveryState === "sent" || existing.deliveryState === "failed")
  ) {
    return [...messages];
  }
  const next = [...messages];
  // Command responses are not revisioned.  A realtime reaction delta can
  // therefore land while the invoke is in flight; do not replace that newer
  // reaction state with the response's older snapshot.
  const reactions = options.preserveReactions
    ? existing.reactions
    : incoming.reactions ?? existing.reactions;
  next[index] = reactions === incoming.reactions
    ? incoming
    : { ...incoming, reactions };
  return next;
}

export function reactionsEqual(
  left: ChatMessage["reactions"],
  right: ChatMessage["reactions"],
): boolean {
  return sameReactions(left, right);
}
