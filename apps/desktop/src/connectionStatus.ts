import type { ConnectionState } from "./models";

/**
 * Human-readable connection banner copy for the desktop shell.
 * Pure mapping so unit tests can exercise the real shipped labels without the UI tree.
 */
export function connectionBannerLabel(
  state: ConnectionState,
  pending: number,
): string | null {
  if (state === "connected" && pending === 0) return null;
  if (state === "offline") {
    return pending > 0
      ? `Offline — ${pending} message${pending === 1 ? "" : "s"} safely queued`
      : "Offline — local channels remain available";
  }
  if (state === "catching_up") {
    return "Catching up and delivering queued messages…";
  }
  if (state === "connecting") {
    return "Connecting to your Exo Link network…";
  }
  // connected with pending outbox
  return `Delivering ${pending} queued message${pending === 1 ? "" : "s"}…`;
}

/** Whether the banner should offer a Retry control. */
export function connectionBannerShowsRetry(
  state: ConnectionState,
  pending: number,
): boolean {
  return state === "offline" || (state === "connected" && pending > 0);
}

/** Compact status chip for chrome / tray tooling. */
export function connectionStatusChip(state: ConnectionState): {
  tone: "good" | "warn" | "bad" | "idle";
  label: string;
} {
  switch (state) {
    case "connected":
      return { tone: "good", label: "Connected" };
    case "connecting":
      return { tone: "warn", label: "Connecting" };
    case "catching_up":
      return { tone: "warn", label: "Catching up" };
    case "offline":
      return { tone: "bad", label: "Offline" };
    default: {
      const _exhaustive: never = state;
      return _exhaustive;
    }
  }
}
