/** localStorage key for global push-to-talk preference. */
export const PUSH_TO_TALK_STORAGE_KEY = "exocord.push-to-talk";

export type PushToTalkEvent =
  | { type: "keydown"; key: string; target: EventTarget | null }
  | { type: "keyup"; key: string; target: EventTarget | null }
  | { type: "blur" }
  | { type: "deafen"; deafened: boolean }
  | { type: "leave" }
  | { type: "preference"; enabled: boolean };

export type PushToTalkDecision =
  | { action: "none" }
  | { action: "hold" }
  | { action: "release" }
  | { action: "force_mute" };

export function readPushToTalkEnabled(): boolean {
  if (typeof window === "undefined") return false;
  return window.localStorage.getItem(PUSH_TO_TALK_STORAGE_KEY) === "1";
}

export function writePushToTalkEnabled(enabled: boolean): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(PUSH_TO_TALK_STORAGE_KEY, enabled ? "1" : "0");
}

/** True when the event target is an editable field where Space must type. */
export function isTextEntryTarget(target: EventTarget | null): boolean {
  if (!target || typeof target !== "object") return false;
  // Duck-typed so unit tests can drive the same helper without a full DOM.
  const el = target as {
    tagName?: string;
    isContentEditable?: boolean;
    getAttribute?: (name: string) => string | null;
    closest?: (selector: string) => unknown;
  };
  const tag = el.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (el.isContentEditable) return true;
  if (typeof el.closest === "function") {
    try {
      if (el.closest("[contenteditable='true'], [contenteditable='']")) {
        return true;
      }
    } catch {
      // ignore non-DOM stand-ins
    }
  }
  const role =
    typeof el.getAttribute === "function" ? el.getAttribute("role") : null;
  if (role === "textbox" || role === "searchbox" || role === "combobox") {
    return true;
  }
  return false;
}

function isSpaceKey(key: string): boolean {
  return key === " " || key === "Spacebar" || key === "Space";
}

/**
 * Pure PTT state machine used by the desktop shell.
 * Enabling the mode starts muted; Space holds open the mic outside text fields.
 * Blur, leave, and deafen all fail closed (mute).
 */
export function reducePushToTalk(
  state: {
    enabled: boolean;
    holding: boolean;
    voiceConnected: boolean;
    deafened: boolean;
  },
  event: PushToTalkEvent,
): { holding: boolean; decision: PushToTalkDecision; enabled: boolean } {
  let { enabled, holding } = state;

  if (event.type === "preference") {
    enabled = event.enabled;
    if (enabled) {
      // Enabling PTT always fails closed to muted until Space is held.
      return { enabled, holding: false, decision: { action: "force_mute" } };
    }
    // Disabling mid-hold releases transmit.
    if (holding) {
      return { enabled, holding: false, decision: { action: "release" } };
    }
    return { enabled, holding: false, decision: { action: "none" } };
  }

  if (!enabled || !state.voiceConnected) {
    return { enabled, holding: false, decision: { action: "none" } };
  }

  if (event.type === "blur" || event.type === "leave") {
    if (holding) {
      return { enabled, holding: false, decision: { action: "force_mute" } };
    }
    return { enabled, holding: false, decision: { action: "none" } };
  }

  if (event.type === "deafen") {
    if (event.deafened && holding) {
      return { enabled, holding: false, decision: { action: "force_mute" } };
    }
    return { enabled, holding, decision: { action: "none" } };
  }

  if (event.type === "keydown" && isSpaceKey(event.key)) {
    if (isTextEntryTarget(event.target)) {
      return { enabled, holding, decision: { action: "none" } };
    }
    if (state.deafened) {
      return { enabled, holding: false, decision: { action: "none" } };
    }
    if (!holding) {
      return { enabled, holding: true, decision: { action: "hold" } };
    }
    return { enabled, holding: true, decision: { action: "none" } };
  }

  if (event.type === "keyup" && isSpaceKey(event.key)) {
    if (holding) {
      return { enabled, holding: false, decision: { action: "release" } };
    }
    return { enabled, holding: false, decision: { action: "none" } };
  }

  return { enabled, holding, decision: { action: "none" } };
}
