import type { Member, VoiceParticipant } from "./models";

/** Values that are useful to the renderer but should never be shown as a name. */
const INTERNAL_ID_PATTERN = /^(?:[a-f0-9]{8,}|[a-z0-9]+(?:[-_:][a-z0-9]+){1,})$/i;
const LOWERCASE_HANDLE_PATTERN = /^[a-z][a-z0-9._-]{1,31}$/;

export function isUnsafeVoiceLabel(
  value: string | undefined,
  memberId: string,
  member?: Pick<Member, "handle">,
): boolean {
  const normalized = value?.trim();
  if (!normalized) return true;
  if (normalized.toLocaleLowerCase() === memberId.trim().toLocaleLowerCase()) {
    return true;
  }
  if (
    member?.handle &&
    normalized.toLocaleLowerCase() === member.handle.trim().toLocaleLowerCase()
  ) {
    return true;
  }
  // Transport metadata often falls back to a lowercase handle or the local
  // participant marker.  Those values are useful for routing, never for UI.
  if (normalized.toLocaleLowerCase() === "you") return true;
  return (
    INTERNAL_ID_PATTERN.test(normalized) ||
    LOWERCASE_HANDLE_PATTERN.test(normalized)
  );
}

export function resolveVoiceDisplayName(
  participant: Pick<VoiceParticipant, "memberId" | "displayName">,
  member?: Pick<Member, "name" | "handle">,
): string {
  const memberName = member?.name?.trim();
  if (memberName) return memberName;
  if (!isUnsafeVoiceLabel(participant.displayName, participant.memberId, member)) {
    return participant.displayName!.trim();
  }
  return "Member";
}
