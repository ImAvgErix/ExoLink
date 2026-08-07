export const CACHE_RESET_CONFIRMATION = "RESET LOCAL CACHE";

export function cacheResetConfirmed(value: string): boolean {
  return value.trim() === CACHE_RESET_CONFIRMATION;
}
