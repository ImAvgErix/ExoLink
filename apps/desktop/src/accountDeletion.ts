export const ACCOUNT_DELETE_CONFIRMATION = "DELETE MY ACCOUNT";

export function accountDeleteConfirmed(value: string): boolean {
  return value.trim() === ACCOUNT_DELETE_CONFIRMATION;
}

