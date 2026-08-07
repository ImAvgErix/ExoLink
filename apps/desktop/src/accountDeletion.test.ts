import { describe, expect, it } from "vitest";
import {
  ACCOUNT_DELETE_CONFIRMATION,
  accountDeleteConfirmed,
} from "./accountDeletion";

describe("account deletion confirmation", () => {
  it("requires the complete exact phrase", () => {
    expect(accountDeleteConfirmed(ACCOUNT_DELETE_CONFIRMATION)).toBe(true);
    expect(accountDeleteConfirmed(` ${ACCOUNT_DELETE_CONFIRMATION} `)).toBe(true);
    expect(accountDeleteConfirmed("delete my account")).toBe(false);
    expect(accountDeleteConfirmed("DELETE ACCOUNT")).toBe(false);
    expect(accountDeleteConfirmed("")).toBe(false);
  });
});
