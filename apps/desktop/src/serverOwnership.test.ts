import { describe, expect, it } from "vitest";
import { serverNameConfirmed } from "./serverOwnership";

describe("server ownership confirmation", () => {
  it("requires the exact case-sensitive server name", () => {
    expect(serverNameConfirmed("Night Shift", "Night Shift")).toBe(true);
    expect(serverNameConfirmed("night shift", "Night Shift")).toBe(false);
    expect(serverNameConfirmed(" Night Shift ", "Night Shift")).toBe(false);
    expect(serverNameConfirmed("", "Night Shift")).toBe(false);
  });
});
