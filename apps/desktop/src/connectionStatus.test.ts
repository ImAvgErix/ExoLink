import { describe, expect, it } from "vitest";
import {
  connectionBannerLabel,
  connectionBannerShowsRetry,
  connectionStatusChip,
} from "./connectionStatus";
import type { ConnectionState } from "./models";

describe("connectionBannerLabel", () => {
  it("hides the banner when connected with an empty outbox", () => {
    expect(connectionBannerLabel("connected", 0)).toBeNull();
  });

  it("reports offline with queued messages using pluralization", () => {
    expect(connectionBannerLabel("offline", 1)).toBe(
      "Offline — 1 message safely queued",
    );
    expect(connectionBannerLabel("offline", 3)).toBe(
      "Offline — 3 messages safely queued",
    );
    expect(connectionBannerLabel("offline", 0)).toBe(
      "Offline — local channels remain available",
    );
  });

  it("labels connecting and catch-up honestly", () => {
    expect(connectionBannerLabel("connecting", 0)).toBe(
      "Connecting to your Exo Link network…",
    );
    expect(connectionBannerLabel("catching_up", 2)).toBe(
      "Catching up and delivering queued messages…",
    );
  });

  it("shows delivery progress when connected with pending messages", () => {
    expect(connectionBannerLabel("connected", 1)).toBe(
      "Delivering 1 queued message…",
    );
    expect(connectionBannerLabel("connected", 4)).toBe(
      "Delivering 4 queued messages…",
    );
  });
});

describe("connectionBannerShowsRetry", () => {
  it("offers retry offline or when delivery is stuck with pending work", () => {
    expect(connectionBannerShowsRetry("offline", 0)).toBe(true);
    expect(connectionBannerShowsRetry("connected", 2)).toBe(true);
    expect(connectionBannerShowsRetry("connected", 0)).toBe(false);
    expect(connectionBannerShowsRetry("connecting", 0)).toBe(false);
    expect(connectionBannerShowsRetry("catching_up", 1)).toBe(false);
  });
});

describe("connectionStatusChip", () => {
  const cases: Array<[ConnectionState, string, string]> = [
    ["connected", "good", "Connected"],
    ["connecting", "warn", "Connecting"],
    ["catching_up", "warn", "Catching up"],
    ["offline", "bad", "Offline"],
  ];

  it.each(cases)("%s maps to tone=%s label=%s", (state, tone, label) => {
    expect(connectionStatusChip(state)).toEqual({ tone, label });
  });
});
