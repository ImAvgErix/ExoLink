import { describe, expect, it } from "vitest";
import { mockBootstrap } from "./mockData";

describe("browser mock attachment fixture", () => {
  it("keeps a deterministic local image on the active preview message", () => {
    const message = mockBootstrap.messages.find(
      (candidate) => candidate.id === "m-7",
    );
    const attachment = message?.attachments?.[0];

    expect(attachment).toMatchObject({
      id: "mock-attachment-liquid-glass",
      filename: "liquid-glass-preview.svg",
      contentType: "image/svg+xml",
      url: "/mock/attachment-preview.svg",
      width: 1200,
      height: 800,
      animated: false,
    });
    expect(attachment?.size).toBeGreaterThan(0);
    expect(attachment?.url).not.toMatch(/^https?:/i);
  });
});
