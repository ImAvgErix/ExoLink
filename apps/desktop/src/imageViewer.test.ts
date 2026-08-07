import { describe, expect, it } from "vitest";
import {
  createImageViewerState,
  imageViewerReducer,
  resolveAttachmentUrl,
} from "./imageViewer";

describe("image viewer state", () => {
  it("opens and closes with a clean zoom/error state", () => {
    const opened = imageViewerReducer(createImageViewerState(), { type: "open" });
    expect(opened.open).toBe(true);
    const failed = imageViewerReducer(opened, {
      type: "error",
      message: "offline",
    });
    expect(failed.error).toBe("offline");
    expect(failed.loading).toBe(false);
    const closed = imageViewerReducer(failed, { type: "close" });
    expect(closed.open).toBe(false);
    expect(closed.zoom).toBe(1);
    expect(closed.error).toBeNull();
  });

  it("clamps zoom and only pans while zoomed", () => {
    const initial = createImageViewerState(true);
    const zoomed = imageViewerReducer(initial, { type: "set_zoom", zoom: 8 });
    expect(zoomed.zoom).toBe(4);
    const panned = imageViewerReducer(zoomed, {
      type: "pan",
      x: 30,
      y: -12,
    });
    expect(panned.offsetX).toBe(30);
    const reset = imageViewerReducer(panned, { type: "set_zoom", zoom: 1 });
    expect(reset.offsetX).toBe(0);
    expect(reset.offsetY).toBe(0);
  });

  it("recenters when stepping back to fit", () => {
    const zoomed = imageViewerReducer(createImageViewerState(true), {
      type: "set_zoom",
      zoom: 1.25,
    });
    const panned = imageViewerReducer(zoomed, {
      type: "pan",
      x: 48,
      y: -16,
    });
    const fitted = imageViewerReducer(panned, { type: "zoom_out" });
    expect(fitted.zoom).toBe(1);
    expect(fitted.offsetX).toBe(0);
    expect(fitted.offsetY).toBe(0);
  });
});

describe("attachment URL resolution", () => {
  it("resolves relative media paths against the configured origin", () => {
    expect(resolveAttachmentUrl("/media/image.webp", "https://cdn.example/room"))
      .toBe("https://cdn.example/media/image.webp");
    expect(resolveAttachmentUrl("https://images.example/image.webp", "https://cdn.example"))
      .toBe("https://images.example/image.webp");
    expect(resolveAttachmentUrl("blob:preview")).toBe("blob:preview");
  });
});
