export interface ImageViewerState {
  open: boolean;
  zoom: number;
  offsetX: number;
  offsetY: number;
  loading: boolean;
  error: string | null;
}

export type ImageViewerAction =
  | { type: "open" }
  | { type: "close" }
  | { type: "load_start" }
  | { type: "load" }
  | { type: "error"; message?: string }
  | { type: "zoom_in" }
  | { type: "zoom_out" }
  | { type: "set_zoom"; zoom: number }
  | { type: "pan"; x: number; y: number }
  | { type: "reset" };

export const IMAGE_VIEWER_MIN_ZOOM = 0.5;
export const IMAGE_VIEWER_MAX_ZOOM = 4;
export const IMAGE_VIEWER_ZOOM_STEP = 0.25;

export function clampImageZoom(zoom: number): number {
  if (!Number.isFinite(zoom)) return 1;
  return Math.min(IMAGE_VIEWER_MAX_ZOOM, Math.max(IMAGE_VIEWER_MIN_ZOOM, zoom));
}

export function createImageViewerState(open = false): ImageViewerState {
  return {
    open,
    zoom: 1,
    offsetX: 0,
    offsetY: 0,
    loading: open,
    error: null,
  };
}

export function imageViewerReducer(
  state: ImageViewerState,
  action: ImageViewerAction,
): ImageViewerState {
  switch (action.type) {
    case "open":
      return createImageViewerState(true);
    case "close":
      return createImageViewerState(false);
    case "load_start":
      return { ...state, loading: true, error: null };
    case "load":
      return { ...state, loading: false, error: null };
    case "error":
      return {
        ...state,
        loading: false,
        error: action.message ?? "This image could not be loaded.",
      };
    case "zoom_in":
      return {
        ...state,
        zoom: clampImageZoom(state.zoom + IMAGE_VIEWER_ZOOM_STEP),
      };
    case "zoom_out":
      {
        const zoom = clampImageZoom(state.zoom - IMAGE_VIEWER_ZOOM_STEP);
        return {
          ...state,
          zoom,
          ...(zoom <= 1 ? { offsetX: 0, offsetY: 0 } : {}),
        };
      }
    case "set_zoom": {
      const zoom = clampImageZoom(action.zoom);
      return {
        ...state,
        zoom,
        ...(zoom <= 1 ? { offsetX: 0, offsetY: 0 } : {}),
      };
    }
    case "pan":
      return state.zoom > 1
        ? { ...state, offsetX: action.x, offsetY: action.y }
        : { ...state, offsetX: 0, offsetY: 0 };
    case "reset":
      return { ...state, zoom: 1, offsetX: 0, offsetY: 0 };
    default:
      return state;
  }
}

/** Resolve API-relative media URLs without rewriting blob/data previews. */
export function resolveAttachmentUrl(value: string, baseUrl?: string): string {
  const trimmed = value.trim();
  if (!trimmed || /^(?:blob:|data:|https?:|file:|tauri:)/i.test(trimmed)) {
    return trimmed;
  }
  const fallback =
    baseUrl ??
    (typeof window !== "undefined" && window.location?.href
      ? window.location.href
      : "http://localhost/");
  try {
    return new URL(trimmed, fallback).toString();
  } catch {
    return trimmed;
  }
}

export const normalizeAttachmentUrl = resolveAttachmentUrl;
