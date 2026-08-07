import {
  createElement,
  type ComponentPropsWithRef,
  type ElementType,
  type ReactNode,
} from "react";

/** Stable IDs are part of the CSS contract; do not randomize them per render. */
export const LIQUID_GLASS_REGULAR_FILTER_ID =
  "exocord-liquid-glass-regular";
export const LIQUID_GLASS_CLEAR_FILTER_ID = "exocord-liquid-glass-clear";

export type GlassVariant = "regular" | "clear";

/**
 * The SVG filter graph lives in the document so Chromium/WebView2 can resolve
 * it from `backdrop-filter: url(#...)`. It is deliberately inert and hidden:
 * it must never take part in layout, hit testing, or the accessibility tree.
 */
export function LiquidGlassDefs() {
  return (
    <svg
      className="liquid-glass-defs"
      aria-hidden="true"
      focusable="false"
      tabIndex={-1}
      width="1"
      height="1"
      viewBox="0 0 1 1"
    >
      <defs>
        <filter
          id={LIQUID_GLASS_REGULAR_FILTER_ID}
          x="-14%"
          y="-18%"
          width="128%"
          height="136%"
          filterUnits="objectBoundingBox"
          colorInterpolationFilters="sRGB"
        >
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.018 0.032"
            numOctaves="2"
            seed="17"
            result="regular-noise"
          />
          <feDisplacementMap
            in="SourceGraphic"
            in2="regular-noise"
            scale="6"
            xChannelSelector="R"
            yChannelSelector="B"
            result="regular-refraction"
          />
          <feGaussianBlur
            in="regular-refraction"
            stdDeviation="0.55"
            result="regular-soft"
          />
          <feColorMatrix
            in="regular-soft"
            type="matrix"
            values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 0.98 0"
            result="regular-tint"
          />
          <feBlend
            in="regular-tint"
            in2="SourceGraphic"
            mode="screen"
          />
        </filter>
        <filter
          id={LIQUID_GLASS_CLEAR_FILTER_ID}
          x="-16%"
          y="-20%"
          width="132%"
          height="140%"
          filterUnits="objectBoundingBox"
          colorInterpolationFilters="sRGB"
        >
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.012 0.024"
            numOctaves="2"
            seed="23"
            result="clear-noise"
          />
          <feDisplacementMap
            in="SourceGraphic"
            in2="clear-noise"
            scale="8"
            xChannelSelector="R"
            yChannelSelector="B"
            result="clear-refraction"
          />
          <feGaussianBlur
            in="clear-refraction"
            stdDeviation="0.4"
            result="clear-soft"
          />
          <feColorMatrix
            in="clear-soft"
            type="matrix"
            values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 0.96 0"
            result="clear-tint"
          />
          <feBlend in="clear-tint" in2="SourceGraphic" mode="screen" />
        </filter>
      </defs>
    </svg>
  );
}

type GlassSurfaceProps<T extends ElementType> = {
  as?: T;
  variant?: GlassVariant;
  children?: ReactNode;
  className?: string;
} & Omit<ComponentPropsWithRef<T>, "className" | "children">;

/**
 * Adds one bounded glass plane without changing the semantic element supplied
 * by the caller. Child controls remain ordinary DOM controls; they never get
 * their own backdrop filter.
 */
export function GlassSurface<T extends ElementType = "div">({
  as,
  variant = "regular",
  className,
  children,
  ...props
}: GlassSurfaceProps<T>) {
  const Component = (as ?? "div") as ElementType;
  const classes = ["glass-surface", `glass-surface-${variant}`, className]
    .filter(Boolean)
    .join(" ");
  return createElement(
    Component,
    {
      ...props,
      className: classes,
      // The WebGL renderer owns a bounded list of these planes. Keeping the
      // marker on the semantic element means the DOM remains the hit target
      // and the GPU layer never needs to mirror or read application pixels.
      "data-glass-surface": "true",
      "data-glass-variant": variant,
    },
    children,
  );
}
