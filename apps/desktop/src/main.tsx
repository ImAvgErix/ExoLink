import {
  Component,
  StrictMode,
  type ErrorInfo,
  type ReactNode,
} from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import App from "./App";
import { LiquidGlassDefs } from "./LiquidGlass";
import "./tokens.css";
import "./styles.css";

class RendererErrorBoundary extends Component<
  { children: ReactNode },
  { error: string | null }
> {
  state = { error: null as string | null };

  static getDerivedStateFromError(error: unknown) {
    return {
      error:
        error instanceof Error
          ? error.message
          : "The interface stopped unexpectedly.",
    };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    console.error("Exocord renderer failed", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <main className="renderer-failure">
          <section role="alert">
            <span>Exocord</span>
            <h1>The interface needs a reload.</h1>
            <p>{this.state.error}</p>
            <button type="button" onClick={() => window.location.reload()}>
              Reload
            </button>
          </section>
        </main>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RendererErrorBoundary>
      <LiquidGlassDefs />
      <App />
    </RendererErrorBoundary>
  </StrictMode>,
);
