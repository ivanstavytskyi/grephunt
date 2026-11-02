import { Component, type ReactNode } from "react";

type Props = { children: ReactNode; title: string };
type State = { message: string | null };

/** A failure in one panel stays in that panel. The shell and the other routes keep working. */
export class PanelBoundary extends Component<Props, State> {
  state: State = { message: null };

  static getDerivedStateFromError(error: Error): State {
    return { message: error.message || "This panel failed." };
  }

  render() {
    if (this.state.message) {
      return (
        <div className="m-6 rounded-lg border border-rose-500/40 bg-ink-panel px-4 py-3 text-sm text-rose-200">
          <p>
            {this.props.title} stopped: {this.state.message}
          </p>
          <button
            type="button"
            aria-label={`Try ${this.props.title} again`}
            className="mt-3 rounded-md bg-ink-raised px-3 py-1.5 text-ink-text"
            onClick={() => this.setState({ message: null })}
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
