import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cloud, ExternalLink, LoaderCircle } from "lucide-react";
import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { cancelSnykLogin, disconnectSnyk, fetchSnykStatus, startSnykLogin, type SnykStatus } from "@/lib/api";

const POPUP_NAME = "grephunt-snyk-login";
const POPUP_FEATURES = "popup,width=560,height=720";

/** Only Snyk's own authorization page may be opened. */
export function isSnykAuthUrl(value: string | null | undefined): value is string {
  if (!value) return false;
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    return (
      url.protocol === "https:" &&
      (host === "snyk.io" || host.endsWith(".snyk.io")) &&
      url.pathname.endsWith("/oauth2/authorize")
    );
  } catch {
    return false;
  }
}

function waitingPage(popup: Window) {
  try {
    popup.document.title = "Connecting to Snyk";
    popup.document.body.style.cssText = "font-family: system-ui, sans-serif; padding: 32px; color: #222";
    popup.document.body.textContent = "Opening the Snyk sign-in page…";
  } catch {
    // The window already shows Snyk's page.
  }
}

export function SnykConnect({ onChange }: { onChange?: (status: SnykStatus) => void }) {
  const queryClient = useQueryClient();
  const popup = useRef<Window | null>(null);
  const status = useQuery({
    queryKey: ["snyk"],
    queryFn: fetchSnykStatus,
    refetchInterval: (query) => {
      const login = query.state.data?.login;
      return login === "preparing" || login === "waiting" ? 1500 : false;
    },
  });
  const data = status.data;
  const busy = data?.login === "preparing" || data?.login === "waiting";

  useEffect(() => {
    if (data) onChange?.(data);
  }, [data, onChange]);

  useEffect(() => {
    if (!data) return;
    const window_ = popup.current;
    if (data.login === "waiting" && isSnykAuthUrl(data.url) && window_ && !window_.closed) {
      try {
        if (window_.location.href !== data.url) window_.location.href = data.url;
      } catch {
        // Cross-origin: the window is already on Snyk's page.
      }
    }
    if (data.connected && data.login === "connected") {
      if (window_ && !window_.closed) window_.close();
      popup.current = null;
    }
    if (data.login === "failed" && window_ && !window_.closed) {
      window_.close();
      popup.current = null;
    }
  }, [data]);

  const refresh = (next: SnykStatus) => queryClient.setQueryData(["snyk"], next);

  const connect = useMutation({
    mutationFn: startSnykLogin,
    onSuccess: refresh,
    onError: (error: Error) => {
      popup.current?.close();
      popup.current = null;
      toast.error(error.message);
    },
  });
  const cancel = useMutation({ mutationFn: cancelSnykLogin, onSuccess: refresh });
  const disconnect = useMutation({
    mutationFn: disconnectSnyk,
    onSuccess: (next) => {
      refresh(next);
      toast.success("Snyk disconnected");
    },
  });

  const onConnect = () => {
    // Opened in the click itself, so the browser does not block it. It moves to Snyk's page when the CLI prints it.
    const opened = window.open("", POPUP_NAME, POPUP_FEATURES);
    if (opened) waitingPage(opened);
    popup.current = opened;
    connect.mutate();
  };

  const onCancel = () => {
    popup.current?.close();
    popup.current = null;
    cancel.mutate();
  };

  return (
    <div className="rounded-lg border border-ink-line bg-ink-panel px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-start gap-2">
          <Cloud className="mt-0.5 size-4 text-ink-muted" aria-hidden="true" />
          <div>
            <p className="text-sm">Snyk</p>
            <p className="text-xs leading-5 text-ink-muted">
              {data?.connected
                ? "Connected. Snyk scanners upload project data to Snyk: Code sends the source, Open Source sends the dependency list."
                : "Snyk Code and Snyk Open Source run in Snyk's cloud and need a Snyk account."}
            </p>
          </div>
        </div>
        {data?.connected ? (
          <Button type="button" variant="outline" size="sm" disabled={disconnect.isPending} onClick={() => disconnect.mutate()}>
            Disconnect Snyk
          </Button>
        ) : busy ? (
          <Button type="button" variant="outline" size="sm" onClick={onCancel}>
            <LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" />
            Cancel
          </Button>
        ) : (
          <Button type="button" size="sm" disabled={connect.isPending || status.isLoading} onClick={onConnect}>
            Connect Snyk
          </Button>
        )}
      </div>
      {data?.login === "preparing" && (
        <p className="mt-2 text-xs text-ink-muted">Getting the Snyk CLI {data.cli_version} (first time only, about 190 MB)…</p>
      )}
      {data?.login === "waiting" && (
        <p className="mt-2 text-xs leading-5 text-ink-muted">
          Sign in on the Snyk page in the popup and allow access. This page updates by itself.{" "}
          {isSnykAuthUrl(data.url) && (
            <a
              className="inline-flex items-center gap-1 text-signal underline-offset-2 hover:underline"
              href={data.url}
              target={POPUP_NAME}
              rel="noopener noreferrer"
            >
              Open the Snyk sign-in page
              <ExternalLink className="size-3" aria-hidden="true" />
            </a>
          )}
        </p>
      )}
      {data?.login === "failed" && data.error && <p className="mt-2 text-xs text-rose-300">{data.error}</p>}
    </div>
  );
}
