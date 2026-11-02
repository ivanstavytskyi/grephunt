import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRoot } from "react-dom/client";
import { Toaster } from "sonner";
import { PanelBoundary } from "@/components/panel-boundary";
import { Shell } from "@/components/shell";
import { Navigation, scanIdFromPath, useNavigation } from "@/lib/nav";
import { NewScanPage } from "@/pages/new-scan";
import { ScanDetailPage } from "@/pages/scan-detail";
import "@fontsource-variable/geist/wght.css";
import "@fontsource-variable/geist-mono/wght.css";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
    },
  },
});

function Pages() {
  const { path } = useNavigation();
  const scanId = scanIdFromPath(path);
  if (!scanId) {
    return (
      <PanelBoundary title="New scan">
        <NewScanPage />
      </PanelBoundary>
    );
  }
  return (
    <PanelBoundary key={scanId} title="Scan">
      <ScanDetailPage scanId={scanId} />
    </PanelBoundary>
  );
}

createRoot(document.getElementById("root")!).render(
  <QueryClientProvider client={queryClient}>
    <Navigation>
      <Shell>
        <Pages />
      </Shell>
    </Navigation>
    <Toaster theme="dark" />
  </QueryClientProvider>,
);
