import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

function stripWebkitTextSizeAdjust() {
  return {
    name: "strip-webkit-text-size-adjust",
    generateBundle(_options: unknown, bundle: Record<string, { type: string; fileName?: string; source?: string | Uint8Array }>) {
      for (const item of Object.values(bundle)) {
        if (item.type === "asset" && typeof item.source === "string" && item.fileName?.endsWith(".css")) {
          item.source = item.source.replace(/-webkit-text-size-adjust:\s*100%;?/g, "text-size-adjust:100%;");
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), stripWebkitTextSizeAdjust()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:4000",
        ws: true,
      },
    },
  },
});
