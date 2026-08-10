import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    // Needed so the dev server's websocket (hot reload) works
    // when accessed via localhost from outside the container.
    watch: {
      usePolling: true,
    },
  },
  preview: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
  },
});
