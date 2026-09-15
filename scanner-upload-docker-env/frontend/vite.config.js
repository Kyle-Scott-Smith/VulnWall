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
  test: {
    // "node" is enough for the pure-logic tests (no DOM/render involved),
    // and avoids pulling jsdom in for tests that don't need it.
    environment: "node",
    include: ["src/__tests__/**/*.test.{js,jsx}"],
  },
});
