import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const frontendDirectory = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  root: frontendDirectory,
  base: process.env.GITHUB_ACTIONS ? "/pgp-interactive-demo/" : "/",
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8000",
    },
  },
  build: {
    outDir: fileURLToPath(new URL("../pgp_demo/static", import.meta.url)),
    emptyOutDir: true,
  },
});
