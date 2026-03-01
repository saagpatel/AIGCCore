import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import process from "node:process";

const vitePort = Number(process.env.VITE_PORT ?? "1420");
const viteHost = process.env.VITE_HOST;
const viteCacheDir = process.env.VITE_CACHE_DIR;

export default defineConfig({
  plugins: [react()],
  cacheDir: viteCacheDir,
  server: {
    host: viteHost,
    strictPort: true,
    port: vitePort
  }
});
