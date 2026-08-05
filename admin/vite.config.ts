import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: new URL(".", import.meta.url).pathname,
  base: "/admin/",
  plugins: [react()],
  build: {
    outDir: new URL("../dist/admin", import.meta.url).pathname,
    emptyOutDir: true,
    sourcemap: true,
    target: "es2022",
  },
});
