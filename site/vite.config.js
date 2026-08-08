import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

// Project page (wo1and29.github.io/woland-guard/), not a user page, so every
// asset URL needs the repo name prefixed.
export default defineConfig({
  base: "/woland-guard/",
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        en: resolve(__dirname, "en/index.html"),
      },
    },
  },
});
