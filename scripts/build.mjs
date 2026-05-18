#!/usr/bin/env node
import { build } from "vite";
import { resolve } from "node:path";

await build({
  configFile: resolve("vite.config.js"),
  build: {
    rollupOptions: {
      input: resolve("index.html"),
      output: {
        entryFileNames: "assets/app.js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});

