import { defineConfig } from "vite";
import { resolve } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  base: "./",
  resolve: {
    preserveSymlinks: true,
    alias: {
      "constitute-ui/styles.css": resolve(__dirname, "../constitute-ui/src/styles.css"),
      "constitute-ui/runtime-shell-state": resolve(__dirname, "../constitute-ui/src/runtime-shell-state.js"),
      "constitute-ui/runtime-surface-client": resolve(__dirname, "../constitute-ui/src/runtime-surface-client.js"),
      "constitute-ui/surface-app-contract": resolve(__dirname, "../constitute-ui/src/surface-app-contract.js"),
      "constitute-ui/surface-module-registry": resolve(__dirname, "../constitute-ui/src/surface-module-registry.js"),
      "constitute-ui/surface-selection-read-model": resolve(__dirname, "../constitute-ui/src/surface-selection-read-model.js"),
      "constitute-ui": resolve(__dirname, "../constitute-ui/src/index.js"),
      "constitute-runner": resolve(__dirname, "../constitute-runner/src/index.js"),
      "constitute-protocol": resolve(__dirname, "../constitute-protocol/src/index.js")
    }
  }
});
