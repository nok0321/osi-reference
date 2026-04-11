import { defineConfig } from "vitest/config";
import solidPlugin from "vite-plugin-solid";

export default defineConfig({
  plugins: [solidPlugin({ hot: false })],
  test: {
    globals: true,
    // Server tests (Node.js), frontend tests (jsdom)
    environmentMatchGlobs: [
      ["server/**", "node"],
      ["src/**", "jsdom"],
    ],
    setupFiles: ["./src/test/setup.ts"],
    deps: {
      optimizer: {
        web: {
          include: [],
        },
      },
    },
  },
  resolve: {
    conditions: ["development", "browser"],
  },
});
