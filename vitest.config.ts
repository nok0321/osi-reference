import { defineConfig } from "vitest/config";
import solidPlugin from "vite-plugin-solid";

export default defineConfig({
  plugins: [solidPlugin({ hot: false })],
  test: {
    environment: "jsdom",
    globals: true,
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
