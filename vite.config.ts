import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  plugins: [
    solidPlugin(),
    VitePWA({
      registerType: "autoUpdate",
      manifest: {
        name: "OSI Reference",
        short_name: "OSI Ref",
        description: "Interactive OSI model learning tool with auth & security visualization",
        theme_color: "#0a1628",
        background_color: "#0a1628",
        display: "standalone",
        start_url: "/overview",
        icons: [
          {
            src: "/icon-192.svg",
            sizes: "192x192",
            type: "image/svg+xml",
          },
        ],
      },
      workbox: {
        globPatterns: ["**/*.{js,css,html,svg,png,woff2}"],
      },
    }),
  ],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://localhost:3001",
        changeOrigin: true,
      },
    },
  },
  build: {
    target: "esnext",
    rollupOptions: {
      output: {
        manualChunks: {
          "d3-core": ["d3-selection", "d3-transition"],
          "solid-vendor": ["solid-js", "solid-js/web"],
        },
      },
    },
  },
});
