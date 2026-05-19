import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig(({ mode }) => {
  const isDev = mode === "development";

  return {
    plugins: [react(), tailwindcss()],

    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },

    server: {
      host: true,
      port: 3000,

      proxy: isDev
        ? {
            "/odata": {
              target: "http://localhost:4004",
              changeOrigin: true,
              secure: false,
            },
          }
        : undefined,
    },

    build: {
      outDir: "dist",
      emptyOutDir: true,
    },
  };
});