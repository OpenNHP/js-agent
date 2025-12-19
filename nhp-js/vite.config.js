import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "src/nhp.js",
      name: "nhp-js",           // global name for IIFE/UMD
      fileName: "nhp-js-lib"
    },
    rollupOptions: {
      // external: [], // list deps here if needed
    }
  }
});
