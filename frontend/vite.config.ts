import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  // passing this to run in docker, to work properly in docker
  server: {
    host: true,
  },
  plugins: [react()],
});
