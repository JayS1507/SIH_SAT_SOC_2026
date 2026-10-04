import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The app calls the same-origin /api/v1 (Vercel rewrite / nginx proxy in
// production). In `npm run dev`, proxy it to the local FastAPI server.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": process.env.VITE_DEV_API_ORIGIN || "http://127.0.0.1:8000" },
  },
});
