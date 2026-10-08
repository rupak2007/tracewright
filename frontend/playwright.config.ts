import { defineConfig } from "@playwright/test";

// Runs against a live stack (docker compose up) at E2E_BASE_URL, using the Chrome already installed
// on the machine (no browser download). E2E_CAPTURE points at the capture to upload.
export default defineConfig({
  testDir: "./e2e",
  timeout: 240_000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env["E2E_BASE_URL"] ?? "http://127.0.0.1:8080",
    channel: process.env["E2E_CHANNEL"] ?? "chrome",
    acceptDownloads: true,
    trace: "off",
  },
});
