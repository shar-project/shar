import { defineConfig } from "@playwright/test";

const physicalGpuProjects =
  process.env.SHAR_TEST_PHYSICAL_GPU === "1"
    ? [
        {
          name: "chromium-physical",
          use: {
            browserName: "chromium",
            launchOptions: {
              args: [
                "--enable-unsafe-webgpu",
                "--use-angle=vulkan",
                "--enable-features=Vulkan",
                "--disable-vulkan-surface",
                "--ignore-gpu-blocklist",
                "--disable-software-rasterizer",
              ],
            },
          },
        },
      ]
    : [];

export default defineConfig({
  testDir: "./test/browser",
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:4173",
    viewport: { width: 1280, height: 720 },
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
        launchOptions: {
          args: [
            "--enable-unsafe-webgpu",
            "--use-angle=vulkan",
            "--enable-features=Vulkan",
            "--disable-vulkan-surface",
            "--use-vulkan=swiftshader",
            "--enable-unsafe-swiftshader",
          ],
        },
      },
    },
    { name: "firefox", use: { browserName: "firefox" } },
    { name: "webkit", use: { browserName: "webkit" } },
    ...physicalGpuProjects,
  ],
  webServer: {
    command: "node test/browser-server.mjs",
    url: "http://127.0.0.1:4173/healthz",
    reuseExistingServer: false,
    timeout: 15_000,
  },
});
