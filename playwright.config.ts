import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './scripts/testing',
  testMatch: 'e2e-playwright.ts',
  timeout: 300_000, // 5 minutes per test (shares expiry tests need time)
  expect: {
    timeout: 30_000, // 30s for individual assertions
  },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.SERVER_URL || 'https://localhost:8443',
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    actionTimeout: 30_000,
    navigationTimeout: 30_000,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
        // Chromium flags for self-signed cert handling
        launchOptions: {
          args: ['--ignore-certificate-errors'],
        },
      },
    },
  ],
});
