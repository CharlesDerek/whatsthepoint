const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/browser',
  workers: 1,
  use: {
    baseURL: 'http://127.0.0.1:18080',
    headless: true,
    viewport: {width: 1440, height: 1000},
    screenshot: 'only-on-failure',
  },
  outputDir: 'artifacts/browser',
  webServer: {
    command: 'node scripts/browser-server.cjs',
    url: 'http://127.0.0.1:18080/healthz',
    reuseExistingServer: false,
    timeout: 180000
  }
});
