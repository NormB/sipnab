// SPDX-License-Identifier: MIT OR Apache-2.0

// Playwright drives the BUILT site, not a dev server.
//
// Every other gate in this repository is static analysis over the source tree:
// `zola build` runs in exactly one local gate and one CI step, and no Rust test
// reads rendered output at all. So a template that parses, passes Vale, and
// renders a broken page is invisible to all of them -- which is how two Pages
// deploys failed in one afternoon on one feature.
//
// `webServer` serves `website/public` so a run measures the same bytes GitHub
// Pages publishes. Pointing at `zola serve` instead would test a development
// build with different asset URLs, which is a different artifact.

const { defineConfig, devices } = require('@playwright/test');

// The bundled Chromium, which is already on this machine for other work.
// Playwright would download its own copy otherwise, and on aarch64 that is a
// download this repository has been bitten by before -- Zola ships no aarch64
// Linux binary, and the site could not be built locally until someone noticed.
const BUNDLED_CHROME =
  process.env.SIPNAB_E2E_CHROME ||
  `${process.env.HOME}/.cache/ms-playwright/chromium-1223/chrome-linux/chrome`;

module.exports = defineConfig({
  testDir: './tests',
  // A journey test that flakes gets muted, and a muted test is worse than none:
  // it reports green while measuring nothing. One retry absorbs a genuinely
  // flaky network idle; more would hide a real intermittent failure.
  retries: process.env.CI ? 1 : 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  use: {
    baseURL: process.env.SIPNAB_E2E_BASE_URL || 'http://127.0.0.1:1111',
    trace: 'retain-on-failure',
    launchOptions: { executablePath: BUNDLED_CHROME },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: process.env.SIPNAB_E2E_BASE_URL
    ? undefined
    : {
        // `python3 -m http.server` rather than a Node server: it is already
        // present everywhere this runs, and serving static files is the whole
        // requirement.
        command: 'python3 -m http.server 1111 --directory ../website/public',
        url: 'http://127.0.0.1:1111/',
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
      },
});
