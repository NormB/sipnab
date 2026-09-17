// SPDX-License-Identifier: MIT OR Apache-2.0

// /download/ must not move under the reader once it has painted.
//
// e2e/lighthouserc.json budgets this page's cumulative layout shift, and for
// weeks that budget carried a "known defect, cause not identified" note: ~0.11
// CLS, attributed by Lighthouse to no element. On 2026-09-17 it measured
// 0.15008 against a 0.15 ceiling and turned main red. Two mechanisms were
// behind it, measured frame by frame:
//
// 1. The platform-detection banner. `#dl-detect` shipped `hidden`, but
//    `.dl-detect { display: flex }` beats the UA sheet's `[hidden]` rule, so it
//    rendered anyway -- empty, one line tall. Its text was filled in only once
//    `navigator.userAgentData.getHighEntropyValues()` resolved, which is a real
//    asynchronous round trip. The filled text wrapped the "not right?" link onto
//    a second line, the banner grew 35px, and everything below it moved: 0.0559,
//    identical in every run. The same bug showed readers without JavaScript an
//    empty "Detected: -- the highlighted choice below is the one you want."
//
// 2. The web-font swap (fonts.bunny.net, `display=swap`) reflowing paragraphs.
//    That one is timing-dependent, which is why a single Lighthouse number could
//    not tell the two apart.
//
// This file covers the first mechanism deterministically. Lighthouse cannot:
// whether an async callback lands before or after first paint is a race, and a
// race is exactly what produced a gate that passed for weeks and then did not.
// Here the test owns the timing -- it holds the CPU hint until IT decides to
// deliver it -- so the shift either happens every run or never.
//
// Web fonts are blocked in the layout tests so the second mechanism cannot
// contribute a shift and make the first look present or absent by accident.

const { test, expect } = require('@playwright/test');

// Lighthouse 12's desktop preset (lighthouse/core/config/constants.js), which
// is the configuration e2e/lighthouserc.json measures. The Mac UA matters: it is
// the detection branch Lighthouse exercises, and "Intel Mac" is what every Mac
// browser reports regardless of the chip.
const LIGHTHOUSE_DESKTOP = {
  viewport: { width: 1350, height: 940 },
  deviceScaleFactor: 1,
  userAgent:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
};

// Replaces navigator.userAgentData with one whose getHighEntropyValues() does
// not settle until the test calls window.__deliverCpuHint(architecture). A
// real browser's answer arrives "soon"; this one arrives exactly when told, or
// never. Every layout-shift entry from navigation onward is recorded.
function installControlledHintAndShiftRecorder() {
  let deliver;
  const pending = new Promise((resolve) => {
    deliver = resolve;
  });
  window.__deliverCpuHint = (architecture) => deliver({ architecture });
  const fake = {
    brands: [],
    mobile: false,
    platform: 'macOS',
    getHighEntropyValues: () => pending,
  };
  Object.defineProperty(Navigator.prototype, 'userAgentData', {
    configurable: true,
    get: () => fake,
  });

  window.__shifts = [];
  const describe = (node) => {
    if (!node) return '(gone)';
    if (node.nodeType !== 1) return `#text "${(node.textContent || '').trim().slice(0, 30)}"`;
    return node.tagName.toLowerCase() + (node.id ? `#${node.id}` : '') +
      (typeof node.className === 'string' && node.className ? `.${node.className.split(' ')[0]}` : '');
  };
  const record = (entries) => {
    for (const e of entries) {
      if (e.hadRecentInput) continue;
      window.__shifts.push({
        value: Number(e.value.toFixed(4)),
        moved: e.sources.map((s) => `${describe(s.node)} y ${Math.round(s.previousRect.y)} -> ${Math.round(s.currentRect.y)}`),
      });
    }
  };
  window.__shiftObserver = new PerformanceObserver((list) => record(list.getEntries()));
  window.__shiftObserver.observe({ type: 'layout-shift', buffered: true });
  window.__takeShifts = () => {
    record(window.__shiftObserver.takeRecords());
    return window.__shifts;
  };
}

// Two animation frames: one for the DOM change to be laid out, one for the
// layout-shift entry it produced to be queued where takeRecords() can see it.
async function settle(page) {
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

test.describe('without JavaScript', () => {
  test.use({ javaScriptEnabled: false });

  test('the platform-detection banner stays hidden', async ({ page }) => {
    await page.goto('/download/');
    // Nothing can fill it, so showing it shows a sentence with a hole in it.
    await expect(page.locator('#dl-detect')).toBeHidden();
  });
});

test.describe('platform detection under the Lighthouse desktop preset', () => {
  test.use(LIGHTHOUSE_DESKTOP);

  test.beforeEach(async ({ page }) => {
    await page.route(/fonts\.bunny\.net/, (route) => route.abort());
    await page.addInitScript(installControlledHintAndShiftRecorder);
  });

  test('is shown without waiting for the CPU hint', async ({ page }) => {
    await page.goto('/download/');
    // The hint is never delivered in this test. The user agent alone already
    // names the platform, so the banner must say so on its own.
    await expect(page.locator('#dl-detect')).toBeVisible();
    await expect(page.locator('#dl-detect-plat')).toHaveText('macOS · Intel/AMD (x86_64 / amd64)');
    await expect(page.locator('.dl-tab[data-os="mac"] .dl-tab-you')).toHaveCount(1);
  });

  test('a CPU hint that agrees with the user agent moves nothing', async ({ page }) => {
    await page.goto('/download/');
    await settle(page);
    await page.evaluate(() => window.__deliverCpuHint('x86'));
    await settle(page);
    await expect(page.locator('#dl-detect-plat')).toHaveText('macOS · Intel/AMD (x86_64 / amd64)');

    const shifts = await page.evaluate(() => window.__takeShifts());
    expect(shifts, `layout shifts on /download/ with web fonts blocked:\n${JSON.stringify(shifts, null, 2)}`).toEqual([]);
  });
});
