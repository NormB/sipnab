// SPDX-License-Identifier: MIT OR Apache-2.0

// The site's web fonts are its own, and loading them never moves a page.
//
// Until 2026-09-17 base.html pulled Inter and JetBrains Mono from
// fonts.bunny.net with `display=swap`. Swap renders the fallback first and
// re-lays the page out in the real font whenever it arrives, and on /download/
// that re-wrapped paragraphs and moved the platform tiles: 0.049-0.094 of
// cumulative layout shift on CI, the part of that page's Lighthouse budget left
// after the detection banner was fixed. Lighthouse could only sample that as a
// race; this file holds the fonts back and releases them on its own schedule.
//
// The faces are now the same files, served from /fonts/ (the @fontsource 5.3.0
// packages Bunny itself serves -- the woff2 bytes and unicode-ranges match), with
// `font-display: optional` and the latin faces preloaded. `optional` gives a
// font a block period of about 100ms (CSS Fonts 4 recommends 100ms or less) and
// no swap period: a font that is not ready by then is not used for that page
// view, so it can never re-lay out text already on screen.

const { test, expect } = require('@playwright/test');
const { settle, layoutBoxes } = require('./layout-probe');

test('every web font comes from the site itself', async ({ page, baseURL }) => {
  const origin = new URL(baseURL).origin;
  const fonts = [];
  page.on('request', (r) => {
    if (r.resourceType() === 'font') fonts.push(r.url());
  });
  for (const path of ['/', '/download/', '/docs/', '/analyze/']) {
    await page.goto(path, { waitUntil: 'networkidle' });
  }
  // Every page sets body and code text in a web font, so none requested means
  // the check below compared nothing.
  expect(fonts.length, 'font requests seen').toBeGreaterThan(0);
  expect(fonts.filter((u) => new URL(u).origin !== origin)).toEqual([]);
});

test('both families load', async ({ page }) => {
  await page.goto('/');
  // document.fonts.load() fetches the faces a font string needs even when
  // `optional` chose not to render them, so a wrong URL, a missing file or a
  // CSP that blocks font-src fails here instead of silently leaving every
  // reader on the fallback stack.
  const statuses = await page.evaluate(async () => {
    const out = {};
    for (const spec of ['400 16px Inter', '500 16px Inter', '600 16px Inter', '700 16px Inter',
      '400 16px "JetBrains Mono"', '500 16px "JetBrains Mono"']) {
      try {
        out[spec] = (await document.fonts.load(spec, 'sipnab')).map((f) => f.status);
      } catch (e) {
        out[spec] = [`rejected: ${e}`];
      }
    }
    return out;
  });
  for (const [spec, s] of Object.entries(statuses)) expect(s, spec).toEqual(['loaded']);
});

for (const path of ['/', '/download/']) {
  test(`a font that arrives late moves nothing on ${path}`, async ({ page }) => {
    let release;
    const gate = new Promise((r) => {
      release = r;
    });
    let held = 0;
    await page.route('**/*', async (route) => {
      if (route.request().resourceType() !== 'font') return route.continue();
      held += 1;
      await gate;
      return route.continue();
    });

    // Not `load`: the load event waits on the fonts this test is holding.
    await page.goto(path, { waitUntil: 'domcontentloaded' });
    await expect.poll(() => held, { message: 'no font was requested' }).toBeGreaterThan(0);
    // Well past the block period, so the page has committed to the fallback.
    // This is the one fixed wait in the file, and it is a property of the CSS
    // being tested rather than a guess at how long something takes.
    await page.waitForTimeout(600);
    await settle(page);
    const before = await layoutBoxes(page);

    release();
    await page.waitForFunction(() => document.fonts.status === 'loaded');
    await settle(page);
    const after = await layoutBoxes(page);

    const moved = after.map((box, i) => (box === before[i] ? null : `${before[i]}  ->  ${box}`)).filter(Boolean);
    expect(after.length, 'the font arriving added or removed elements').toBe(before.length);
    expect(moved.slice(0, 15), `${moved.length} layout boxes changed when the fonts arrived`).toEqual([]);
  });
}
