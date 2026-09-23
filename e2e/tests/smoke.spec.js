// SPDX-License-Identifier: MIT OR Apache-2.0

// Smoke tests over the BUILT site.
//
// The bar here is deliberately not "the page returned 200". A Zola build that
// renders an empty template returns 200 for every route, so a status-code suite
// stays green through exactly the failure it was added to catch. Each test
// below asserts something the page must CONTAIN to be useful.

const { test, expect } = require('@playwright/test');

test.describe('homepage', () => {
  test('states what sipnab is and offers a download', async ({ page }) => {
    await page.goto('/');
    // The tagline, not the <title>: a title survives a template that renders
    // nothing else.
    await expect(page.locator('body')).toContainText(/SIP/i);
    const download = page.locator('a[href*="/download"]').first();
    await expect(download).toBeVisible();
  });

  test('advertises a version that looks like a release', async ({ page }) => {
    await page.goto('/');
    // Pinning the SHAPE, not the number. A test pinned to 0.5.130 fails on
    // every release and gets updated without being read, which trains people
    // to update it without reading it.
    //
    // The badge, not the body text. This read `/\b0\.\d+\.\d+\b/` over the
    // whole page, and the homepage writes every version as `v0.5.x` -- there
    // is no word boundary between the `v` and the `0`, so it could never match,
    // and no workflow ran it to find that out.
    await expect(page.locator('.hero-title .version-badge')).toHaveText(/^v\d+\.\d+\.\d+$/);
  });

  test('every download link points at a real release asset host', async ({ page }) => {
    await page.goto('/download/');
    const hrefs = await page.locator('a[href*="releases/download"]').evaluateAll(
      (as) => as.map((a) => a.getAttribute('href')),
    );
    expect(hrefs.length).toBeGreaterThan(0);
    for (const href of hrefs) {
      expect(href).toMatch(/^https:\/\/github\.com\/NormB\/sipnab\/releases\/download\/v\d/);
    }
  });
});

// Content that exists only once a script has run is content a reader may
// never see. The homepage hid its capability cards and stat tiles at opacity 0
// until an IntersectionObserver saw them scroll into view. A full-page
// screenshot never scrolls, a reader who jumps past a section never triggers
// it, and while a deploy's new inline-script hash is not yet in the CDN's CSP
// the script does not run at all. Each of those left "What you can do with it"
// and "Measured, not promised" as headings over blank space.
test.describe('homepage content does not wait on a script', () => {
  const SELECTORS = ['.feature-card', '.arch-item', '.notes-card', '.comparison-table'];

  async function opacities(page) {
    return page.evaluate((sels) => sels.flatMap((s) => [...document.querySelectorAll(s)].map(
      (e) => `${s} ${getComputedStyle(e).opacity}`,
    )), SELECTORS);
  }

  test('every card and tile is opaque on load, without scrolling', async ({ page }) => {
    await page.goto('/');
    const all = await opacities(page);
    expect(all.length, 'found no cards or tiles at all').toBeGreaterThan(8);
    expect(all.filter((o) => !o.endsWith(' 1'))).toEqual([]);
  });

  test('every card and tile is opaque with scripting off', async ({ browser }) => {
    const context = await browser.newContext({ javaScriptEnabled: false });
    const page = await context.newPage();
    await page.goto('/');
    const all = await opacities(page);
    expect(all.length, 'found no cards or tiles at all').toBeGreaterThan(8);
    expect(all.filter((o) => !o.endsWith(' 1'))).toEqual([]);
    await context.close();
  });

  // Scripting on, but the page's inline script refused, which is what a
  // browser does between a deploy and the CSP job that pins the new hash.
  test('every card and tile is opaque when the inline script is blocked', async ({ page }) => {
    await page.route('**/', async (route) => {
      const res = await route.fetch();
      const body = (await res.text()).replace(/<script>[\s\S]*?<\/script>/g, '');
      await route.fulfill({ response: res, body });
    });
    await page.goto('/');
    const all = await opacities(page);
    expect(all.length, 'found no cards or tiles at all').toBeGreaterThan(8);
    expect(all.filter((o) => !o.endsWith(' 1'))).toEqual([]);
  });
});

test.describe('documentation', () => {
  test('the docs index lists pages and they resolve', async ({ page }) => {
    await page.goto('/docs/');
    const links = page.locator('a[href*="/docs/"]');
    const count = await links.count();
    // A docs index that lists nothing is the failure this catches; the site
    // has dozens of pages, so a handful means the template broke.
    expect(count).toBeGreaterThan(5);
  });

  test('a deep documentation page renders its own content', async ({ page }) => {
    const res = await page.goto('/docs/filter-dsl/');
    expect(res.status()).toBe(200);
    await expect(page.locator('h1, h2').first()).toBeVisible();
    const text = await page.locator('body').innerText();
    expect(text.length).toBeGreaterThan(500);
  });
});

test.describe('search', () => {
  test('the search control exists and accepts input', async ({ page }) => {
    await page.goto('/');
    // The search field lives inside a modal that the trigger opens. Filling it
    // without opening the modal only ever worked because an unstyled build --
    // one whose CSS the CSP blocked -- left the overlay visible. Open it the
    // way a reader does, so this test fails when the control is really broken
    // rather than passing because the page lost its stylesheet.
    const trigger = page.locator('#search-trigger');
    if ((await trigger.count()) > 0) {
      await trigger.first().click();
    }
    const box = page.locator('input[type="search"], input[id*="search"]').first();
    if ((await box.count()) === 0) {
      test.skip(true, 'no search control on this page');
    }
    await expect(box).toBeVisible();
    await box.fill('dialog');
    await expect(box).toHaveValue('dialog');
  });
});

test.describe('no page ships a broken asset', () => {
  test('the homepage loads every asset it references', async ({ page }) => {
    const failed = [];
    page.on('response', (r) => {
      if (r.status() >= 400) failed.push(`${r.status()} ${r.url()}`);
    });
    await page.goto('/', { waitUntil: 'networkidle' });
    expect(failed, `assets the homepage could not load:\n${failed.join('\n')}`).toEqual([]);
  });
});

// A code block's language badge and copy button sat on top of the command's
// first line. On a phone the command runs wider than the screen, so its end
// scrolled under them: /docs/first-cli-triage/ showed "curl -LO
// https://sipnab.com/demos/sampl" with the rest hidden behind "BASH". And the
// copy button only appeared on hover, which a touch screen never sends.
// /download faded its header, platform tabs and open panel in over 0.6s.
// That is the same pattern that left the homepage blank when its script did
// not run, and it made the first thing a reader sees arrive late.
test('the download page shows its content without an entrance animation', async ({ page }) => {
  await page.goto('/download/', { waitUntil: 'domcontentloaded' });
  const states = await page.evaluate(() => ['.dl-hero', '.dl-tabs', '.dl-panel.active'].map((sel) => {
    const e = document.querySelector(sel);
    if (!e) return `${sel} missing`;
    const cs = getComputedStyle(e);
    return `${sel} opacity=${cs.opacity} animation=${cs.animationName}`;
  }));
  expect(states).toEqual([
    '.dl-hero opacity=1 animation=none',
    '.dl-tabs opacity=1 animation=none',
    '.dl-panel.active opacity=1 animation=none',
  ]);
});

// The Scalar viewer renders the OpenAPI document's own title ("sipnab REST
// API") as a second h1 under the page's "OpenAPI reference", so a screen
// reader's page outline had two top-level headings.
test('the API reference page has one top-level heading', async ({ page }) => {
  await page.goto('/api-reference/');
  await page.waitForSelector('#scalar-app h1', { timeout: 15000 });
  await page.waitForTimeout(500);
  const levels = await page.evaluate(() => [...document.querySelectorAll('h1')].map(
    (h) => h.getAttribute('aria-level') || '1',
  ));
  expect(levels.filter((l) => l === '1')).toEqual(['1']);
});

test.describe('docs code blocks on a phone', () => {
  test('the badge and copy button sit above the code, and the button shows', async ({ browser }) => {
    const context = await browser.newContext({
      viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true,
    });
    const page = await context.newPage();
    await page.goto('/docs/first-cli-triage/');
    const blocks = await page.evaluate(() => [...document.querySelectorAll('.doc-body pre:not(.mermaid)')]
      .slice(0, 6)
      .map((pre) => {
        const box = pre.getBoundingClientRect();
        const codeTop = box.top + parseFloat(getComputedStyle(pre).paddingTop);
        const btn = pre.querySelector('.doc-copy-btn');
        const b = btn.getBoundingClientRect();
        const badge = getComputedStyle(pre, '::before');
        const badgeBottom = badge.content === 'none' || badge.display === 'none' ? box.top
          : box.top + parseFloat(badge.top || '0') + parseFloat(badge.height || '0');
        return { buttonBottom: b.bottom, badgeBottom, codeTop, opacity: getComputedStyle(btn).opacity };
      }));
    expect(blocks.length, 'no code blocks found').toBeGreaterThan(2);
    for (const b of blocks) {
      expect(b.buttonBottom, 'the copy button overlaps the first line of code').toBeLessThanOrEqual(b.codeTop + 1);
      expect(b.badgeBottom, 'the language badge overlaps the first line of code').toBeLessThanOrEqual(b.codeTop + 1);
      expect(b.opacity, 'the copy button is invisible on a touch screen').toBe('1');
    }
    await context.close();
  });
});
