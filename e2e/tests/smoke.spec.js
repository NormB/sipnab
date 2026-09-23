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
  // Refused the way the browser refuses it: a policy with no inline hash.
  // The first version cut the <script> elements out with a regex, which
  // CodeQL (js/bad-tag-filter) rightly calls an incomplete HTML filter, and
  // which tested a page with no script rather than a page whose script the
  // browser would not run.
  test('every card and tile is opaque when the inline script is blocked', async ({ page }) => {
    await page.route('**/', async (route) => {
      const res = await route.fetch();
      await route.fulfill({
        response: res,
        headers: { ...res.headers(), 'content-security-policy': "script-src 'self'" },
      });
    });
    const refused = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error' && /Content Security Policy/i.test(msg.text())) refused.push(msg.text());
    });
    await page.goto('/');
    expect(refused.length, 'the policy refused no inline script, so this proves nothing').toBeGreaterThan(0);
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
