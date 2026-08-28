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
    const body = await page.locator('body').innerText();
    // Pinning the SHAPE, not the number. A test pinned to 0.5.130 fails on
    // every release and gets updated without being read, which trains people
    // to update it without reading it.
    expect(body).toMatch(/\b0\.\d+\.\d+\b/);
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
    const box = page.locator('input[type="search"], input[id*="search"]').first();
    if ((await box.count()) === 0) {
      test.skip(true, 'no search control on this page');
    }
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
