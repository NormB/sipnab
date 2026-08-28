// SPDX-License-Identifier: MIT OR Apache-2.0

// The homepage's two entry points, exercised in a real browser.
//
// Both are guarded statically in tests/site_journey_test.rs
// (`homepage_offers_a_zero_install_path`,
// `homepage_demo_wall_leads_with_outcomes`), and static analysis over the
// template is exactly the wrong instrument for the failure this file exists
// for: the arrow-key roving over the demo tablist reads a flat `.demo-tab`
// list, seven of which now sit inside a collapsed disclosure. Stepping onto a
// collapsed tab focuses NOTHING -- `.focus()` on a `display:none` element is a
// silent no-op -- while the following `.click()` still swaps the panel. The
// template parses, Vale passes, `zola build` succeeds, every Rust gate is
// green, and the reader watches the demo change under a focus ring that never
// moved. Only a browser can see it, so a browser checks it.

const { test, expect } = require('@playwright/test');

test('the hero offers the zero-install analyzer above the fold', async ({ page }) => {
  await page.goto('/');
  const cta = page.locator('.hero-actions a[href$="/analyze/"]');
  await expect(cta).toBeVisible();
  await expect(page.locator('.hero-actions-note')).toContainText(/in your browser/i);
});

test('disclosure collapses tabs 4-10 and roving respects it', async ({ page }) => {
  await page.goto('/');
  const tabs = page.locator('.demo-tab');
  expect(await tabs.count()).toBe(11);
  let visible = 0;
  for (let i = 0; i < 11; i++) if (await tabs.nth(i).isVisible()) visible++;
  expect(visible, 'visible tabs while collapsed').toBe(4);

  // A visible tab opens ITS panel (index derived from id, not NodeList order).
  await page.locator('#demo-tab-2').click();
  await expect(page.locator('#demo-panel-2')).toHaveClass(/active/);

  // Collapsed roving: ArrowRight from the last visible tab wraps to tab 0,
  // it does not step onto hidden tab 4.
  await page.locator('#demo-tab-3').click();
  await page.locator('#demo-tab-3').press('ArrowRight');
  expect(await page.evaluate(() => document.activeElement.id)).toBe('demo-tab-0');
  await expect(page.locator('#demo-panel-0')).toHaveClass(/active/);

  // Open it.
  await page.locator('#demo-more-btn').click();
  await expect(page.locator('#demo-more-btn')).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('#demo-more-btn')).toContainText('Fewer demos');
  visible = 0;
  for (let i = 0; i < 11; i++) if (await tabs.nth(i).isVisible()) visible++;
  expect(visible, 'visible tabs while open').toBe(11);

  // Open roving traverses all eleven.
  await page.locator('#demo-tab-3').click();
  await page.locator('#demo-tab-3').press('ArrowRight');
  expect(await page.evaluate(() => document.activeElement.id)).toBe('demo-tab-4');
  await expect(page.locator('#demo-panel-4')).toHaveClass(/active/);

  // A previously hidden tab opens its own panel.
  await page.locator('#demo-tab-10').click();
  await expect(page.locator('#demo-panel-10')).toHaveClass(/active/);

  // Collapsing while a hidden tab is selected falls back to the first.
  await page.locator('#demo-more-btn').click();
  await expect(page.locator('#demo-more-btn')).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('#demo-panel-0')).toHaveClass(/active/);
  await expect(page.locator('#demo-tab-0')).toHaveClass(/active/);
});
