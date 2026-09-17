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

test('the disclosure hides the collapsed tabs and roving respects it', async ({ page }) => {
  await page.goto('/');
  const tabs = page.locator('.demo-tab');

  // WHICH tabs lead and which collapse is the template's decision, pinned by
  // `homepage_demo_wall_leads_with_outcomes` in tests/site_journey_test.rs.
  // This spec checks that the browser honors whatever that decision is, so it
  // counts from the markup instead of restating it. It used to say "eleven
  // tabs, four visible"; the wall grew to twelve and five, the Rust test was
  // updated, and this file -- which no workflow ran -- stayed red on main.
  const ids = await tabs.evaluateAll((ts) => ts.map((t) => t.id));
  const total = ids.length;
  expect(ids, 'tab ids run demo-tab-0 upward with no gap').toEqual(
    Array.from({ length: total }, (_, i) => `demo-tab-${i}`),
  );
  const collapsed = await page.locator('#demo-tabs-more .demo-tab').count();
  const leading = total - collapsed;
  // Without both groups there is no disclosure to test, and every assertion
  // below would pass about nothing.
  expect(collapsed, 'tabs inside #demo-tabs-more').toBeGreaterThan(0);
  expect(leading, 'tabs outside #demo-tabs-more').toBeGreaterThan(2);
  const lastLeading = `demo-tab-${leading - 1}`;

  const countVisible = async () => {
    let n = 0;
    for (let i = 0; i < total; i++) if (await tabs.nth(i).isVisible()) n++;
    return n;
  };
  expect(await countVisible(), 'visible tabs while collapsed').toBe(leading);

  // A visible tab opens ITS panel (index derived from id, not NodeList order).
  await page.locator('#demo-tab-2').click();
  await expect(page.locator('#demo-panel-2')).toHaveClass(/active/);

  // Collapsed roving: ArrowRight from the last visible tab wraps to tab 0,
  // it does not step onto the first collapsed tab.
  await page.locator(`#${lastLeading}`).click();
  await page.locator(`#${lastLeading}`).press('ArrowRight');
  expect(await page.evaluate(() => document.activeElement.id)).toBe('demo-tab-0');
  await expect(page.locator('#demo-panel-0')).toHaveClass(/active/);

  // Open it.
  await page.locator('#demo-more-btn').click();
  await expect(page.locator('#demo-more-btn')).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('#demo-more-btn')).toContainText('Fewer demos');
  expect(await countVisible(), 'visible tabs while open').toBe(total);

  // Open roving steps from the last leading tab onto the first collapsed one.
  await page.locator(`#${lastLeading}`).click();
  await page.locator(`#${lastLeading}`).press('ArrowRight');
  expect(await page.evaluate(() => document.activeElement.id)).toBe(`demo-tab-${leading}`);
  await expect(page.locator(`#demo-panel-${leading}`)).toHaveClass(/active/);

  // A previously hidden tab opens its own panel.
  await page.locator(`#demo-tab-${total - 1}`).click();
  await expect(page.locator(`#demo-panel-${total - 1}`)).toHaveClass(/active/);

  // Collapsing while a hidden tab is selected falls back to the first.
  await page.locator('#demo-more-btn').click();
  await expect(page.locator('#demo-more-btn')).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('#demo-panel-0')).toHaveClass(/active/);
  await expect(page.locator('#demo-tab-0')).toHaveClass(/active/);
});
