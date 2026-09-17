// SPDX-License-Identifier: MIT OR Apache-2.0

// Shared by the specs that assert a page does not move. Not a spec itself:
// Playwright only collects *.spec.js, and site_journey_test's
// every_e2e_spec_runs_in_the_quality_workflow only lists those.

// Two animation frames: one for the DOM change to be laid out, one for the
// layout-shift entry it produced to be queued where takeRecords() can see it.
async function settle(page) {
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
}

// The layout box of every element on the page, keyed by position in the DOM.
// This is the direct form of "moves nothing". The Layout Instability API is not
// enough on its own: a badge put back into the tile's flex row pushed each
// download icon 70px sideways and it reported no shift at all (checked
// 2026-09-17 by mutation), while a reader would watch the icon jump.
//
// offset* rather than getBoundingClientRect(), because the panels animate in
// with a transform and a transform is not layout -- but summed up the whole
// offsetParent chain. A single offsetLeft is relative to the nearest positioned
// ancestor, so marking a tile `position: relative` changed every child's
// offsetLeft without moving a pixel, and the first version of this check
// failed the correct implementation. Borders are added back for the same
// reason (see the loop).
async function layoutBoxes(page) {
  return page.evaluate(() =>
    Array.from(document.body.querySelectorAll('*'))
      .filter((e) => e instanceof HTMLElement)
      .map((e, i) => {
        let x = 0;
        let y = 0;
        for (let n = e; n; n = n.offsetParent) {
          // offsetLeft starts at the parent's PADDING edge, so its border
          // (clientLeft) has to be added back or a 1px-bordered tile becoming
          // positioned reads as its children moving 1px.
          x += n.offsetLeft + (n.offsetParent ? n.offsetParent.clientLeft : 0);
          y += n.offsetTop + (n.offsetParent ? n.offsetParent.clientTop : 0);
        }
        const cls = typeof e.className === 'string' && e.className ? `.${e.className.split(' ')[0]}` : '';
        return `${i} ${e.tagName.toLowerCase()}${e.id ? `#${e.id}` : ''}${cls} ${x},${y} ${e.offsetWidth}x${e.offsetHeight}`;
      }),
  );
}

module.exports = { settle, layoutBoxes };
