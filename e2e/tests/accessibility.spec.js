// SPDX-License-Identifier: MIT OR Apache-2.0

// Accessibility gates over the BUILT site, via axe-core.
//
// WHY A BROWSER AND NOT A TEMPLATE TEST
//
// tests/site_journey_test.rs already reads website/templates/*.html by regular
// expression and asserts on individual attributes -- the hero's
// `fetchpriority`, the demo disclosure's `aria-expanded`. Those are the checks
// static analysis can make. What it structurally cannot do is compute a
// contrast ratio, resolve which element is actually focusable after CSS, or
// notice that a heading level was skipped once four templates and a Markdown
// body were composed into one document. axe-core needs a rendered DOM with
// styles applied, so it runs here.
//
// RULESET: wcag2a + wcag2aa
//
// Scoped with `withTags(['wcag2a', 'wcag2aa'])`, which selects the axe rules
// that map to a WCAG 2.0/2.1 Level A or AA success criterion. Deliberately NOT
// the full default ruleset:
//
//   * `best-practice` rules are axe's own house style, not a standard. They are
//     good advice, and several of them ("region", "landmark-one-main") would
//     fire on the analyzer page for reasons that are a design decision rather
//     than a defect. A gate that mixes a standard with taste gets argued with
//     and then muted.
//   * `wcag2aaa` is not the target. AAA contrast (7:1) would reject the site's
//     entire palette, which is a redesign, not a bug fix.
//   * `wcag21a`/`wcag21aa` tags are included implicitly by axe for rules that
//     carry both; naming the 2.0 tags keeps the selection stable across
//     axe-core minor versions, which have moved individual rules between the
//     2.1 and 2.2 tag sets before.
//
// SEVERITY: fail on serious + critical
//
// axe grades every violation `minor | moderate | serious | critical`. This
// gate fails on the top two and prints the rest. That is not leniency for its
// own sake: `moderate` covers rules like `landmark-unique` and heading-order
// where the fix is often a template restructure with a real chance of
// regressing layout, and a gate that lands red on day one gets disabled on day
// one. Moderate and minor findings are printed on every run, so raising the
// bar later is a one-line change against a known list rather than an
// exploration.
//
// The severity floor is asserted by a test at the bottom of this file, so the
// filter cannot be quietly widened to `critical` only.
//
// INCOMPLETE RESULTS ARE GATED TOO, WITH ONE NAMED EXCEPTION
//
// axe returns a fourth bucket beside violations/passes/inapplicable:
// `incomplete`, meaning the rule applied but axe could not decide. Most
// projects drop it, and dropping it is how the one real defect this gate found
// would have been missed -- `aria-prohibited-attr` on the analyzer's outcome
// list came back incomplete, not as a violation, because axe cannot know
// whether a screen reader will expose an `aria-label` on a bare `<div>`. It
// does not; the fix was a real one.
//
// `color-contrast` is excluded from that treatment, because on this site every
// incomplete instance of it is a case the rule cannot decide by construction
// rather than a case needing review: a decorative `aria-hidden` caret whose
// content is a single glyph ("Element content contains only non-text
// characters"), or a `<code>` block inside a demo panel that another element
// overlaps. Gating on those means gating on axe's uncertainty about
// characters that are not text.

const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

// Level A and AA. See the ruleset note above before changing this.
const WCAG_TAGS = ['wcag2a', 'wcag2aa'];

// The severities that fail a build. See the severity note above.
const BLOCKING_IMPACTS = ['serious', 'critical'];

// Rules whose `incomplete` results are advisory rather than blocking. See the
// note above -- one entry, one reason, and the reason is a property of the
// rule rather than of a page we would rather not fix.
const INCOMPLETE_NOT_GATED = ['color-contrast'];

// One page per template that renders on the published site, because a
// violation lives in a template and not in a URL:
//
//   /             index.html    -- hero, demo tablist, feature grid
//   /docs/        section.html  -- the generated docs index
//   /docs/tui/    page.html     -- a generated docs page (Markdown body,
//                                 sidebar, in-page table of contents)
//   /download/    download.html -- platform tables, checksums, copy buttons
//
// Adding a template to the site without adding it here leaves it ungated, so
// the list is asserted against the rendered site by
// `every_template_backed_page_is_covered` below.
const PAGES = [
  { url: '/', template: 'index.html' },
  { url: '/docs/', template: 'section.html' },
  { url: '/docs/tui/', template: 'page.html' },
  { url: '/download/', template: 'download.html' },
];

/** Render one axe finding as something a reader can act on without opening a report. */
function describe(v) {
  const where = v.nodes
    .slice(0, 5)
    .map((n) => {
      // `incomplete` nodes carry no failureSummary -- axe did not conclude, so
      // there is nothing to summarize. Fall back to the check messages, which
      // are what say WHY it could not decide.
      const why =
        n.failureSummary ||
        [...(n.any || []), ...(n.all || []), ...(n.none || [])]
          .map((c) => `${c.id}: ${c.message}`)
          .join('\n') ||
        '(no detail reported)';
      return `      ${n.target.join(' ')}\n        ${why.replace(/\n/g, '\n        ')}`;
    })
    .join('\n');
  const more = v.nodes.length > 5 ? `\n      ... and ${v.nodes.length - 5} more node(s)` : '';
  return `  [${v.impact}] ${v.id}: ${v.help}\n    ${v.helpUrl}\n${where}${more}`;
}

async function scan(page, url) {
  await page.goto(url, { waitUntil: 'networkidle' });
  return new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
}

/** Everything that must be zero for a page to pass: violations plus reviewable incompletes. */
function blockingFindings(results) {
  const violations = results.violations.filter((v) => BLOCKING_IMPACTS.includes(v.impact));
  const undecided = results.incomplete.filter(
    (v) => BLOCKING_IMPACTS.includes(v.impact) && !INCOMPLETE_NOT_GATED.includes(v.id),
  );
  return [...violations, ...undecided];
}

for (const { url, template } of PAGES) {
  test(`axe: ${url} (${template}) has no serious or critical WCAG 2 A/AA violations`, async ({
    page,
  }) => {
    const results = await scan(page, url);

    const blocking = blockingFindings(results);
    const advisory = [
      ...results.violations.filter((v) => !BLOCKING_IMPACTS.includes(v.impact)),
      ...results.incomplete.filter((v) => !blocking.includes(v)),
    ];

    // Printed on every run, pass or fail. A finding nobody can see is a finding
    // nobody fixes, and this is the list to work from when the floor is raised.
    if (advisory.length > 0) {
      console.log(`axe advisory (not gated) on ${url}:\n${advisory.map(describe).join('\n')}`);
    }

    expect(
      blocking,
      `serious/critical WCAG 2 A/AA violations on ${url} (${template}):\n${blocking
        .map(describe)
        .join('\n')}`,
    ).toEqual([]);
  });
}

// THE PREMISE, CHECKED BEFORE ANY RESULT FROM THIS FILE IS BELIEVED.
//
// Zola renders every internal URL as an ABSOLUTE `config.base_url` URL, and
// base_url is `https://sipnab.com`. Serve that build on 127.0.0.1 and the page
// asks the real production site for its stylesheet, its script and every
// image -- except it does not even get that far, because base.html's own
// `default-src 'self'` blocks all of them as cross-origin.
//
// The result is a page that returns 200, renders its full HTML, satisfies every
// smoke test, and has NO CSS APPLIED. Measured on this repository on
// 2026-08-28: `document.styleSheets.length` 1 instead of 2, `body`
// background the browser default instead of #0a0e14, and axe reporting ZERO
// violations on all five pages -- because with no stylesheet there are no
// computed colors to fail a contrast check and no `overflow-x: auto` to make a
// region scrollable. Rebuilt with `--base-url http://127.0.0.1:1111`, the same
// five pages produced two genuine serious violations.
//
// A clean run against an unstyled page is the exact shape of a gate that
// measures nothing and reports success, so the premise is asserted rather than
// assumed. Build the site under test with:
//
//     zola build --base-url http://127.0.0.1:1111
//
// (127.0.0.1 is exempt from the policy's `upgrade-insecure-requests`, so an
// http origin is fine; a hostname would not be.)
test('the site under test serves its own assets (a CSS-less page cannot fail a contrast check)', async ({
  page,
}) => {
  const failures = [];
  page.on('requestfailed', (r) => failures.push(`${r.failure()?.errorText} ${r.url()}`));
  page.on('response', (r) => {
    if (r.status() >= 400) failures.push(`HTTP ${r.status()} ${r.url()}`);
  });
  await page.goto('/', { waitUntil: 'networkidle' });

  const { sheets, bg, nodes } = await page.evaluate(() => ({
    sheets: document.styleSheets.length,
    bg: getComputedStyle(document.body).backgroundColor,
    nodes: document.querySelectorAll('*').length,
  }));

  expect(
    failures,
    `the page under test could not load its own assets. If these are \
https://sipnab.com/... URLs the site was built with the production base_url \
and its own CSP blocked them; rebuild with \
\`zola build --base-url ${new URL(page.url()).origin}\`:\n  ${failures.join('\n  ')}`,
  ).toEqual([]);

  // A stylesheet OBJECT is not a stylesheet that applied: a blocked <link>
  // still leaves an entry in document.styleSheets on some paths. The
  // background color is the witness that rules were actually computed, and
  // this site's is an explicit dark value, never the browser default.
  expect(bg, 'body background -- a default white means no site CSS applied').not.toBe(
    'rgba(0, 0, 0, 0)',
  );
  expect(bg).not.toBe('rgb(255, 255, 255)');
  expect(sheets, 'stylesheets attached to the homepage').toBeGreaterThanOrEqual(2);
  // 460 measured on 2026-08-28; a floor well under it catches a template that
  // rendered its shell and nothing else.
  expect(nodes, 'DOM elements on the homepage').toBeGreaterThan(200);
});

// A scan that analyzed nothing passes. axe returns an empty `violations` array
// for a page it never reached, for a selector that matched no element, and for
// a build where the injection failed -- three different bugs with one green
// symptom, which is the shape this repository has been bitten by before.
//
// `passes` is the witness: it is the list of rules axe evaluated and that held.
// A real page produces dozens. Zero means the ruleset was empty or the DOM was.
test('the axe scan actually evaluated rules (an empty scan is not a pass)', async ({ page }) => {
  const results = await scan(page, '/');
  // Measured 2026-08-28 at e403d109: 30 rules passed on the homepage, 25-28 on
  // the other four pages. 20 is a floor under the real figure, not a guess --
  // low enough not to fail on an ordinary content change, high enough that the
  // 10-pass reading a half-rendered page produced (observed on this repository
  // while a concurrent `zola build` had emptied website/public) fails here.
  expect(results.passes.length, 'axe rules that ran and passed on the homepage').toBeGreaterThan(20);
  // The tag filter narrowed the run rather than selecting everything: every
  // rule axe reports on must carry one of the tags asked for.
  for (const r of [...results.passes, ...results.violations]) {
    expect(
      r.tags.some((t) => WCAG_TAGS.includes(t)),
      `rule ${r.id} ran but carries none of ${WCAG_TAGS.join(', ')} (tags: ${r.tags.join(', ')})`,
    ).toBe(true);
  }
});

// The gate's own configuration, asserted rather than assumed. Narrowing
// BLOCKING_IMPACTS to ['critical'] would silently halve the gate while every
// test above still passed; this fails instead.
test('the gate blocks on serious as well as critical', async () => {
  expect(BLOCKING_IMPACTS).toContain('critical');
  expect(BLOCKING_IMPACTS).toContain('serious');
  expect(WCAG_TAGS).toEqual(['wcag2a', 'wcag2aa']);
  // The incomplete exemption list is a single named rule with a documented
  // reason. Appending to it is how this gate would be hollowed out one page at
  // a time, so growing it has to be a deliberate edit here as well.
  expect(INCOMPLETE_NOT_GATED).toEqual(['color-contrast']);
});

// Every page the site renders from its own template is scanned. The PAGES list
// is hand-written, so it drifts the moment someone adds a template -- and the
// failure mode is silent: the new page is simply never checked.
//
// The homepage's own navigation is the oracle. Anything reachable from it that
// is a top-level site area must either be in PAGES or be listed here as a
// deliberate exclusion with a reason.
const NOT_SCANNED = {
  // The analyzer is a WebAssembly application, not a document. Its empty state
  // is worth scanning, but its post-load state depends on a PCAP parse, and
  // axe against a half-populated call table reports on rows that exist only in
  // that run. Covered by its own targeted test below instead.
  '/analyze/': 'scanned separately in its empty state; post-parse DOM is data-dependent',
  // Contributor License Agreement: a static prose page rendered by page.html,
  // which /docs/tui/ already covers.
  '/cla/': 'page.html is already covered by /docs/tui/',
  // Release notes index, rendered by notes.html; entries are generated from
  // release metadata and change on every release.
  '/notes/': 'notes.html renders generated release metadata',
};

test('every top-level site area is either scanned or excluded with a reason', async ({ page }) => {
  await page.goto('/');
  const areas = await page.locator('a[href^="/"]').evaluateAll((as) =>
    as
      .map((a) => new URL(a.getAttribute('href'), 'http://x').pathname)
      // Top-level only: /docs/filter-dsl/ is the same template as /docs/tui/.
      .filter((p) => /^\/[a-z0-9-]*\/?$/.test(p)),
  );
  const covered = new Set([...PAGES.map((p) => p.url), ...Object.keys(NOT_SCANNED)]);
  const uncovered = [...new Set(areas)].filter((p) => !covered.has(p));
  expect(
    uncovered,
    `site areas linked from the homepage that no axe test covers and no exclusion explains:\n  ${uncovered.join(
      '\n  ',
    )}`,
  ).toEqual([]);
});

// The analyzer's empty state -- the first thing a visitor arriving from the
// homepage call to action sees, and the one part of that page whose DOM does
// not depend on a parse.
test('axe: /analyze/ empty state has no serious or critical violations', async ({ page }) => {
  await page.goto('/analyze/', { waitUntil: 'networkidle' });
  const results = await new AxeBuilder({ page })
    .withTags(WCAG_TAGS)
    // The results region is empty until a capture is parsed; scanning it is
    // scanning nothing, and excluding it keeps the finding list about the
    // empty state this test is named for.
    .exclude('#results')
    .analyze();
  const blocking = blockingFindings(results);
  expect(
    blocking,
    `serious/critical WCAG 2 A/AA violations on /analyze/:\n${blocking.map(describe).join('\n')}`,
  ).toEqual([]);
});
