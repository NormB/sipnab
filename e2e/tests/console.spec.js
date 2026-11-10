// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

// The web console (`--api-console`), in a real browser.
//
// WHAT IS UNDER TEST
//
// The four files sipnab embeds from src/output/api/console/ and serves at
// /console/. The Rust tests beside the module (src/output/api/console.rs) hold
// the server to its routes and headers. They cannot run the scripts, so every
// rule about what the page DOES is here: what it sends, what it draws, what it
// says when a request fails, and that captured text never becomes markup.
//
// HOW THE PAGE IS SERVED
//
// Playwright answers every request itself. The console files are read from the
// source tree and answered with the headers the server sends, the
// Content-Security-Policy included, so a script the policy refuses is refused
// here too. The `/v1/` routes are answered from a fixture each test builds.
// No sipnab binary runs: the job that runs this file has none, and a fixture
// can hold values no capture file is easy to make hold.
//
// The header values are the server's. `the_browser_tests_use_the_server_headers`
// in src/output/api/console.rs fails if a header below differs from the one
// the server sends.

const fs = require('fs');
const path = require('path');
const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

const CONSOLE_DIR =
  process.env.SIPNAB_CONSOLE_DIR || path.join(__dirname, '..', '..', 'src', 'output', 'api', 'console');

const CONTENT_SECURITY_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const SECURITY_HEADERS = {
  'content-security-policy': CONTENT_SECURITY_POLICY,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
  'x-frame-options': 'DENY',
  'cross-origin-resource-policy': 'same-origin',
};

const FILES = {
  '/console/': ['index.html', 'text/html; charset=utf-8'],
  '/console/console.css': ['console.css', 'text/css; charset=utf-8'],
  '/console/console.js': ['console.js', 'text/javascript; charset=utf-8'],
  '/console/console-core.js': ['console-core.js', 'text/javascript; charset=utf-8'],
};

const TOKEN = 'console-test-token-0123456789abcdef';

// Captured values an attacker chooses. Each would run, or load, if the page
// ever wrote it as markup or as a link.
const MARKUP = '<img src=x onerror="window.__pwned=1">';
const SCRIPT = '"><script>window.__pwned=1</script>';
const SCHEME = 'javascript:window.__pwned=1';
// A Call-ID that is a path of its own. Sent raw it would name another route.
const PATH_CALL_ID = 'a/../../persistence?enabled=false#x%00';

const RUNTIME = {
  schema_version: 1,
  uptime_seconds: 93784,
  dialogs: { used: 2, capacity: 100000, pct: 0.002 },
  streams: { used: 1, capacity: 10000, pct: 0.01 },
  capture_packets_total: 852,
};

function summary(callId, extra = {}) {
  return {
    call_id: callId,
    state: 'Completed',
    method: 'INVITE',
    from_user: 'alice',
    to_user: 'bob',
    msg_count: 8,
    final_status_code: 200,
    updated_at: '2026-09-15T14:00:03+02:00',
    ...extra,
  };
}

function page1(dialogs, cursor = 'v2:7', instance = 'capture-a') {
  return {
    schema_version: 1,
    dialogs,
    returned: dialogs.length,
    next_cursor: cursor,
    capture_identity: { node: 'capture-01', instance },
  };
}

function detail(callId, extra = {}) {
  return {
    schema_version: 1,
    call_id: callId,
    state: 'Completed',
    method: 'INVITE',
    from: 'alice',
    to: 'bob',
    from_display: 'Alice Example',
    to_display: 'Bob Example',
    final_status_code: 200,
    final_status_reason: 'OK',
    msg_count: 8,
    duration_sec: 45.2,
    timing: { pdd_ms: 847, setup_ms: 2134, retransmits: 0 },
    sdp_timeline: [
      {
        timestamp: '2026-09-15T12:00:00Z',
        direction: 'offer',
        codecs: ['PCMU', 'telephone-event'],
        media_addr: '192.0.2.1',
        media_port: 10000,
        mode: 'sendrecv',
      },
    ],
    streams: [
      {
        ssrc: '0x1a2b3c4d',
        codec: 'PCMU',
        src: '192.0.2.1:10000',
        dst: '192.0.2.2:20000',
        packets: 4820,
        loss_pct: 0,
        jitter_ms: 2.1,
      },
    ],
    ...extra,
  };
}

function tree(callId, legs) {
  return {
    schema_version: 1,
    root_call_id: callId,
    legs: legs || [
      { call_id: callId, depth: 0, parent_call_id: null, score: null, strategy: null, followed: true },
      { call_id: 'leg-b@sbc.example.com', depth: 1, parent_call_id: callId, score: 100, strategy: 'session_id', followed: true },
    ],
    truncated: false,
  };
}

const PROBLEM_401 = { type: 'https://sipnab.com/problems/unauthorized', title: 'Unauthorized', status: 401 };

function json(route, status, body) {
  return route.fulfill({
    status,
    contentType: status >= 400 ? 'application/problem+json' : 'application/json',
    body: JSON.stringify(body),
  });
}

// Serve the console files and answer `/v1/` from `handlers`: a map from
// "<pathname>" to a function (route, url, request) or to a body answered 200.
// Returns the list of API requests seen, each as { path, search, auth }.
async function serve(page, handlers) {
  const seen = [];
  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const file = FILES[url.pathname];
    if (file) {
      return route.fulfill({
        status: 200,
        headers: { ...SECURITY_HEADERS, 'content-type': file[1] },
        body: fs.readFileSync(path.join(CONSOLE_DIR, file[0]), 'utf8'),
      });
    }
    if (url.pathname.startsWith('/v1/')) {
      // The raw request target: what the server would be asked for.
      const raw = request.url().slice(url.origin.length);
      seen.push({ path: url.pathname, raw, search: url.search, auth: await request.headerValue('authorization') });
      const handler = handlers[url.pathname] ?? handlers['*'];
      if (handler === undefined) {
        return json(route, 404, { type: 'https://sipnab.com/problems/not-found', title: 'Not Found', status: 404 });
      }
      if (typeof handler === 'function') {
        return handler(route, url, request);
      }
      return json(route, 200, handler);
    }
    return route.fulfill({ status: 404, headers: SECURITY_HEADERS, body: '' });
  });
  return seen;
}

// The usual capture: two dialogs, one page.
function usual(overrides = {}) {
  const a = 'call-a@example.com';
  return {
    '/v1/runtime': RUNTIME,
    '/v1/dialogs/tail': page1([summary(a), summary('call-b@example.com', { state: 'Failed', final_status_code: 486 })]),
    [`/v1/dialogs/${encodeURIComponent(a)}`]: detail(a),
    [`/v1/dialogs/${encodeURIComponent(a)}/tree`]: tree(a),
    ...overrides,
  };
}

async function open(page) {
  await page.goto('/console/');
  await expect(page.getByRole('heading', { level: 1, name: 'sipnab console' })).toBeVisible();
}

async function connect(page, token = TOKEN) {
  await open(page);
  await page.getByLabel('API token').fill(token);
  await page.getByRole('button', { name: 'Connect' }).click();
}

// Fails the test if the browser reported a refused load or script: the page
// must work under its own policy.
function watchPolicy(page) {
  const violations = [];
  page.on('console', (message) => {
    if (message.type() === 'error' && /Content Security Policy|Refused to/i.test(message.text())) {
      violations.push(message.text());
    }
  });
  page.on('pageerror', (error) => violations.push(String(error)));
  return violations;
}

// ── Success ───────────────────────────────────────────────────────────────

test.describe('success', () => {
  test('the page loads under its own policy with no refused load', async ({ page }) => {
    const violations = watchPolicy(page);
    await serve(page, usual());
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    expect(violations).toEqual([]);
  });

  test('connecting sends the token as a bearer credential', async ({ page }) => {
    const seen = await serve(page, usual());
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    expect(seen.length).toBeGreaterThan(0);
    for (const request of seen) {
      expect(request.auth, request.path).toBe(`Bearer ${TOKEN}`);
    }
  });

  test('the status header shows uptime, store use and packets', async ({ page }) => {
    await serve(page, usual());
    await connect(page);
    await expect(page.locator('#runtime-uptime')).toHaveText('1d 2h 3m 4s');
    await expect(page.locator('#runtime-dialogs')).toHaveText('2 of 100000 (0.0%)');
    await expect(page.locator('#runtime-streams')).toHaveText('1 of 10000 (0.0%)');
    await expect(page.locator('#runtime-packets')).toHaveText('852');
  });

  test('the list shows each dialog with its state in words', async ({ page }) => {
    await serve(page, usual());
    await connect(page);
    const failed = page.locator('#dialog-rows tr', { hasText: 'call-b@example.com' });
    await expect(failed.locator('td').nth(0)).toHaveText('Failed');
    await expect(failed.locator('td').nth(5)).toHaveText('486');
    await expect(page.locator('#list-state')).toContainText('Showing 2 dialogs');
  });

  test('a time is shown in UTC with the offset stated', async ({ page }) => {
    await serve(page, usual());
    await connect(page);
    // 14:00:03+02:00 is 12:00:03 UTC.
    await expect(page.locator('#dialog-rows tr').first().locator('td').last()).toHaveText(
      '2026-09-15 12:00:03 UTC (+00:00)',
    );
  });

  test('the first page asks for a bounded number of rows and no cursor', async ({ page }) => {
    const seen = await serve(page, usual());
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    const tail = seen.filter((r) => r.path === '/v1/dialogs/tail');
    expect(tail).toHaveLength(1);
    expect(tail[0].search).toBe('?limit=50');
  });

  test('Load more passes the cursor of the last page back as since', async ({ page }) => {
    let calls = 0;
    const seen = await serve(
      page,
      usual({
        '/v1/dialogs/tail': (route) => {
          calls += 1;
          return json(route, 200, calls === 1 ? page1([summary('call-a@example.com')], 'v2:41') : page1([summary('call-c@example.com')], 'v2:42'));
        },
      }),
    );
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(1);
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    const tail = seen.filter((r) => r.path === '/v1/dialogs/tail');
    expect(tail[1].search).toBe('?limit=50&since=v2%3A41');
  });

  test('opening a dialog shows its fields, SDP, streams and legs', async ({ page }) => {
    await serve(page, usual());
    await connect(page);
    await page.getByRole('button', { name: 'call-a@example.com' }).click();
    await expect(page.getByRole('heading', { level: 2, name: 'Dialog' })).toBeFocused();
    const fields = page.locator('#detail-fields');
    await expect(fields).toContainText('Alice Example');
    await expect(fields).toContainText('200 OK');
    await expect(fields).toContainText('847 ms');
    await expect(page.locator('#sdp-rows tr')).toHaveCount(1);
    await expect(page.locator('#sdp-rows')).toContainText('PCMU, telephone-event');
    await expect(page.locator('#sdp-rows')).toContainText('192.0.2.1 port 10000');
    await expect(page.locator('#stream-rows')).toContainText('0x1a2b3c4d');
    await expect(page.locator('#leg-rows tr')).toHaveCount(2);
    await expect(page.locator('#leg-rows')).toContainText('session_id');
  });

  test('selecting a leg opens that leg', async ({ page }) => {
    const leg = 'leg-b@sbc.example.com';
    const seen = await serve(
      page,
      usual({
        [`/v1/dialogs/${encodeURIComponent(leg)}`]: detail(leg, { from_display: 'Leg B Caller' }),
        [`/v1/dialogs/${encodeURIComponent(leg)}/tree`]: tree(leg),
      }),
    );
    await connect(page);
    await page.getByRole('button', { name: 'call-a@example.com' }).click();
    await page.locator('#leg-rows').getByRole('button', { name: leg }).click();
    await expect(page.locator('#detail-fields')).toContainText('Leg B Caller');
    expect(seen.some((r) => r.raw === `/v1/dialogs/${encodeURIComponent(leg)}/tree`)).toBe(true);
  });

  test('Back to dialogs returns to the list with its rows', async ({ page }) => {
    await serve(page, usual());
    await connect(page);
    await page.getByRole('button', { name: 'call-a@example.com' }).click();
    await page.getByRole('button', { name: 'Back to dialogs' }).click();
    await expect(page.getByRole('heading', { level: 2, name: 'Dialogs' })).toBeFocused();
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
  });

  test('Refresh starts the list again without a cursor', async ({ page }) => {
    const seen = await serve(page, usual());
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect.poll(() => seen.filter((r) => r.path === '/v1/dialogs/tail').length).toBe(2);
    expect(seen.filter((r) => r.path === '/v1/dialogs/tail')[1].search).toBe('?limit=50');
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
  });

  test('an empty token field sends no Authorization header', async ({ page }) => {
    const seen = await serve(page, usual());
    await connect(page, '');
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    for (const request of seen) {
      expect(request.auth, request.path).toBeNull();
    }
  });

  test('progress is announced in the polite live region', async ({ page }) => {
    await serve(page, usual());
    await connect(page);
    const status = page.locator('#status');
    await expect(status).toHaveAttribute('aria-live', 'polite');
    await expect(status).toHaveText('Loaded 2 dialogs.');
  });

  test('the whole path works from the keyboard alone', async ({ page }) => {
    await serve(page, usual());
    await open(page);
    await page.getByLabel('API token').focus();
    await page.keyboard.type(TOKEN);
    await page.keyboard.press('Enter');
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    await page.getByRole('button', { name: 'call-a@example.com' }).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#leg-rows tr')).toHaveCount(2);
    await page.getByRole('button', { name: 'Back to dialogs' }).focus();
    await page.keyboard.press('Space');
    await expect(page.locator('#view-list')).toBeVisible();
  });
});

// ── Failure ───────────────────────────────────────────────────────────────

test.describe('failure', () => {
  test('a refused token says so and stays on the form', async ({ page }) => {
    await serve(page, { '*': (route) => json(route, 401, PROBLEM_401) });
    await connect(page);
    await expect(page.locator('#error')).toContainText('The API refused the token (401)');
    await expect(page.locator('#error')).toContainText('Paste a valid token');
    await expect(page.locator('#view-connect')).toBeVisible();
    await expect(page.locator('#view-list')).toBeHidden();
  });

  test('a token refused mid-session is dropped and the form returns', async ({ page }) => {
    let revoked = false;
    const seen = await serve(
      page,
      usual({
        '/v1/dialogs/tail': (route) =>
          revoked ? json(route, 401, PROBLEM_401) : json(route, 200, page1([summary('call-a@example.com')])),
      }),
    );
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(1);
    revoked = true;
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect(page.locator('#view-connect')).toBeVisible();
    await expect(page.locator('#error')).toContainText('refused the token (401)');
    await expect(page.locator('#dialog-rows tr')).toHaveCount(0);
    // The dropped token is not sent again.
    const before = seen.length;
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect.poll(() => seen.length).toBeGreaterThan(before);
    expect(seen[before].auth).toBeNull();
  });

  test('a 403 shows what the API said about the Host header', async ({ page }) => {
    const said = 'Host header is not allowed: proxy.example.com. If clients reach this server by that name, start sipnab with --api-allowed-host proxy.example.com.';
    await serve(page, { '*': (route) => json(route, 403, { title: 'Forbidden', status: 403, detail: said }) });
    await connect(page);
    await expect(page.locator('#error')).toContainText('forbids this request (403)');
    await expect(page.locator('#error')).toContainText(said);
  });

  test('a rate-limited list says to wait and keeps the session', async ({ page }) => {
    await serve(
      page,
      usual({ '/v1/dialogs/tail': (route) => json(route, 503, { title: 'Service Unavailable', status: 503 }) }),
    );
    await connect(page);
    await expect(page.locator('#error')).toContainText('busy or is limiting requests');
    await expect(page.locator('#error')).toContainText('(503)');
    await expect(page.locator('#list-state')).toHaveText('Not loaded: the dialog list.');
    await expect(page.locator('#view-list')).toBeVisible();
  });

  test('an API that does not answer is reported as unreachable', async ({ page }) => {
    await serve(page, { '*': (route) => route.abort('connectionrefused') });
    await connect(page);
    await expect(page.locator('#error')).toContainText('no answer from the API');
    await expect(page.locator('#view-connect')).toBeVisible();
  });

  test('a dialog the capture no longer holds is a 404 with what to do', async ({ page }) => {
    await serve(page, usual({ '/v1/dialogs/call-a%40example.com': undefined, '/v1/dialogs/call-a%40example.com/tree': undefined }));
    await connect(page);
    await page.getByRole('button', { name: 'call-a@example.com' }).click();
    await expect(page.locator('#error')).toContainText('does not have it (404)');
    await expect(page.locator('#error')).toContainText('Go back to the list');
    await expect(page.locator('#detail-state')).toHaveText('Not loaded: the dialog.');
  });

  test('a cursor the API refuses shows its reason', async ({ page }) => {
    let calls = 0;
    await serve(
      page,
      usual({
        '/v1/dialogs/tail': (route) => {
          calls += 1;
          return calls === 1
            ? json(route, 200, page1([summary('call-a@example.com')]))
            : json(route, 400, { title: 'Bad Request', status: 400, detail: 'since: cursor version 9 is not read' });
        },
      }),
    );
    await connect(page);
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect(page.locator('#error')).toContainText('refused the request (400)');
    await expect(page.locator('#error')).toContainText('since: cursor version 9 is not read');
    // The rows already shown stay.
    await expect(page.locator('#dialog-rows tr')).toHaveCount(1);
  });

  test('a token with a space is refused before any request', async ({ page }) => {
    const seen = await serve(page, usual());
    await connect(page, 'two words');
    await expect(page.locator('#error')).toContainText('cannot');
    expect(seen).toHaveLength(0);
    await expect(page.getByLabel('API token')).toBeFocused();
  });

  test('a body that is not JSON is an error, not an empty list', async ({ page }) => {
    await serve(
      page,
      usual({ '/v1/dialogs/tail': (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<html>proxy login</html>' }) }),
    );
    await connect(page);
    await expect(page.locator('#error')).toContainText('the API answered 200');
    await expect(page.locator('#dialog-rows tr')).toHaveCount(0);
  });

  test('a failed leg tree leaves the dialog shown and says which part failed', async ({ page }) => {
    await serve(
      page,
      usual({
        '/v1/dialogs/call-a%40example.com/tree': (route) => json(route, 500, { title: 'Internal Server Error', status: 500 }),
      }),
    );
    await connect(page);
    await page.getByRole('button', { name: 'call-a@example.com' }).click();
    await expect(page.locator('#detail-fields')).toContainText('Alice Example');
    await expect(page.locator('#legs-state')).toHaveText('Not loaded: the call legs.');
    await expect(page.locator('#error')).toContainText('the call legs');
    await expect(page.locator('#error')).toContainText('500');
  });

  test('the error region is an alert', async ({ page }) => {
    await serve(page, { '*': (route) => json(route, 401, PROBLEM_401) });
    await connect(page);
    await expect(page.getByRole('alert')).toContainText('refused the token');
  });

  test('a 500 on connect does not keep the token', async ({ page }) => {
    let broken = true;
    const seen = await serve(
      page,
      usual({ '/v1/runtime': (route) => (broken ? json(route, 500, { title: 'Internal Server Error', status: 500 }) : json(route, 200, RUNTIME)) }),
    );
    await connect(page);
    await expect(page.locator('#error')).toContainText('the API answered 500');
    await expect(page.locator('#view-connect')).toBeVisible();
    broken = false;
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    expect(seen[seen.length - 1].auth).toBeNull();
  });
});

// ── Edge: hostile captured values ─────────────────────────────────────────

async function expectNothingRan(page) {
  expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
  await expect(page.locator('main img, main script, main iframe, main a, main [onerror], main [style]')).toHaveCount(0);
}

test.describe('edge', () => {
  test('markup in a Call-ID is shown as text and nothing runs', async ({ page }) => {
    await serve(page, usual({ '/v1/dialogs/tail': page1([summary(MARKUP)]) }));
    await connect(page);
    await expect(page.locator('#dialog-rows th').first()).toHaveText(MARKUP);
    await expectNothingRan(page);
  });

  test('markup in the From and To users is shown as text', async ({ page }) => {
    await serve(page, usual({ '/v1/dialogs/tail': page1([summary('call-x@example.com', { from_user: SCRIPT, to_user: MARKUP })]) }));
    await connect(page);
    const cells = page.locator('#dialog-rows tr').first().locator('td');
    await expect(cells.nth(2)).toHaveText(SCRIPT);
    await expect(cells.nth(3)).toHaveText(MARKUP);
    await expectNothingRan(page);
  });

  test('a javascript: URI in a captured field never becomes a link', async ({ page }) => {
    await serve(page, usual({ '/v1/dialogs/tail': page1([summary(SCHEME, { from_user: SCHEME, state: SCHEME })]) }));
    await connect(page);
    await page.getByRole('button', { name: SCHEME }).click();
    await expect(page.locator('#view-detail')).toBeVisible();
    await expectNothingRan(page);
  });

  test('markup in every detail field is shown as text', async ({ page }) => {
    const hostile = detail(MARKUP, {
      from: SCRIPT,
      to: MARKUP,
      from_display: MARKUP,
      to_display: SCRIPT,
      final_status_reason: MARKUP,
      state: SCRIPT,
      method: MARKUP,
      sdp_timeline: [{ timestamp: MARKUP, direction: SCRIPT, codecs: [MARKUP, SCRIPT], media_addr: MARKUP, media_port: SCRIPT, mode: MARKUP }],
      streams: [{ ssrc: MARKUP, codec: SCRIPT, src: MARKUP, dst: SCRIPT, packets: MARKUP, loss_pct: SCRIPT, jitter_ms: MARKUP }],
    });
    await serve(
      page,
      usual({
        '/v1/dialogs/tail': page1([summary(MARKUP)]),
        [`/v1/dialogs/${encodeURIComponent(MARKUP)}`]: hostile,
        [`/v1/dialogs/${encodeURIComponent(MARKUP)}/tree`]: tree(MARKUP, [
          { call_id: SCRIPT, depth: MARKUP, parent_call_id: MARKUP, score: SCRIPT, strategy: MARKUP, followed: true },
        ]),
      }),
    );
    await connect(page);
    await page.locator('#dialog-rows').getByRole('button').first().click();
    await expect(page.locator('#detail-fields dd').first()).toHaveText(MARKUP);
    await expect(page.locator('#sdp-rows th').first()).toHaveText(MARKUP);
    await expect(page.locator('#stream-rows th').first()).toHaveText(MARKUP);
    await expect(page.locator('#leg-rows th').first()).toHaveText(SCRIPT);
    await expectNothingRan(page);
  });

  test('markup in an API error detail is shown as text', async ({ page }) => {
    await serve(page, { '*': (route) => json(route, 403, { title: 'Forbidden', status: 403, detail: MARKUP }) });
    await connect(page);
    await expect(page.locator('#error')).toContainText(MARKUP);
    expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
    await expect(page.locator('#error *')).toHaveCount(0);
  });

  test('a Call-ID that is a path is sent as one encoded segment', async ({ page }) => {
    const seen = await serve(page, usual({ '/v1/dialogs/tail': page1([summary(PATH_CALL_ID)]) }));
    await connect(page);
    await page.locator('#dialog-rows').getByRole('button').first().click();
    await expect.poll(() => seen.filter((r) => r.raw.startsWith('/v1/dialogs/a')).length).toBe(2);
    const sent = seen.filter((r) => r.raw.startsWith('/v1/dialogs/a')).map((r) => r.raw).sort();
    const segment = encodeURIComponent(PATH_CALL_ID);
    expect(sent).toEqual([`/v1/dialogs/${segment}`, `/v1/dialogs/${segment}/tree`]);
    // No request left the two routes the page meant: nothing reached
    // /v1/persistence, and no request carried a query or a method but GET.
    expect(seen.some((r) => r.path.includes('persistence') && !r.raw.includes('%2F'))).toBe(false);
  });

  test('the page only ever sends GET', async ({ page }) => {
    const methods = new Set();
    page.on('request', (request) => methods.add(request.method()));
    await serve(page, usual());
    await connect(page);
    await page.getByRole('button', { name: 'call-a@example.com' }).click();
    await expect(page.locator('#leg-rows tr')).toHaveCount(2);
    expect([...methods]).toEqual(['GET']);
  });

  test('the token is in no storage, cookie or URL after connecting', async ({ page, context }) => {
    await serve(page, usual());
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    const kept = await page.evaluate(() => ({
      local: JSON.stringify(Object.entries(localStorage)),
      session: JSON.stringify(Object.entries(sessionStorage)),
      cookie: document.cookie,
      url: location.href,
      html: document.documentElement.outerHTML,
      field: document.getElementById('token').value,
    }));
    for (const [where, value] of Object.entries(kept)) {
      expect(value, where).not.toContain(TOKEN);
    }
    expect(await context.cookies()).toEqual([]);
    expect(kept.field).toBe('');
  });

  test('a reload forgets the token', async ({ page }) => {
    const seen = await serve(page, usual());
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    await page.reload();
    await expect(page.locator('#view-connect')).toBeVisible();
    const before = seen.length;
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect.poll(() => seen.length).toBeGreaterThan(before);
    expect(seen[before].auth).toBeNull();
  });

  test('Disconnect clears the rows and the token', async ({ page }) => {
    const seen = await serve(page, usual());
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    await page.getByRole('button', { name: 'Disconnect' }).click();
    await expect(page.locator('#status')).toHaveText('Disconnected. The token was cleared from this page.');
    await expect(page.locator('#dialog-rows tr')).toHaveCount(0);
    await expect(page.locator('#runtime')).toBeHidden();
    const before = seen.length;
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect.poll(() => seen.length).toBeGreaterThan(before);
    expect(seen[before].auth).toBeNull();
  });

  test('a capture with no dialogs says so and what to do', async ({ page }) => {
    await serve(page, usual({ '/v1/dialogs/tail': page1([], null) }));
    await connect(page);
    await expect(page.locator('#list-state')).toContainText('No dialogs yet');
    await expect(page.locator('#list-state')).toContainText('Select Refresh');
    await expect(page.getByRole('button', { name: 'Load more' })).toBeHidden();
  });

  test('a dialog that changes again is updated in place, not listed twice', async ({ page }) => {
    let calls = 0;
    await serve(
      page,
      usual({
        '/v1/dialogs/tail': (route) => {
          calls += 1;
          return json(
            route,
            200,
            calls === 1
              ? page1([summary('call-a@example.com', { state: 'Ringing' }), summary('call-b@example.com')], 'v2:2')
              : page1([summary('call-a@example.com', { state: 'InCall' })], 'v2:3'),
          );
        },
      }),
    );
    await connect(page);
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect(page.locator('#dialog-rows tr', { hasText: 'InCall' })).toHaveCount(1);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
    await expect(page.locator('#dialog-rows tr', { hasText: 'Ringing' })).toHaveCount(0);
  });

  test('a page with no new cursor keeps the last one', async ({ page }) => {
    let calls = 0;
    const seen = await serve(
      page,
      usual({
        '/v1/dialogs/tail': (route) => {
          calls += 1;
          return json(route, 200, calls === 1 ? page1([summary('call-a@example.com')], 'v2:9') : page1([], null));
        },
      }),
    );
    await connect(page);
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect.poll(() => calls).toBe(2);
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect.poll(() => calls).toBe(3);
    const tail = seen.filter((r) => r.path === '/v1/dialogs/tail');
    expect(tail[2].search).toBe('?limit=50&since=v2%3A9');
    await expect(page.locator('#dialog-rows tr')).toHaveCount(1);
  });

  test('a swapped capture restarts the list from the first page', async ({ page }) => {
    let calls = 0;
    const seen = await serve(
      page,
      usual({
        '/v1/dialogs/tail': (route, url) => {
          calls += 1;
          if (calls === 1) {
            return json(route, 200, page1([summary('old-call@example.com')], 'v2:5', 'capture-a'));
          }
          return json(route, 200, page1(url.searchParams.has('since') ? [] : [summary('new-call@example.com')], 'v2:1', 'capture-b'));
        },
      }),
    );
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(1);
    await page.getByRole('button', { name: 'Load more' }).click();
    await expect(page.locator('#dialog-rows')).toContainText('new-call@example.com');
    await expect(page.locator('#dialog-rows')).not.toContainText('old-call@example.com');
    const tail = seen.filter((r) => r.path === '/v1/dialogs/tail');
    expect(tail[tail.length - 1].search).toBe('?limit=50');
  });

  test('missing and null fields read "not reported", never "undefined" or "null"', async ({ page }) => {
    const bare = 'bare@example.com';
    await serve(
      page,
      usual({
        '/v1/dialogs/tail': page1([{ call_id: bare, state: null, updated_at: null }]),
        [`/v1/dialogs/${encodeURIComponent(bare)}`]: { call_id: bare },
        [`/v1/dialogs/${encodeURIComponent(bare)}/tree`]: { legs: [] },
      }),
    );
    await connect(page);
    await expect(page.locator('#dialog-rows td').first()).toHaveText('not reported');
    await page.getByRole('button', { name: bare }).click();
    await expect(page.locator('#sdp-state')).toHaveText('This dialog carried no SDP.');
    await expect(page.locator('#streams-state')).toHaveText('sipnab matched no RTP stream to this dialog.');
    await expect(page.locator('#legs-state')).toHaveText('The API returned no legs for this dialog.');
    const text = await page.locator('main').innerText();
    expect(text).not.toMatch(/\bundefined\b|\bnull\b|NaN/);
  });

  test('a time that is not a time is shown as it came', async ({ page }) => {
    await serve(page, usual({ '/v1/dialogs/tail': page1([summary('call-a@example.com', { updated_at: 'yesterday' })]) }));
    await connect(page);
    await expect(page.locator('#dialog-rows tr').first().locator('td').last()).toHaveText('yesterday');
  });

  test('text that only looks like a date to the browser is not shown as a time', async ({ page }) => {
    // Chromium's Date reads each of these as some instant. None is RFC 3339.
    const cases = [MARKUP, '1', 'March 7', '2026-09-15'];
    await serve(
      page,
      usual({ '/v1/dialogs/tail': page1(cases.map((value, i) => summary(`call-${i}@example.com`, { updated_at: value }))) }),
    );
    await connect(page);
    for (const [i, value] of cases.entries()) {
      await expect(page.locator('#dialog-rows tr').nth(i).locator('td').last()).toHaveText(value);
    }
    await expectNothingRan(page);
  });

  test('a truncated leg walk says more legs exist', async ({ page }) => {
    const t = tree('call-a@example.com');
    t.truncated = true;
    await serve(page, usual({ '/v1/dialogs/call-a%40example.com/tree': t }));
    await connect(page);
    await page.getByRole('button', { name: 'call-a@example.com' }).click();
    await expect(page.locator('#legs-state')).toContainText('more legs exist');
  });

  test('a leg reached by a timing guess says it was not followed, in words', async ({ page }) => {
    const call = 'call-a@example.com';
    await serve(
      page,
      usual({
        '/v1/dialogs/call-a%40example.com/tree': tree(call, [
          { call_id: call, depth: 0, parent_call_id: null, score: null, strategy: null, followed: true },
          { call_id: 'guess@example.com', depth: 1, parent_call_id: call, score: 40, strategy: 'timing_heuristic', followed: false },
        ]),
      }),
    );
    await connect(page);
    await page.getByRole('button', { name: call }).click();
    await expect(page.locator('#leg-rows tr').nth(1).locator('td').last()).toHaveText('No: a timing guess is not followed');
  });

  test('an answer that arrives after Disconnect is dropped', async ({ page }) => {
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    await serve(
      page,
      usual({
        '/v1/dialogs/tail': async (route) => {
          await held;
          return json(route, 200, page1([summary('late@example.com')]));
        },
      }),
    );
    await connect(page);
    await expect(page.locator('#list-state')).toHaveText('Loading dialogs.');
    await page.getByRole('button', { name: 'Disconnect' }).click();
    release();
    await expect(page.locator('#view-connect')).toBeVisible();
    await page.waitForTimeout(200);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(0);
  });

  test('the table says it is busy while a page loads', async ({ page }) => {
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    await serve(
      page,
      usual({
        '/v1/dialogs/tail': async (route) => {
          await held;
          return json(route, 200, page1([summary('call-a@example.com')]));
        },
      }),
    );
    await connect(page);
    await expect(page.locator('#dialogs')).toHaveAttribute('aria-busy', 'true');
    await expect(page.locator('#list-state')).toHaveText('Loading dialogs.');
    release();
    await expect(page.locator('#dialogs')).toHaveAttribute('aria-busy', 'false');
  });

  test('at 320 px wide the page does not scroll sideways', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 640 });
    await serve(page, usual({ '/v1/dialogs/tail': page1([summary('a-very-long-call-id-0123456789abcdef0123456789abcdef@a-long-host-name.example.com')]) }));
    await connect(page);
    await expect(page.locator('#dialog-rows tr')).toHaveCount(1);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });

  test('the focused control shows a focus ring', async ({ page }) => {
    await serve(page, usual());
    await open(page);
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    const ring = await page.evaluate(() => {
      const style = getComputedStyle(document.activeElement);
      return { tag: document.activeElement.tagName, width: parseFloat(style.outlineWidth), kind: style.outlineStyle };
    });
    expect(ring.tag).toBe('INPUT');
    expect(ring.kind).toBe('solid');
    expect(ring.width).toBeGreaterThanOrEqual(2);
  });
});

// ── Accessibility: axe-core, WCAG 2 A and AA, each view in each scheme ─────

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

async function expectNoViolations(page) {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  const found = results.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
  expect(found).toEqual([]);
}

for (const scheme of ['light', 'dark']) {
  test.describe(`accessibility, ${scheme}`, () => {
    test.use({ colorScheme: scheme });

    test('the connect form with an error has no WCAG A or AA violation', async ({ page }) => {
      await serve(page, { '*': (route) => json(route, 401, PROBLEM_401) });
      await connect(page);
      await expect(page.locator('#error')).toContainText('refused the token');
      await expectNoViolations(page);
    });

    test('the dialog list has no WCAG A or AA violation', async ({ page }) => {
      await serve(page, usual());
      await connect(page);
      await expect(page.locator('#dialog-rows tr')).toHaveCount(2);
      await expectNoViolations(page);
    });

    test('the dialog detail has no WCAG A or AA violation', async ({ page }) => {
      await serve(page, usual());
      await connect(page);
      await page.getByRole('button', { name: 'call-a@example.com' }).click();
      await expect(page.locator('#leg-rows tr')).toHaveCount(2);
      await expectNoViolations(page);
    });
  });
}
