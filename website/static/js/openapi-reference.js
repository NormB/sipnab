// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Vendored beside this file:
//
//   scalar.min.js  @scalar/api-reference 1.67.0, MIT, https://github.com/scalar/scalar
//                  dist/browser/standalone.js, unmodified
//                  sha256 d150e6d9ec333062cb15870704bb9eb6ec6fa99ce3fe5b164a53bc0470e838ee
//
// Vendored rather than loaded from a CDN because the site's CSP is
// `script-src 'self'` with no CDN host, which is the same reason
// mermaid.min.js sits in this directory. THIRD-PARTY-NOTICES.md is generated
// from `cargo metadata` and covers Rust crates only, so the attribution the
// MIT licence asks for is here.
//
// Mounts the vendored Scalar reference over sipnab's generated OpenAPI 3.1
// document.
//
// This file exists because the site's Content-Security-Policy is
// `script-src 'self'` with no `unsafe-inline`: every inline <script> has to be
// hashed into a Cloudflare transform rule by ops/cloudflare/refresh_csp_hashes.py
// and pinned in tests/site_journey_test.rs. Configuration passed to Scalar from
// an inline block would therefore need a hash refresh on every wording change.
// An external file needs none, and is the same arrangement diagram-viewer.js
// already uses.
//
// Three of the defaults below are not cosmetic:
//
//   proxyUrl  Scalar defaults to routing "send request" through
//             https://proxy.scalar.com. `connect-src 'self'` blocks that, so
//             the default would fail on the wire AND route a reader's request
//             through a third party if the policy were ever relaxed.
//   telemetry Defaults to ON. A documentation page that reports back on its
//             readers is not something this site ships.
//   withDefaultFonts
//             Defaults to ON, and pulls a webfont from https://fonts.scalar.com.
//             `font-src 'self' https://fonts.bunny.net` blocks it; turning it
//             off is what makes the page render as designed rather than as a
//             fallback stack after a blocked request.
(function () {
  'use strict';

  var mount = document.getElementById('scalar-app');
  if (!mount) {
    return;
  }

  // The bundle failing to load must not leave an empty page with no
  // explanation: the document itself is still readable, and the hand-written
  // reference is still there.
  if (!window.Scalar || typeof window.Scalar.createApiReference !== 'function') {
    var note = document.createElement('p');
    note.className = 'scalar-fallback';
    note.textContent =
      'The interactive reference did not load. The OpenAPI document is at ' +
      '/openapi.json, and the written reference is at /docs/api/.';
    mount.appendChild(note);
    return;
  }

  window.Scalar.createApiReference(mount, {
    url: mount.getAttribute('data-openapi-url') || '/openapi.json',
    // The site has one palette and no toggle (base.html pins theme-color to
    // #0a0e14), so the reference is not offered a choice it cannot honor.
    darkMode: true,
    forceDarkModeState: 'dark',
    withDefaultFonts: false,
    telemetry: false,
    proxyUrl: '',
    // Every request this page could send goes to the reader's own sipnab, on
    // their own machine, which `connect-src 'self'` forbids the page to reach.
    // A button that cannot work is worse than no button: it reads as a broken
    // API rather than as a browser policy.
    hideTestRequestButton: true,
    hideClientButton: true,
    persistAuth: false,
    showSidebar: true,
    documentDownloadType: 'json',
  });
})();
