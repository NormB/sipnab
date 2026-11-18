// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
'use strict';

// Runs the platform-detection script of website/templates/download.html for
// one visitor and prints what it did to the banner as JSON.
//
//   node download_detect_harness.js <download.html> '<config json>'
//
// config: {"ua": "...", "maxTouchPoints": 0, "arch": "arm" | "x86" | null}
//
// The script is read out of the template itself (the first <script> after
// the #dl-detect banner), and the banner's elements are built from the
// template's own markup, so a renamed id or a moved script fails here instead
// of passing against a copy. scripts/tests/test_download_no_windows_offer.py
// drives it; a browser is not needed because the script only reads
// navigator and writes to the banner's elements and the download tiles.

const fs = require('fs');
const vm = require('vm');

const [templatePath, configJson] = process.argv.slice(2);
const config = JSON.parse(configJson);
const html = fs.readFileSync(templatePath, 'utf8');

const bannerStart = html.indexOf('<div class="dl-detect" id="dl-detect"');
if (bannerStart < 0) { throw new Error('no #dl-detect banner in ' + templatePath); }
const scriptStart = html.indexOf('<script>', bannerStart);
const scriptEnd = html.indexOf('</script>', scriptStart);
if (scriptStart < 0 || scriptEnd < 0) { throw new Error('no detection script after #dl-detect'); }
const bannerMarkup = html.slice(bannerStart, html.indexOf('{#', bannerStart));
const source = html.slice(scriptStart + '<script>'.length, scriptEnd);

function element(id, hidden) {
  const attrs = {};
  const classes = [];
  return {
    id: id,
    hidden: hidden,
    textContent: '',
    attrs: attrs,
    classes: classes,
    setAttribute: function (k, v) { attrs[k] = String(v); },
    getAttribute: function (k) { return Object.prototype.hasOwnProperty.call(attrs, k) ? attrs[k] : null; },
    hasAttribute: function (k) { return Object.prototype.hasOwnProperty.call(attrs, k); },
    removeAttribute: function (k) { delete attrs[k]; },
    classList: { add: function (c) { classes.push(c); } },
  };
}

const elements = {};
const idPattern = /<[a-z]+\b([^>]*)\bid="([^"]+)"([^>]*)>/g;
let match;
while ((match = idPattern.exec(bannerMarkup)) !== null) {
  const attributes = match[1] + ' ' + match[3];
  elements[match[2]] = element(match[2], /(^|\s)hidden(\s|=|$)/.test(attributes));
}

const tiles = [element('tile-arm', false), element('tile-x86', false)];
tiles[0].setAttribute('data-arch', 'arm');
tiles[1].setAttribute('data-arch', 'x86');

const document = {
  readyState: 'complete',
  getElementById: function (id) { return Object.prototype.hasOwnProperty.call(elements, id) ? elements[id] : null; },
  querySelectorAll: function (selector) {
    const arch = /^\.dl-tile\[data-arch="([^"]*)"\]$/.exec(selector);
    if (!arch) { throw new Error('unexpected selector ' + selector); }
    return tiles.filter(function (t) { return t.getAttribute('data-arch') === arch[1]; });
  },
  addEventListener: function (name, callback) { callback(); },
};

const navigator = { userAgent: config.ua, maxTouchPoints: config.maxTouchPoints || 0 };
let hintAsked = false;
if (config.arch) {
  navigator.userAgentData = {
    getHighEntropyValues: function () { hintAsked = true; return Promise.resolve({ architecture: config.arch }); },
  };
}

vm.runInNewContext(source, { document: document, navigator: navigator });

setImmediate(function () {
  const out = { elements: {}, cpuTiles: [], hintAsked: hintAsked };
  Object.keys(elements).forEach(function (id) {
    const e = elements[id];
    out.elements[id] = { hidden: e.hidden, text: e.textContent, dataOs: e.getAttribute('data-os') };
  });
  tiles.forEach(function (t) {
    if (t.classes.indexOf('dl-tile--cpu') >= 0) { out.cpuTiles.push(t.getAttribute('data-arch')); }
  });
  process.stdout.write(JSON.stringify(out));
});
