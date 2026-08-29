// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Documentation search, backed by Pagefind.
//
// EXTERNAL on purpose, not for tidiness. The production Content-Security-
// Policy carries `script-src 'self'` with no 'unsafe-inline': every inline
// <script> on this site has to be pinned by sha256 in a Cloudflare transform
// rule that ops/cloudflare/refresh_csp_hashes.py regenerates from the
// DEPLOYED HTML. A file loaded with `src=` needs none of that -- it is
// already same-origin, it is already allowed, and it cannot go stale against
// a hash list the way an inline block can.
//
// Everything this file loads is same-origin for the same reason. There is no
// CDN, no `https://` anywhere below: the Pagefind runtime and its index
// chunks are written into the site's own /pagefind/ directory by the build
// (see the "Index the site for search (Pagefind)" step in
// .github/workflows/pages.yml), so `connect-src 'self'` and `script-src
// 'self'` cover them without a single policy exception.
(function () {
  "use strict";

  // Root-relative, because config.toml's base_url is the apex. Pagefind's
  // own chunk URLs are resolved from this module's `import.meta.url`, so
  // naming the entry point is enough to place the whole index.
  var PAGEFIND_JS = "/pagefind/pagefind.js";
  var MAX_RESULTS = 8;
  var DEBOUNCE_MS = 150;
  var MIN_QUERY = 2;

  var box = document.getElementById("doc-search");
  if (!box) {
    return;
  }
  var input = document.getElementById("doc-search-input");
  var out = document.getElementById("doc-search-results");
  if (!input || !out) {
    return;
  }

  // Only the most recent query may write results. Without this the slower of
  // two in-flight searches wins whenever it lands last, and the box shows
  // matches for a prefix the reader has already finished typing past.
  var generation = 0;
  var timer = null;

  function clear() {
    while (out.firstChild) {
      out.removeChild(out.firstChild);
    }
  }

  function message(text) {
    clear();
    var p = document.createElement("p");
    p.className = "search-no-results";
    p.textContent = text;
    out.appendChild(p);
  }

  // Pagefind marks the matched terms in an excerpt with <mark> tags. The
  // markup is dropped rather than inserted: nothing here ever assigns
  // innerHTML, so no build-time string can become an element on the page.
  function plain(html) {
    // Repeat until stable, and be honest about why.
    //
    // CodeQL reports js/incomplete-multi-character-sanitization here. For THIS
    // regex the report is a pattern match rather than a demonstrated bug: `<`
    // to the first `>` is greedy, so a pass cannot join a leftover `<` to a
    // later `>` and manufacture a tag. Measured against nine adversarial
    // inputs -- `<<a>script>alert(1)<</a>/script>`, `<scr<a>ipt>`, `<a<b>c>`
    // among them -- one pass and the fixed point agree on all nine.
    //
    // The loop is kept anyway, for two reasons that do not depend on that
    // measurement holding: it closes a standing high alert, and it makes the
    // function robust to a future edit that narrows the pattern to something
    // removal-based like /<script>/g, where a single pass IS incomplete. The
    // strip is not load-bearing for safety either way -- nothing in this file
    // assigns innerHTML, and `the_search_script_never_assigns_inner_html`
    // holds that line.
    //
    // Bounded so a pathological input cannot spin.
    var out = String(html || "");
    for (var i = 0; i < 16; i++) {
      var next = out.replace(/<[^>]*>/g, "");
      if (next === out) {
        return next;
      }
      out = next;
    }
    return out.replace(/[<>]/g, "");
  }

  function render(items) {
    clear();
    if (!items.length) {
      message("No matches. The full documentation index is below.");
      return;
    }
    items.forEach(function (item) {
      var link = document.createElement("a");
      link.className = "search-result";
      link.href = item.url;

      var title = document.createElement("span");
      title.className = "search-result-title";
      title.textContent = (item.meta && item.meta.title) || item.url;

      var body = document.createElement("span");
      body.className = "search-result-body";
      body.textContent = plain(item.excerpt);

      link.appendChild(title);
      link.appendChild(body);
      out.appendChild(link);
    });
  }

  function run(engine, query) {
    var mine = ++generation;
    engine
      .search(query)
      .then(function (found) {
        if (mine !== generation) {
          return null;
        }
        return Promise.all(
          found.results.slice(0, MAX_RESULTS).map(function (hit) {
            return hit.data();
          })
        );
      })
      .then(function (items) {
        if (!items || mine !== generation) {
          return;
        }
        render(items);
      })
      .catch(function () {
        if (mine === generation) {
          message("Search is unavailable. The documentation index is below.");
        }
      });
  }

  // The box ships `hidden` in the template and is revealed HERE, after the
  // engine has actually loaded. That is the whole no-JavaScript story: with
  // scripting off this file never runs, the attribute is never removed, and
  // the reader is served the documentation index that the page already
  // renders instead of an input that swallows every keystroke. The same
  // holds when the index is missing -- a site built by `zola build` alone,
  // with no Pagefind step -- because the import below rejects and the catch
  // leaves the box exactly as the template shipped it.
  import(PAGEFIND_JS)
    .then(function (pagefind) {
      return Promise.resolve(pagefind.init ? pagefind.init() : null).then(
        function () {
          return pagefind;
        }
      );
    })
    .then(function (engine) {
      box.hidden = false;
      input.addEventListener("input", function () {
        var query = input.value.trim();
        if (timer) {
          clearTimeout(timer);
        }
        if (query.length < MIN_QUERY) {
          generation++;
          clear();
          return;
        }
        timer = setTimeout(function () {
          run(engine, query);
        }, DEBOUNCE_MS);
      });
      input.addEventListener("keydown", function (event) {
        if (event.key === "Escape") {
          input.value = "";
          generation++;
          clear();
        }
      });
    })
    .catch(function () {
      box.hidden = true;
    });
})();
