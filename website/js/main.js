/* sipnab documentation — main.js */

(function () {
  "use strict";

  /* ── Sidebar toggle (mobile) ──────────────────────────────────────── */

  var hamburger = document.querySelector(".hamburger");
  var sidebar = document.querySelector(".sidebar");
  var overlay = document.querySelector(".sidebar-overlay");

  if (hamburger && sidebar) {
    hamburger.addEventListener("click", function () {
      sidebar.classList.toggle("open");
      if (overlay) overlay.classList.toggle("visible");
    });
  }

  if (overlay) {
    overlay.addEventListener("click", function () {
      sidebar.classList.remove("open");
      overlay.classList.remove("visible");
    });
  }

  // Close sidebar on nav link click (mobile)
  document.querySelectorAll(".sidebar a").forEach(function (link) {
    link.addEventListener("click", function () {
      if (window.innerWidth <= 768) {
        sidebar.classList.remove("open");
        if (overlay) overlay.classList.remove("visible");
      }
    });
  });

  /* ── Active nav highlighting ──────────────────────────────────────── */

  var navLinks = document.querySelectorAll(".sidebar a[href]");
  var currentPath = window.location.pathname;

  // Normalize: strip trailing slash, handle index files
  function normalizePath(path) {
    path = path.replace(/\/$/, "");
    path = path.replace(/\/index\.html$/, "");
    if (path === "") path = "/";
    return path;
  }

  var current = normalizePath(currentPath);

  navLinks.forEach(function (link) {
    var href = link.getAttribute("href");
    // Resolve relative hrefs against the current page
    var resolved;
    try {
      resolved = new URL(href, window.location.href).pathname;
    } catch (e) {
      resolved = href;
    }
    var linkPath = normalizePath(resolved);

    if (linkPath === current) {
      link.classList.add("active");
    } else if (current !== "/" && linkPath !== "/" && current.startsWith(linkPath)) {
      // Partial match for parent sections — but only mark exact matches as active
    }
  });

  /* ── Scroll spy for anchor links on the same page ─────────────────── */

  var headings = document.querySelectorAll("h2[id], h3[id]");

  if (headings.length > 0) {
    var scrollTimer = null;
    window.addEventListener("scroll", function () {
      if (scrollTimer) return;
      scrollTimer = setTimeout(function () {
        scrollTimer = null;
        var scrollPos = window.scrollY + 80;
        var activeId = null;

        headings.forEach(function (h) {
          if (h.offsetTop <= scrollPos) {
            activeId = h.id;
          }
        });

        navLinks.forEach(function (link) {
          var href = link.getAttribute("href");
          if (href && href.startsWith("#")) {
            if (href === "#" + activeId) {
              link.classList.add("active");
            } else {
              link.classList.remove("active");
            }
          }
        });
      }, 100);
    });
  }

  /* ── Copy-to-clipboard on code blocks ─────────────────────────────── */

  document.querySelectorAll("pre").forEach(function (pre) {
    pre.style.cursor = "pointer";

    pre.addEventListener("click", function () {
      var code = pre.querySelector("code");
      var text = (code || pre).textContent;

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          pre.classList.add("copied");
          setTimeout(function () {
            pre.classList.remove("copied");
          }, 1500);
        });
      } else {
        // Fallback for older browsers
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand("copy");
          pre.classList.add("copied");
          setTimeout(function () {
            pre.classList.remove("copied");
          }, 1500);
        } catch (e) {
          // silent fail
        }
        document.body.removeChild(ta);
      }
    });
  });
})();
