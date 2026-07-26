// Renders mermaid diagrams and gives each one a pan/zoom control box that can
// be collapsed and dragged out of the way.
//
// Why this exists: these diagrams are also published to the GitHub wiki, where
// GitHub's own mermaid viewer pins its controls to the bottom-right corner —
// directly over diagram text, with no way to move or hide them. On our own site
// we control the viewer, so the control box here is collapsible and draggable,
// and both its position and collapsed state persist across pages and reloads.
//
// Loaded only on pages that set `has_diagrams = true` in their frontmatter, so
// the 3.4 MB mermaid bundle never reaches a page without a diagram.

(function () {
  "use strict";

  var STORE_POS = "sipnab.diagramControls.pos";
  var STORE_HIDDEN = "sipnab.diagramControls.hidden";
  var MIN_SCALE = 0.4;
  var MAX_SCALE = 6;

  /** Read a JSON value from localStorage, tolerating a disabled/full store. */
  function load(key, fallback) {
    try {
      var raw = window.localStorage.getItem(key);
      return raw === null ? fallback : JSON.parse(raw);
    } catch (e) {
      return fallback;
    }
  }

  /** Persist a JSON value, ignoring failures (private mode, quota). */
  function save(key, value) {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (e) {
      /* non-fatal: the viewer still works, it just will not remember */
    }
  }

  /** Clamp `n` into [lo, hi]. */
  function clamp(n, lo, hi) {
    return n < lo ? lo : n > hi ? hi : n;
  }

  /**
   * Wire pan/zoom plus a collapsible, draggable control box onto one rendered
   * diagram.
   *
   * @param {HTMLElement} figure wrapper holding the rendered <svg>
   */
  function attachViewer(figure) {
    var svg = figure.querySelector("svg");
    if (!svg) return;

    var state = { scale: 1, x: 0, y: 0 };

    // mermaid emits its own width/height; drop them so the SVG fills the
    // figure and our transform is the only thing that scales it.
    svg.removeAttribute("width");
    svg.removeAttribute("height");
    svg.style.transformOrigin = "0 0";
    svg.style.display = "block";

    function apply() {
      svg.style.transform =
        "translate(" + state.x + "px," + state.y + "px) scale(" + state.scale + ")";
      zoomLabel.textContent = Math.round(state.scale * 100) + "%";
    }

    function zoomBy(factor, originX, originY) {
      var next = clamp(state.scale * factor, MIN_SCALE, MAX_SCALE);
      var ratio = next / state.scale;
      // Keep the point under the cursor fixed while scaling.
      state.x = originX - (originX - state.x) * ratio;
      state.y = originY - (originY - state.y) * ratio;
      state.scale = next;
      apply();
    }

    function reset() {
      state.scale = 1;
      state.x = 0;
      state.y = 0;
      apply();
    }

    // ── control box ────────────────────────────────────────────────────
    var controls = document.createElement("div");
    controls.className = "diagram-controls";

    var grip = document.createElement("button");
    grip.type = "button";
    grip.className = "diagram-grip";
    grip.setAttribute("aria-label", "Move diagram controls");
    grip.title = "Drag to move";
    grip.textContent = "⠿";

    var zoomOut = document.createElement("button");
    zoomOut.type = "button";
    zoomOut.setAttribute("aria-label", "Zoom out");
    zoomOut.title = "Zoom out";
    zoomOut.textContent = "−";

    var zoomLabel = document.createElement("span");
    zoomLabel.className = "diagram-zoom-label";

    var zoomIn = document.createElement("button");
    zoomIn.type = "button";
    zoomIn.setAttribute("aria-label", "Zoom in");
    zoomIn.title = "Zoom in";
    zoomIn.textContent = "+";

    var resetBtn = document.createElement("button");
    resetBtn.type = "button";
    resetBtn.setAttribute("aria-label", "Reset zoom and position");
    resetBtn.title = "Reset";
    resetBtn.textContent = "⤾";

    var collapse = document.createElement("button");
    collapse.type = "button";
    collapse.className = "diagram-collapse";
    collapse.setAttribute("aria-label", "Hide diagram controls");
    collapse.title = "Hide controls";
    collapse.textContent = "×";

    controls.appendChild(grip);
    controls.appendChild(zoomOut);
    controls.appendChild(zoomLabel);
    controls.appendChild(zoomIn);
    controls.appendChild(resetBtn);
    controls.appendChild(collapse);

    // The reopen affordance, shown once the box is hidden. Small and in the
    // corner so it never covers meaningful diagram area.
    var reopen = document.createElement("button");
    reopen.type = "button";
    reopen.className = "diagram-reopen";
    reopen.setAttribute("aria-label", "Show diagram controls");
    reopen.title = "Show controls";
    reopen.textContent = "⚙";

    figure.appendChild(controls);
    figure.appendChild(reopen);

    function setHidden(hidden) {
      figure.classList.toggle("controls-hidden", hidden);
      controls.setAttribute("aria-hidden", hidden ? "true" : "false");
      save(STORE_HIDDEN, hidden);
    }

    collapse.addEventListener("click", function () {
      setHidden(true);
      reopen.focus();
    });
    reopen.addEventListener("click", function () {
      setHidden(false);
      collapse.focus();
    });

    zoomIn.addEventListener("click", function () {
      zoomBy(1.25, figure.clientWidth / 2, figure.clientHeight / 2);
    });
    zoomOut.addEventListener("click", function () {
      zoomBy(0.8, figure.clientWidth / 2, figure.clientHeight / 2);
    });
    resetBtn.addEventListener("click", reset);

    // ── dragging the control box ────────────────────────────────────────
    // Position is stored as a right/bottom offset so it stays anchored to the
    // same corner when the figure is resized.
    var pos = load(STORE_POS, null);
    function placeControls(right, bottom) {
      var maxRight = Math.max(0, figure.clientWidth - controls.offsetWidth);
      var maxBottom = Math.max(0, figure.clientHeight - controls.offsetHeight);
      controls.style.right = clamp(right, 0, maxRight) + "px";
      controls.style.bottom = clamp(bottom, 0, maxBottom) + "px";
    }
    if (pos && typeof pos.right === "number" && typeof pos.bottom === "number") {
      placeControls(pos.right, pos.bottom);
    }

    var dragging = false;
    var startX = 0;
    var startY = 0;
    var startRight = 0;
    var startBottom = 0;

    function onDown(e) {
      dragging = true;
      var p = e.touches ? e.touches[0] : e;
      startX = p.clientX;
      startY = p.clientY;
      var box = controls.getBoundingClientRect();
      var host = figure.getBoundingClientRect();
      startRight = host.right - box.right;
      startBottom = host.bottom - box.bottom;
      controls.classList.add("dragging");
      e.preventDefault();
    }

    function onMove(e) {
      if (!dragging) return;
      var p = e.touches ? e.touches[0] : e;
      placeControls(startRight - (p.clientX - startX), startBottom - (p.clientY - startY));
      e.preventDefault();
    }

    function onUp() {
      if (!dragging) return;
      dragging = false;
      controls.classList.remove("dragging");
      var box = controls.getBoundingClientRect();
      var host = figure.getBoundingClientRect();
      save(STORE_POS, {
        right: Math.round(host.right - box.right),
        bottom: Math.round(host.bottom - box.bottom),
      });
    }

    grip.addEventListener("mousedown", onDown);
    grip.addEventListener("touchstart", onDown, { passive: false });
    window.addEventListener("mousemove", onMove);
    window.addEventListener("touchmove", onMove, { passive: false });
    window.addEventListener("mouseup", onUp);
    window.addEventListener("touchend", onUp);

    // Keyboard: the grip is a real button, so arrows nudge it for anyone not
    // using a pointer.
    grip.addEventListener("keydown", function (e) {
      var step = e.shiftKey ? 20 : 4;
      var box = controls.getBoundingClientRect();
      var host = figure.getBoundingClientRect();
      var right = host.right - box.right;
      var bottom = host.bottom - box.bottom;
      if (e.key === "ArrowLeft") right += step;
      else if (e.key === "ArrowRight") right -= step;
      else if (e.key === "ArrowUp") bottom += step;
      else if (e.key === "ArrowDown") bottom -= step;
      else return;
      placeControls(right, bottom);
      save(STORE_POS, { right: Math.round(right), bottom: Math.round(bottom) });
      e.preventDefault();
    });

    // ── panning the diagram itself ──────────────────────────────────────
    var panning = false;
    var panX = 0;
    var panY = 0;
    figure.addEventListener("mousedown", function (e) {
      if (controls.contains(e.target) || reopen.contains(e.target)) return;
      panning = true;
      panX = e.clientX - state.x;
      panY = e.clientY - state.y;
      figure.classList.add("panning");
    });
    window.addEventListener("mousemove", function (e) {
      if (!panning) return;
      state.x = e.clientX - panX;
      state.y = e.clientY - panY;
      apply();
    });
    window.addEventListener("mouseup", function () {
      panning = false;
      figure.classList.remove("panning");
    });

    // Ctrl/⌘+wheel zooms; a bare wheel keeps scrolling the page, so the
    // diagram never traps the reader's scroll.
    figure.addEventListener(
      "wheel",
      function (e) {
        if (!e.ctrlKey && !e.metaKey) return;
        var rect = figure.getBoundingClientRect();
        zoomBy(e.deltaY < 0 ? 1.12 : 0.89, e.clientX - rect.left, e.clientY - rect.top);
        e.preventDefault();
      },
      { passive: false }
    );

    setHidden(load(STORE_HIDDEN, false) === true);
    apply();
  }

  /** Render every mermaid block on the page, then attach a viewer to each. */
  async function run() {
    var blocks = Array.prototype.slice.call(
      document.querySelectorAll("pre.mermaid, pre > code.language-mermaid")
    );
    if (blocks.length === 0) return;

    var mermaid = window.mermaid;
    if (!mermaid) return;

    var dark =
      document.documentElement.dataset.theme === "dark" ||
      window.matchMedia("(prefers-color-scheme: dark)").matches;

    mermaid.initialize({
      startOnLoad: false,
      theme: dark ? "dark" : "neutral",
      securityLevel: "strict",
      sequence: { useMaxWidth: false },
    });

    for (var i = 0; i < blocks.length; i++) {
      var block = blocks[i];
      // Normalize: Zola may emit <pre><code class="language-mermaid">.
      var host = block.tagName === "PRE" ? block : block.parentElement;
      var source = block.textContent;

      var figure = document.createElement("figure");
      figure.className = "diagram-figure";

      try {
        var rendered = await mermaid.render("sipnab-diagram-" + i, source);
        // innerHTML is correct here and is not an injection surface. The diagram
        // source is authored in this repository (docs/internals/*.md) and baked
        // into the page at build time — no visitor input reaches it; this viewer
        // only runs on pages that declare `has_diagrams`. mermaid.render()
        // returns an SVG string precisely for this assignment, and it runs under
        // `securityLevel: "strict"` above, which sanitizes diagram labels.
        figure.innerHTML = rendered.svg;
      } catch (err) {
        // A diagram that fails to render must not blank the page: leave the
        // source visible, which is still readable prose-adjacent text.
        continue;
      }

      host.replaceWith(figure);
      attachViewer(figure);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run);
  } else {
    run();
  }
})();
