// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

// A copy button on every code block of a docs page and a notes page.
//
// The button does two jobs. It copies the block, and the docs are mostly shell
// commands. It is also the focusable element inside a block that scrolls
// sideways: a reader on a keyboard reaches the button with Tab, and the
// browser then scrolls the block with the arrow keys. Without it a long line
// in a code block cannot be read without a pointer (WCAG 2.2, success
// criterion 2.1.1). The notes pages had no button until 2026-11-10, when
// axe-core reported 125 such blocks on 22 of them.
//
// One file for both templates, loaded with `defer`: the page is parsed before
// it runs, and a script the site serves needs no hash in the content security
// policy. `:not(.mermaid)` is load-bearing: the diagram viewer reads a diagram
// block's textContent as its source. A button appended to one put the word
// "copy" inside the diagram, and mermaid failed to parse it.
(function () {
  document.querySelectorAll(".doc-content pre:not(.mermaid)").forEach(function (pre) {
    var btn = document.createElement("button");
    btn.className = "doc-copy-btn";
    btn.type = "button";
    btn.setAttribute("aria-label", "Copy code");
    btn.textContent = "copy";
    btn.addEventListener("click", function () {
      var code = pre.querySelector("code");
      var text = (code ? code.innerText : pre.innerText).replace(/\n$/, "");
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = "copied";
        btn.classList.add("copied");
        setTimeout(function () { btn.textContent = "copy"; btn.classList.remove("copied"); }, 1600);
      });
    });
    pre.appendChild(btn);
  });
})();
