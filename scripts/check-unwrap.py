#!/usr/bin/env python3
"""Fail if `.unwrap()` or `.expect()` appears on a production path under src/.

Run from the repo root:  python3 scripts/check-unwrap.py
Prints each violation on stderr and the count on stdout, and EXITS NON-ZERO
when there is any. The exit status is the signal the hook reads — an earlier
draft had the hook parse `2>&1 | tail -1`, which merges unbuffered stderr with
buffered stdout, so a violation line could arrive last and be read as the
count.

This lived inline in the hook as `python3 -c "..."`. Two reasons it does not
any more: a double-quoted shell string mangles Python containing quotes (an
edit to it produced `line 105: mod: command not found`), and a scanner with a
subtle scoping rule needs to be testable on its own — `scripts/test-pre-commit.sh`
now exercises it directly.
"""
import os, sys

# Scope a #[cfg(test)] exemption to the item it annotates, not to the rest of
# the file. The previous scanner set a latch on the first #[cfg(test)] and never
# cleared it, so every line below one was exempt — 11 files under src/ put a
# per-item #[cfg(test)] above production code, and src/tui/controllers/mod.rs
# latched at line 23 of 1659.
#
# `mod tests` exempts its whole block; anything else (a #[cfg(test)] use, fn or
# const) exempts only that item. Depth is tracked by brace counting, which is
# approximate for braces inside string literals — approximate in the SAFE
# direction, since a stray brace ends an exemption early rather than extending
# it.
count = 0
for root, _dirs, files in os.walk('src'):
    for f in sorted(files):
        if not f.endswith('.rs') or f.endswith('_test.rs'):
            continue
        rel = os.path.join(root, f).replace(os.sep, '/')
        if rel == 'src/bin/gen_fixture.rs':
            continue
        depth = 0
        exempt_until = None   # exempt while depth > this
        pending = False       # saw #[cfg(test)], deciding what it annotates
        for i, line in enumerate(open(rel), 1):
            stripped = line.strip()
            opens = line.count('{')
            closes = line.count('}')

            if pending and stripped and not stripped.startswith('#['):
                if stripped.startswith('mod ') or stripped.startswith('pub mod '):
                    exempt_until = depth          # whole module
                elif opens > closes:
                    exempt_until = depth          # item with a body
                else:
                    pending = False               # one-line item: this line only
                    depth += opens - closes
                    continue
                pending = False

            if stripped == '#[cfg(test)]':
                pending = True

            exempt = exempt_until is not None
            depth += opens - closes
            if exempt_until is not None and depth <= exempt_until:
                exempt_until = None

            if exempt:
                continue
            if stripped.startswith('///') or stripped.startswith('//!') or stripped.startswith('//'):
                continue
            if '.unwrap()' in line or '.expect(' in line:
                count += 1
                print(f'  {rel}:{i}: {stripped}', file=sys.stderr)
print(count)
raise SystemExit(1 if count else 0)
