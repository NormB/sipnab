#!/usr/bin/env python3
"""Fail if `.unwrap()`, `.expect()`, `panic!`, `unreachable!`, `todo!` or
`unimplemented!` appears on a production path under src/.

Run from the repo root:  python3 scripts/check-unwrap.py

The four macros joined the ban on 2026-09-02. The scan covered the two method
spellings of "abort here" and none of the macro spellings, and a clippy
restriction-lint measurement found zero of the former under src/ beside six
sites of the latter that nothing had ever looked at. A site that genuinely
cannot be reached stays, with a comment that names the macro and says why:

    // gate: unreachable because the index is drawn from 0..LABELS.len()
    _ => unreachable!("column index {i} out of range"),

on the same line, or in the comment block directly above the site (an
attribute line between them is stepped over, since comments go above
attributes). The reason is mandatory and at least three words: a marker
that gives none is a waiver nobody explained, and it is REPORTED, not
honored. The marker must name the macro it covers, so one cannot be copied
from a `panic!` onto an `unreachable!` without saying so. scripts/tests/
test_check_unwrap.py drives every one of those rules.
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
import os, re, sys, tomllib

# Every workspace member's src/, derived from Cargo.toml -- not the literal
# path 'src'. That literal made a path prefix the proxy for "production code",
# and crates/sipnab-audio/src/lib.rs sits outside it: it compiles to
# libsipnab_audio.so, which build-deb.sh installs to usr/lib/sipnab/, and an
# .unwrap() appended there passed the hook and committed. The crate has none
# today, so this closed a live hole rather than a live defect -- but the ban is
# stated as a property of production code, and a second workspace member is
# production code.
with open('Cargo.toml', 'rb') as fh:
    MEMBERS = tomllib.load(fh).get('workspace', {}).get('members', ['.'])
ROOTS = [d for d in ('src' if m == '.' else f'{m}/src' for m in MEMBERS) if os.path.isdir(d)]
if len(ROOTS) < 2:
    print(
        f'check-unwrap: derived only {len(ROOTS)} source roots ({ROOTS}) from '
        f'workspace members {MEMBERS} -- the ban is not covering what it claims',
        file=sys.stderr,
    )
    raise SystemExit(2)

# ── Lexing, because brace COUNTING is not brace matching ───────────────────
# The exemption below is scoped by tracking `{`/`}` depth. Counting the raw
# characters per line is wrong in both directions, and the second one is a
# silent hole rather than a loud nuisance:
#
#   * An unmatched `}` inside a string collapses the depth and ends an
#     exemption EARLY, so test code is scanned as production. Observed with
#     `body.find("\n}")` inside a `#[cfg(test)] mod`.
#   * An unmatched `{` inside a string INFLATES the depth, so the exemption
#     never ends and leaks over every line of production code that FOLLOWS the
#     test item. Every unwrap()/expect() there is then silently exempt and the
#     gate reports OK while checking nothing.
#
# So strip the things that are not code before counting: line comments, block
# comments (which nest in Rust), char and byte-char literals (`'\u{7FFF}'`
# carries braces), and every string form -- plain, byte, C, and raw with any
# number of hashes. String and block-comment state carries across lines, since
# both may span them.
#
# The stripped text is also what the `.unwrap()` search reads, so a mention in
# a doc comment or inside a panic message is no longer a violation.
_CODE, _STR, _RAW, _BLOCK = 0, 1, 2, 3
_START = (_CODE, 0)

# The macro spellings of "abort here". Matched on the STRIPPED line, so a
# mention inside a string or a comment is prose, and with a boundary on the
# left so `my_panic!` -- somebody's own macro -- is not the standard one.
# `core::panic!` and `std::panic!` are, and `::` is not an identifier char.
_ABORT = re.compile(r'(?<![A-Za-z0-9_])(panic|unreachable|todo|unimplemented)!\s*\(')
# The per-site exception: `// gate: <macro> because <reason>`. Searched on
# the RAW line, because it lives in a comment and the stripping removed it.
_GATE_MARK = re.compile(r'//\s*gate:\s*(panic|unreachable|todo|unimplemented)\s+because\b(.*)$')
# Fewer words than this after `because` is a marker, not a reason.
_REASON_WORDS = 3


def gate_marker(raw_lines, i):
    """The `gate:` marker covering the site on 1-based line `i`, or None.

    Returns `(macro, reason)`. Looked for on the line itself first, then
    upward through the contiguous block of line comments directly above it.
    Attribute lines (`#[...]`) are stepped over, not stopped at, because the
    natural place for the comment is above the `#[cfg(...)]` that gates the
    site. Anything else -- code, a blank line -- ends the block: the marker
    is local to ONE site, and a marker that reached past code would exempt
    whatever happened to follow it.
    """
    m = _GATE_MARK.search(raw_lines[i - 1])
    if m:
        return m.group(1), m.group(2).strip()
    j = i - 2
    while j >= 0:
        s = raw_lines[j].strip()
        if s.startswith('#['):
            j -= 1
            continue
        if not s.startswith('//'):
            return None
        m = _GATE_MARK.search(s)
        if m:
            return m.group(1), m.group(2).strip()
        j -= 1
    return None

# The only characters that can begin a non-code region. Jumping to the next one
# with a regex keeps this a per-region loop rather than a per-character one:
# 160k lines of src/ scan in well under the time a hook can notice.
_INTERESTING = re.compile(r'[/"\']')


def _is_test_cfg(stripped):
    """True for a cfg attribute that only compiles under `cfg(test)`.

    This used to be `stripped == '#[cfg(test)]'`, an exact string match, so a
    CONDITIONALLY compiled test module — `#[cfg(all(test, target_os = "linux"))]`,
    which is how you write a test module for a platform-specific code path — was
    scanned as production code and every `.expect()` in it reported. That is a
    normal Rust pattern, and the checker calling it a production violation is a
    false positive that pushes an author toward deleting the cfg or bypassing
    the hook.

    Deliberately narrow. `all(test, ...)` is exempt because every arm must hold,
    so the item cannot exist outside a test build. `any(test, ...)` is NOT: it
    compiles when the OTHER arm holds, which is production. `not(test)` is
    production by definition. Getting that backwards would silently exempt real
    code, which is the failure this whole check exists to prevent.
    """
    if not (stripped.startswith('#[cfg(') and stripped.endswith(')]')):
        return False
    inner = stripped[len('#[cfg('):-len(')]')].strip()
    if inner == 'test':
        return True
    if inner.startswith('all(') and inner.endswith(')'):
        # Split the top-level arms of all(...) and look for a bare `test`.
        args, depth, cur = [], 0, ''
        for ch in inner[len('all('):-1]:
            if ch == ',' and depth == 0:
                args.append(cur.strip())
                cur = ''
                continue
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            cur += ch
        args.append(cur.strip())
        return 'test' in args
    return False


def _raw_hashes(line, q):
    """Hash count if the `"` at index `q` opens a raw string, else None.

    Reads backwards over `#*` to an `r`, past an optional `b`/`c` byte- or
    C-string prefix, and refuses when that lands mid-identifier -- otherwise a
    variable whose name ends in `r` followed by a quote would be read as a raw
    string opener and swallow the rest of the file. `r#type` is a raw
    IDENTIFIER, not a string, and is rejected here because no `"` follows.
    """
    j, n = q, 0
    while j > 0 and line[j - 1] == '#':
        j -= 1
        n += 1
    if j == 0 or line[j - 1] != 'r':
        return None
    j -= 1
    if j > 0 and line[j - 1] in 'bc':
        j -= 1
    if j > 0 and (line[j - 1].isalnum() or line[j - 1] == '_'):
        return None
    return n


def strip_noncode(line, state):
    """Return (code, next_state): `line` with comments and literals removed.

    `state` threads unterminated strings and block comments across lines. The
    caller checks it at EOF: a file that ends mid-literal means this function
    misread something and swallowed real code, which is exactly the shape that
    turns the gate into a no-op.
    """
    kind, n = state
    out = []
    i, end = 0, len(line)
    while i < end:
        if kind == _CODE:
            m = _INTERESTING.search(line, i)
            if m is None:
                out.append(line[i:])
                break
            out.append(line[i:m.start()])
            i = m.start()
            ch = line[i]
            if ch == '/':
                nxt = line[i + 1:i + 2]
                if nxt == '/':
                    break                       # line comment: rest is not code
                if nxt == '*':
                    kind, n = _BLOCK, 1
                    i += 2
                    continue
                out.append(ch)                  # division
                i += 1
                continue
            if ch == '"':
                h = _raw_hashes(line, i)
                if h is None:
                    kind = _STR
                else:
                    kind, n = _RAW, h
                i += 1
                continue
            # A `'` is a char literal, a byte-char literal, or a lifetime.
            # `'a'` is a char and `'a` is a lifetime, told apart by whether the
            # quote closes two characters on; an escape form (`'\n'`, `'\''`,
            # `'\u{1F600}'`) is scanned to its closing quote so its braces and
            # quotes never reach the counter.
            if line[i + 1:i + 2] == '\\':
                j = i + 1
                while j < end:
                    if line[j] == '\\':
                        j += 2
                    elif line[j] == "'":
                        break
                    else:
                        j += 1
                i = j + 1 if j < end else end
                continue
            if line[i + 2:i + 3] == "'":
                i += 3
                continue
            out.append(ch)                      # lifetime tick: harmless code
            i += 1
        elif kind == _STR:
            while i < end:
                c = line[i]
                if c == '\\':
                    i += 2                      # escape, incl. line continuation
                elif c == '"':
                    i += 1
                    kind = _CODE
                    break
                else:
                    i += 1
        elif kind == _RAW:
            closer = '"' + '#' * n              # raw strings have no escapes
            j = line.find(closer, i)
            if j < 0:
                i = end
            else:
                i = j + len(closer)
                kind, n = _CODE, 0
        else:                                   # _BLOCK; Rust nests these
            while i < end:
                if line.startswith('*/', i):
                    n -= 1
                    i += 2
                    if n == 0:
                        kind = _CODE
                        break
                elif line.startswith('/*', i):
                    n += 1
                    i += 2
                else:
                    i += 1
    return ''.join(out), (kind, n)


# Scope a #[cfg(test)] exemption to the item it annotates, not to the rest of
# the file. The previous scanner set a latch on the first #[cfg(test)] and never
# cleared it, so every line below one was exempt — 11 files under src/ put a
# per-item #[cfg(test)] above production code, and src/tui/controllers/mod.rs
# latched at line 23 of 1659.
#
# `mod tests` exempts its whole block; anything else (a #[cfg(test)] use, fn or
# const) exempts only that item.
count = 0
scanned = 0
for src_root in ROOTS:
  for root, _dirs, files in os.walk(src_root):
      for f in sorted(files):
          if not f.endswith('.rs') or f.endswith('_test.rs'):
              continue
          rel = os.path.join(root, f).replace(os.sep, '/')
          # A dev-only fixture generator, never shipped and never on a request
          # path; a panic there fails the person regenerating a fixture, loudly,
          # which is the correct behavior for that tool.
          if rel == 'src/bin/gen_fixture.rs':
              continue
          scanned += 1
          depth = 0
          exempt_depths = []   # exempt while depth > this
          pending = False       # saw #[cfg(test)], deciding what it annotates
          _waived_until = None  # last line covered by an #[expect] waiver
          state = _START
          _lines = open(rel).readlines()
          for i, line in enumerate(_lines, 1):
              code, state = strip_noncode(line, state)
              stripped = code.strip()
              opens = code.count('{')
              closes = code.count('}')

              # This line is the whole of a one-line `#[cfg(test)]` item.
              one_line = False
              if pending and stripped and not stripped.startswith('#['):
                  if (
                      stripped.startswith('mod ')
                      or stripped.startswith('pub mod ')
                      or opens > closes
                  ):
                      exempt_depths.append(depth)   # module, or item with a body
                  else:
                      one_line = True               # one-line item: this line only
                  pending = False

              if _is_test_cfg(stripped):
                  pending = True

              exempt = one_line or bool(exempt_depths)
              depth += opens - closes
              # Pop every exemption this line closed, innermost first. A STACK
              # and not a scalar: a `#[cfg(test)]` item nested inside a
              # `#[cfg(test)] mod` -- a helper carrying the attribute it does
              # not need, which is ordinary enough -- used to OVERWRITE the
              # module's depth, so the helper's closing brace ended the
              # module's exemption too and every test line after it was scanned
              # as production. Restoring the outer depth is what keeps the two
              # independent.
              while exempt_depths and depth <= exempt_depths[-1]:
                  exempt_depths.pop()

              if exempt:
                  continue
              # A REVIEWED waiver: `#[expect(clippy::unwrap_used, reason = ..)]`.
              #
              # This is not a second rule loosening the first. `src/lib.rs` and
              # `src/main.rs` both carry `#![warn(clippy::unwrap_used)]` and
              # clippy runs with `-D warnings`, so the attribute is checked by
              # the compiler rather than by convention -- and `expect` (unlike
              # `allow`) FAILS when the lint stops firing, so a waiver cannot
              # outlive the code it covers. Without this the text scan and
              # clippy disagree about one rule, and the only way to satisfy both
              # is to write something less safe than the literal it guards.
              #
              # A reason is mandatory. A bare waiver is the thing nobody reads.
              # The abort macros. Checked before the unwrap waiver below,
              # because that waiver is a statement about `.unwrap()` and
              # says nothing about a `panic!` on the same lines.
              abort = _ABORT.search(code)
              if abort:
                  macro = abort.group(1)
                  mark = gate_marker(_lines, i)
                  if mark is None or mark[0] != macro:
                      count += 1
                      print(f'  {rel}:{i}: {line.strip()}', file=sys.stderr)
                  elif len(mark[1].split()) < _REASON_WORDS:
                      count += 1
                      print(
                          f'  {rel}:{i}: {macro}!() carries a gate: marker with no '
                          f'reason; a waiver nobody explained',
                          file=sys.stderr,
                      )
              if _waived_until is not None and i <= _waived_until:
                  continue
              if stripped.startswith('#[expect('):
                  # The attribute may span lines -- rustfmt breaks it whenever
                  # the reason string is long, which is most of the time. Read
                  # the whole attribute before judging it, or the multi-line
                  # form (the common one) is never recognized and the waiver
                  # appears to work only where it was needed least.
                  attr, j = '', i - 1
                  while j < len(_lines) and ')]' not in attr:
                      attr += _lines[j]
                      j += 1
                  if 'clippy::unwrap_used' not in attr and 'clippy::expect_used' not in attr:
                      continue
                  if 'reason' not in attr:
                      count += 1
                      print(
                          f'  {rel}:{i}: #[expect(clippy::unwrap_used)] with no '
                          f'reason = "..."; a waiver nobody explained',
                          file=sys.stderr,
                      )
                  # Covers the attribute's own multi-line form plus the
                  # expression it annotates. Bounded deliberately: a waiver that
                  # swallowed the rest of a function would exempt code nobody
                  # reviewed.
                  _waived_until = j + 2
                  continue
              if '.unwrap()' in code or '.expect(' in code:
                  count += 1
                  # The RAW line, not the stripped one: the report is read
                  # against an editor, and `map.get("port").unwrap()` printed
                  # as `map.get().unwrap()` is not the line anybody can find.
                  print(f'  {rel}:{i}: {line.strip()}', file=sys.stderr)

          # A .rs file the compiler accepts ends outside every literal and with
          # its braces balanced. Anything else means the lexer above lost the
          # thread, and a lexer that lost the thread reports the rest of the
          # file as exempt or as comment — a count of zero that means nothing.
          # Refuse rather than pass, same as the empty-walk guard below.
          if state != _START or depth != 0:
              print(
                  f'check-unwrap: {rel} ended in lexer state {state} at brace '
                  f'depth {depth}, expected {_START} at depth 0 -- the literal '
                  f'and comment stripping misread this file, so its result is '
                  f'not trustworthy',
                  file=sys.stderr,
              )
              raise SystemExit(2)
# A walk that reads nothing reports zero violations, which is
# indistinguishable from a clean tree.
if scanned == 0:
    print(
        f'check-unwrap: scanned no files under {ROOTS} -- the walk is broken, '
        f'and a count of {count} means nothing',
        file=sys.stderr,
    )
    raise SystemExit(2)
print(count)
raise SystemExit(1 if count else 0)
