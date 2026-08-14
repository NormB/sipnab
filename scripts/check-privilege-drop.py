#!/usr/bin/env python3
"""Refuse a commit that weakens the privilege-drop path.

WHY THIS EXISTS
---------------
On 2026-08-05 an automated security scan caught `src/privilege.rs` with four
controls disabled at once: `PR_SET_DUMPABLE` swapped for `PR_GET_DUMPABLE` and
guarded with `if false &&`, the `chdir("/")` after `chroot()` deleted, and both
`drop_supplementary_groups()` and `set_no_new_privs()` removed from the drop
path.

Those were transient mutations from a mutation-testing pass, and they were
restored. The problem is that nothing would have stopped them being committed.
A deliberately-disabled security control still COMPILES and still PASSES every
test that does not specifically cover it, so `cargo clippy` and `cargo test`
both stay green while the process keeps its capabilities.

This gate reads the source instead of running it, deliberately. The dangerous
moment is a half-restored mutation in a tree that does not build: there
`cargo test` fails for an unrelated compile error, and a reviewer reads the
failure as "the build is broken" rather than "the sandbox is off". A text scan
answers regardless of whether anything compiles.

WHAT IT CHECKS, AND WHAT IT CANNOT
----------------------------------
Four things: that each control is PRESENT, that none has been NEUTRALISED in
place (a call left written down but unable to run), that supplementary groups
are surrendered BEFORE the GID, and that the binary's entry point still calls
`block_privilege_escalation()`.

That last one is here because presence in `privilege.rs` was not enough once.
`set_no_new_privs()` sat inside `drop_privileges`, below an early return taken
whenever the process is not root -- so `sipnab --setup-caps`, the install the
documentation recommends, ran a whole capture without the flag while this gate
reported the control present. Presence and REACHABILITY are different
questions, and the first is worth nothing on its own.

The ordering check is not stylistic either. On Darwin the effective GID is
element zero of the group vector (`#define cr_gid cr_groups[0]`), and `setgroups_internal()`
refuses to leave the vector empty -- `if (ngrp < 1) { ngrp = 1; newgroups[0] = 0; }`
-- so `setgroups(0, NULL)` writes GID 0, wheel, and the following `setgid` is
what clears it. Reversed, a macOS process finishes the drop holding egid 0 with a
uid of `nobody`. A presence-only check passes against that happily, which is why
position is read as well.

Reading one call site is still not the same as knowing which branch runs, and
this cannot verify that any syscall SUCCEEDED. Those belong in
`tests/privilege_drop_test.rs`, which reads the process's credentials and the
kernel's own flags back after the call rather than reading the source text.
"""

import re
import sys
from pathlib import Path

TARGET = Path("src/privilege.rs")

# The binary's entry point, which must still reach the hardening call. A
# control that exists but is never called is the defect this line was added
# for; see the module docstring.
ENTRY = Path("src/main.rs")
ENTRY_CALL = "privilege::block_privilege_escalation()"

# (needle, human name, why it matters if it disappears)
REQUIRED = [
    (
        "libc::prctl(libc::PR_SET_DUMPABLE, 0",
        "PR_SET_DUMPABLE",
        "core dumps stay enabled, so a crash writes captured SIP -- credentials, "
        "DTMF digits, call contents -- to disk where any local user may read it",
    ),
    (
        'libc::chdir(c"/".as_ptr())',
        'chdir("/") after chroot',
        "chroot(2) does NOT move the working directory. Leaving it outside the "
        "new root lets the process walk back out with relative paths -- the "
        "classic chroot escape, and the reason chroot alone is not a sandbox",
    ),
    (
        "drop_supplementary_groups()?",
        "drop_supplementary_groups",
        "the process keeps every supplementary group root belonged to, so "
        "dropping to an unprivileged UID still leaves it in e.g. `disk` or "
        "`docker` -- both of which are root by another route",
    ),
    (
        "set_no_new_privs()?",
        "set_no_new_privs (PR_SET_NO_NEW_PRIVS)",
        "a setuid binary reachable from the running process can hand privileges "
        "straight back, which on the capability install (`sipnab --setup-caps`, "
        "no root, no uid to drop) is the only escalation route there is",
    ),
    (
        "libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1",
        "prctl(PR_SET_NO_NEW_PRIVS, 1)",
        "the call would still be named and still be reached while setting "
        "nothing -- the PR_GET_DUMPABLE mutation this gate already knows about, "
        "wearing the other flag's name",
    ),
]

# Patterns that leave the call textually present while stopping it running.
# `if false &&` is not hypothetical: it is what the scan actually found.
NEUTRALISERS = [
    (r"\bif\s+false\b", "`if false` guard"),
    (r"\bfalse\s*&&", "`false &&` short-circuit"),
    (r"&&\s*false\b", "`&& false` short-circuit"),
    (r"\bPR_GET_DUMPABLE\b", "PR_GET_DUMPABLE (reads the flag instead of setting it)"),
    (r"cfg!\(any\(\)\)", "`cfg!(any())`, which is always false"),
]


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments so a commented-out call cannot satisfy a check.

    Deliberately naive about comment markers inside string literals: this file
    has none, and erring toward stripping too much can only cause a FALSE
    ALARM, never a miss. A gate that fails loudly when it is confused is the
    right direction for this one.
    """
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    return re.sub(r"//[^\n]*", " ", src)


def production_region(src: str) -> str:
    """Everything before `#[cfg(test)]`.

    The test module legitimately names these symbols while asserting the
    failure paths, and it may hold a mutation mid-run. Only shipped code is
    in scope.
    """
    marker = src.find("#[cfg(test)]")
    return src if marker < 0 else src[:marker]


def main() -> int:
    if not TARGET.exists():
        print(
            f"check-privilege-drop: {TARGET} does not exist. Either the file "
            f"moved and this gate must be repointed, or the privilege-drop "
            f"path was deleted outright. Refusing either way.",
            file=sys.stderr,
        )
        return 2

    raw = TARGET.read_text()
    code = strip_comments(production_region(raw))

    # A scan that reads nothing reports a clean file, which is
    # indistinguishable from a safe one.
    if len(code) < 500:
        print(
            f"check-privilege-drop: only {len(code)} bytes of production code "
            f"found in {TARGET} -- the region split is broken and a pass here "
            f"means nothing.",
            file=sys.stderr,
        )
        return 2

    failures = []

    # ORDER, not just presence. On Darwin `setgroups(0, NULL)` does not empty the
    # group vector -- it writes one entry holding GID 0 (wheel) -- and only the
    # `setgid` that follows overwrites it. Reversed, a macOS process ends the drop
    # with egid 0 while its uid reads `nobody`. Presence checks alone would pass
    # against that, which is why this one reads positions.
    g = code.find("drop_supplementary_groups()")
    sg = code.find("set_gid(")
    if g >= 0 and sg >= 0 and g > sg:
        failures.append(
            "  OUT OF ORDER: set_gid is called before drop_supplementary_groups\n"
            "    On macOS setgroups(0, NULL) leaves GID 0 (wheel) in the group\n"
            "    vector and the following setgid is what clears it. In this order\n"
            "    the process finishes the drop holding egid 0 with a uid of\n"
            "    `nobody` -- root by group, wearing an unprivileged uid."
        )

    for needle, name, why in REQUIRED:
        if needle not in code:
            failures.append(
                f"  MISSING: {name}\n"
                f"    looked for: {needle}\n"
                f"    if it is gone: {why}"
            )

    # REACHABILITY. A control present in privilege.rs that nothing calls is
    # exactly the state this repo shipped in until 2026-08-14.
    if not ENTRY.exists():
        failures.append(
            f"  MISSING: {ENTRY} does not exist\n"
            f"    Either the entry point moved and this gate must be repointed,\n"
            f"    or nothing calls the hardening any more."
        )
    elif ENTRY_CALL not in strip_comments(ENTRY.read_text()):
        failures.append(
            f"  UNREACHABLE: {ENTRY} does not call {ENTRY_CALL}\n"
            f"    PR_SET_NO_NEW_PRIVS has no precondition and is one-way, so it is\n"
            f"    set once at the top of the run. Without that call every mode --\n"
            f"    including the unprivileged `--setup-caps` install the docs\n"
            f"    recommend -- captures with escalation through exec still open."
        )

    for pattern, name in NEUTRALISERS:
        for m in re.finditer(pattern, code):
            line = code[: m.start()].count("\n") + 1
            failures.append(
                f"  NEUTRALISED: {name} at approx {TARGET}:{line}\n"
                f"    The control is still written down but cannot run. That is "
                f"worse than deleting it, because review sees the call and stops "
                f"looking."
            )

    if failures:
        print(
            "check-privilege-drop: the privilege-drop path is weaker than it "
            "must be.\n",
            file=sys.stderr,
        )
        print("\n".join(failures), file=sys.stderr)
        print(
            "\nIf you are mid mutation-test, restore the control before "
            "committing. If you are changing this path deliberately, update "
            "scripts/check-privilege-drop.py in the SAME commit and say why in "
            "the message -- do not silence it separately.",
            file=sys.stderr,
        )
        return 1

    print(
        f"{len(REQUIRED)} controls present and reached, none neutralised, "
        f"groups before GID"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
