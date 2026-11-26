#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Check the site's RFC 9116 security.txt, and that it is not near its Expires.

The file is website/static/.well-known/security.txt and the site serves it at
https://sipnab.com/.well-known/security.txt. RFC 9116 requires a `Contact` and
exactly one `Expires` (sections 2.5.3 and 2.5.5); a file past its `Expires` is
stale and "should not be used" (section 5.3). This check fails while 30 days
or fewer are left, so the file is renewed before it expires.

    check-security-txt.py --file website/static/.well-known/security.txt
    check-security-txt.py --site website/public    # the built site, before upload
    check-security-txt.py --url https://sipnab.com/.well-known/security.txt

Each mode also holds the file to the project: the first `Contact` is the
address SECURITY.md publishes, `Canonical` is the site's own URL, and
`Policy` and `Preferred-Languages` are present. `--site` also refuses any
hidden path in the built tree other than `.well-known/`, because pages.yml
uploads hidden paths so that `.well-known/` is deployed.

To renew: set `Expires` in the file to a date at most 366 days from today
(RFC 9116 recommends less than a year), commit it, and let pages.yml deploy.

Exit status: 0 when the file passes, 1 when it does not (each problem on
standard error), 2 on a usage error.
"""

import argparse
import datetime as dt
import pathlib
import re
import sys
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
WELL_KNOWN = ".well-known"
PATH = "/.well-known/security.txt"

# Section 4 ABNF: the registered fields and how often each may appear.
URI_FIELDS = ("acknowledgments", "canonical", "contact", "encryption",
              "hiring", "policy")
NAMES = {
    "acknowledgments": "Acknowledgments",
    "canonical": "Canonical",
    "contact": "Contact",
    "encryption": "Encryption",
    "expires": "Expires",
    "hiring": "Hiring",
    "policy": "Policy",
    "preferred-languages": "Preferred-Languages",
}

# field-name (RFC 5322 section 3.6.8): printable US-ASCII except ":".
FIELD = re.compile(r"^([\x21-\x39\x3b-\x7e]+): (.*)$")
# URI (RFC 3986 section 3): a scheme, then only characters a URI may hold.
URI = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.\-]*:"
    r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$")
# date-time (RFC 3339 section 5.6): the offset is required.
DATE_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?"
    r"([Zz]|[+-]\d{2}:\d{2})$")
# Language-Tag (RFC 5646 section 2.1), the langtag shape.
LANG_TAG = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")


def parse_date_time(value):
    """The aware datetime an RFC 3339 date-time names, or None."""
    m = DATE_TIME.match(value)
    if not m:
        return None
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    frac = m.group(7) or ""
    micro = int((frac[1:] + "000000")[:6]) if frac else 0
    off = m.group(8)
    if off in ("Z", "z"):
        tz = dt.timezone.utc
    else:
        sign = 1 if off[0] == "+" else -1
        hours, minutes = int(off[1:3]), int(off[4:6])
        if hours > 23 or minutes > 59:
            return None
        tz = dt.timezone(sign * dt.timedelta(hours=hours, minutes=minutes))
    try:
        return dt.datetime(year, month, day, hour, minute, second, micro,
                           tzinfo=tz)
    except ValueError:
        return None


def parse(data):
    """(fields, problems): fields as (line number, lower-case name, value)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        return [], [f"the file is not UTF-8 ({e.reason} at byte {e.start})"]
    found, bad = [], []
    if text and not text.endswith("\n"):
        bad.append("the last line has no line end (RFC 9116 section 2.2)")
    for number, line in enumerate(text.split("\n"), start=1):
        if line.endswith("\r"):
            line = line[:-1]
        line = line.rstrip(" \t")
        if not line or line.startswith("#"):
            continue
        m = FIELD.match(line)
        if not m:
            bad.append(f"line {number} is not a field (`Name: value`) or a "
                       f"comment: {line[:60]!r}")
            continue
        found.append((number, m.group(1).lower(), m.group(2).strip(" \t")))
    return found, bad


def problems(data, now, warn_days=30, max_days=366):
    """Every way `data` fails RFC 9116 or is near its Expires at `now`."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now needs a time zone")
    found, bad = parse(data)
    by_name = {}
    for number, name, value in found:
        by_name.setdefault(name, []).append((number, value))

    if not by_name.get("contact"):
        bad.append("no Contact field (RFC 9116 section 2.5.3 requires one)")
    for name in URI_FIELDS:
        for number, value in by_name.get(name, []):
            label = NAMES[name]
            if not URI.match(value):
                bad.append(f"line {number}: {label} {value!r} is not a URI "
                           f"(an address needs `mailto:`)")
            elif re.match(r"^http:", value, re.I):
                bad.append(f"line {number}: {label} {value!r} is a web URI "
                           f"that does not begin with https://")

    langs = by_name.get("preferred-languages", [])
    if len(langs) > 1:
        bad.append(f"Preferred-Languages appears {len(langs)} times; "
                   f"RFC 9116 section 2.5.8 allows one")
    for number, value in langs:
        tags = [t.strip(" \t") for t in value.split(",")]
        if not all(tags) or not all(LANG_TAG.match(t) for t in tags):
            bad.append(f"line {number}: Preferred-Languages {value!r} is not "
                       f"a comma-separated list of language tags")

    expires = by_name.get("expires", [])
    if not expires:
        bad.append("no Expires field (RFC 9116 section 2.5.5 requires one)")
    elif len(expires) > 1:
        bad.append(f"Expires appears {len(expires)} times; RFC 9116 section "
                   f"2.5.5 allows one")
    else:
        number, value = expires[0]
        when = parse_date_time(value)
        if when is None:
            bad.append(f"line {number}: Expires {value!r} is not an RFC 3339 "
                       f"date-time with a time zone")
        else:
            left = when - now
            if left <= dt.timedelta(0):
                bad.append(f"Expires {value} has passed: the file expired")
            elif left > dt.timedelta(days=max_days):
                bad.append(f"Expires {value} is more than {max_days} days "
                           f"away; RFC 9116 recommends less than a year")
            elif left <= dt.timedelta(days=warn_days):
                bad.append(f"Expires {value} is {left.days} days away, "
                           f"within {warn_days}: renew the file (set Expires "
                           f"at most {max_days} days out)")
    return bad


def content_type_problems(header):
    """How a Content-Type header fails `text/plain; charset=utf-8` (section 3)."""
    if not header:
        return ["no Content-Type; RFC 9116 section 3 requires text/plain "
                "with charset utf-8"]
    parts = [p.strip() for p in header.split(";")]
    bad = []
    if parts[0].lower() != "text/plain":
        bad.append(f"Content-Type {header!r} is not text/plain")
    charset = None
    for p in parts[1:]:
        key, _, value = p.partition("=")
        if key.strip().lower() == "charset":
            charset = value.strip().strip('"').lower()
    if charset != "utf-8":
        bad.append(f"Content-Type {header!r} does not set charset utf-8")
    return bad


def hidden_paths(root):
    """Paths under `root` that start with a dot, other than `.well-known/`.

    Each is named once, relative to `root`; nothing below it is listed."""
    root = pathlib.Path(root)
    out = []

    def walk(directory):
        for entry in sorted(directory.iterdir()):
            rel = entry.relative_to(root).as_posix()
            if entry.name.startswith("."):
                if rel == WELL_KNOWN and entry.is_dir():
                    walk(entry)
                    continue
                out.append(rel)
                continue
            if entry.is_dir() and not entry.is_symlink():
                walk(entry)

    walk(root)
    return sorted(out)


def project_problems(data, security_md, base_url):
    """How the file disagrees with SECURITY.md and the site's base URL."""
    found, _ = parse(data)
    values = {}
    for _, name, value in found:
        values.setdefault(name, []).append(value)
    bad = []
    emails = re.findall(r"\*\*([^*@\s]+@[^*\s]+)\*\*", security_md)
    if not emails:
        bad.append("SECURITY.md names no reporting address in bold")
    else:
        want = f"mailto:{emails[0]}"
        contacts = values.get("contact", [])
        if not contacts or contacts[0] != want:
            bad.append(f"the first Contact must be {want}, the address "
                       f"SECURITY.md publishes; found {contacts}")
    canonical = base_url.rstrip("/") + PATH
    if canonical not in values.get("canonical", []):
        bad.append(f"no Canonical {canonical}")
    for name in ("policy", "preferred-languages"):
        if not values.get(name):
            bad.append(f"no {NAMES[name]} field")
    return bad


def base_url():
    config = (REPO / "website/config.toml").read_text(encoding="utf-8")
    m = re.search(r'^base_url = "([^"]+)"', config, re.M)
    if not m:
        raise SystemExit("website/config.toml has no base_url")
    return m.group(1)


def judge(source, data, warn_days):
    """Report on one file's bytes; True when it passes."""
    security_md = (REPO / "SECURITY.md").read_text(encoding="utf-8")
    now = dt.datetime.now(dt.timezone.utc)
    bad = problems(data, now, warn_days=warn_days)
    bad += project_problems(data, security_md, base_url())
    for p in bad:
        print(f"{source}: {p}", file=sys.stderr)
    if not bad:
        print(f"{source}: ok")
    return not bad


def fetch(url):
    """(content type, body) of `url`. Not driven by a test: it reaches the
    network. The checks it feeds are the functions above."""
    req = urllib.request.Request(url, headers={"User-Agent": "sipnab-ci"})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
        return r.headers.get("Content-Type"), r.read()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", type=pathlib.Path, help="a security.txt file")
    mode.add_argument("--site", type=pathlib.Path, help="a built site tree")
    mode.add_argument("--url", help="the live https URL of the file")
    ap.add_argument("--warn-days", type=int, default=30,
                    help="fail while this many days or fewer are left")
    args = ap.parse_args(argv)

    if args.url:
        if not args.url.startswith("https://"):
            print(f"{args.url}: RFC 9116 section 3 requires https",
                  file=sys.stderr)
            return 1
        try:
            ctype, data = fetch(args.url)
        except (urllib.error.URLError, OSError) as e:
            print(f"{args.url}: cannot read: {e}", file=sys.stderr)
            return 1
        bad = content_type_problems(ctype)
        for p in bad:
            print(f"{args.url}: {p}", file=sys.stderr)
        ok = judge(args.url, data, args.warn_days)
        return 0 if ok and not bad else 1

    ok = True
    if args.site:
        path = args.site / WELL_KNOWN / "security.txt"
        for rel in hidden_paths(args.site):
            print(f"{args.site}: hidden path {rel} would be published; only "
                  f"{WELL_KNOWN}/ may start with a dot", file=sys.stderr)
            ok = False
    else:
        path = args.file
    try:
        data = path.read_bytes()
    except OSError as e:
        print(f"{path}: cannot read: {e.strerror}", file=sys.stderr)
        return 1
    ok = judge(str(path), data, args.warn_days) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
