#!/usr/bin/env python3
"""Recompute CSP sha256 hashes for the site's inline scripts and update the
Cloudflare response-header transform rule for sipnab.com.

The site is served by GitHub Pages (which cannot set response headers), so
security headers are injected at the Cloudflare edge. The CSP's script-src
whitelists inline <script> blocks by hash instead of 'unsafe-inline'.

RUN THIS AFTER EVERY DEPLOY THAT CHANGES AN INLINE <script> in
website/templates/ — otherwise the header CSP blocks the changed script.

Auth: CLOUDFLARE_DNS_TOKEN (or CLOUDFLARE_API_TOKEN) in the environment or
~/.env. The token needs Zone->DNS->Edit, Zone->Zone Settings->Edit and
Zone->Transform Rules->Edit on the zone.

Usage: python3 refresh_csp_hashes.py [--dry-run]
"""
import base64
import hashlib
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET

ZONE = "sipnab.com"
SITE = "https://www.sipnab.com"
API = "https://api.cloudflare.com/client/v4"

# <script> blocks without src=; type= must be executable (or absent)
_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>", re.S | re.I)
_EXECUTABLE_TYPES = ("text/javascript", "module", "application/javascript")


def extract_inline_scripts(html):
    """Return the bodies of executable inline <script> blocks in html."""
    out = []
    for attrs, body in _SCRIPT_RE.findall(html):
        m = re.search(r"type\s*=\s*[\"']([^\"']+)", attrs)
        if m and m.group(1) not in _EXECUTABLE_TYPES:
            continue  # data block, e.g. application/ld+json
        out.append(body)
    return out


def sha256_token(body):
    """CSP source token ('sha256-<b64>') for an inline script body."""
    digest = hashlib.sha256(body.encode()).digest()
    return "'sha256-%s'" % base64.b64encode(digest).decode()


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "csp-hash-refresh/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")  # keep 404 page body


def _token():
    tok = os.environ.get("CLOUDFLARE_DNS_TOKEN") or os.environ.get("CLOUDFLARE_API_TOKEN")
    if not tok and os.path.exists(os.path.expanduser("~/.env")):
        for line in open(os.path.expanduser("~/.env")):
            if line.startswith(("CLOUDFLARE_DNS_TOKEN=", "CLOUDFLARE_API_TOKEN=")):
                tok = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not tok:
        sys.exit("no CLOUDFLARE_DNS_TOKEN in environment or ~/.env")
    return tok


def _api(tok, method, path, body=None):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode() or "{}")


def collect_hashes():
    urls = [
        e.text
        for e in ET.fromstring(_fetch(SITE + "/sitemap.xml")).iter()
        if e.tag.endswith("loc")
    ]
    urls.append(SITE + "/this-page-does-not-exist-404probe")  # 404 template
    tokens = {}
    for u in urls:
        for body in extract_inline_scripts(_fetch(u)):
            tokens.setdefault(sha256_token(body), []).append(u)
    return tokens


def csp(script_hashes):
    return (
        "default-src 'self'; "
        "script-src 'self' 'wasm-unsafe-eval' %s; "
        # ~141 style= attributes on the site require 'unsafe-inline' here
        "style-src 'self' 'unsafe-inline' https://fonts.bunny.net; "
        "font-src https://fonts.bunny.net; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; upgrade-insecure-requests; frame-ancestors 'none'"
    ) % " ".join(sorted(script_hashes))


def headers(script_hashes):
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": csp(script_hashes),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }


def main():
    dry = "--dry-run" in sys.argv
    tokens = collect_hashes()
    print("distinct inline-script hashes: %d" % len(tokens))
    for t, pages in sorted(tokens.items()):
        print("  %s  (%d pages)" % (t, len(pages)))
    hdrs = headers(tokens)
    if dry:
        print("\n--dry-run: not updating Cloudflare. CSP would be:\n" + hdrs["Content-Security-Policy"])
        return
    tok = _token()
    zid = _api(tok, "GET", "/zones?name=" + ZONE)["result"][0]["id"]
    rule = {
        "description": "security headers (GitHub Pages origin cannot set headers)",
        "expression": "true",
        "action": "rewrite",
        "action_parameters": {
            "headers": {k: {"operation": "set", "value": v} for k, v in hdrs.items()}
        },
    }
    r = _api(
        tok, "PUT",
        "/zones/%s/rulesets/phases/http_response_headers_transform/entrypoint" % zid,
        {"rules": [rule]},
    )
    if not r.get("success"):
        sys.exit("rule update failed: " + json.dumps(r.get("errors")))
    print("transform rule updated")


if __name__ == "__main__":
    main()
