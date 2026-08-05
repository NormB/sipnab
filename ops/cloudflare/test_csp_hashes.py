"""Tests for the inline-script extraction/hashing used by refresh_csp_hashes.py.

Run: python3 ops/cloudflare/test_csp_hashes.py
"""
import base64
import hashlib
import os
import re
import tempfile

from refresh_csp_hashes import csp, extract_inline_scripts, sha256_token, write_headers


def check(name, cond):
    print("%-52s %s" % (name, "ok" if cond else "FAIL"))
    if not cond:
        raise SystemExit(1)


HTML = """
<script>alert(1)</script>
<script src="/app.js"></script>
<script type="application/ld+json">{"@context":"x"}</script>
<script type="module">import x from './x.js'</script>
<SCRIPT>
multi
line
</SCRIPT>
<script type="text/javascript">alert(2)</script>
"""

bodies = extract_inline_scripts(HTML)

check("skips src= scripts", "import" not in " ".join(b for b in bodies if "app.js" in b) and len(bodies) == 4)
check("skips JSON-LD data blocks", not any("@context" in b for b in bodies))
check("keeps bare <script>", "alert(1)" in bodies)
check("keeps type=module", "import x from './x.js'" in bodies)
check("keeps type=text/javascript", "alert(2)" in bodies)
check("keeps multiline + case-insensitive tag", "\nmulti\nline\n" in bodies)

# hash token matches CSP sha256-<base64> convention
tok = sha256_token("alert(1)")
want = "'sha256-%s'" % base64.b64encode(hashlib.sha256(b"alert(1)").digest()).decode()
check("sha256 token format", tok == want)

# empty and adversarial inputs
check("empty html -> no scripts", extract_inline_scripts("") == [])
check("nested quotes/backslash body survives",
      extract_inline_scripts("<script>var s='a\\\\'; //\"</script>")[0] == "var s='a\\\\'; //\"")
check("NUL byte body hashed not crashed",
      sha256_token("a\x00b").startswith("'sha256-"))

# The published policy must never grant 'unsafe-inline' for scripts. style-src
# keeps it deliberately (inline style= attributes are not hashable), so check
# the script directive specifically rather than the whole policy string.
script_src = re.search(r"script-src([^;]*);", csp(["'sha256-x'"])).group(1)
check("script-src does not grant 'unsafe-inline'", "'unsafe-inline'" not in script_src)
check("script-src carries the hash tokens", "'sha256-x'" in script_src)

# write_headers rewrites exactly the CSP line and leaves the rest alone.
HEADERS = "\n".join([
    "# Content-Security-Policy in a comment must NOT be rewritten",
    "/*",
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'",
    "  X-Frame-Options: DENY",
    "",
])
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "_headers")
    with open(p, "w") as f:
        f.write(HEADERS)
    write_headers(p, ["'sha256-abc'"])
    out = open(p).read()
    lines = out.split("\n")
    check("rewrote the CSP line in place", lines[3] == "  Content-Security-Policy: " + csp(["'sha256-abc'"]))
    check("left the comment line alone", lines[0] == HEADERS.split("\n")[0])
    check("left the other headers alone",
          lines[1:3] == HEADERS.split("\n")[1:3] and lines[4] == "  X-Frame-Options: DENY")
    check("dropped 'unsafe-inline' from script-src",
          "'unsafe-inline'" not in re.search(r"script-src([^;]*);", out).group(1))

    # A file with no CSP line must fail loudly: a silent no-op would leave the
    # caller believing a policy was published.
    q = os.path.join(d, "no_csp")
    with open(q, "w") as f:
        f.write("/*\n  X-Frame-Options: DENY\n")
    try:
        write_headers(q, ["'sha256-abc'"])
        check("missing CSP line is an error", False)
    except SystemExit as e:
        check("missing CSP line is an error", "expected exactly 1" in str(e))

print("all tests passed")
