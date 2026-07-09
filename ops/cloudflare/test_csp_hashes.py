"""Tests for the inline-script extraction/hashing used by refresh_csp_hashes.py.

Run: python3 ops/cloudflare/test_csp_hashes.py
"""
import base64
import hashlib

from refresh_csp_hashes import extract_inline_scripts, sha256_token


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

print("all tests passed")
