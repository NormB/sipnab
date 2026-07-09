# Cloudflare edge security headers for sipnab.com

`sipnab.com` is served by GitHub Pages behind the Cloudflare proxy. GitHub
Pages cannot set response headers, so a Cloudflare **response-header
transform rule** injects them at the edge: HSTS (1y, includeSubDomains),
CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
Permissions-Policy, COOP and CORP.

The CSP's `script-src` allows the site's inline `<script>` blocks by
**sha256 hash** instead of `'unsafe-inline'`.

## `refresh_csp_hashes.py`

> **After every deploy that changes an inline `<script>` in
> `website/templates/`, run:**
>
> ```sh
> python3 ops/cloudflare/refresh_csp_hashes.py            # crawl + update rule
> python3 ops/cloudflare/refresh_csp_hashes.py --dry-run  # inspect only
> ```
>
> Otherwise the header CSP silently blocks the changed script for visitors.
> (Long-term alternative: externalize the inline scripts to `.js` files and
> drop the hashes entirely.)

The script crawls the live site's sitemap (plus the 404 template), hashes
every executable inline script, and rewrites the transform rule.

`style-src` keeps `'unsafe-inline'` because the templates use many inline
`style=` attributes (not hashable). The `<meta http-equiv>` CSP in
`base.html` remains for defense-in-depth; browsers enforce the intersection.

## Credentials

`CLOUDFLARE_DNS_TOKEN` (or `CLOUDFLARE_API_TOKEN`) in the environment or
`~/.env` (not in git), with Zone→Zone Settings→Edit and
Zone→Transform Rules→Edit on the zone.

## Tests

```sh
python3 ops/cloudflare/test_csp_hashes.py
```
