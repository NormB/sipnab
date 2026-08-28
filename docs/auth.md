# Bearer-token authentication

The REST API (`--api`) and HTTP MCP server (`--mcp --mcp-transport http`, see
[mcp.md](mcp.md)) authenticate clients with
`Authorization: Bearer <token>`.
[cli-reference.md](cli-reference.md#network-listeners) lists every related flag.
sipnab supports two token kinds, checked with a constant-time comparison:

1. **Static secrets** — `--api-key` / `--mcp-token` (or `--mcp-token-file`,
   `$SIPNAB_API_KEY` / `$SIPNAB_MCP_TOKEN` env). A fixed shared secret with
   **no expiry**. Simple, but nothing expires or revokes it short of a restart.
2. **Signed self-describing tokens** — HMAC-signed tokens that carry their own
   expiry and id, enabling **expiry, rotation, and revocation** without a
   server-side session store. This page documents those.

> On a non-loopback bind, a token (static or signed) is **required** — the
> server refuses to start otherwise. On loopback with no token configured,
> requests pass (unchanged legacy behavior).

## Token format

```text
s2.<base64url(payload)>.<base64url(HMAC-SHA256)>
```

- `payload` is compact JSON
  `{"id":"<jti>","exp":<unix_seconds>,"aud":"<api|mcp>","scope":"<metrics|read>"}`.
- The signature is `HMAC-SHA256(signing_key, "s2." + base64url(payload))`.
- base64url is URL-safe, no padding.

`scope` appears **only when it narrows something**. A `full` token — the
default — omits the claim, so its payload is the three-field
`{"id":...,"exp":...,"aud":...}` form, and a payload carrying no `scope`
means `full`. Seeing `scope` in a decoded payload therefore always means
"restricted". See [*Scope*](#scope-what-a-token-may-reach) below.

Verification is **stateless**: the server recomputes the HMAC, compares it in
constant time against every configured signing key, then checks the audience,
`exp > now`, the scope the route demands, and that `id` is not revoked. A
malformed token loses (fail-closed).

## Audience binding

`aud` names the surface a token belongs to. The HTTP MCP endpoint turns away a
token minted from `--api-signing-key`, and the REST API turns away one minted
from `--mcp-signing-key` — **even when both surfaces carry the same signing
key**. Since the two surfaces read separate
flags and separate environment variables, reusing one secret across them is an
easy mistake. Before audience binding it silently granted cross-surface access.

The version prefix is part of the signed input, so an `s2` token cannot be
rewritten as `s1` to shed its binding — the signature no longer matches.

### Why the server refuses legacy `s1` tokens

The pre-`aud` `s1` format is **no longer accepted**. It carried no audience, so
an `s1` token authenticated against both surfaces — honoring it would have left
the binding above best-effort rather than absolute.

If you are still holding an `s1` token, it now returns `401`. Re-mint with
`--mint-token`. Since the default TTL is one hour, most callers have
rotated naturally already. Long-TTL tokens are the ones to check.

## 1. Configure a signing key

Give the server one or more HMAC signing keys (use a long, random secret). Each
surface reads its own flag, so configure the one you are actually exposing.

The REST API takes `--api-signing-key`:

```bash
sipnab -N -I capture.pcap --api 127.0.0.1:8080 \
  --api-signing-key "$(openssl rand -hex 32)"
```

The HTTP MCP server takes `--mcp-signing-key`. Running both of these mints two
unrelated keys — deliberate, since a token binds to one audience anyway:

```bash
sipnab -N -I capture.pcap --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
  --mcp-signing-key "$(openssl rand -hex 32)"
```

You can also pass keys through `--api-signing-key-file` / `--mcp-signing-key-file`
(file contents, trimmed) or the `$SIPNAB_API_SIGNING_KEY` /
`$SIPNAB_MCP_SIGNING_KEY` environment variables. `--api-signing-key` /
`--mcp-signing-key` are **repeatable** (see *Rotation*).

## 2. Mint (issue) a token

`--mint-token` signs a token with the **first** configured signing key, prints
it, and exits — it does not start any capture or server.

An API token at the default one-hour TTL needs nothing but the signing key:

```bash
sipnab --mint-token --api-signing-key "$KEY"
```

An MCP token for a CI runner gets a 24-hour life and an explicit id that a
denylist can name later:

```bash
sipnab --mint-token --mcp-signing-key "$KEY" --mcp-token-ttl 86400 --token-id ci-runner-1
```

`--api-token-ttl` / `--mcp-token-ttl` (default `3600`) set the lifetime, and
`--token-id` sets the `jti` (defaults to a generated id). Distribute the printed
token to clients.

### Scope: what a token may reach

`--token-scope` narrows a token to part of its surface. It takes `full` (the
default), `metrics`, or `read`:

| Scope | Surface | What it reaches |
|---|---|---|
| `full` | either | Everything on the token's audience. |
| `metrics` | REST API | `GET /metrics`, and nothing else. Every `/v1/` route answers `401`. |
| `read` | MCP | Only the tools `tools/list` marks read-only. Calling any other tool gets a JSON-RPC error refusal, not a `401`. |

Why bother: sipnab decrypts TLS, so `/v1/dialogs` and `/v1/streams` hand back
message bodies — the call content itself. A metrics scrape needs one counter,
not that. The same argument covers `read` on the MCP side, where a `full`
token can also stop the server, export files, and aim the capture elsewhere.

Each narrow scope names something that lives on exactly one surface, so sipnab
refuses a cross-surface mint rather than printing a token that could never
authorize what its scope names. `--token-scope metrics` with
`--mcp-signing-key` fails at mint time, and so does `--token-scope read` with
`--api-signing-key`.

Mint a scrape-only token for the REST API:

```bash
TOKEN="$(sipnab --mint-token --token-scope metrics --api-signing-key "$KEY")"
```

Then **confirm the scope took effect**. A token that quietly stayed `full`
looks identical from the outside, and the payload is the only record of what
you minted:

```bash
python3 - "$TOKEN" <<'PY'
import base64, sys
p = sys.argv[1].split(".")[1]
print(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode())
PY
```

```json
{"id":"tok-1770000000000000","exp":1770003600,"aud":"api","scope":"metrics"}
```

`"scope":"metrics"` is the claim doing the work. A decoded payload with **no**
`scope` field is a `full` credential — one that reads dialogs and the message
bodies underneath — so mint it again rather than shipping it.

The signature covers the claim, so a holder cannot widen a token by editing or
stripping `scope` — the signature stops matching. Static `--api-key` /
`--mcp-token` secrets carry no claims at all and are therefore always `full`.
Scoping needs a signed token.

## 3. Use a token

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/dialogs
```

That returns `200` when the token is valid, unexpired, non-revoked, and wide
enough for the route — *and* the request asks for something that exists. A
failure is not automatically a `401`:

| Status | What happened |
|---|---|
| `503` | The client is over its per-IP rate budget (100 requests/second) or the in-flight cap (`--api-max-conn`). **The rate limiter runs before authentication**, so this answer arrives whether the credential is good, bad, or missing — see [rest-api.md](rest-api.md#bind-address--connection-limits). |
| `401` | Missing, non-Bearer, malformed, expired, revoked, wrong-audience, or wrong-key credential — **or a good credential scoped too narrowly for the route**. A `metrics` token verifies fine and still gets `401` on `/v1/dialogs`, because that route demands `full`. |
| `404` | The credential passed, but nothing matches: no dialog carries that Call-ID on `/v1/dialogs/{call_id}`, or no stream carries that SSRC on `/v1/streams/{id}`. |
| `400` | The credential passed, but the request does not parse: `/v1/streams/{id}` got an id that is not hexadecimal. |
| `408` | The handler exceeded the request timeout. |

Reading a `401` as "bad token" is safe. Reading a `503` that way is not — a
`503` says nothing about the credential, because nothing looked at it yet.

`/health` needs no credential and skips the rate limiter entirely.

## 4. Expiry

A token stops verifying (`401`) once `exp <= now` — no server action needed. Mint
short-lived tokens for CI/automation and longer-lived ones sparingly.

## 5. Rotation

Two independent mechanisms:

- **Token rotation:** mint a new token before the old one expires, switch
  clients over, and let the old token lapse. Multiple tokens are valid
  simultaneously.
- **Signing-key rotation:** pass `--api-signing-key`/`--mcp-signing-key` more
  than once. The **first** key mints; **all** keys verify. To roll a key:
  add the new key alongside the old, mint with the new key, migrate clients,
  then drop the old key on the next restart.

## 6. Revocation

To kill a still-valid token before its `exp`, add its `id` to a denylist file
and point the server at it. Both steps matter — an id in a file no server
reads revokes nothing:

```bash
# Run all of these, in order.
echo "ci-runner-1" >> /etc/sipnab/revoked.txt
sipnab ... --api-signing-key "$KEY" --api-revoked-file /etc/sipnab/revoked.txt
```

The file is one token `id` per line (blank lines and `#` comments ignored). It
is **re-read when its mtime changes**, so appending an id revokes that token
within the next request — no restart required. (Because signed tokens are
otherwise valid until `exp`, a denylist is the revocation mechanism for the
stateless model.)

## Security notes

- Signing keys and tokens are secrets — prefer `*-signing-key-file` or env over
  argv (argv is visible in `ps`).
- Signature and static-secret comparison runs in **constant time**.
- Do not choose a static `--api-key`/`--mcp-token` shaped like `s2.x.y` — it
  would parse as a (failing) signed token rather than matching a static
  secret. (An `s1.x.y` shape is no longer a recognized version, so it is
  treated as an ordinary opaque secret.)
- Static secrets carry no audience. If you set the same static
  `--api-key` and `--mcp-token`, that one secret opens both surfaces. Audience
  binding applies to signed tokens only.
- TLS for the REST API is **not yet built in**; terminate TLS at a reverse proxy
  for non-loopback deployments.
