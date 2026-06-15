# Bearer-token authentication

The REST API (`--api`) and HTTP MCP server (`--mcp --mcp-transport http`)
authenticate clients with `Authorization: Bearer <token>`. sipnab supports two
token kinds, checked with a constant-time comparison:

1. **Static secrets** — `--api-key` / `--mcp-token` (or `--mcp-token-file`,
   `$SIPNAB_API_SIGNING_KEY`-style env). A fixed shared secret with **no
   expiry**. Simple, but cannot be expired or revoked without restarting.
2. **Signed self-describing tokens** — HMAC-signed tokens that carry their own
   expiry and id, enabling **expiry, rotation, and revocation** without a
   server-side session store. This page documents those.

> On a non-loopback bind, a token (static or signed) is **required** — the
> server refuses to start otherwise. On loopback with no token configured,
> requests pass (unchanged legacy behavior).

## Token format

```
s1.<base64url(payload)>.<base64url(HMAC-SHA256)>
```

- `payload` is compact JSON `{"id":"<jti>","exp":<unix_seconds>}`.
- The signature is `HMAC-SHA256(signing_key, "s1." + base64url(payload))`.
- base64url is URL-safe, no padding.

Verification is **stateless**: the server recomputes the HMAC, compares it in
constant time against every configured signing key, then checks `exp > now` and
that `id` is not revoked. Any malformed token is rejected (fail-closed).

## 1. Configure a signing key

Give the server one or more HMAC signing keys (use a long, random secret):

```bash
# REST API
sipnab -N -I capture.pcap --api 127.0.0.1:8080 \
  --api-signing-key "$(openssl rand -hex 32)"

# HTTP MCP
sipnab -N -I capture.pcap --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
  --mcp-signing-key "$(openssl rand -hex 32)"
```

Keys may also be supplied via `--api-signing-key-file` / `--mcp-signing-key-file`
(file contents, trimmed) or the `$SIPNAB_API_SIGNING_KEY` /
`$SIPNAB_MCP_SIGNING_KEY` environment variables. `--api-signing-key` /
`--mcp-signing-key` are **repeatable** (see *Rotation*).

## 2. Mint (issue) a token

`--mint-token` signs a token with the **first** configured signing key, prints
it, and exits — it does not start any capture or server:

```bash
# 1-hour API token (default TTL 3600s)
sipnab --mint-token --api-signing-key "$KEY"

# 24-hour MCP token with an explicit id (for later revocation)
sipnab --mint-token --mcp-signing-key "$KEY" --mcp-token-ttl 86400 --token-id ci-runner-1
```

`--api-token-ttl` / `--mcp-token-ttl` (default `3600`) set the lifetime;
`--token-id` sets the `jti` (defaults to a generated id). Distribute the printed
token to clients.

## 3. Use a token

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/dialogs
```

A valid, unexpired, non-revoked token returns `200`; anything else returns
`401`.

## 4. Expiry

A token is rejected (`401`) once `exp <= now` — no server action needed. Mint
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
and point the server at it:

```bash
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
- Signatures and static secrets are compared in **constant time**.
- Do not choose a static `--api-key`/`--mcp-token` shaped like `s1.x.y` — it
  would be parsed as a (failing) signed token rather than matched as a static
  secret.
- TLS for the REST API is **not yet built in**; terminate TLS at a reverse proxy
  for non-loopback deployments.
