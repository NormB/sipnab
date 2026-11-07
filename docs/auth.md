# Bearer-token authentication

Two servers authenticate clients with `Authorization: Bearer <token>`:

- the REST API (`--api`),
- the HTTP MCP server (`--mcp --mcp-transport http`, see [mcp.md](mcp.md)).

[cli-reference.md](cli-reference.md#network-listeners) lists every related flag.
sipnab supports two token kinds, checked with a constant-time comparison:

- **Static secrets** — `--api-key` / `--mcp-token` (or `--mcp-token-file`,
  `$SIPNAB_API_KEY` / `$SIPNAB_MCP_TOKEN` env).
  - A fixed shared secret with **no expiry**.
  - Simple, but nothing expires or revokes it short of a restart.
- **Signed self-describing tokens** — HMAC-signed tokens that carry their own
  expiry and id.
  - They enable **expiry, rotation, and revocation** without a server-side session store.
  - This page documents those.

> On a non-loopback bind, sipnab **requires** a token (static or signed).
> The server refuses to start otherwise.
>
> On loopback with no token configured, requests pass without a credential,
> as long as their `Host` header names this server.
> A web page that rebinds its own name to `127.0.0.1` is
> refused with `403`. See
> [Which `Host` names the API answers](rest-api.md#which-host-names-the-api-answers).

The steps below set up signed tokens from scratch. After the steps, this page covers:

- what a token contains,
- how its audience binds it to one server,
- [the credential and TLS of every listener](#secure-every-listener),
  including the metrics endpoint and the HEP listener, which use no bearer
  token.

## Configure a signing key

Give the server one or more HMAC signing keys (use a long, random secret).
Each surface reads its own flag. So configure the one you are actually exposing.

The REST API takes `--api-signing-key`:

```bash
sipnab -N -I capture.pcap --api 127.0.0.1:8080 \
  --api-signing-key "$(openssl rand -hex 32)"
```

The HTTP MCP server takes `--mcp-signing-key`. Running both of these mints two
unrelated keys. That is deliberate, since a token binds to one audience anyway:

```bash
sipnab -N -I capture.pcap --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
  --mcp-signing-key "$(openssl rand -hex 32)"
```

You can also pass keys through:

- `--api-signing-key-file` / `--mcp-signing-key-file` (file contents, trimmed),
- the `$SIPNAB_API_SIGNING_KEY` / `$SIPNAB_MCP_SIGNING_KEY` environment variables.

`--api-signing-key` / `--mcp-signing-key` are **repeatable** (see *Rotation*).

## Mint (issue) a token

`--mint-token` signs a token with the **first** configured signing key.
It prints the token and exits. It does not start any capture or server.

An API token at the default one-hour TTL needs nothing but the signing key:

```bash
sipnab --mint-token --api-signing-key "$KEY"
```

An MCP token for a CI runner gets a 24-hour life and an explicit id that a
denylist can name later:

```bash
sipnab --mint-token --mcp-signing-key "$KEY" --mcp-token-ttl 86400 --token-id ci-runner-1
```

- `--api-token-ttl` / `--mcp-token-ttl` (default `3600`) set the lifetime.
- `--token-id` sets the `jti` (defaults to a generated id).

Distribute the printed token to clients.

### Scope: what a token may reach

`--token-scope` sets what a token may reach. It takes `full` (the default),
`metrics`, `read`, `actions`, `admin`, `audio`, `inventory` or `fleet-report`:

| Scope | Surface | What it reaches |
|---|---|---|
| `full` | either | Every read route or tool on the token's audience. Not the actions, and not the live-audio routes. |
| `metrics` | REST API | `GET /metrics`, and nothing else. Every `/v1/` route answers `401`. |
| `read` | MCP | Only the tools `tools/list` marks read-only. Calling any other tool gets a JSON-RPC error refusal, not a `401`. |
| `actions` | either | Everything `full` reaches, plus the actions that change another system, such as a TFPS ban, where the server enables them with `--allow-action`. It lifts only the bans it placed. |
| `admin` | either | Everything `actions` reaches, and it also lifts a ban another caller placed, for example one placed by a token since lost. |
| `audio` | REST API | The live-audio routes under `/v1/calls/`, and nothing else. No other scope reaches them. |
| `inventory` | REST API | `GET /v1/inventory`, and a fleet center's `GET /v1/fleet/members`, and nothing else. `full`, `actions` and `admin` reach it too. For [`sipnab fleet inventory`](fleet.md). |
| `fleet-report` | REST API | A fleet center's `POST /v1/fleet/ingest`, and nothing else; no other scope reaches it. Its `--token-id` is the member's name. For [a fleet center](fleet.md#run-a-fleet-center). |

Give each client the narrowest scope that does its job:

- A `full` REST token reads call content, including SIP messages that sipnab
  decrypted from TLS. A metrics scrape needs only `metrics`.
- On MCP, a `full` token can also stop the server, export files, and point
  the capture elsewhere. A diagnostic agent needs only `read`.

`metrics` and `audio` exist only on the REST API, and `read` only on MCP. A
mint that pairs one with the other surface's signing key fails and prints no
token:

```bash
sipnab --mint-token --token-scope metrics --mcp-signing-key "$KEY"
```

```text
--token-scope metrics applies to the REST API only; the MCP surface has no /metrics endpoint
```

It exits with status `2`.

Mint a scrape-only token for the REST API:

```bash
TOKEN="$(sipnab --mint-token --token-scope metrics --api-signing-key "$KEY")"
```

Then confirm the scope took effect. A `full` token and a `metrics` token look
alike until you decode the payload, the part between the two dots:

```bash
python3 - "$TOKEN" <<'PY'
import base64, sys
p = sys.argv[1].split(".")[1]
print(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode())
PY
```

```json
{"id":"tok-1792151388671087","exp":1792154988,"aud":"api","scope":"metrics"}
```

- `"scope":"metrics"` is the claim that narrows the token.
- A decoded payload with **no** `scope` field is a `full` credential. If you
  meant to mint a narrower one, mint it again.

The signature covers the claim.

- So a holder cannot widen a token by editing or stripping `scope`.
  The signature stops matching.
- Static `--api-key` / `--mcp-token` secrets carry no claims at all.
  They are therefore always `full`.
- Scoping needs a signed token.

## Use a token

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/dialogs
```

That returns `200` when both of these hold:

- the token is valid, unexpired, non-revoked, and wide enough for the route,
- *and* the request asks for something that exists.

A failure is not automatically a `401`:

| Status | What happened |
|---|---|
| `403` | The `Host` header names a host that is not on the allowlist (`--api-allowed-host` / `--mcp-allowed-host`). sipnab checks it before the rate limiter and authentication, so the credential was never read. |
| `503` | The client is over its per-IP rate budget (`--api-rate-limit-per-peer`, 100 requests a second by default) or the in-flight cap (`--api-max-conn`, 100 by default). **The rate limiter runs before authentication**, so this answer arrives whether the credential is good, bad, or missing — see [rest-api.md](rest-api.md#bind-address--connection-limits). |
| `401` | Missing, non-Bearer, malformed, expired, revoked, wrong-audience, or wrong-key credential — **or a good credential scoped too narrowly for the route**. A `metrics` token verifies fine and still gets `401` on `/v1/dialogs`, because that route demands `full`. |
| `404` | The credential passed, but nothing matches: no dialog carries that Call-ID on `/v1/dialogs/{call_id}`, or no stream carries that SSRC on `/v1/streams/{id}`. |
| `400` | The credential passed, but the request does not parse: `/v1/streams/{id}` got an id that is not hexadecimal. |
| `408` | The handler exceeded the request timeout. |

Reading a `401` as "bad token" is safe. Reading a `503` that way is not.
A `503` says nothing about the credential, because nothing looked at it yet.

On the HTTP MCP surface a `401` also carries a `WWW-Authenticate: Bearer`
challenge:

- `error="invalid_token"` when the client presented a credential that failed,
- no error code at all when it presented none.

So the two read differently in a log. The REST API answers with the status alone. See
[the MCP security model](mcp-protocol.md#security-model).

On the REST API, `/health` needs no credential and skips the rate limiter
entirely. On the HTTP MCP server, `/health` takes the bearer token like every
other route, and answers `401` without it.

## Expiry

A token stops verifying (`401`) once `exp <= now`. It needs no server action.

- Mint short-lived tokens for CI/automation.
- Mint longer-lived ones sparingly.

## Rotation

Two independent mechanisms:

- **Token rotation:**
  - Mint a new token before the old one expires.
  - Switch clients over.
  - Let the old token lapse.
  - Multiple tokens are valid simultaneously.
- **Signing-key rotation:** pass `--api-signing-key`/`--mcp-signing-key` more
  than once.
  - The **first** key mints. **All** keys verify.
  - To roll a key:
    - add the new key alongside the old,
    - mint with the new key,
    - migrate clients,
    - then drop the old key on the next restart.

## Revocation

To kill a still-valid token before its `exp`:

- add its `id` to a denylist file,
- point the server at it.

Both steps matter. An id in a file no server reads revokes nothing:

- Add the token's `id` to the denylist file:

   ```bash
   echo "ci-runner-1" >> /etc/sipnab/revoked.txt
   ```

- Start the server with the denylist file:

   ```bash
   sipnab -N -I capture.pcap --api 127.0.0.1:8080 --api-signing-key "$KEY" --api-revoked-file /etc/sipnab/revoked.txt
   ```

The HTTP MCP server takes `--mcp-revoked-file` the same way. This run minted
an MCP token with `--token-id ci-runner-1`, started the server with an empty
denylist, and appended the id while the server ran:

```bash
sipnab -N -I capture.pcap --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
  --mcp-signing-key-file /etc/sipnab/mcp-signing.key --mcp-revoked-file /etc/sipnab/revoked.txt
```

The same token got `200` from `/health` before the append and `401` after it,
with this challenge:

```text
www-authenticate: Bearer realm="sipnab", error="invalid_token", error_description="The access token is invalid or has expired"
```

The file is one token `id` per line (blank lines and `#` comments ignored).

It is **re-read when its mtime changes**.

- So appending an id revokes that token within the next request.
- It needs no restart.
- (Signed tokens are otherwise valid until `exp`. So a denylist is the revocation mechanism for the
  stateless model.)

## Secure every listener

sipnab has four network listeners. Each takes its own credential and its own
certificate, and each refuses a routable bind that has no credential:

| Listener | Credential | TLS flags | Config keys | Routable bind with no credential |
|---|---|---|---|---|
| REST API (`--api`) | bearer token: `--api-key` or `--api-signing-key[-file]` | `--api-tls-cert`, `--api-tls-key` | `[api] tls_cert`, `tls_key` | refused, exit 2 |
| MCP over HTTP (`--mcp-transport http`) | bearer token: `--mcp-token[-file]` or `--mcp-signing-key[-file]` | `--mcp-tls-cert`, `--mcp-tls-key` | `[mcp] tls_cert`, `tls_key` | refused, exit 2 |
| Metrics (`--metrics`) | HTTP Basic: `--metrics-auth-file` holding `user:password` | `--metrics-tls-cert`, `--metrics-tls-key` | `[metrics] tls_cert`, `tls_key` | refused, exit 2 |
| HEP (`--hep-listen`) | source allowlist `--hep-allow`, or shared secret `--hep-auth-file` | `--hep-listen-transport tls`, `--hep-tls-cert`, `--hep-tls-key` | `[hep] tls_cert`, `tls_key` | refused, exit 1 |

The exact refusal messages are in [A service that does not
start](run-as-a-service.md#a-service-that-does-not-start).

TLS encrypts the path, and the credential in the second column says who the
client is. The REST API and MCP over HTTP can also ask each client for a
certificate from your own CA (`--api-tls-client-ca`, `--mcp-tls-client-ca`),
and then refuse a client without one. The token is still required: see
[Require client certificates](mtls.md). The metrics and HEP listeners ask for
none.

### Make a certificate

Clients check the certificate against the name they connect to. For a private
deployment, make a small CA and sign one certificate for the capture host:

- Make the CA:

  ```bash
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout ca.key -out ca.pem -days 365 -subj "/CN=sipnab example CA"
  ```

- Make the host's key and request:

  ```bash
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout capture01.key -out capture01.csr -subj "/CN=capture01.example.net"
  ```

- Sign it, naming the host in `subjectAltName`:

  ```bash
  # Run all of these, in order.
  printf 'subjectAltName=DNS:capture01.example.net\nextendedKeyUsage=serverAuth\n' > ext.cnf
  openssl x509 -req -in capture01.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -extfile ext.cnf -out capture01.pem
  ```

- Restrict the key. sipnab refuses a key any other user can read, with
  `the API TLS private key is world-readable (mode 0644); chmod 600 it` and
  exit status 2:

  ```bash
  chmod 600 capture01.key
  ```

Clients need `ca.pem`. Keep `ca.key` off the capture host.

**sipnab reads these files before it drops root.** A run started as root,
under `sudo` or as a root service, opens the capture, reads its key and
credential files, and then drops to `nobody` (or the `--user` account). So a
file only root can read (`chmod 600`) works on a root run. That covers the
REST and MCP signing keys and token files, the metrics credential, the REST,
MCP, metrics and HEP certificates and keys, the HEP CA files and
`--hep-auth-file`, `--tls-key`, `--srtp-keys`, `--dtls-keylog` and
`--redact-key-file`.

The exception is a revocation list, `--api-revoked-file` or
`--mcp-revoked-file`. sipnab reads it again whenever it changes, as the user
it dropped to, so that user must be able to read it. When it cannot, the run
stops with exit status 2 right after the drop, because a list sipnab cannot
read revokes nothing.

A systemd unit with `User=sipnab` starts as `sipnab` and drops nothing, so
there every file must be readable by `sipnab`. Give the service its own
account and its group read access:

```bash
# Run all of these, in order.
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin sipnab
sudo chown root:sipnab capture01.key api-signing.key mcp-signing.key metrics.auth
sudo chmod 640 capture01.key api-signing.key mcp-signing.key metrics.auth
```

### Serve all four over TLS

One run can serve all four, with one certificate:

```bash
sipnab -N \
  --hep-listen 0.0.0.0:9063 --hep-listen-transport tls \
    --hep-tls-cert capture01.pem --hep-tls-key capture01.key --hep-allow 192.0.2.0/24 \
  --api 0.0.0.0:8443 --api-signing-key-file api-signing.key \
    --api-tls-cert capture01.pem --api-tls-key capture01.key --api-allowed-host capture01.example.net \
  --mcp --mcp-transport http --mcp-bind 0.0.0.0:8731 --mcp-signing-key-file mcp-signing.key \
    --mcp-tls-cert capture01.pem --mcp-tls-key capture01.key --mcp-allowed-host capture01.example.net \
  --metrics 0.0.0.0:9443 --metrics-auth-file metrics.auth \
    --metrics-tls-cert capture01.pem --metrics-tls-key capture01.key
```

Make the three credential files first:

```bash
# Run all of these, in order.
umask 077
openssl rand -hex 32 > api-signing.key
openssl rand -hex 32 > mcp-signing.key
printf 'scraper:%s\n' "$(openssl rand -hex 16)" > metrics.auth
```

The startup lines confirm each one:

```text
INFO sipnab::capture::hep: HEP listener started on 0.0.0.0:9063 (tls)
INFO sipnab::output::prometheus_server: Prometheus metrics server serves HTTPS only (TLS 1.2/1.3)
INFO sipnab::output::api: REST API serves HTTPS only (TLS 1.2/1.3, ALPN http/1.1)
INFO sipnab::mcp::transport::http: MCP HTTP serves HTTPS only (TLS 1.2/1.3, ALPN http/1.1)
```

With `--hep-allow` and no secret, the HEP listener also warns that it trusts
the addresses each sender claims: add `--hep-auth-file` to remove that.

Check each listener from a client that holds `ca.pem`:

```bash
# Run all of these, in order.
TOKEN="$(SIPNAB_API_SIGNING_KEY="$(cat api-signing.key)" sipnab --mint-token)"
curl --cacert ca.pem https://capture01.example.net:8443/health
curl --cacert ca.pem -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" https://capture01.example.net:8443/v1/stats
curl --cacert ca.pem -u "$(cat metrics.auth)" -s https://capture01.example.net:9443/metrics | head -1
```

```text
ok
200
# HELP sipnab_responses_total Total SIP responses by code class
```

What a client sees when something is missing:

| Request | Answer |
|---|---|
| no `--cacert` | curl exits 60: `SSL certificate problem: unable to get local issuer certificate` |
| plain `http://` to a TLS port | no HTTP answer; curl exits 1 |
| metrics without `-u` | `401` |
| a `metrics`-scope token on `/v1/stats` | `401` |

[Run sipnab as a HEP relay](examples.md#carry-the-feed-over-tcp-and-tls) shows
the HEP sender's side. A sender that does not trust the collector's issuer
stops at startup with exit status 2:

```text
Failed to create HEP sender: Failed to establish a TLS session with '127.0.0.1:19063': invalid peer certificate: UnknownIssuer
```

The listener logs nothing for that failed handshake at the default level, so
read the sender's side. The release container image holds no CA bundle: a
sender in it needs `--hep-tls-ca` even for a collector with a public
certificate, and stops with `no system CA bundle found; name the collector's
issuer with --hep-tls-ca` without it.

### Scrape the HTTPS metrics endpoint from Prometheus

Prometheus needs the user name, the password, and the CA. Put the password
alone in a file Prometheus can read, then add the job:

```yaml
scrape_configs:
  - job_name: sipnab
    scheme: https
    basic_auth:
      username: scraper
      password_file: /etc/prometheus/sipnab.pass
    tls_config:
      ca_file: /etc/prometheus/sipnab-ca.pem
    static_configs:
      - targets: ["capture01.example.net:9443"]
```

Prometheus 3.5.0 with that job reported the target up:

```bash
curl -s -G http://localhost:9090/api/v1/query --data-urlencode 'query=up{job="sipnab"}'
```

```text
{'__name__': 'up', 'instance': 'capture01.example.net:9443', 'job': 'sipnab'} 1
```

That line is the query's result, printed from its JSON. The REST API also
serves the metrics, on `/metrics`, to a token minted with `--token-scope
metrics`.

## Token format

```text
s2.<base64url(payload)>.<base64url(HMAC-SHA256)>
```

- `payload` is compact JSON
  `{"id":"<jti>","exp":<unix_seconds>,"aud":"<api|mcp>","scope":"<metrics|read|actions|admin|audio>"}`.
- The signature is `HMAC-SHA256(signing_key, "s2." + base64url(payload))`.
- base64url is URL-safe, no padding.

`scope` appears **only when it narrows something**.

- A `full` token — the default — omits the claim.
  So its payload is the three-field `{"id":"<jti>","exp":<unix_seconds>,"aud":"<api|mcp>"}` form.
- A payload carrying no `scope` means `full`.
- Seeing `scope` in a decoded payload therefore always means
  "restricted". See [Scope: what a token may reach](#scope-what-a-token-may-reach) above.

Verification is **stateless**. The server:

- recomputes the HMAC,
- compares it in constant time against every configured signing key,
- then checks:
  - the audience,
  - `exp > now`,
  - the scope the route demands,
  - that `id` is not revoked.

A malformed token loses (fail-closed).

## Audience binding

`aud` names the surface a token belongs to.

- The HTTP MCP endpoint turns away a token minted from `--api-signing-key`.
- The REST API turns away one minted from `--mcp-signing-key`.
- This holds **even when both surfaces carry the same signing
  key**.

The version prefix is part of the signed input. So an `s2` token cannot be
rewritten as another version to remove its audience.

### Replace an `s1` token

sipnab accepts only `s2` tokens. A token that begins `s1.` carries no
audience and gets `401` on both surfaces. Mint a replacement with
`--mint-token` against the signing key of the surface the client uses.

## Security notes

- Signing keys and tokens are secrets.
  Prefer `*-signing-key-file` or env over argv (argv is visible in `ps`).
- Signature and static-secret comparison runs in **constant time**.
- Do not choose a static `--api-key`/`--mcp-token` shaped like `s2.x.y`.
  - It would parse as a (failing) signed token rather than matching a static secret.
  - (An `s1.x.y` shape is no longer a recognized version.
    So sipnab treats it as an ordinary opaque secret.)
- Static secrets carry no audience.
  - If you set the same static `--api-key` and `--mcp-token`, that one secret opens both surfaces.
  - Audience binding applies to signed tokens only.
- Anyone on the path can read a bearer credential sent over plain HTTP.
  For a non-loopback deployment, do one of these:
  - serve the REST API over HTTPS with `--api-tls-cert` and `--api-tls-key`,
    and HTTP MCP with `--mcp-tls-cert` and `--mcp-tls-key`,
  - or terminate TLS at a reverse proxy in front of a loopback bind.
  - Passing only one of a pair stops sipnab at startup.
    It does not serve plain HTTP on a port meant for HTTPS.
  - See [API TLS](rest-api.md#api-tls) and [MCP TLS](mcp-deploy.md#mcp-tls).
