# MCP server setup

Step-by-step bootstrap for running sipnab as an MCP server. For what the
server exposes and why, see [mcp-overview.md](./mcp-overview.md); for the
tool catalog, see [mcp-tools.md](./mcp-tools.md).

Build requirement: the `mcp` feature (stdio) or `mcp-http` (HTTP), e.g.

```bash
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

## 1. Local agent (stdio) — zero setup

```bash
sipnab --mcp -I capture.pcap        # analyze a pcap
sudo sipnab --mcp -d eth0           # live capture (root / CAP_NET_RAW)
```

Claude Desktop / Claude Code client entry:

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-I", "/path/to/capture.pcap"]
    }
  }
}
```

No token is needed: stdio is a private pipe between client and server.

## 2. Remote agent (HTTP) — token bootstrap

Non-loopback binds **require** a bearer token. Generate one once:

```bash
sudo mkdir -p /etc/sipnab
head -c 32 /dev/urandom | base64 | sudo tee /etc/sipnab/mcp.token >/dev/null
sudo chmod 600 /etc/sipnab/mcp.token
```

Start the server (here: HEP listener feeding it, common on a capture host):

```bash
sipnab --mcp --mcp-transport http \
       --mcp-bind 0.0.0.0:8731 \
       --mcp-token-file /etc/sipnab/mcp.token \
       --mcp-allowed-host capture01.example.net \
       -L 0.0.0.0:9060 --hep-parse
```

- `--mcp-token-file` is preferred over `--mcp-token`/`SIPNAB_MCP_TOKEN`
  (no token in `ps` output or unit files).
- `--mcp-allowed-host` extends rmcp's DNS-rebind protection (only
  `localhost`/`127.0.0.1`/`::1` are accepted by default) to the hostname
  your clients actually use. `*` disables the check — only do that behind
  a network-level allowlist.

Give the client the token:

```bash
sudo cat /etc/sipnab/mcp.token
```

and configure it as a bearer token for `http://capture01.example.net:8731`.

## 3. systemd unit

`/etc/systemd/system/sipnab-mcp.service` (a packaged variant ships in
[`contrib/sipnab.service`](../contrib/sipnab.service)):

```ini
[Unit]
Description=sipnab MCP server (HEP listener)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sipnab --mcp --mcp-transport http \
    --mcp-bind 127.0.0.1:8731 \
    --mcp-token-file /etc/sipnab/mcp.token \
    -L 0.0.0.0:9060 --hep-parse
User=sipnab
Group=sipnab
NoNewPrivileges=true
ProtectSystem=strict
ReadOnlyPaths=/etc/sipnab
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sipnab-mcp
```

The HEP listener needs no capture privileges (plain UDP socket), so the
unit runs as an unprivileged user. For live interface capture instead of
HEP, grant the binary `CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw+ep /usr/local/bin/sipnab
```

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `--mcp-transport http` rejected | Built without `mcp-http`. Rebuild with `--features mcp-http` (run `sipnab --version` to see compiled features). |
| 401 from the server | Token mismatch — compare the client's bearer token with the token file; check for a trailing newline stripped by your client. |
| 403 / host rejected | DNS-rebind protection: add the hostname clients use via `--mcp-allowed-host`. |
| Server starts, then "no packets" | If feeding via HEP, confirm the sender targets the `-L` port and watch for the idle warning (`no packets for 30s`) in the logs. |
