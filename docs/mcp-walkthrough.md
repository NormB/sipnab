# MCP walkthrough — every deployment scenario, step by step

[MCP Server](mcp.md) is the reference: every flag, tool, and error code. This
page walks a **first-time sipnab user** through each deployment scenario,
command by command, on every machine involved. Steps are tagged with the
host they run on: **[server]** (where sipnab runs), **[laptop]** (where
your MCP client / Claude Code runs), or **[proxy]** (your SIP proxy, in
the HEP scenario).

Every command here was verified end to end against a real build at 0.5.20. The
flag names are held to the current CLI by `docs_drift_test`, but the walkthrough
itself has not been re-run since, so treat the transcript as illustrative rather
than freshly measured.

The client steps use Claude Code; the server side is identical for every
MCP-capable agent. If you drive Codex CLI, Cursor, VS Code, Gemini CLI, or
Windsurf instead, do the same scenario and swap the registration step —
[Registering other MCP clients](#registering-other-mcp-clients-codex-cursor-vs-code-gemini-cli-windsurf)
has the exact config for each.

## Choosing a scenario

| You have | You want | Scenario |
|---|---|---|
| A pcap and an agent on the same machine | Interactive post-mortem | [1](#scenario-1--agent-and-sipnab-on-the-same-machine-stdio) |
| sipnab on a production server, Claude Code on your laptop | Ad-hoc remote debugging, zero server setup | [2A](#scenario-2a--ssh-launched-stdio-ad-hoc-zero-server-configuration) |
| Same, but a capture that's always on | Persistent queryable service | [2B](#scenario-2b--persistent-http-service-with-a-bearer-token) / [2C](#scenario-2c--ssh-tunnel--loopback-http-persistent-nothing-exposed) |
| OpenSIPS / Kamailio proxies you can't run sipnab on (or a Homer box) | Central capture host aggregating HEP | [3](#scenario-3--central-capture-host-fed-by-hep) |
| Agents outside your network | Hardened public endpoint | [4](#scenario-4--internet-exposed-endpoint-nginx-tls-in-front) |
| Many capture hosts | One client config covering all of them | [5](#scenario-5--a-fleet-of-capture-hosts) |
| No human in the loop | Scheduled / scripted diagnostics | [6](#scenario-6--headless--scheduled-diagnostics) |

Two invariants that apply everywhere:

1. **The binary must have MCP compiled in.** All released artifacts
   (installer script, tarballs, `.deb`, `.rpm`) are built with the full
   feature set, so this is only a concern for source builds — but always
   confirm with `sipnab --version`: the features list must include `mcp`
   (stdio) and, for the HTTP scenarios, `mcp-http`.
2. **`--mcp` requires `-N`.** In stdio mode stdout *is* the JSON-RPC wire,
   so the TUI and stdout-writing flags (`--json`, `--report`, …) are
   rejected. Corollary: one sipnab process is either your TUI **or** your
   MCP server, never both — run two processes if you want both.

---

## Step 0 — install sipnab (every server, once)

On each machine that will *run* sipnab (in scenario 1 that's the laptop
itself):

1. **[server]** Install. The installer picks the right build for your OS,
   CPU, and glibc, verifies its sha256, and installs to `/usr/local/bin`:

   ```bash
   curl -fsSL https://www.sipnab.com/install.sh | sh
   ```

   Debian/Ubuntu and RHEL/Fedora users can use the `.deb` / `.rpm`
   packages instead (headless servers: the `-noaudio` variant skips the
   ALSA dependency) — see [the install guide](install.md) for all channels.

2. **[server]** Verify the features:

   ```bash
   sipnab --version
   # sipnab 0.5.62 (...) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics
   ```

   If `mcp` is missing you have a source build without features — rebuild
   with `cargo install sipnab --features full`.

3. **[server]** Smoke-test the MCP server with no client involved. Use any
   pcap you have (or grab a public sample first:
   `curl -LO https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/SIP_CALL_RTP_G711`):

   ```bash
   # Run all of these, in order.
   {
     echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}'
     sleep 0.3
     echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
     sleep 0.1
     echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"stats","arguments":{}}}'
     sleep 0.5
   } | sipnab --mcp -N -I SIP_CALL_RTP_G711 --quiet | tail -1
   ```

   Expected: a JSON-RPC result whose `text` payload contains
   `"dialog_count"`. If you see that, sipnab's MCP server works on this
   machine and every remaining problem is wiring, not sipnab.

---

## Scenario 1 — agent and sipnab on the same machine (stdio)

The MCP client launches sipnab as a child process and talks JSON-RPC over
the pipe. No port, no token, nothing to deploy.

### 1A. Post-mortem on a capture file

1. **[laptop]** Do [Step 0](#step-0--install-sipnab-every-server-once) on
   this machine (here the "server" is your laptop).

2. **[laptop]** Register the server with Claude Code. The `--` separates
   `claude mcp add`'s own flags from the command it should launch:

   ```bash
   claude mcp add sipnab -- sipnab --mcp -N -I "$PWD/capture.pcap" --quiet
   ```

   Claude Desktop instead: edit
   `~/Library/Application Support/Claude/claude_desktop_config.json`
   (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

   ```json
   {
     "mcpServers": {
       "sipnab": {
         "command": "sipnab",
         "args": ["--mcp", "-N", "-I", "/path/to/capture.pcap", "--quiet"]
       }
     }
   }
   ```

   and restart Claude Desktop.

3. **[laptop]** Verify the client sees it:

   ```bash
   claude mcp list          # sipnab ✓ connected
   ```

4. **[laptop]** Use it. Start `claude` and ask:

   > which calls in this capture had one-way audio, and why?

   Watch the agent call `find_problems {"kinds":["one-way"]}`, then
   `rtp_stats` / `get_dialog_report` on what it finds.

### 1B. Live capture on the same box

Live interface capture needs `CAP_NET_RAW`, and your MCP client isn't
running as root.

1. **[laptop]** Grant the capability to the binary once:

   ```bash
   sudo setcap cap_net_raw+ep /usr/local/bin/sipnab
   ```

2. **[laptop]** Find your interface name (`ip -br link`), then:

   ```bash
   claude mcp add sipnab-live -- sipnab --mcp -N -d eth0 --quiet
   ```

3. **[laptop]** Verify with `claude mcp list`, generate or wait for SIP
   traffic, and ask the agent for `stats` — `dialog_count` should climb.

State is per-session: the capture starts when the agent connects and dies
with it. For "always capturing, query whenever" on one box, use the
scenario-2B service bound to `127.0.0.1` (loopback needs no token) and add
it with `claude mcp add --transport http sipnab http://127.0.0.1:8731/mcp`.

---

## Scenario 2 — sipnab on a remote/production server, Claude Code on a laptop

A designed-for use case, not a workaround: the MCP surface is **read-only
by construction** (no tool sends SIP or mutates capture state), every
response is bounded, and non-loopback HTTP binds refuse to start without a
bearer token. Three wirings, in increasing order of setup.

### Scenario 2A — SSH-launched stdio: ad-hoc, zero server configuration

The MCP "command" is simply `ssh`. Nothing listens on the server; your SSH
key is the authentication; when the session ends, nothing is left running.

1. **[server]** Do [Step 0](#step-0--install-sipnab-every-server-once).
   That's *all* the server setup there is.

2. **[laptop]** Confirm non-interactive SSH works — a password prompt
   would hang the MCP client forever:

   ```bash
   ssh -o BatchMode=yes prod01.example.net true && echo SSH OK
   ```

   If that fails, set up key auth first (`ssh-keygen`, `ssh-copy-id`).

3. **[laptop]** Register the server. Use the **absolute path** to sipnab —
   non-interactive SSH sessions get a minimal PATH that often misses
   `/usr/local/bin`:

   ```bash
   claude mcp add sipnab-prod -- \
     ssh prod01.example.net /usr/local/bin/sipnab --mcp -N \
         -I /var/spool/captures/outage-0722.pcap --quiet
   ```

   (The pcap path is a path **on the server**.)

4. **[laptop]** Verify the client picked it up — the entry should read
   `sipnab-prod ✓ connected`:

   ```bash
   claude mcp list
   ```

   Then start an agent against it and ask, for example, *"summarize the
   failed calls in this capture"*:

   ```bash
   claude
   ```

Live capture over SSH works too, if the remote binary has the capability
(`sudo setcap cap_net_raw+ep /usr/local/bin/sipnab` on the server, once):

```bash
claude mcp add sipnab-prod-live -- \
  ssh prod01.example.net /usr/local/bin/sipnab --mcp -N -d eth0 --quiet
```

Each agent session spawns a fresh sipnab: perfect for pcap post-mortems,
wrong for accumulating live state — that's 2B/2C.

### Scenario 2B — persistent HTTP service with a bearer token

For a capture that runs continuously and answers agents whenever they ask.
Keep this shape on a trusted network (LAN/VPN): the token authenticates,
but the transport is plaintext HTTP. Across untrusted networks use 2C
or 4.

1. **[server]** Do [Step 0](#step-0--install-sipnab-every-server-once).

2. **[server]** Create the unprivileged user the service will run as:

   ```bash
   sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin sipnab
   ```

   Then grant the binary capture rights. Skip this second command if you'll
   feed HEP instead (scenario 3): a HEP listener is a plain UDP socket, so
   `cap_net_raw` would be privilege the service never uses.

   ```bash
   sudo setcap cap_net_raw+ep /usr/local/bin/sipnab
   ```

3. **[server]** Generate the bearer token file:

   ```bash
   # Run all of these, in order.
   sudo mkdir -p /etc/sipnab
   head -c 32 /dev/urandom | base64 | sudo tee /etc/sipnab/mcp.token >/dev/null
   sudo chmod 600 /etc/sipnab/mcp.token
   ```

4. **[server]** Install the systemd unit as
   `/etc/systemd/system/sipnab-mcp.service`. `--mcp-allowed-host` must
   name whatever the laptop will put in the URL — without it, DNS-rebind
   protection answers `403 Forbidden: Host header is not allowed`:

   ```ini
   [Unit]
   Description=sipnab MCP server
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   ExecStart=/usr/local/bin/sipnab --mcp -N --mcp-transport http \
       --mcp-bind 0.0.0.0:8731 \
       --mcp-token-file /etc/sipnab/mcp.token \
       --mcp-allowed-host prod01.example.net \
       -d eth0
   User=sipnab
   Group=sipnab
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   PrivateTmp=true
   ReadOnlyPaths=/etc/sipnab
   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

5. **[server]** Start it and check it came up:

   ```bash
   # Run all of these, in order.
   sudo systemctl daemon-reload
   sudo systemctl enable --now sipnab-mcp
   systemctl status sipnab-mcp --no-pager
   ```

   If it exits immediately with a token error, you bound non-loopback
   without a readable token file — that refusal is deliberate (fail
   closed).

6. **[server]** Verify locally before involving the laptop. The `curl` reads
   `$TOKEN` out of the shell the first line sets, so the two only work
   together:

   ```bash
   # Run all of these, in order.
   TOKEN=$(sudo cat /etc/sipnab/mcp.token)
   curl -sS http://127.0.0.1:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
   ```

   Expected: a `serverInfo` block naming the sipnab instructions string.

7. **[server]** Open tcp/8731 to your laptop's network in whatever
   firewall governs this host (nftables/ufw/cloud security group) —
   ideally to specific source addresses, not the world.

8. **[laptop]** Copy the token, then register the server. First, somewhere
   to keep it that only you can read:

   ```bash
   mkdir -p ~/.config/sipnab && chmod 700 ~/.config/sipnab
   ```

   Now fetch the token. Run this one by itself and read what it prints: your
   local shell creates and truncates `prod01.token` *before* `ssh` runs, so a
   failed connection or a `sudo` that wants a password leaves you holding an
   empty file rather than no file at all.

   ```bash
   ssh prod01.example.net sudo cat /etc/sipnab/mcp.token > ~/.config/sipnab/prod01.token
   ```

   Check that the file is non-empty and matches the server's, then close its
   permissions:

   ```bash
   chmod 600 ~/.config/sipnab/prod01.token
   ```

   Finally register the server. The `$(cat …)` resolves when you run this, so
   an empty token file here registers an empty bearer and every later call
   comes back `401`:

   ```bash
   claude mcp add --transport http \
     --header "Authorization: Bearer $(cat ~/.config/sipnab/prod01.token)" \
     sipnab-prod http://prod01.example.net:8731/mcp
   ```

9. **[laptop]** Verify the client connected — the entry should read
   `sipnab-prod ✓ connected`:

   ```bash
   claude mcp list
   ```

   Then start an agent and ask it something only the running capture can
   answer, for example *"any calls with one-way audio right now?"*:

   ```bash
   claude
   ```

### Scenario 2C — SSH tunnel + loopback HTTP: persistent, nothing exposed

The best of both: the service runs continuously but binds only loopback,
so there's no token to manage and no port to firewall. The SSH tunnel is
the auth *and* the encryption.

1. **[server]** Follow 2B steps 1–2, then install the same unit **with two
   changes**: bind loopback and drop the token/allowed-host flags
   (loopback binds require neither):

   ```ini
   ExecStart=/usr/local/bin/sipnab --mcp -N --mcp-transport http \
       --mcp-bind 127.0.0.1:8731 \
       -d eth0
   ```

   ```bash
   sudo systemctl daemon-reload && sudo systemctl enable --now sipnab-mcp
   ```

2. **[server]** Verify locally — same curl as 2B step 6, minus the
   `Authorization` header.

3. **[laptop]** Open the tunnel (add `autossh` or a systemd user unit if
   you want it self-healing):

   ```bash
   ssh -f -N -L 8731:127.0.0.1:8731 prod01.example.net
   ```

4. **[laptop]** Register against localhost — the default host allowlist
   already accepts `127.0.0.1`:

   ```bash
   claude mcp add --transport http sipnab-prod http://127.0.0.1:8731/mcp
   ```

   Then confirm the client reaches the server through the tunnel:

   ```bash
   claude mcp list
   ```

5. **[laptop]** When the tunnel drops (laptop sleep, network change), MCP
   calls fail with connection errors; re-run step 3. That's the one
   operational cost of this shape.

### Which remote wiring?

| | 2A ssh-stdio | 2B HTTP+token | 2C tunnel |
|---|---|---|---|
| Server setup | install only | unit + token | unit |
| Open port | none | 8731 | none |
| Live state persists between sessions | no | yes | yes |
| Several people/agents at once | one server each | yes | yes (each tunnels) |
| Crosses untrusted networks safely | yes (SSH) | no — use 4 | yes (SSH) |

---

## Scenario 3 — central capture host fed by HEP

You usually can't (and shouldn't) run a packet-capturing debugger on every
production SIP proxy. Instead the proxies mirror signaling to one capture
host via HEP — OpenSIPS, Kamailio, and FreeSWITCH all speak it — and one
sipnab MCP service sees calls from the whole estate. The HEP listener is a
plain UDP socket: **no capture privileges, no setcap, fully unprivileged.**

1. **[server]** Do [Step 0](#step-0--install-sipnab-every-server-once)
   and create the user (2B step 2, *without* the `setcap`).

2. **[server]** Install `/etc/systemd/system/sipnab-mcp.service` — this
   variant listens for HEP on udp/9063 and serves MCP on loopback (pair it
   with the 2C tunnel; for the 2B token shape instead, use its
   `--mcp-bind`/token/allowed-host lines):

   ```ini
   [Unit]
   Description=sipnab MCP server (HEP listener)
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   ExecStart=/usr/local/bin/sipnab --mcp -N --mcp-transport http \
       --mcp-bind 127.0.0.1:8731 \
       -L 0.0.0.0:9063 --hep-parse
   User=sipnab
   Group=sipnab
   NoNewPrivileges=true
   ProtectSystem=strict
   PrivateTmp=true
   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

   ```bash
   sudo systemctl daemon-reload && sudo systemctl enable --now sipnab-mcp
   ```

3. **[server]** Open udp/9063 from the proxies' addresses in the host
   firewall.

4. **[proxy]** Point each proxy's HEP mirror at the capture host.

   OpenSIPS (3.x) — `opensips.cfg`:

   ```text
   loadmodule "proto_hep.so"
   loadmodule "tracer.so"
   modparam("tracer", "trace_id",
       "[sipnab]uri=hep:capture01.example.net:9063;version=3;transport=udp")
   ```

   and in the main route (traces the dialog's SIP both ways):

   ```text
   trace("sipnab", "t", "sip");
   ```

   Kamailio — the `siptrace` module with `duplicate_uri` pointed at
   `sip:capture01.example.net:9063` and HEP mode enabled; see the
   [siptrace docs](https://kamailio.org/docs/modules/stable/modules/siptrace.html)
   for the handful of modparams.

5. **[server]** Verify HEP is arriving. Place a test call through a
   proxy, then:

   ```bash
   curl -sS http://127.0.0.1:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
   ```

   then watch `journalctl -u sipnab-mcp -f` — a
   `no packets for 30s` warning means the HEP sender isn't reaching the
   `-L` port (firewall, wrong port, wrong host).

6. **[laptop]** Wire up exactly as scenario
   [2C](#scenario-2c--ssh-tunnel--loopback-http-persistent-nothing-exposed)
   steps 3–4 (or 2B steps 8–9 for the token shape). Then ask across the
   estate: *"search all proxies' traffic for Call-ID X and render the
   ladder."*

### Coexisting with Homer (or any observability host)

A Homer / heplify-server box is a natural home for sipnab — the HEP
plumbing from the proxies already exists. Two things to arrange:

- **Port**: heplify-server owns udp/9060, so sipnab takes its own
  (udp/9063 above) and each proxy mirrors to **both** destinations —
  OpenSIPS: add a second `trace_id` and a second `trace()` call;
  Kamailio: a second duplicate destination. If a sender can't dup, put a
  small UDP fan-out (e.g. socat) in front.
- **Budget**: cap sipnab's footprint with `[limits]`
  ([below](#load-on-a-busy-server)) so the box's primary tenant keeps its
  headroom.

Anything else on the host — an OpenTelemetry collector, Prometheus, etc. —
is simply a neighbor process; sipnab neither speaks OTLP nor conflicts
with it.

---

## Scenario 4 — internet-exposed endpoint (nginx TLS in front)

When agents connect from outside your network and SSH isn't an option:
keep sipnab on loopback and let nginx own the public endpoint.

1. **[server]** Build the loopback service with a token: 2B steps 1–3,
   then a unit whose ExecStart binds loopback but keeps auth and allows
   the public hostname (nginx forwards the client's `Host:` header):

   ```ini
   ExecStart=/usr/local/bin/sipnab --mcp -N --mcp-transport http \
       --mcp-bind 127.0.0.1:8731 \
       --mcp-token-file /etc/sipnab/mcp.token \
       --mcp-allowed-host capture.example.com \
       -d eth0
   ```

2. **[server]** Install nginx and certbot:

   ```bash
   sudo apt install nginx certbot python3-certbot-nginx
   ```

   Then issue the certificate. certbot needs `capture.example.com` already
   resolving to this host, asks for a contact address, and rewrites the nginx
   config in place — run it on its own so you can answer it:

   ```bash
   sudo certbot --nginx -d capture.example.com
   ```

3. **[server]** Site config (`/etc/nginx/sites-available/sipnab-mcp`,
   symlink into `sites-enabled`, `sudo nginx -t && sudo systemctl reload
   nginx`):

   ```nginx
   server {
       listen 443 ssl;
       server_name capture.example.com;
       ssl_certificate     /etc/letsencrypt/live/capture.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/capture.example.com/privkey.pem;

       location /mcp {
           proxy_pass http://127.0.0.1:8731;
           proxy_set_header Host $host;
           proxy_buffering off;          # SSE responses must stream
           proxy_read_timeout 3600s;
       }
   }
   ```

   `proxy_buffering off` is load-bearing: the streamable-HTTP transport
   answers with `text/event-stream`, and buffering proxies stall it.

4. **[server]** Firewall: open tcp/443 only; 8731 stays closed to the
   outside.

5. **[laptop]** Token copy as in 2B step 8, then:

   ```bash
   claude mcp add --transport http \
     --header "Authorization: Bearer $(cat ~/.config/sipnab/capture.token)" \
     sipnab-prod https://capture.example.com/mcp
   ```

6. **[laptop]** Verify with `claude mcp list`; on failure, test the path
   layer by layer: curl against `https://capture.example.com/mcp` from
   the laptop, then the loopback curl (2B step 6) on the server.

---

## Scenario 5 — a fleet of capture hosts

Run scenario 2B, 2C, or 4 on each capture host, then give each its own
entry in one client config:

1. **[each server]** Any persistent wiring above (2B shown here).

2. **[laptop]** Register them all — the loop is one command and does nothing
   unless you take the whole of it:

   ```bash
   # Run all of these, in order.
   for h in nyc1 chi1 lax1; do
     claude mcp add --transport http \
       --header "Authorization: Bearer $(cat ~/.config/sipnab/$h.token)" \
       "sipnab-$h" "https://$h.example.net/mcp"
   done
   ```

   Then confirm all three registered:

   ```bash
   claude mcp list
   ```

3. **[laptop]** Ask cross-fleet questions — tool names are namespaced per
   server (`mcp__sipnab-nyc1__list_dialogs`,
   `mcp__sipnab-chi1__list_dialogs`, …), so the agent can fan out:

   > the caller says the 14:02 UTC call dropped; find its Call-ID on all
   > three sites and compare the ladders.

---

## Scenario 6 — headless / scheduled diagnostics

Nothing about MCP requires an interactive session.

**Agent-in-cron** — headless Claude Code against any wiring above:

1. **[laptop or ops host]** Confirm the MCP server is registered
   (`claude mcp list`), then test a one-shot run:

   ```bash
   claude -p "Using the sipnab MCP tools: list problem dialogs from the \
   last 24h, get reports for the worst three, and summarize likely root \
   causes." --allowedTools "mcp__sipnab-prod__*"
   ```

2. **[laptop or ops host]** Wrap it in cron/systemd-timer, writing to a
   file or a ticket system:

   ```text
   0 7 * * * claude -p "..." --allowedTools "mcp__sipnab-prod__*" \
             > /var/log/sipnab/daily-triage.md 2>&1
   ```

**No LLM at all** — the MCP server is also just a stable JSON-RPC API for
scripts: the Python/TypeScript clients in
[mcp.md § Client cookbook](mcp.md#client-cookbook) drive the same tools
directly (e.g. a nightly job calling `find_problems` and opening a ticket
when the count is nonzero).

---

## Registering other MCP clients (Codex, Cursor, VS Code, Gemini CLI, Windsurf)

Every scenario above is client-agnostic on the server side: stdio wirings
(1, 2A) hand the client a command to launch, HTTP wirings (2B, 2C, 4) hand
it a URL plus a bearer token. Only the registration step differs per
agent. The table maps it; snippets follow.

| Client | Config lives in | stdio | Streamable HTTP |
|---|---|---|---|
| Claude Code | `claude mcp add` | ✓ | ✓ `--transport http` + header |
| Claude Desktop | `claude_desktop_config.json` | ✓ | via Settings → Connectors |
| Codex CLI | `~/.codex/config.toml` | ✓ `command`/`args` | ✓ `url` + `bearer_token_env_var` |
| Cursor | `~/.cursor/mcp.json` | ✓ `command`/`args` | ✓ `url` + `headers` |
| VS Code (Copilot agent mode) | `.vscode/mcp.json` | ✓ `type: stdio` | ✓ `type: http` + `headers` |
| Gemini CLI | `~/.gemini/settings.json` | ✓ `command` | ✓ `httpUrl` + `headers` |
| Windsurf (Cascade) | `~/.codeium/windsurf/mcp_config.json` | ✓ `command`/`args` | ✓ `serverUrl` + `headers` |

For the remote-stdio wiring (scenario 2A), every stdio snippet below works
unchanged with `command` set to `ssh` and the sipnab invocation moved into
`args` — exactly as in the Claude Code example there.

### Codex CLI

`~/.codex/config.toml` (shared by the ChatGPT desktop app and IDE
extension), one TOML table per server — `command` means stdio, `url` means
streamable HTTP, mixing both is rejected:

```toml
# stdio — scenario 1/2A
[mcp_servers.sipnab]
command = "sipnab"
args = ["--mcp", "-N", "-I", "/path/to/capture.pcap", "--quiet"]

# streamable HTTP — scenario 2B/2C/4; token read from the named env var
[mcp_servers.sipnab-prod]
url = "https://capture.example.com/mcp"
bearer_token_env_var = "SIPNAB_MCP_TOKEN"
```

`bearer_token_env_var` names a variable read from the environment codex is
launched with, so the export and the launch have to happen in the same shell:

```bash
# Run all of these, in order.
export SIPNAB_MCP_TOKEN=$(cat ~/.config/sipnab/prod01.token)
codex   # then e.g.: "which calls had one-way audio?"
```

Or from the CLI: `codex mcp add sipnab -- sipnab --mcp -N -I capture.pcap --quiet`

### Cursor

`~/.cursor/mcp.json` (or per-project `.cursor/mcp.json`). `${env:VAR}`
interpolation keeps the token out of the file:

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-N", "-I", "/path/to/capture.pcap", "--quiet"]
    },
    "sipnab-prod": {
      "url": "https://capture.example.com/mcp",
      "headers": { "Authorization": "Bearer ${env:SIPNAB_MCP_TOKEN}" }
    }
  }
}
```

### VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json` — note the root key is `servers` and every entry needs
an explicit `type`. MCP tools appear in **agent mode** only (invisible in
Ask/Edit):

```json
{
  "servers": {
    "sipnab": {
      "type": "stdio",
      "command": "sipnab",
      "args": ["--mcp", "-N", "-I", "/path/to/capture.pcap", "--quiet"]
    },
    "sipnab-prod": {
      "type": "http",
      "url": "https://capture.example.com/mcp",
      "headers": { "Authorization": "Bearer ${env:SIPNAB_MCP_TOKEN}" }
    }
  }
}
```

### Gemini CLI

`~/.gemini/settings.json` — exactly one transport key per server:
`command` (stdio), `httpUrl` (streamable HTTP), or `url` (legacy SSE).
Use `httpUrl` for sipnab:

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-N", "-I", "/path/to/capture.pcap", "--quiet"]
    },
    "sipnab-prod": {
      "httpUrl": "https://capture.example.com/mcp",
      "headers": { "Authorization": "Bearer your-token-here" }
    }
  }
}
```

### Windsurf (Cascade)

`~/.codeium/windsurf/mcp_config.json` — remote servers use `serverUrl`,
and `${file:...}` interpolation reads the token straight from the file you
copied in scenario 2B step 8:

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-N", "-I", "/path/to/capture.pcap", "--quiet"]
    },
    "sipnab-prod": {
      "serverUrl": "https://capture.example.com/mcp",
      "headers": { "Authorization": "Bearer ${file:/home/you/.config/sipnab/prod01.token}" }
    }
  }
}
```

Two universal gotchas, regardless of client: the `Host:` your client sends
must be in sipnab's `--mcp-allowed-host` allowlist (403 otherwise), and
plaintext-HTTP registrations belong on trusted networks only — the same
rules as scenarios 2B and 4.

---

## Load on a busy server

Two distinct costs; both are small, and both are cappable.

**The capture path** dwarfs the MCP path and is the one to size. Reference
numbers ([benchmarks](benchmarks.md), modest 14-core aarch64 host):
1.2M pkts/s single-core offline reconstruction on a ~93%-RTP corpus, 2.9M
at two cores. For scale: a proxy doing 100 CPS with ~10 SIP messages per
call generates ~1k signaling packets/s — three orders of magnitude below
one core's budget. What actually costs:

- **Live `-d` capture of media**: RTP dominates packet counts. If you only
  need signaling analysis, don't capture media (BPF filter on port 5060,
  or feed HEP — proxies mirror signaling only), and RTP tracking cost
  disappears.
- **HEP ingest** is the cheapest input: an unprivileged UDP socket, and
  `hep_rate_limit` (default 50k pps) hard-caps what sipnab will accept.
- **Memory is bounded, not open-ended**: `[limits]` defaults cap tracked
  dialogs (100k), RTP streams (50k), messages per dialog (500), and TCP
  reassembly (10k). Tighten these on a shared box; a
  `dialog_limit = 20000`-class config keeps sipnab a well-behaved tenant.

**The MCP query path** is noise by comparison: read-only lookups against
in-memory stores, every response bounded (`limit` ≤ 1000, snippets ≤ 4 KB,
≤ 1000 messages per page). An agent conversation makes a handful of tool
calls; there is no polling loop unless you build one. If you want *zero*
load on the SIP server itself, that's scenario 3: the proxy pays only for
HEP mirroring and sipnab lives elsewhere.

## Security implications

What the design already gives you (details in
[mcp.md § Security model](mcp.md#security-model)):

- **Read-only, no control plane.** No MCP tool sends SIP, writes files, or
  changes capture state — a compromised or confused agent can disclose
  data, not take over the server. Capture lifecycle belongs to systemd.
- **Fail-closed remote access.** Non-loopback HTTP binds refuse to start
  without a bearer token; tokens compare in constant time; DNS-rebind
  protection rejects unexpected `Host:` headers; the listener binds after
  privilege drop.

What remains **your** call:

- **Captured SIP is sensitive.** Dialogs carry phone numbers, IPs,
  User-Agents, digest `Authorization` headers, and (if captured) media
  stats. Two consequences: treat the MCP endpoint with the same care as
  the pcaps themselves, and remember that whatever a tool returns is sent
  to the agent's model provider — if that's a cloud LLM, capture content
  leaves your network by design. Scope what the server can see (BPF
  filter, signaling-only HEP) to what you're comfortable exporting.
- **Prefer wirings with no listening surface.** 2A/2C expose nothing;
  2B is plaintext HTTP (LAN/VPN only); 4 is the only shape that belongs
  on the public internet, and even there sipnab stays on loopback behind
  TLS with a token.
- **Token hygiene.** Use `--mcp-token-file` (0600, root-owned) rather than
  `--mcp-token`/env — flags and environments leak via `ps` and unit files.
  Rotation/expiry via signed tokens is available ([auth.md](auth.md)).
- **Contain the process.** Run as a dedicated user with the systemd
  hardening shown above (`NoNewPrivileges`, `ProtectSystem`); HEP ingest
  needs no capabilities at all.

## Troubleshooting ladder

Work outward from the server; each layer has a definitive test.

| Layer | Test | Good sign |
|---|---|---|
| Binary | `sipnab --version` | features include `mcp` / `mcp-http` |
| MCP core | Step 0's stdio one-liner | `"dialog_count"` in the reply |
| HTTP service | loopback curl (2B step 6) | `serverInfo` block |
| Network path | same curl from the laptop | same |
| Client | `claude mcp list` | ✓ connected |

HTTP status decoder: `401` wrong/missing bearer token · `403` `Host:` not
in the allowlist (`--mcp-allowed-host`) · `404` path isn't exactly `/mcp` ·
`406` missing `Accept: application/json, text/event-stream`. More in
[mcp.md § Troubleshooting](mcp.md#troubleshooting); the
[raw HTTP test](mcp.md#raw-http-test) there is a working curl carrying every
required header.
