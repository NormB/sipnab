# sipnab MCP diagnostic harness

A self-contained Docker Compose stack that stands up a live SIP environment
and exposes **sipnab as an MCP server** so an external system (e.g. your
laptop) can diagnose the SIP/RTP traffic flowing through **`opensips-1`**
using an AI agent.

```
  ┌─────────┐   INVITE/REGISTER/...    ┌────────────────────────────────┐
  │ sipp-uac│ ───────────────────────▶ │  opensips-1  (owns netns)      │
  │ .0.21   │                          │   ├─ rtpengine  (media anchor)  │
  └─────────┘                          │   └─ sipnab     (capture + MCP) │
  ┌─────────┐ ◀───────────────────────  │                                │
  │ sipp-uas│      relayed call         │  publishes :5060/udp :8731     │
  │ .0.20   │                          │            :30000-30050/udp     │
  └─────────┘                          └────────────────┬───────────────┘
                                                         │ MCP HTTP :8731
        your laptop  ──────── Bearer token ──────────────┘
        (Claude agent: list_dialogs, find_problems, rtp_stats, ...)
```

Because OpenSIPS anchors **all media through rtpengine**, every SIP message
*and* every RTP packet transits the `opensips-1` network namespace — which
`rtpengine` and `sipnab` share. So `sipnab` has a single capture point that
sees the entire conversation, and serves it over MCP.

## Components

| Service     | Image source                              | Role |
|-------------|-------------------------------------------|------|
| `opensips-1`| built from `NormB/opensips` @ `d8586fa6`  | registrar + stateful proxy; owns the shared netns + published ports |
| `rtpengine` | trixie `rtpengine-daemon` (userspace)     | media relay; shares `opensips-1` netns |
| `sipnab`    | built from this repo (`mcp-http` feature) | live capture on the shared netns + MCP HTTP server |
| `sipp-uas`  | trixie `sip-tester`                       | answers relayed calls |
| `sipp-uac`  | trixie `sip-tester`                       | loops public SIPp scenarios through `opensips-1` |

## Prerequisites

- Docker + Compose v2 (`docker compose`), with network egress to build.
- The sibling `~/opensips` fork is **not** required at build time — OpenSIPS
  is cloned from GitHub at the pinned commit. To build from your working
  tree instead, see *Build OpenSIPS from a local checkout* below.
- `sudo` for `make host-prep` (a one-line sysctl; see below). `make up` runs it
  automatically.

### Host networking note (important)

These containers talk over a Docker bridge. If the host has
`net.bridge.bridge-nf-call-iptables=1` **and** a default-`DROP` iptables
`FORWARD` policy (common on hardened hosts), bridged SIP/RTP frames get
diverted into the L3/iptables path and silently dropped before reaching the
containers — calls time out with no obvious error. `make host-prep` (invoked by
`make up`) sets `net.bridge.bridge-nf-call-iptables=0` at runtime so
intra-bridge frames stay on the L2 path. To persist across reboots:

```bash
echo 'net.bridge.bridge-nf-call-iptables=0' | sudo tee /etc/sysctl.d/99-sipnab-harness.conf
```

Build images use `network: host` because this environment's Docker daemon
forces container DNS to `8.8.8.8`, which is blocked; host networking lets the
build steps use the host resolver. Runtime is unaffected (containers use
static IPs on the bridge).

## Quick start

```bash
cd harness
make up        # generates the MCP token, builds all images, starts the stack
make ps        # check everything is healthy
make logs      # watch SIPp call flow + sipnab capture
```

`make up` ends by printing the connection block for your laptop (also via
`make laptop`). Verify the MCP endpoint locally first:

```bash
make mcp-test  # initialize + tools/list + stats + list_dialogs, using the token
```

## Connect your laptop

`make laptop` prints ready-to-paste config. In short, on the laptop:

```bash
claude mcp add --transport http sipnab "http://<HOST_IP>:8731/mcp" \
    --header "Authorization: Bearer <TOKEN>"
```

Then ask the agent to diagnose `opensips-1`:

- *"List the active SIP dialogs and flag any with problems."*
- *"Show RTP quality — MOS, jitter, packet loss — for the current streams."*
- *"Any security findings: scanners, malformed messages, digest leaks?"*

The token is in `secrets/mcp.token`. The host must allow inbound TCP on the
MCP port (default 8731) from your laptop.

## Your laptop as a SIP endpoint

`opensips-1` also publishes SIP and the RTP range, so your laptop can
register/call **into** the proxy and have sipnab diagnose that traffic. The
host-side SIP port is `SIP_HOST_PORT` in `.env` (default `5060`; this repo's
`.env` uses `5062` because the host already runs a SIP service on 5060):

- Register a softphone to `<HOST_IP>:<SIP_HOST_PORT>` (any user; no auth).
- Place a call to `sip:service@<HOST_IP>:<SIP_HOST_PORT>` — it is relayed to the
  UAS with media anchored by rtpengine, fully visible to sipnab.

## Traffic / scenarios

`sipp-uac` continuously cycles a curated subset of the public scenarios in
`~/sipp-scenarios` (see `make scenarios`). Happy-path scenarios complete;
fault-injection scenarios (broken SDP, bogus codec, malformed message) are
*expected* to error — they give the diagnosing agent real problems to find.
Add or remove scenarios in `sipp/run-uac-loop.sh` and drop the XML (plus any
media pcap) into `sipp/scenarios/`.

## Persisting a pcap (second capture method)

`sipnab` live-captures and serves MCP. To *also* write a pcap fixture, set
`CAPTURE_PCAP` for the sipnab service (e.g. in `docker-compose.yml` or via
`environment`) to a path under `/captures`, then re-analyze offline:

```bash
CAPTURE_PCAP=/captures/opensips-1.pcap docker compose up -d sipnab
# later:
docker compose run --rm --entrypoint sipnab sipnab -N -I /captures/opensips-1.pcap --report
```

## Configuration

Copy `.env.example` to `.env` and adjust (subnet, IPs, published ports,
`SIPNAB_MCP_ALLOWED_HOST`, OpenSIPS git ref, loop pause). `make up` creates
`.env` from the example on first run.

### Build OpenSIPS from a local checkout

Point the build at your working tree instead of GitHub:

```yaml
# docker-compose.yml -> services.opensips-1.build
build:
  context: ../../opensips      # your local fork
  dockerfile: ../sipnab/harness/opensips/Dockerfile.local
```

(A `COPY . .` Dockerfile variant; not provided by default to avoid shipping
your `.git` into the build context.)

## Security notes

- MCP is **read-only** by design; no tool sends SIP or mutates state.
- The non-loopback MCP bind **requires** the bearer token (sipnab refuses to
  start otherwise). Keep `secrets/mcp.token` secret; it is git-ignored.
- `SIPNAB_MCP_ALLOWED_HOST` defaults to `*` (host-header check disabled) for
  convenience. For a hardened setup, set it to your host's name/IP and front
  sipnab with nginx/TLS, or restrict the port with a firewall.

## Troubleshooting

- **All SIPp calls time out / `make mcp-test` shows `dialog_count: 0`.** The
  bridge isn't delivering frames to the containers — run `make host-prep` (see
  *Host networking note*). Confirm with
  `cat /proc/sys/net/bridge/bridge-nf-call-iptables` (should be `0`).
- **Edited `opensips.cfg.tmpl` / the opensips image and calls broke.** `rtpengine`
  and `sipnab` share `opensips-1`'s network namespace, so recreating `opensips-1`
  invalidates theirs. Use `make recreate` (or
  `docker compose up -d --force-recreate`) rather than restarting `opensips-1`
  alone.
- **`sipnab` keeps restarting with a token permission error.** The token is read
  after sipnab drops to `nobody`; `make token` writes it world-readable (644) for
  this reason. If you created it by hand, `chmod 644 secrets/mcp.token`.
- **Port already in use on `make up`.** Another service holds 5060/8731/RTP on the
  host. Change `SIP_HOST_PORT` / `MCP_PORT` / `RTP_MIN..RTP_MAX` in `.env`.
- **`stream_count: 0` but dialogs appear.** RTP isn't being captured — confirm the
  media range published by `opensips-1` matches `RTP_PORTRANGE` the sipnab
  entrypoint captures (default `30000-30050`).

## Teardown

```bash
make down      # stop + remove containers
make clean     # also remove built images and captured pcaps
```
