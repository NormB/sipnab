+++
title = "Deployments"
description = "Four reference topologies for sipnab: one host, a fleet of SIP servers sending HEP, an observability stack, and AI agents over MCP."
template = "overview.html"

[extra]
has_diagrams = true
+++

sipnab is one binary that captures and analyzes SIP and RTP. The same binary
runs in each of the four arrangements on this page. Each section describes one
arrangement:

- the situation it fits,
- how the parts connect,
- what runs on which machine,
- what the operator gets,
- and what the arrangement does not provide.

Each section ends with links to the guides that set it up.

These are reference topologies. They are not customer deployments and not case
studies.

- Every operational step lives in the linked guides.
- Each guide states the setup it ran on.
- This page adds no commands or configuration of its own.

Terms used on this page:

- **HEP** (Homer Encapsulation Protocol). A SIP proxy such as OpenSIPS or
  Kamailio copies each SIP message into a HEP packet and sends it to a
  collector. sipnab can be that collector (`-L`) or a sender (`-H`). See
  [HEP](/docs/glossary/#hep) in the glossary.
- **MCP** (Model Context Protocol). The protocol an AI agent uses to call
  tools. With `--mcp`, sipnab offers its analysis as MCP tools. See
  [MCP](/docs/glossary/#mcp) in the glossary.
- **TUI** (text user interface). The interactive full-screen view sipnab
  opens when it runs without `-N`.
- **RTP and RTCP.** RTP carries the audio. RTCP is its control channel, in
  which each end reports the loss and delay it sees.
- **SBC** (session border controller) and **B2BUA** (back-to-back user agent).
  - An SBC sits at the edge of a network.
  - Most act as a B2BUA. It ends a call on one side and starts a new call
    on the other.
  - So each side carries its own Call-ID.

| Topology | sipnab runs on | Changes on the SIP servers |
|---|---|---|
| [Single host](#single-host) | The SIP server's own machine | None |
| [A fleet of SIP nodes feeding one sipnab over HEP](#a-fleet-of-sip-nodes-feeding-one-sipnab-over-hep) | One capture host | Each proxy's HEP tracing points at the capture host |
| [An observability stack](#an-observability-stack) | The SIP server's machine or a capture host | None beyond "Single host" or "A fleet of SIP nodes feeding one sipnab over HEP" |
| [AI agents over MCP](#ai-agents-over-mcp) | The agent's machine, a server, or several capture hosts | None beyond "Single host" or "A fleet of SIP nodes feeding one sipnab over HEP" |

## Single host

### Situation

One machine runs the SIP proxy, OpenSIPS or Kamailio. The operator wants to:

- see the calls that pass through it,
- and have sipnab put both legs of each call together,
- without changing the proxy.

### Layout

<pre class="mermaid">
flowchart LR
    C[caller] --&gt;|SIP| P[SIP proxy]
    P --&gt;|SIP| E[callee]
    C &lt;-.-&gt;|RTP| E
    subgraph H[SIP server machine]
        P
        S[sipnab, reading the interface]
    end
    P -.-&gt;|packets on the wire| S
</pre>

Plain-text description:

- A caller and a callee exchange SIP through a proxy on one machine.
- sipnab runs on the same machine and reads the network interface.
- The audio flows directly between caller and callee. It does not pass through
  the proxy.
- sipnab sees that audio only where it crosses this machine's interface.
- In the guides' test setup both test endpoints ran on the proxy's machine. So
  it did.

### What runs where

| Machine | Runs |
|---|---|
| SIP server | The proxy (OpenSIPS or Kamailio), unchanged, and sipnab reading the interface |

### What the operator gets

- sipnab reads the SIP that passes through the proxy off the wire.
  - So it needs no module and no configuration change on the proxy.
  - It sees the caller's leg into the proxy and the proxy's leg out to the
    callee.
  - It puts them together into one call.
- A headless run prints each message as it passes. It prints a report of the
  calls at the end. The guides use this command, quoted from
  [Watch a call through OpenSIPS](/docs/opensips-sipnab/#watch-a-call-through-opensips) in "Run sipnab beside OpenSIPS":
  `sudo sipnab -N -d any --duration 30 --report`
- The report includes an `RTP Streams:` table with the call's audio streams.
- The same view is available in the TUI, which updates as calls happen.
- The proxy may also anchor media on rtpengine or rtpproxy on the same machine.
  Then sipnab can name the relayed media by the call it belongs to:
  - by reading the relay's control traffic,
  - and for rtpengine also by asking the relay which calls it holds.
- The capture can run as a systemd service.
- It can run without root once the binary holds the capture capabilities.

### What it does not provide

- sipnab watches ports 5060-5061 by default. A proxy listening elsewhere needs
  `--portrange`, as the guides' "When something does not work" sections
  describe.
- It sees only this machine's traffic.
  - Media may flow end to end and never cross the machine. Then no capture
    there can see it.
  - Calls on other SIP servers need the topology "A fleet of SIP nodes feeding one sipnab over HEP".

### Guides

- [Run sipnab beside OpenSIPS](/docs/opensips-sipnab/), including
  [With Kamailio on the same machine](/docs/opensips-sipnab/#with-kamailio-on-the-same-machine)
- [Run sipnab beside Kamailio](/docs/kamailio-sipnab/)
- [Let sipnab name rtpengine's media](/docs/rtpengine-sipnab/), from
  "Install sipnab" to "Ask the relay about one call", for a relay on the
  proxy's machine
- [Let sipnab name rtpproxy's media](/docs/rtpproxy-sipnab/),
  [Name the calls on the proxy's machine](/docs/rtpproxy-sipnab/#name-the-calls-on-the-proxy-s-machine)
- [Walk through the terminal UI](/docs/tui/) and
  [Triage a capture from the command line](/docs/first-cli-triage/)
- [Run sipnab as a service](/docs/cookbook/#run-sipnab-as-a-service) and
  [Run a live capture without giving sipnab root](/docs/cookbook/#run-a-live-capture-without-giving-sipnab-root)

## A fleet of SIP nodes feeding one sipnab over HEP

### Situation

Several SIP servers carry production traffic. The operators may install nothing
new on them.

- Each proxy already has a HEP tracing module.
- The operator wants one place to analyze calls from all of them.

### Layout

<pre class="mermaid">
flowchart LR
    P1[SIP proxy 1] --&gt;|HEP over UDP| S
    P2[SIP proxy 2] --&gt;|HEP over UDP| S
    P3[SIP proxy 3] --&gt;|HEP over UDP| S
    subgraph C[capture host]
        S[sipnab HEP listener]
    end
</pre>

Plain-text description:

- Each SIP proxy uses its own HEP tracing module. It sends a copy of its SIP
  messages to one capture host.
- sipnab runs on the capture host as a HEP listener.
- The proxies run nothing from sipnab.

### What runs where

| Machine | Runs |
|---|---|
| Each SIP server | The proxy, with its HEP tracing module pointed at the capture host |
| Capture host | sipnab, listening for HEP |

### What the operator gets

- **Nothing installed on production.**
  - For OpenSIPS and Kamailio, the proxy's own HEP module sends to a listener
    on another machine.
  - The proxy pays only for HEP mirroring.
- **An unprivileged listener.** The HEP listener is a plain UDP socket. So it
  needs no capture privileges.
- **A guarded listener.**
  - sipnab refuses a non-loopback HEP listener unless it has one of these:
    - a source allowlist (`--hep-allow`),
    - or a shared secret (`--hep-auth` or `--hep-auth-file`).
  - A loopback listener needs neither.
- **A roster of senders.**
  - The listener records each sender. The key of each entry is the capture id
    it claims and the address it sends from.
  - Each entry has its packet count and whether it has gone silent.
  - It also lists every address it refused and the reason. Examples are a
    wrong shared secret or an address outside the allowlist.
  - The roster is available:
    - at the end of a headless run,
    - over the REST API,
    - from the MCP `hep_senders` tool,
    - and in the TUI.
  - It covers the current run only.
- **Encrypted transport where needed.** The listener accepts HEP over UDP,
  TCP, or TLS. A TCP or TLS listener reads HEP version 3 only.
- **Forwarding.** sipnab can also send HEP to another collector (`--hep-send`):
  - SIP as HEP protocol type 1,
  - and RTCP as type 5.
  - It never forwards RTP.
- **Bounded memory.**
  - Default caps limit tracked dialogs, RTP streams, messages per dialog, and
    TCP reassembly.
  - An operator can tighten each on a shared host, as
    [Keep a long-running capture inside a memory budget](/docs/cookbook/#keep-a-long-running-capture-inside-a-memory-budget)
    describes.

### What it does not provide

- **No media quality from HEP alone.**
  - A HEP feed carries no RTP. So a run that only listens for HEP measures no
    media.
  - One sipnab can take signaling from HEP and media from a network interface
    in the same process.
  - But that arrangement supports one mirroring node per sipnab.
- **No delivery guarantee over UDP.**
  - HEP over UDP drops packets silently when the listener cannot keep up.
  - `--hep-rate-limit` caps what sipnab accepts.
- **Kamailio sends to one destination.**
  - Kamailio's `siptrace` sends to one `duplicate_uri`.
  - A second line replaces the first. It does not add a destination.

### Guides

- [Wire HEP from your SIP stack to a central sipnab](/docs/cookbook/#wire-hep-from-your-sip-stack-to-a-central-sipnab):
  [the listener](/docs/cookbook/#set-up-the-listener), the
  [OpenSIPS, Kamailio, rtpengine and FreeSWITCH configuration](/docs/cookbook/#configure-the-sip-server-to-mirror),
  [verification](/docs/cookbook/#verify-packets-are-arriving), and
  [the sender roster](/docs/cookbook/#find-who-feeds-the-collector-and-who-it-refuses)
- [Take signaling from HEP and media off the wire, in one process](/docs/cookbook/#take-signaling-from-hep-and-media-off-the-wire-in-one-process)
- [sipnab as a second HEP receiver](/docs/homer-sipnab/#sipnab-as-a-second-receiver).
  - It is for a proxy that already sends HEP to an existing collector.
  - It covers OpenSIPS and Kamailio.
- [Run sipnab as a HEP relay](/docs/cookbook/#run-sipnab-as-a-hep-relay)
  and [Carry the feed over TCP and TLS](/docs/cookbook/#carry-the-feed-over-tcp-and-tls)
- [Collect captures from several SIP servers in one place](/docs/mcp-estate/#collect-captures-from-several-sip-servers-in-one-place),
  the same arrangement with an MCP service on the capture host
- [Understand the load on a busy server](/docs/mcp-deploy/#understand-the-load-on-a-busy-server)
  and [Keep a long-running capture inside a memory budget](/docs/cookbook/#keep-a-long-running-capture-inside-a-memory-budget)

## An observability stack

### Situation

The operator already runs, or plans to run, Prometheus and Grafana for the SIP
proxy's own statistics.

- The proxy's statistics say what the proxy did.
- The operator also wants numbers about the calls as they appeared on the wire.

### Layout

<pre class="mermaid">
flowchart LR
    P[SIP proxy] --&gt;|own statistics| PR[Prometheus]
    S[sipnab] --&gt;|/metrics| PR
    PR --&gt; G[Grafana dashboards]
</pre>

Plain-text description:

- Prometheus scrapes two endpoints:
  - the SIP proxy's statistics,
  - and sipnab's `/metrics`.
- Grafana draws dashboards from what Prometheus stored.
- sipnab can run in either place:
  - on the proxy's machine (topology "Single host"),
  - or on a capture host fed by HEP (topology "A fleet of SIP nodes feeding one sipnab over HEP").
- Prometheus and Grafana can be on the same machine or on another one.

### What runs where

| Machine | Runs |
|---|---|
| SIP server | The proxy, publishing its own statistics, and in the co-located case sipnab |
| Capture host (optional) | sipnab fed by HEP, as in the topology "A fleet of SIP nodes feeding one sipnab over HEP" |
| Monitoring host (or the same machine) | Prometheus and Grafana |

### What the operator gets

- **Call metrics beside proxy metrics.**
  - sipnab's metrics describe the calls on the wire:
    - how many completed and failed,
    - post-dial delay,
    - and audio quality.
  - In the same Prometheus they sit beside the proxy's series on one dashboard.
- **Two ways to serve metrics.**
  - A standalone metrics server (`--metrics`),
  - or `/metrics` on the REST API's port.
  - Both publish the same series.
- **A dashboard and alert rules.**
  - A Grafana dashboard ships in the repository as
    `contrib/grafana/sipnab-dashboard.json`. It imports as **sipnab Overview**.
  - Example alerting rules ship as `contrib/prometheus/sipnab-alerts.yml`.
- **A bundled test stack.**
  - `contrib/observability` is a Docker Compose stack with Prometheus, Grafana,
    an OpenTelemetry collector, and Tempo.
  - The same compose file serves sipnab on the same host or on a remote capture
    host.
  - Only the `SIPNAB_HOST` setting changes.
- **Protected scrapes.**
  - sipnab refuses a non-loopback metrics bind without credentials.
  - The standalone metrics server can serve HTTPS.

### What it does not provide

- **Metrics carry no SIP.**
  - A scrape reports counts, not which call they came from.
  - Finding the call needs the capture itself. Use the TUI, the REST API, MCP,
    or HEP.
- **Media series need the media.**
  - The MOS, jitter and loss series need sipnab to see the audio.
  - A HEP-only capture host receives no RTP. That is the topology
    "A fleet of SIP nodes feeding one sipnab over HEP".
- **No traces.**
  - sipnab does not speak OTLP.
  - The collector and Tempo in the bundled stack are neighbors, not sipnab
    outputs.
- **The history lives in Prometheus.**
  - sipnab publishes current numbers.
  - Prometheus keeps the series over time. Grafana draws them.

### Guides

- [Add Prometheus and Grafana to your voice stack](/docs/prometheus/), the
  proxy side, including
  [Put the parts on different machines](/docs/prometheus/#put-the-parts-on-different-machines)
- [Add sipnab's metrics to Prometheus](/docs/prometheus-sipnab/), co-located:
  [run sipnab with its metrics on a free port](/docs/prometheus-sipnab/#run-sipnab-with-its-metrics-on-a-free-port),
  [scrape it](/docs/prometheus-sipnab/#scrape-sipnab), and
  [import the dashboard](/docs/prometheus-sipnab/#import-sipnab-s-dashboard)
- [Graph call rate, response codes and PDD over time](/docs/cookbook/#graph-call-rate-response-codes-and-pdd-over-time),
  the bundled stack and a remote sipnab
- [Prometheus metrics](/docs/metrics/), every series and its meaning, and
  [Metrics TLS](/docs/metrics/#metrics-tls)
- [Use the optional integrations in contrib](/docs/contrib/), which lists the
  stack, the dashboard and the alert rules

## AI agents over MCP

### Situation

An operator wants an AI agent to answer questions about calls.

- Examples are why a call failed or why its audio was bad.
- The agent calls sipnab's analysis directly. It does not parse text output.
- The capture may be:
  - a file on the operator's laptop,
  - live traffic on one server,
  - or traffic across several capture hosts.

### Layout on one machine or one server

<pre class="mermaid">
flowchart LR
    subgraph L[Same machine]
        A1[agent] &lt;--&gt;|stdio| S1[sipnab]
    end
    subgraph R[Laptop and one server]
        A2[agent on laptop] &lt;--&gt;|SSH, or HTTP with a token| S2[sipnab on server]
    end
</pre>

Plain-text description:

- On one machine, the agent starts sipnab as a child process. It talks to it
  over standard input and output.
- With a server, the agent on the laptop reaches sipnab on the server in one of
  three ways:
  - by starting it through SSH,
  - through an HTTP service with a bearer token,
  - or through an SSH tunnel to an HTTP service bound to loopback.

### Layout across an estate

<pre class="mermaid">
flowchart LR
    A[agent on laptop]
    A --&gt;|1. ask the SBC first| N1[sipnab on the SBC]
    A --&gt;|2. look up the identifier it returned| N2[sipnab on the proxy]
    A --&gt;|3. one hop further in| N3[sipnab on the PBX]
</pre>

Plain-text description:

- One agent registers several sipnab MCP servers.
- Each server keeps its own capture. The agent joins the answers.
- The agent can follow one call across an SBC, a proxy and a PBX (the phone
  system serving the extensions).
  - It asks the SBC first.
  - It carries the identifier it returns to the next node.
- In the centralized alternative, the nodes send HEP to one capture host
  (topology "A fleet of SIP nodes feeding one sipnab over HEP"). One sipnab answers for all of
  them.

### What runs where

| Arrangement | Agent machine | sipnab machine | Listening port |
|---|---|---|---|
| Same machine | Laptop | Laptop, started by the agent | None |
| SSH, nothing listening | Laptop | Server, started over SSH | None |
| HTTP service with a token | Laptop | Server, running continuously | The MCP port |
| SSH tunnel to loopback | Laptop | Server, running continuously | None exposed |
| Behind a TLS reverse proxy | Laptop | Server on loopback | 443, on the reverse proxy |
| Several capture hosts | Laptop | Each capture host | Per host, as above |

### What the operator gets

- **Analysis as tools.**
  - The agent calls sipnab's tools. Examples:
    - find problem calls,
    - report on one call,
    - or read RTP statistics.
  - It receives structured answers.
- **No setup for local use.** On one machine the agent starts sipnab itself:
  - no port,
  - no token,
  - and nothing keeps running after the session ends.
- **A capture that outlives the session.** As a service, sipnab keeps
  capturing between agent sessions. It answers when asked.
- **A choice of agents.**
  - The server side is the same for every MCP client.
  - The guide gives the registration for Claude Code, Claude Desktop, Codex
    CLI, Cursor, VS Code, Gemini CLI and Windsurf.
- **Several hosts from one agent.** Each registered server gets its own tool
  namespace. So one agent can ask several sites the same question.
- **Cross-node correlation with stated strength.**
  - `find_correlated` reports two things for each leg it matches:
    - the strategy that matched,
    - and whether that was an identifier both ends agreed on or a timing guess.
  - `--node-name` attributes each answer to a node.
- **Runs without an agent.** The MCP server is also a JSON-RPC API. So a
  script or a scheduled job can call the same tools.
- **Fail-closed defaults.**
  - No MCP tool sends SIP.
  - Non-loopback HTTP binds refuse to start without a bearer token.
  - Some tools each stay off until a server-side flag enables them. These are
    the tools that:
    - write files,
    - replace the loaded capture,
    - shut the server down,
    - or attach TLS probes.

### What it does not provide

- **Captured SIP leaves with the answer.**
  - Dialogs carry phone numbers, IP addresses and authentication headers.
  - Whatever a tool returns goes to the agent's model provider.
- **The HTTP service is plaintext unless given a certificate.**
  - Keep it on a trusted network.
  - Or use the SSH shapes or a TLS reverse proxy.
- **Federation cannot prove what the signaling does not carry.**
  - Consider a B2BUA that emits no `Session-ID` or `X-Call-ID` and rewrites the
    media description (SDP).
  - Across it, nothing in the signaling proves two legs are one call.
  - sipnab reports a timing match as a guess.
- **Multi-host wiring, as stated in the guide.** The estate guide records two
  things:
  - its tunnel, NAT and jump-host commands were not run against three real
    hosts,
  - and it measured the correlation behavior it shows on three sipnab servers
    on one host.

### Guides

- [Connect an AI agent (MCP)](/docs/mcp/), the introduction
- [Connect an AI agent to sipnab](/docs/mcp-deploy/): start at
  [Find your setup](/docs/mcp-deploy/#find-your-setup) and
  [The three shapes, at a glance](/docs/mcp-deploy/#the-three-shapes-at-a-glance)
  - [Run sipnab and your agent on the same machine](/docs/mcp-deploy/#run-sipnab-and-your-agent-on-the-same-machine)
  - [Connect Claude Code on your laptop to sipnab on a server](/docs/mcp-deploy/#connect-claude-code-on-your-laptop-to-sipnab-on-a-server)
  - [Keep a capture running between agent sessions](/docs/mcp-deploy/#keep-a-capture-running-between-agent-sessions)
  - [Keep a capture running without exposing a port](/docs/mcp-deploy/#keep-a-capture-running-without-exposing-a-port)
  - [Which remote setup should I use?](/docs/mcp-deploy/#which-remote-setup-should-i-use)
  - [Use an agent other than Claude Code](/docs/mcp-deploy/#use-an-agent-other-than-claude-code)
  - [Run diagnostics on a schedule, with no agent attached](/docs/mcp-deploy/#run-diagnostics-on-a-schedule-with-no-agent-attached)
  - [Security implications](/docs/mcp-deploy/#security-implications)
- [Run MCP across an estate](/docs/mcp-estate/)
  - [Collect captures from several SIP servers in one place](/docs/mcp-estate/#collect-captures-from-several-sip-servers-in-one-place)
  - [Reach sipnab from outside your network](/docs/mcp-estate/#reach-sipnab-from-outside-your-network)
  - [Query many capture hosts from one agent](/docs/mcp-estate/#query-many-capture-hosts-from-one-agent)
  - [Follow one call across an SBC and its PBXes](/docs/mcp-estate/#follow-one-call-across-an-sbc-and-its-pbxes)
  - [Choose between federated and centralized](/docs/mcp-estate/#choose-between-federated-and-centralized)
- [Let an AI agent ask sipnab about your calls](/docs/cookbook/#let-an-ai-agent-ask-sipnab-about-your-calls)
  in the cookbook

## What all four share

- sipnab is a single binary with no database. A run keeps its state in
  memory, within the caps described in the topology
  "A fleet of SIP nodes feeding one sipnab over HEP".
- The topologies combine. Prometheus can also scrape a capture host fed by
  HEP, and that host can answer agents over MCP. That combines three
  topologies:
  - "A fleet of SIP nodes feeding one sipnab over HEP",
  - "An observability stack",
  - "AI agents over MCP".
