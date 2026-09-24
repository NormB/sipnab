# Runnable client examples

These Python clients demonstrate multi-step operator tasks. Run commands from
the repository root with Python 3. The programs use its standard library.
Their parsing and analysis tests run in CI without a lab. A complete live run
requires the services described in the [capture harness](vcon-harness.md).

| Program | What it does | Live prerequisites |
|---|---|---|
| [leg_correlate.py](../clients/python/leg_correlate.py) | Joins proxy dialogs and relay streams; refuses to treat one instance as two witnesses | Two sipnab REST endpoints |
| [mcp_probe.py](../clients/python/mcp_probe.py) | Queries both capture nodes over MCP and compares their identities | Two HTTP MCP endpoints |
| [vcon_view.py](../clients/python/vcon_view.py) | Lists stored vCons, renders one and extracts WAV audio | The harness conserver backend |

Inspect each program's options before a live run:

- `python3 clients/python/leg_correlate.py --help`
- `python3 clients/python/mcp_probe.py --help`
- `python3 clients/python/vcon_view.py --help`

Run the local regression suite:

```bash
# Run all of these, in order.
python3 -m venv .venv-client-tests
. .venv-client-tests/bin/activate
python3 -m pip install --require-hashes -r clients/python/requirements-test.txt
python3 -m compileall -q clients/python
python3 -m pytest clients/python/tests -q
```

## Reference-page programs

Each Python, Go, JavaScript and TypeScript example on the
[REST API](rest-api.md), [Prometheus metrics](prometheus-metrics.md) and
[MCP deployment](mcp-deploy.md) pages is the core of one of these programs. A
test holds each page's example to its program byte for byte. CI builds every
program and runs it against a sipnab replaying committed captures.

| Program | What it does | Go | JavaScript | Python |
|---|---|---|---|---|
| `health` | `GET /health` | [main.go](../clients/go/health/main.go) | [health.mjs](../clients/javascript/health.mjs) | [health.py](../clients/python/health.py) |
| `list-dialogs` | Lists failed dialogs | [main.go](../clients/go/list-dialogs/main.go) | [list-dialogs.mjs](../clients/javascript/list-dialogs.mjs) | [list_dialogs.py](../clients/python/list_dialogs.py) |
| `get-dialog` | One dialog's state and message count | [main.go](../clients/go/get-dialog/main.go) | [get-dialog.mjs](../clients/javascript/get-dialog.mjs) | [get_dialog.py](../clients/python/get_dialog.py) |
| `dialog-report` | One call's media diagnosis | [main.go](../clients/go/dialog-report/main.go) | [dialog-report.mjs](../clients/javascript/dialog-report.mjs) | [dialog_report.py](../clients/python/dialog_report.py) |
| `list-streams` | RTP streams with MOS below 3.0 | [main.go](../clients/go/list-streams/main.go) | [list-streams.mjs](../clients/javascript/list-streams.mjs) | [list_streams.py](../clients/python/list_streams.py) |
| `get-stream` | One stream's codec and packet count | [main.go](../clients/go/get-stream/main.go) | [get-stream.mjs](../clients/javascript/get-stream.mjs) | [get_stream.py](../clients/python/get_stream.py) |
| `stats` | Dialog totals and post-dial delay | [main.go](../clients/go/stats/main.go) | [stats.mjs](../clients/javascript/stats.mjs) | [stats.py](../clients/python/stats.py) |
| `metrics` | The Prometheus exposition | [main.go](../clients/go/metrics/main.go) | [metrics.mjs](../clients/javascript/metrics.mjs) | [metrics.py](../clients/python/metrics.py) |

Each REST program reads the base URL from `SIPNAB_URL` (default
`http://127.0.0.1:8080`) and the token from `SIPNAB_API_KEY`. `get-dialog`,
`dialog-report` and `get-stream` take the Call-ID or SSRC as their first
argument. Run one against a sipnab started with `--api 127.0.0.1:8080`:

```bash
# Run all of these, in order.
export SIPNAB_API_KEY=my-secret-token
python3 clients/python/list_dialogs.py
(cd clients/go && go run ./list-dialogs)
node clients/javascript/list-dialogs.mjs
```

The MCP stdio clients start sipnab themselves:
[`sipnab_mcp.py`](../clients/python/sipnab_mcp.py) needs the SDK from
[`clients/python/requirements-mcp.txt`](https://github.com/NormB/sipnab/blob/main/clients/python/requirements-mcp.txt), and
[`sipnab-mcp.ts`](../clients/typescript/sipnab-mcp.ts) needs `npm ci` in
`clients/typescript`. Both take a capture path.

Run everything CI runs, against a sipnab built with the `api` and `mcp`
features:

```bash
scripts/smoke-clients.sh target/debug/sipnab
```

For Rust, see the [library API](library.md) and its executable rustdoc examples.
For individual CLI commands, use the [cookbook](examples.md). C and C++ have no
client examples, so no C or C++ bar applies yet. The `c` blocks in
[capture tuning](tuning-capture.md) quote libpcap's source and are citations,
not examples.
