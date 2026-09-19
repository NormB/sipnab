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
python3 -m pip install pytest==8.4.2
python3 -m compileall -q clients/python
python3 -m pytest clients/python/tests -q
```

For Rust, see the [library API](library.md) and its executable rustdoc examples.
For individual CLI commands, use the [cookbook](examples.md). Go, JavaScript,
C and C++ lifecycle examples remain gaps. Snippets in reference pages do not
establish runnable client coverage for those languages.
