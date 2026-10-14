# contrib

Optional integrations you can adopt if they suit your deployment.

- sipnab runs without any of it.
- None of it ships inside the `.deb`, `.rpm`, or Homebrew formula.
  [`packaging/`](../packaging/README.md) builds those.

Treat these as starting points to copy and adapt. They are not configuration
the project keeps in lockstep with your infrastructure.

| Path | What it is |
|------|------------|
| `sipnabrc.example` | Annotated starter config. Parsed by `config_wiring_test.rs` with the real loader, so every key in it is one sipnab actually reads. |
| `mcp/trace-call.py` | Follows one call across several sipnab MCP nodes without an interactive agent. Standard library only. Walked through in [the MCP deployment guide](../docs/mcp-deploy.md#drive-it-from-a-script). |
| `observability/` | Docker Compose stack — Prometheus, Grafana, OTel Collector, Tempo — wired to sipnab's `--metrics` endpoint (`sipnab --metrics 0.0.0.0:9100`). Has its own [README](observability/README.md). |
| `grafana/sipnab-dashboard.json` | Single importable Grafana dashboard, for an existing Grafana rather than the stack above. |
| `prometheus/sipnab-alerts.yml` | Example alerting rules. |
| `fail2ban/` | Filter and jail configuration that turns sipnab's scanner-detection output into bans. |

## Where things live

The split is by who maintains the contract, not by who wrote the file. All of
this is first-party:

- **`packaging/`** — release machinery.
  - It runs on every tag, gated by CI.
  - A broken path there breaks a published artifact.
- **`contrib/`** — examples.
  - Nothing here runs unless you choose to run it.
  - The only automated check is that `sipnabrc.example` still parses.
