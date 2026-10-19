# MCP tool reference: tls bundle

The `tls` bundle reads SIP inside TLS without keys through kernel uprobes, and
lists which TLS libraries this host runs.

Load only these tools with `--mcp-tools tls`, or combine bundles as [Choosing
which tools load](mcp-tools.md#choosing-which-tools-load) describes. Every
tool on this page follows the [rules every tool
follows](mcp-tools.md#rules-every-tool-follows), and each section states only
what its tool does differently. The [MCP tool reference](mcp-tools.md) lists
the other bundles and finds any tool by name.

| Tool | Parameters | Returns |
|---|---|---|
| [`start_tls_capture`](#start_tls_capture) | `flavors?`, `libraries?` | installs kernel uprobes and reads SIP plaintext with no key; needs `--mcp-allow-tls-capture` |
| [`stop_tls_capture`](#stop_tls_capture) | -- | stops that capture and removes its kernel probes |
| [`list_tls_libraries`](#list_tls_libraries) | -- | which TLS libraries this host runs, and whether sipnab could read their plaintext without keys |


## Capture control (opt-in, off by default)

The tools that change server state rather than read it. `start_tls_capture` stays off until you enable it on the server. `stop_tls_capture` needs no flag.

### `start_tls_capture`

Installs kernel uprobes on this host's TLS libraries and reads SIP plaintext
from them — no key, no certificate, and no restart of the process observed.

**Needs `--mcp-allow-tls-capture` and root.** The flag is off by default and
separate from `--mcp-allow-open-capture`: that flag lets an agent read a file
from the file root, and this one lets it attach probes to a running process's
TLS library and read its plaintext. The server must also be reading a file
that it has finished loading, not a live interface.

Call [`list_tls_libraries`](#list_tls_libraries) first to see what it would
probe.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `flavors?` | array of string | `openssl`, `wolfssl` | every flavor found |
| `libraries?` | array of string | paths this server can open; for a containerized process, the form that `list_tls_libraries` returns as `probe_path`: `/proc/<pid>/root/` followed by the library's path inside the container, such as `/proc/954/root/usr/lib/libssl.so.3` | the libraries discovered on this host |

```jsonc
// start_tls_capture { }                                  // every library found
// start_tls_capture { "flavors": ["openssl"] }          // one flavor only
// start_tls_capture { "libraries": ["/proc/954/root/usr/lib/libssl.so.3"] }
{
  "schema_version": 1,
  "running": true,
  "targets": ["/proc/954/root/usr/lib/libssl.so.3:SSL_write"],
  "messages": 0,
  "lost": null,
  "uptime_sec": 0,
  "error": null,
  "summary": "Probing 1 TLS library. Poll start_tls_capture's sibling stop_tls_capture, or capture_status, to see messages arrive. An attach failure appears there rather than here, because the probes are installed on a background thread."
}
```

Dialogs from this source carry no addresses and port 0, because a uprobe
reads the library's buffers and sees no socket.

**Each refusal happens before sipnab installs any kernel probe**, and the error
message names the cause and the fix:

- **Not enabled** (`reason: not_enabled`). Restart the server with
  `--mcp-allow-tls-capture`.
- **Not root** (`reason: unsupported`). sipnab drops privileges after opening
  its capture devices, so a server started with `--user` cannot attach probes
  later. Start it without dropping privileges, or run `sipnab --uprobe-tls` on
  the command line instead.
- **An unknown flavor** (`reason: invalid_choice`, `param: flavors`,
  `valid_values: ["openssl", "wolfssl"]`). sipnab checks the flavor names
  before it checks for root.
- **An unusable library path** (`reason: invalid_value`). Use a `probe_path`
  from `list_tls_libraries`.
- **A TLS capture is already running** (`reason: not_ready`). Call
  `stop_tls_capture` first.
- **The server is reading a live interface** (`reason: not_ready`). A uprobe
  capture cannot run beside a live capture. Start a server that reads a file.
- **A capture is still loading** (`reason: not_ready`). Poll `capture_status`
  until `load.done` is `true`.

Without the flag, the call returns:

```json
{
  "code": -32602,
  "message": "starting a TLS capture is disabled: start sipnab with --mcp-allow-tls-capture to permit it. This is off by default because it attaches kernel probes to a running process's TLS library and reads its plaintext",
  "data": {
    "reason": "not_enabled"
  }
}
```

**sipnab reports an attach failure later, not in this answer.** A background
thread installs the probes, so the call returns as soon as that thread starts.
Call [`stop_tls_capture`](#stop_tls_capture) or `capture_status` to see whether
messages arrive.

### `stop_tls_capture`

Stops the running capture and removes its kernel probes. Safe to call when
nothing is running — it says so rather than failing.

No parameters. Returns:

```jsonc
// stop_tls_capture { }
{
  "schema_version": 1,
  "running": false,
  "targets": ["/proc/954/root/usr/lib/libssl.so.3:SSL_write"],
  "messages": 412,
  "lost": 0,          // records the kernel DROPPED: messages that existed and are missing
  "uptime_sec": 96,
  "error": null,
  "summary": "The TLS capture has stopped and its probes are removed."
}
```

**Call it again until `running` is `false`.** The stop is a request: the
capture thread removes the probes on its way out, one kernel call per probe.
Probes left installed slow every process that maps the library, and they stay
installed after sipnab exits.

Read `lost`. It counts records the kernel dropped because sipnab read them
too slowly: messages that existed and are missing from the capture. A quiet
trunk shows `0`. The dialogs already collected stay in the store after the
stop.

With nothing running, the answer is:

```json
{
  "error": null,
  "lost": null,
  "messages": 0,
  "running": false,
  "schema_version": 1,
  "source_exhausted": true,
  "source_stopped_early": false,
  "summary": "No TLS capture is running on this server.",
  "targets": [],
  "uptime_sec": 0
}
```

### `list_tls_libraries`

Which TLS libraries processes on this host are **actually mapping**, and
whether sipnab could attach a uprobe to read their plaintext. Ask before
concluding that reading SIP over TLS needs keys — and read
`privileged` and `probe_path` before concluding it can.

No parameters. Returns:

```jsonc
{
  "schema_version": 1,
  "supported": true,          // false off Linux, or without the `native` feature
  "privileged": true,         // running as root
  "libraries": [
    {
      "flavor": "OpenSSL",
      "path": "/usr/lib/aarch64-linux-gnu/libssl.so.3",
      "inode": 21143,         // the identity; the PATH is not unique
      "process_count": 12,
      "symbol": "SSL_write",
      "probe_path": "/proc/954/root/usr/lib/aarch64-linux-gnu/libssl.so.3"
    },
    {
      "flavor": "wolfSSL",
      "path": "/usr/lib/aarch64-linux-gnu/libwolfssl.so.42.2.0",
      "inode": 17433084,
      "process_count": 1,
      "symbol": "wolfSSL_write",
      "probe_path": null      // in use, but NOT capturable from here
    }
  ],
  "unreachable_count": 1,
  "summary": "1 of 2 TLS libraries could be read with `sipnab --uprobe-tls`, without any key or certificate. 1 cannot be reached from this server's mount namespace and would be missed."
}
```

**Read `privileged` before believing an empty list.** Unprivileged,
`/proc/<pid>/maps` is readable only for the server's own processes, so a short
list is evidence about privilege rather than about the host. `summary` says
which of the two situations produced the answer, so a relayed conclusion does
not lose it.

**`probe_path: null` means sipnab cannot capture that library's traffic.**
Usually the library belongs to a containerized process whose
`/proc/<pid>/root` this server cannot read. `unreachable_count` counts these
libraries, and `summary` says a capture would miss them.

Use `inode`, not `path`, to tell libraries apart: the same path names
different files in different mount namespaces, so a host with containers can
list several distinct `libssl.so.3` files.
