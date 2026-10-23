# MCP tool reference: tfps bundle

The `tfps` bundle talks to the toll-fraud prevention peer (TFPS): what it
blocks and logs, and the operator's ban, unban and revert actions.

Load only these tools with `--mcp-tools tfps`, or combine bundles as [Choosing
which tools load](mcp-tools.md#choosing-which-tools-load) describes. Every
tool on this page follows the [rules every tool
follows](mcp-tools.md#rules-every-tool-follows), and each section states only
what its tool does differently. The [MCP tool reference](mcp-tools.md) lists
the other bundles and finds any tool by name.

> **The peer this needs.** The tools on this page read [TFPS](https://github.com/sippulse/tfps)
> through its `tfps_ctl` program in JSON mode, the `--json` flag. TFPS v0.2.1
> rejects `--json`; the mode is on TFPS's `master` branch. Until a tagged
> release carries it, build TFPS from `master`.
>
> To check the `tfps_ctl` you have, run
> `tfps_ctl status --json`. One line of JSON means it is ready, and
> `unknown option: --json` means it predates the mode. Against an older
> `tfps_ctl` these answer with that error and name what to install.
>
> `tfps_dropped` is the exception: it needs a `dropped` subcommand that no
> TFPS build has, released or on `master`, so it answers with TFPS's own
> `unknown command: dropped` and says so.

| Tool | Parameters | Returns |
|---|---|---|
| [`tfps_status`](#tfps_status) | -- | Whether the toll-fraud prevention peer (TFPS) runs on this host, and what it reports: enforcement, mode, interface, sources blocked now, database, version |
| [`tfps_banned`](#tfps_banned) | -- | Every source TFPS holds condemned right now, with the rule, what it saw, and when the ban began and lapses |
| [`tfps_dropped`](#tfps_dropped) | -- | Per condemned source, what the enforcement dropped and the last request line the source sent |
| [`tfps_labels`](#tfps_labels) | `limit?` | The TFPS verdict log -- blocked, would-block, exempt -- one row per decision TFPS made about a source |
| [`tfps_ban`](#tfps_ban) | `ip`, `ttl_secs?` | **Write, off by default.** Relays an OPERATOR's decision to condemn a source, recorded in the journal and rate limited, and reports the TFPS answer as given, refusal included |
| [`tfps_unban`](#tfps_unban) | `ip` | **Write, off by default.** Releases a source sipnab banned |
| [`actions_revert`](#actions_revert) | `id?`, `all?` | **Write, off by default.** Backs out one ban sipnab placed, or every one it still holds |


## Security

### `tfps_status`

TFPS is the toll-fraud prevention system an operator may run on the same host
as sipnab: it condemns sources and enforces that decision in the firewall.
sipnab does not decide bans itself. Ask this tool first, to learn whether TFPS
runs on this host and what it reports about itself, before asking what TFPS
did with a source that [`security_findings`](mcp-tools-security.md#security_findings)
reported.

**No parameters.**

TFPS is optional peer software. On a machine without it every `tfps_*` tool
answers the same two fields and nothing else, as a successful result, not an
error:

```jsonc
// tfps_status {}
{
  "installed": false,
  "reason": "tfps_ctl not found on PATH; pass --tfps-ctl or [tfps] ctl"
}
```

With TFPS installed (`--tfps-ctl /usr/local/bin/tfps_ctl`, or `tfps_ctl` on
`PATH`), the answer names the executable that answered and carries its status:

```jsonc
// tfps_status {}
{
  "installed": true,
  "tfps_ctl": "/usr/local/bin/tfps_ctl",
  "status": {
    "enforcement": "active",
    "mode": null,
    "interface": null,
    "map": "own map id 7",
    "blocked_now": 2,
    "pairs": 4,
    "peers": 4,
    "last_checkpoint": 1758200500,
    "db": "/var/lib/tfps/tfps.db",
    "version": "0.2.1"
  }
}
```

Every field is present on every answer, `null` when unknown. `map` names the
block map TFPS read, `own map id N` or `pinned map <path>`. It is `null`,
with `enforcement` `inactive`, when TFPS could open none. `mode` and
`interface` are always `null`: TFPS's JSON mode does not fill them yet.
`pairs` and `peers` count what TFPS has learned, and TFPS currently reports
the same number for both. `last_checkpoint` is Unix seconds.

sipnab looks for `tfps_ctl` only when a
`tfps_*` tool runs: it probes nothing at startup, and a machine without TFPS
logs nothing about it. A peer that exits non-zero, hangs past ten
seconds, or prints something other than the agreed JSON is an `internal_error`
(-32603) whose message carries `tfps_ctl`'s standard error verbatim.

### `tfps_banned`

Every source TFPS holds condemned right now: the address, the rule that
condemned it, what that rule saw, when the ban began and lapses, and whether
the firewall holds it or TFPS is observing only.

**No parameters.** `--mcp-max-rows` bounds the page. `total` is how many rows
TFPS returned, and `truncated` says whether the cap withheld any.

```jsonc
// tfps_banned {}
{
  "installed": true,
  "tfps_ctl": "/usr/local/bin/tfps_ctl",
  "rows": [
    {
      "ip": "198.51.100.10",
      "reason": "user-agent",
      "detail": "⟦untrusted-capture-data⟧pplsip⟦/untrusted-capture-data⟧",
      "first_seen": 1758200000,
      "expires": 1789748119,
      "enforced": true
    },
    {
      "ip": "198.51.100.12",
      "reason": null,
      "detail": null,
      "first_seen": null,
      "expires": null,
      "enforced": true
    }
  ],
  "total": 2,
  "returned": 2,
  "truncated": false
}
```

`detail` is the sender's own text — here the `User-Agent` a scanner chose —
and arrives fenced the way `security_findings` fences its `detail`. Addresses,
rules and timestamps are verbatim. `reason` is the rule that condemned the
source. `reason`, `detail` and `first_seen` are `null` for a block no audit
row explains, such as one an operator made by hand. `first_seen` and
`expires` are Unix seconds, and `expires` is `null` for a ban that does not
lapse.

### `tfps_dropped`

Per condemned source, what the enforcement has done: packets dropped, events
TFPS recorded, when it last saw the source, the rule behind the block, and the
last request line the source sent.

**No parameters.** Bounded by `--mcp-max-rows` like `tfps_banned`.

```jsonc
// tfps_dropped {}
{
  "installed": true,
  "tfps_ctl": "/usr/local/bin/tfps_ctl",
  "rows": [
    {
      "ip": "198.51.100.10",
      "dropped": 30,
      "events": 4,
      "last_seen": "2026-09-03T16:41:00Z",
      "rule": "user-agent",
      "last_request": "⟦untrusted-capture-data⟧OPTIONS sip:100@198.51.100.1 SIP/2.0⟦/untrusted-capture-data⟧"
    }
  ],
  "total": 1,
  "returned": 1,
  "truncated": false
}
```

`last_request` is a request line the source wrote, and arrives fenced. It and
`rule` are `null` when TFPS recorded none.

### `tfps_labels`

The TFPS verdict log: one row per decision about a source, read without a
shell on the TFPS host. Use it to compare TFPS's decisions with the sources
sipnab's scanner detector reported.

| Parameter | Type | Legal values | If omitted |
|---|---|---|---|
| `limit?` | integer? | a positive count of rows, newest first. `0` means the default | one page of `--mcp-max-rows` |

A `limit` that fits in a page passes through to TFPS as `--limit N`. `0`,
absent or more than a page asks TFPS for the page and one row more, which is
how `truncated` knows TFPS held more. So `total` here is how many TFPS
returned, at most a page and one row, not the size of the log. For the whole
log, run `tfps_ctl log --json --limit N` on the TFPS host.

```jsonc
// tfps_labels { "limit": 250 }
{
  "installed": true,
  "tfps_ctl": "/usr/local/bin/tfps_ctl",
  "rows": [
    {
      "ip": "198.51.100.11",
      "reason": "scanner",
      "detail": "⟦untrusted-capture-data⟧sipvicious⟦/untrusted-capture-data⟧",
      "first_seen": 1758200100,
      "expires": null,
      "unbanned_at": null,
      "enforced": true,
      "disposition": "block"
    }
  ],
  "total": 1,
  "returned": 1,
  "truncated": false
}
```

TFPS's audit log records only the blocks it enforced, so today every row has
`disposition` `block` and `enforced` `true`. The log has no columns for a
ban's end yet, so `expires` and `unbanned_at` are always `null`. `first_seen`
is Unix seconds. `detail` arrives fenced.

### `tfps_ban`

Ask TFPS to condemn one source. **Off by default**: sipnab changes no system
outside itself unless the operator starts it with `--allow-action tfps:mcp`
(or `[actions] tfps = ["mcp"]`). Over HTTP the client also needs a token
minted with `--token-scope actions`. Without that, the tool answers
`invalid_params` (-32602) naming the flag, and `tfps_ctl` never runs.

**An operator action relayed through sipnab, not a decision sipnab makes**:
nothing sipnab detects ever comes through this tool. Before it asks TFPS,
sipnab applies these rules and rate limits and records the request in its
actions journal. The durations and rates below are the defaults, which the
[`[action_limits]`](config-reference.md#action_limits) section of the config
file changes:

- sipnab never bans `0.0.0.0`, the broadcast address, or a loopback or
  multicast address, whatever the configuration says;
- every ban expires: `ttl_secs`, or an hour, and 7 days at most. sipnab
  refuses `0`, TFPS's "forever", and anything longer;
- at most 10 actions a minute for the server, 5 for one caller, and one per
  address a minute.

| Parameter | Type | Legal values | If omitted |
|---|---|---|---|
| `ip` | string | an IPv4 address that is not `0.0.0.0`, broadcast, loopback or multicast. The TFPS block map is IPv4, and `tfps_ctl` fails outright on an IPv6 address, so sipnab refuses one itself | required. Anything else is `invalid_params` (-32602) before sipnab asks TFPS |
| `ttl_secs?` | integer? | seconds the ban lasts: 1 to `[action_limits] max_ban_secs` (604800, 7 days, by default) | `[action_limits] default_ban_secs` (3600, an hour, by default) |

The TFPS `ban` command records no free-text reason, so this tool takes none. The
address and the duration reach `tfps_ctl` as arguments and never through a
shell.

```jsonc
// tfps_ban { "ip": "198.51.100.20", "ttl_secs": 3600 }
{
  "id": "a-r-68d9c1f2-4412-3",
  "applied": true,
  "refused": null
}
```

`id` names the action in the journal, and `actions_revert` takes it. A ban TFPS
refuses is not an error: `applied` is `false` and `refused` says why in the
words TFPS uses — `local` for one of the host's own addresses, `declared` for
one its `ignoreip` exempts, and `kernel` when it could not write the block
map:

```jsonc
// tfps_ban { "ip": "192.0.2.1" }
{
  "id": "a-r-68d9c1f2-4412-4",
  "applied": false,
  "refused": "local"
}
```

A well-formed call sipnab does not carry out is an error result
(`isError: true`) whose JSON says which refusal it is, so the agent can act on
it:

```jsonc
// tfps_ban { "ip": "198.51.100.6" }, the sixth this minute
{
  "error": "this caller's actions for the minute are spent; retry in 41 s",
  "refusal": "rate",
  "retry_after_secs": 41
}
```

`refusal` is `rate` (with `retry_after_secs`), `in_doubt` (actions a crash
left unfinished are waiting for TFPS to answer for them), `journal` (sipnab
cannot use the journal), or `tfps` (sipnab could not ask TFPS).

The tool is `readOnlyHint: false` and `destructiveHint: true`, so a host that
confirms destructive calls asks before this one. `idempotentHint: true`,
because banning a banned source changes nothing.

### `tfps_unban`

Ask TFPS to release a source **sipnab banned**. Off by default, behind the
same enabling, rules and limits as `tfps_ban`.

sipnab lifts only a ban it placed and still holds, as its journal records. A
ban TFPS placed itself, or anyone else did, is an error result with `refusal`
`not_owned`, and sipnab does not ask TFPS. A ban belongs to the caller that
placed it: another caller gets `refusal` `not_yours`, and the message names
the owner, unless its token holds the `admin` scope. Because an address rests for a
minute after an action on it, sipnab refuses an unban straight after the ban
with `refusal` `rate`.

| Parameter | Type | Legal values | If omitted |
|---|---|---|---|
| `ip` | string | an IPv4 address | required; anything else, an IPv6 address included, is `invalid_params` (-32602) |

```jsonc
// tfps_unban { "ip": "198.51.100.20" }
{
  "id": "a-r-68d9c1f2-4412-5",
  "applied": true,
  "refused": null
}
```

When TFPS no longer held the ban (it forgets manual bans when it restarts),
the answer is `applied: false, refused: "not-blocked"`, and sipnab no longer
counts the ban as its own. `readOnlyHint: false`, `destructiveHint: false` —
a release restores rather than destroys — and `idempotentHint: true`.

### `actions_revert`

Back out what sipnab did: the ban one action placed, or every ban sipnab
placed that is still in force, newest first. Off by default, behind the same
enabling as `tfps_ban`, and each unban counts against the same rate limits.

| Parameter | Type | Legal values | If omitted |
|---|---|---|---|
| `id?` | string? | an action id from `tfps_ban`'s answer | give exactly one of `id` or `all` |
| `all?` | boolean? | `true` | give exactly one of `id` or `all`. Neither is `invalid_params` (-32602) with `reason: missing_param`; both is `reason: conflicting_params` |

```jsonc
// actions_revert { "all": true }
{
  "reverted": ["a-r-68d9c1f2-4412-3"],
  "lapsed": [],
  "skipped_unknown": [],
  "failed": [],
  "left": []
}
```

sipnab first asks TFPS what it holds. `reverted` lists the actions backed
out, and `lapsed` the addresses whose ban TFPS had already dropped.
`skipped_unknown` lists bans TFPS shows that sipnab cannot prove it placed,
which sipnab never lifts. `failed` lists reverts TFPS refused or sipnab could
not ask it for, and `left` the ones a rate limit stopped before sipnab reached
them. An `id` sipnab holds no ban for
is an error result with `refusal` `not_owned`. Without the `admin` scope, a
caller backs out only the bans it placed: `all` covers those, and another
caller's `id` is an error result with `refusal` `not_yours`.

`readOnlyHint: false`, `destructiveHint: false`, `idempotentHint: true`:
reverting what is already reverted changes nothing.
