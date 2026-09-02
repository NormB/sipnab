+++
title = "A tool list that advertised what the build could not run"
date = 2026-09-01
description = "One feature combination shipped an MCP server listing two tools, with full schemas, that refused every call. The report the refusal told operators to consult had never named the feature it was about."

[extra]
kind = "postmortem"
+++

On 2026-09-01 CI went red on exactly one feature combination. A build of
`native,hep,api,mcp,mcp-http` — no `vcon` — listed `export_vcon` and
`validate_vcon` in `tools/list`, complete with input and output schemas, and
refused every call to them.

`tools/list` is the only contract MCP gives an agent. Everything the agent
knows about what a server can do arrives there. A tool in that list that can
never run is worse than an absent one: the agent plans around it, calls it, and
gets an error naming nothing it could have chosen differently.

## Two facts, hundreds of lines apart

The router composed unconditionally in `src/mcp/server.rs`. Only the inner
helpers carried the feature split, in `src/mcp/tools/vcon.rs`:

```rust
#[cfg(not(feature = "vcon"))]
fn export_containers(
    &self,
    _selection: &Selection,
    _limit: usize,
) -> Result<ExportVconResponse, rmcp::ErrorData> {
    Err(no_exporter())
}
```

Read on its own that arm looks careful. Its doc comment even argued the case:
the tools stay registered rather than disappearing, so an agent asking for a
container learns which build it is talking to instead of getting "no such
tool", which reads as sipnab not supporting vCon at all.

The argument is coherent. It is also the whole defect: a registration and a
refusal that live in different files leave nobody a file to read that shows
both.

Nothing local could see it. The build under test here is `full`, and `full`
carries `vcon`, so every tool that could ever run did run. The combination that
failed is one only CI builds.

## The advice the refusal gave

The refusal ended by pointing somewhere:

> `server_capabilities` lists what this binary carries

That report named ten features — `native`, `tui`, `tls`, `hep`, `api`, `mcp`,
`mcp-http`, `metrics`, `audio`, `plugins` — and had never named `vcon`, `bpf`
or `wasm`. So an operator who followed sipnab's own error message, to the
surface sipnab's own error message nominated, learned nothing about the feature
the error was about.

The report's comment explained why a reader should trust it. It reads from
`cfg!`, so it "cannot claim a feature the binary does not have". That is true
and it is half the rule. Nothing stopped it from omitting a feature the binary
does have, which is the direction that failed.

Both halves went in together. Removing the advertisement is only safe once the
report can answer the question that removal raises — a client that notices two
tools missing needs somewhere to learn why.

## The gate is the agreement, not the tool

`tests/mcp_capability_agreement_test.rs` states the rule in a form that holds
in every build rather than only under `full`:

```rust
assert!(
    present == 0 || present == tools.len(),
    "{module} declares {} tool(s) and {present} of them are \
     registered. A feature-gated module is all or nothing ...",
    tools.len()
);
```

That test deliberately does not consult `cfg!`. A module behind one feature
advertises all of its tools or none of them, whichever features happen to be
on, so the assertion cannot rot into something that only means anything on one
build.

Half a module is exactly what shipped — the tools listed, the exporter absent
— and no test that checks one tool name at a time can see it.

Two of the mutations written against these tests turned out to be compile
errors rather than failing tests, which is a stronger result and worth
reporting as one. Gating a single method out of a `#[tool_router]` impl does
not build at all. Forcing the half-registered state took removing a route after
composition, and that does kill the test.

## What the matrix run found next

The lesson taken from all of this was to stop building one feature set. Running
CI's whole matrix locally before the next push turned up a second defect
immediately.

`scripts/check-feature-deps.py` read `all(a, b)` the way it reads `any(a, b)`.
For `any`, treating each alternative as independent is correct and strict:
`any(api, mcp, vcon)` means a build enabling only `vcon` compiles that file, so
`vcon` alone has to declare what the file imports. Reading those as a union is
the reasoning that let a `--features vcon` build break at 0.5.130.

For `all`, the same reading is wrong. No build compiles `src/mcp/tools/vcon.rs`
with half of `all(mcp, vcon)`, so the pair supplies the imports together.
Demanding that `vcon` declare `rmcp` satisfies a build that cannot exist.

The fix splits the two readings and keeps the strict one strict:

<!-- vale off -->
> Anything mixing the two, or shaped in a way this does not recognize, falls
> back to the STRICT reading — one alternative per feature. A parser that
> guesses permissively when it is confused is a gate that opens when it stops
> understanding what it is looking at.
<!-- vale on -->

The `any` strictness that caught 0.5.130 survives untouched, and it now has a
test that fails if anybody relaxes it. Loosening one half of a gate is the
moment to prove the other half still catches things.

## Worth stealing

Two rules came out of this.

A conditional advertisement and the condition it advertises belong in one
place. If they cannot be, something has to compare them, because a reviewer
reading either file alone finds a defensible design in front of them.

And an error message that tells the reader where to look has made a promise
about that destination. This one sent operators to a report that could not
answer, and the report had a comment explaining why it was trustworthy.
