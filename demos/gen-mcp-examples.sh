#!/usr/bin/env bash
# Regenerate the four MCP examples the homepage publishes.
#
#     demos/gen-mcp-examples.sh           # write them
#     demos/gen-mcp-examples.sh --check   # fail if the published ones drifted
#
# Why these are TEXT and not a VHS recording like every other demo:
#
#   1. The answers ARE text. A reader who wants to try `triage_call` needs to
#      copy the command and read the JSON; a video gives neither.
#   2. A recording cannot be checked. `--check` re-runs all four against the
#      binary and diffs, so the homepage cannot claim an answer the code no
#      longer gives -- which is the exact failure demos/Makefile was written to
#      prevent, and the only form of it that a test can catch.
#   3. VHS needs a headless Chromium through go-rod. This box has none
#      (/opt/google/chrome/chrome dangles at a deleted Playwright download), so
#      a tape here renders nothing at all.
#
# The captures are the ones in tests/pcap-samples: synthetic, RFC 5737
# documentation addresses, and already public in this repo. Nothing here comes
# from a real capture, and nothing here may.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="$ROOT/website/data/mcp-examples"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

BIN="${SIPNAB_BIN:-$ROOT/target/release/sipnab}"
[ -x "$BIN" ] || { echo "gen-mcp-examples: no binary at $BIN (cargo build --release --features tui,mcp)" >&2; exit 1; }

# The same refusal demos/Makefile makes, for the same reason: an example
# rendered by a binary that disagrees with the tree publishes an answer this
# code does not give.
WANT="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
GOT="$("$BIN" --version | awk '{print $2}')"
[ "$GOT" = "$WANT" ] || { echo "gen-mcp-examples: $BIN reports $GOT, Cargo.toml says $WANT" >&2; exit 1; }
case "$("$BIN" --version)" in
    *mcp*) ;;
    *) echo "gen-mcp-examples: $BIN has no mcp feature" >&2; exit 1 ;;
esac

export PATH="$(dirname "$BIN"):$PATH"
mkdir -p "$OUTDIR"
SAMPLES="tests/pcap-samples"
cd "$ROOT" || exit 1

# Each example is one call, named by the question an agent is asking.
#
# MCP_NODE_NAME is set wherever capture_identity appears: it defaults to the
# system hostname, and the machine that generated a demo has no business on the
# homepage. MCP_FILE_ROOT is set only for show_evidence, because the file tools
# stay off until a root is named.
# gen <name> <jq-filter> <command...>
#
# The jq filter is a PARAMETER rather than something applied afterwards because
# the homepage prints the command beside its output. lint_dialog's full answer
# runs to 72 lines, so that panel shows a filtered view -- and if the filter
# lived only in the HTML, the page would print one command and the output of a
# different one. Whatever is published here is what the printed command gives.
# Pass `.` to publish the answer whole.
gen() {
    local name="$1" filter="$2"; shift 2
    local tmp raw; tmp="$(mktemp)"; raw="$(mktemp)"
    if ! "$@" > "$raw" 2>/dev/null || [ ! -s "$raw" ]; then
        echo "gen-mcp-examples: $name produced nothing" >&2
        rm -f "$tmp" "$raw"; return 1
    fi
    if ! jq "$filter" "$raw" > "$tmp" 2>/dev/null || [ ! -s "$tmp" ]; then
        echo "gen-mcp-examples: $name filter '$filter' matched nothing" >&2
        rm -f "$tmp" "$raw"; return 1
    fi
    rm -f "$raw"
    if [ "$CHECK" = 1 ]; then
        # Three fields genuinely differ between two runs of the SAME binary:
        # capture_identity.instance is minted per capture, the generation
        # counters advance, and timing_clock carries a measured clock error.
        # Comparing them verbatim fails every single run, and a gate that
        # always fails gets muted -- so the comparison drops them.
        #
        # Dropping a field would also hide it DISAPPEARING, so the published
        # side is checked for the parent keys first: if capture_identity or
        # timing_clock stops being emitted, that is a regression and this says
        # so rather than passing on two equally-blanked objects.
        for key in capture_identity timing_clock; do
            local pub=no live=no
            jq -e --arg k "$key" 'has($k)' "$OUTDIR/$name.json" >/dev/null 2>&1 && pub=yes
            jq -e --arg k "$key" 'has($k)' "$tmp"               >/dev/null 2>&1 && live=yes
            if [ "$pub" != "$live" ]; then
                echo "REGRESSED: .$key present in published=$pub live=$live for $name" >&2
                rm -f "$tmp"; return 1
            fi
        done
        local volatile='del(.capture_identity.instance,
                            .capture_identity.dialog_generation,
                            .capture_identity.stream_generation,
                            .timing_clock)'
        jq "$volatile" "$OUTDIR/$name.json" > "$tmp.want" 2>/dev/null
        jq "$volatile" "$tmp"              > "$tmp.got"  2>/dev/null
        if ! diff -u "$tmp.want" "$tmp.got" >/dev/null 2>&1; then
            echo "DRIFTED: $name" >&2
            diff -u "$tmp.want" "$tmp.got" | head -30 >&2
            rm -f "$tmp" "$tmp.want" "$tmp.got"; return 1
        fi
        echo "ok: $name"
        rm -f "$tmp.want" "$tmp.got"
    else
        mv "$tmp" "$OUTDIR/$name.json"
        echo "wrote: $name.json"
    fi
    rm -f "$tmp"
    return 0
}

# The environment goes through `env` rather than as a `VAR=x gen ...` prefix:
# bash keeps assignments that precede a FUNCTION call in the shell afterwards,
# so MCP_FILE_ROOT set for show_evidence would silently stay set for every
# later example and quietly enable the file tools in all of them.
rc=0

gen triage '.' env MCP_NODE_NAME=sbc-edge-1 \
    demos/mcp-stdio.sh "$SAMPLES/sip-problem-call.pcap" \
    triage_call '{"call_id":"busy-3a2b1c@192.0.2.30"}' || rc=1

gen lint '.findings[] | select(.severity == "error")' env MCP_NODE_NAME=sbc-edge-1 \
    demos/mcp-stdio.sh "$SAMPLES/sip-lint-findings.pcap" \
    lint_dialog '{"call_id":"lint-maxfwd@192.0.2.10"}' || rc=1

gen evidence '.' env MCP_FILE_ROOT="$SAMPLES" MCP_NODE_NAME=sbc-edge-1 \
    demos/mcp-stdio.sh "$SAMPLES/sip-problem-call.pcap" \
    show_evidence '{"refs":["tests/pcap-samples/sip-problem-call.pcap#5@884d4525ec86f71b"],"max_bytes":64}' || rc=1

gen correlate '.' env MCP_NODE_NAME=sbc-edge-1 \
    demos/mcp-stdio.sh "$SAMPLES/b2bua-asterisk.pcapng" \
    find_correlated '{"call_id":"b2bua-caller-synth@203.0.113.1"}' || rc=1

# The homepage carries the SAME four answers inline, because the site build has
# no step that could read these files at render time and shipping unverifiable
# template logic is worse than shipping duplicated text. Duplication is only
# safe when one side generates the other, so this does: the .json files are the
# source, index.html is written from them, and --check compares. The chain is
#
#     live binary  ->  website/data/mcp-examples/*.json  ->  index.html
#
# and both links are checked -- the first by the diff above, the second here.
sync_html() { # <write|check>
python3 - "$ROOT/website/templates/index.html" "$OUTDIR" "$1" <<'PY'
import html, re, sys, pathlib

page_path, outdir, mode = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
page = pathlib.Path(page_path).read_text()
bad = 0

for name in ("triage", "lint", "evidence", "correlate"):
    body = (outdir / f"{name}.json").read_text().rstrip("\n")
    # &, < and > only: the JSON carries `Contact: <sip:user@host>`, which ends
    # the <code> element early and silently swallows the rest of the block.
    escaped = html.escape(body, quote=False)
    begin = f"<!-- mcp-example:{name} BEGIN -->"
    end = f"<!-- mcp-example:{name} END -->"
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.S)
    found = pattern.search(page)
    if not found:
        print(f"index.html has no marker pair for {name}", file=sys.stderr)
        bad = 1
        continue
    want = f"{begin}\n{escaped}\n{end}"
    if mode == "check":
        if found.group(0) != want:
            print(f"HTML DRIFTED: the {name} block in index.html is not {name}.json",
                  file=sys.stderr)
            bad = 1
    else:
        # A lambda replacement, not a string: a backslash or a \g in the JSON
        # would otherwise be read as a regex group reference.
        page = pattern.sub(lambda _m: want, page, count=1)

if mode == "write" and not bad:
    pathlib.Path(page_path).write_text(page)
sys.exit(bad)
PY
}

if [ "$CHECK" = 1 ]; then
    sync_html check || rc=1
else
    sync_html write && echo "synced: index.html" || rc=1
fi

exit $rc
