#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Derive the syscall allowlist an enforcing seccomp filter would need, from
# runs rather than from a guess.
#
# `docs/design/syscall-sandbox.md` §3 sets out the procedure and §8 puts the
# enforcing filter last, because a mis-derived allowlist kills the process on a
# capture box during the incident the capture was started for. This is that
# procedure, executable, so the last step becomes a measurement instead of a
# judgement call.
#
#   derive-seccomp-allowlist.sh <sipnab> [iface]   run the shapes, print the set
#   derive-seccomp-allowlist.sh --classify         judge a log on stdin
#
# The `--classify` half takes a streamed kernel log and answers two questions:
# did anything get LOST, and has the set CONVERGED. It touches no hardware, so
# `seccomp_derivation_test` drives it with logs this host could never produce.
#
# ── Why the log has to be streamed ──────────────────────────────────────────
#
# Without an audit daemon the records fall back to the kernel ring buffer,
# which loses them two ways.
#
# It rate limits, and says so: `kauditd_printk_skb: N callbacks suppressed`.
# Measured on the lab VM, a twenty-second capture emitted about 1,700 records
# and 50 survived.
#
# It also WRAPS, and says nothing. Reading the log after a run keeps only the
# last few hundred records: that host's buffer holds about 454 audit lines, and
# three different run shapes each came back with 453 to 455 — a number that
# describes the buffer rather than any run. Reading afterwards returned 12
# distinct syscalls where streaming the same shape returned 21.
#
# Nine missing entries is nine ways to kill the process the list was built for,
# so this script streams with `dmesg --follow`, refuses a run in which anything
# was suppressed, and sets `kernel.printk_ratelimit=0` for the duration.
#
# ── Why convergence is the verdict, not the list ────────────────────────────
#
# The set keeps growing as shapes are added, and it does not announce that it
# has stopped. Nine shapes into sipnab's own derivation, a `--report` run made
# an `ioctl` that the previous eight never had. A filter built on the union of
# those eight would have killed every `--report`.
#
# So the output of this script is not "here is your allowlist". It is "here is
# the union, and here is whether the last shapes added anything to it". A list
# that is still growing is not a list.

set -eu

# How many trailing shapes must add nothing before the set counts as settled.
#
# Two is not a proof and is not claimed as one; it is the smallest number that
# distinguishes "still climbing" from "flat", and the verdict text says so.
QUIET_SHAPES_FOR_CONVERGENCE=2

# ── The judge, which is the testable half ───────────────────────────────────
#
# Reads a streamed log on stdin. Exit 0 for a usable derivation, 1 for one that
# lost records or has not converged, 2 for a log with no records at all —
# distinct because an empty log is a run that never installed a filter, which
# is a different mistake from a run that lost some of it.
classify() {
	log=$(cat)

	if printf '%s' "$log" | grep -q 'callbacks suppressed'; then
		dropped=$(printf '%s' "$log" | grep -o 'callbacks suppressed' | wc -l | tr -d ' ')
		printf 'LOST: the kernel suppressed records in %s window(s).\n' "$dropped"
		printf '  A derivation that misses a call yields an allowlist that kills\n'
		printf '  the process it was built for. Set kernel.printk_ratelimit=0 and\n'
		printf '  run it again.\n'
		return 1
	fi

	records=$(printf '%s' "$log" | grep -c 'type=1326' || true)
	if [ "$records" -eq 0 ]; then
		printf 'NO RECORDS: nothing in this log is a seccomp audit record.\n'
		printf '  Either the filter never installed, or the log was collected\n'
		printf '  after the run rather than streamed during it.\n'
		return 2
	fi

	# Per-shape sets, in the order the shapes ran. A shape is a `== SHAPE name`
	# line the caller emits before each run.
	union=""
	quiet=0
	shapes=0
	current=""
	name=""
	report=""
	printf '%s\n' "$log" | {
		while IFS= read -r line; do
			case "$line" in
			"== SHAPE "*)
				if [ -n "$name" ]; then
					printf '%s\t%s\n' "$name" "$current"
				fi
				name=${line#== SHAPE }
				current=""
				;;
			*type=1326*)
				nr=$(printf '%s' "$line" | sed -n 's/.*syscall=\([0-9]*\).*/\1/p')
				[ -n "$nr" ] && current="$current $nr"
				;;
			esac
		done
		[ -n "$name" ] && printf '%s\t%s\n' "$name" "$current"
	} > /tmp/.seccomp-derive-shapes.$$

	while IFS="$(printf '\t')" read -r shape nrs; do
		shapes=$((shapes + 1))
		added=""
		for nr in $nrs; do
			case " $union " in
			*" $nr "*) ;;
			*)
				union="$union $nr"
				added="$added $nr"
				;;
			esac
		done
		if [ -z "$added" ]; then
			quiet=$((quiet + 1))
		else
			quiet=0
		fi
		report="$report$(printf '  %-16s added:%s\n' "$shape" "${added:- nothing}")
"
	done < /tmp/.seccomp-derive-shapes.$$
	rm -f /tmp/.seccomp-derive-shapes.$$

	sorted=$(printf '%s' "$union" | tr ' ' '\n' | grep -v '^$' | sort -n -u | tr '\n' ' ')
	count=$(printf '%s' "$sorted" | wc -w | tr -d ' ')

	printf '%s' "$report"
	printf 'records %s across %s shape(s); union is %s syscall(s):\n' \
		"$records" "$shapes" "$count"
	printf '  %s\n' "$sorted"

	if [ "$quiet" -lt "$QUIET_SHAPES_FOR_CONVERGENCE" ]; then
		printf 'NOT CONVERGED: the last %s shape(s) were still adding syscalls.\n' \
			"$((QUIET_SHAPES_FOR_CONVERGENCE - quiet))"
		printf '  A set that is still growing is not an allowlist. Add shapes --\n'
		printf '  every feature that opens a file, a socket or a device -- until\n'
		printf '  %s in a row add nothing.\n' "$QUIET_SHAPES_FOR_CONVERGENCE"
		return 1
	fi

	printf 'SETTLED: the last %s shapes added nothing.\n' "$QUIET_SHAPES_FOR_CONVERGENCE"
	printf '  Settled is not complete. It means these shapes stopped finding new\n'
	printf '  calls, not that no shape would. A feature nobody exercised here is\n'
	printf '  a kill waiting for the operator who turns it on.\n'
	return 0
}

if [ "${1:-}" = "--classify" ]; then
	classify
	exit $?
fi

# ── The collector, which needs root and real hardware ───────────────────────

BIN=${1:-}
IFACE=${2:-}
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
	printf 'usage: %s <path-to-sipnab> [iface]\n' "$0" >&2
	printf '   or: %s --classify   (judge a streamed log on stdin)\n' "$0" >&2
	exit 64
fi
if [ "$(id -u)" -ne 0 ]; then
	printf 'This half needs root: it reads the kernel log and captures.\n' >&2
	exit 77
fi
if [ -z "$IFACE" ]; then
	IFACE=$(ip -o link show 2>/dev/null | awk -F': ' '$2 !~ /lo/ {print $2; exit}')
fi

OLD_RATELIMIT=$(cat /proc/sys/kernel/printk_ratelimit 2>/dev/null || echo 5)
WORK=$(mktemp -d)
# Armed BEFORE anything it has to undo. Leaving a host with printk rate
# limiting off is a slow way to fill somebody's disk, and a signal arriving
# between the change and the trap would do exactly that — which a restructure
# of this script introduced and `the_collector_restores_the_rate_limit_it_changed`
# caught within the minute.
trap 'sysctl -q kernel.printk_ratelimit="$OLD_RATELIMIT" 2>/dev/null || true; rm -rf "$WORK"' EXIT INT TERM
sysctl -q kernel.printk_ratelimit=0

# One stream per shape, concatenated with markers afterwards.
#
# NOT one stream with markers appended as it runs: `dmesg --follow` holds that
# file open at its own offset, so anything appended alongside it is overwritten
# the moment the next record arrives. The first version did exactly that and
# every shape's calls landed in the first shape, which made a still-growing set
# look settled — the one verdict this script exists to refuse.
shape() {
	name=$1
	shift
	dmesg -C
	dmesg --follow > "$WORK/$name.log" 2>/dev/null &
	follow=$!
	sleep 1
	# A shape that fails is still a shape: what it managed before failing is
	# evidence, and hiding it would understate the set.
	"$@" > /dev/null 2>&1 || true
	sleep 2
	kill "$follow" 2>/dev/null || true
	wait "$follow" 2>/dev/null || true
	printf '%s\n' "$name" >> "$WORK/order"
}

FIXTURE=${SIPNAB_DERIVE_FIXTURE:-tests/pcap-samples/sip-rtp-g711.pcap}
shape offline-report "$BIN" -N -I "$FIXTURE" --report --seccomp log
shape offline-json "$BIN" -N -I "$FIXTURE" --json --seccomp log
shape offline-output "$BIN" -N -I "$FIXTURE" -O "$WORK/copy.pcap" --seccomp log
if [ -n "$IFACE" ]; then
	shape live-count timeout 20 "$BIN" -N -d "$IFACE" --count 200 --seccomp log
	shape live-report timeout 20 "$BIN" -N -d "$IFACE" --count 150 --report --seccomp log
	shape live-sandbox timeout 20 "$BIN" -N -d "$IFACE" --count 150 --sandbox best-effort --seccomp log
fi

COMBINED="$WORK/combined.log"
: > "$COMBINED"
while IFS= read -r name; do
	printf '== SHAPE %s\n' "$name" >> "$COMBINED"
	cat "$WORK/$name.log" >> "$COMBINED"
done < "$WORK/order"

classify < "$COMBINED"
exit $?
