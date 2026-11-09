#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
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
#   derive-seccomp-allowlist.sh --source           `auditctl -s` on stdin: which
#                                                  log holds the records
#   derive-seccomp-allowlist.sh --audit-log-file   auditd.conf on stdin: where
#                                                  the audit log is
#
# The `--classify` half takes a streamed log and answers two questions: did
# anything get LOST, and has the set CONVERGED. It touches no hardware, so
# `seccomp_derivation_test` drives it with logs this host could never produce.
#
# ── Which log holds the records ─────────────────────────────────────────────
#
# The kernel sends each seccomp record to the audit daemon when one is
# connected, and to the kernel ring buffer only when none is. So on a host
# running auditd the records are in its log (`/var/log/audit/audit.log` by
# default, the file `ausearch -m SECCOMP` reads), as `type=SECCOMP` lines, and
# `dmesg` holds none of them. `auditctl -s` prints the connected daemon's
# `pid`, 0 when there is none; `choose_source` reads that and the collector
# follows the log it names. The one parser reads both line formats.
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

# The syscall numbers each shape made, one `<shape>TAB<numbers>` line per shape,
# from a streamed log on stdin. This is a function, and not a pipeline inside
# classify's command substitution, because bash 3.2 (the /bin/bash on macOS)
# refuses a `case` pattern's unmatched `)` inside `$(...)`: "syntax error near
# unexpected token `;;'", which stopped the script from parsing at all there.
shape_table() {
	current=""
	name=""
	while IFS= read -r line; do
		case "$line" in
		"== SHAPE "*)
			if [ -n "$name" ]; then
				printf '%s\t%s\n' "$name" "$current"
			fi
			name=${line#== SHAPE }
			current=""
			;;
		# The kernel log's `audit: type=1326` and the audit log's
		# `type=SECCOMP` are the same record. `syscall=` is the number;
		# the audit log's enriched `SYSCALL=` (the name) is capitalized,
		# and sed matches case.
		*type=1326* | *type=SECCOMP*)
			nr=$(printf '%s' "$line" | sed -n 's/.*syscall=\([0-9]*\).*/\1/p')
			[ -n "$nr" ] && current="$current $nr"
			;;
		esac
	done
	if [ -n "$name" ]; then
		printf '%s\t%s\n' "$name" "$current"
	fi
}

# ── The judge, which is the testable half ───────────────────────────────────
#
# Reads a streamed log on stdin. Exit 0 for a usable derivation, 1 for one that
# lost records or has not converged, 2 for a log with no records at all —
# distinct because an empty log is a run that never installed a filter, which
# is a different mistake from a run that lost some of it.
classify() {
	log=$(cat)

	# The audit path reports loss as a rising `lost` counter, which the
	# collector writes after each shape as `== LOST <n>`.
	lost=$(printf '%s\n' "$log" | awk '$1 == "==" && $2 == "LOST" && $3 + 0 > 0 {n += $3} END {print n + 0}')
	if [ "$lost" -gt 0 ]; then
		printf 'LOST: the audit subsystem lost %s record(s) during the run.\n' "$lost"
		printf '  A derivation that misses a call yields an allowlist that kills\n'
		printf '  the process it was built for. Raise the backlog (auditctl -b\n'
		printf '  65536), check that auditctl -r is 0, and run it again.\n'
		return 1
	fi

	if printf '%s' "$log" | grep -q 'callbacks suppressed'; then
		dropped=$(printf '%s' "$log" | grep -o 'callbacks suppressed' | wc -l | tr -d ' ')
		printf 'LOST: the kernel suppressed records in %s window(s).\n' "$dropped"
		printf '  A derivation that misses a call yields an allowlist that kills\n'
		printf '  the process it was built for. Set kernel.printk_ratelimit=0 and\n'
		printf '  run it again.\n'
		return 1
	fi

	records=$(printf '%s\n' "$log" | grep -c -e 'type=1326' -e 'type=SECCOMP' || true)
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
	report=""
	table=$(printf '%s\n' "$log" | shape_table)

	# Read from a here-document rather than a file: no path to clean up,
	# and none under /tmp for another user to plant a link at while this
	# runs as root.
	while IFS="$(printf '\t')" read -r shape nrs; do
		if [ -z "$shape" ] && [ -z "$nrs" ]; then
			continue
		fi
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
	done <<EOF
$table
EOF

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

# `auditctl -s` on stdin; prints `audit` when a daemon is connected (a
# non-zero `pid`), else `kernel`. No input, as when auditctl is missing or
# refuses, is no daemon.
choose_source() {
	awk '$1 == "pid" && $2 ~ /^[0-9]+$/ && $2 != 0 {found = 1}
		END {print (found ? "audit" : "kernel")}'
}

# auditd.conf on stdin; prints its `log_file`, or auditd's default.
audit_log_file() {
	awk -F= '/^[[:space:]]*log_file[[:space:]]*=/ {
			v = $2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); path = v
		}
		END {print (path != "" ? path : "/var/log/audit/audit.log")}'
}

# The audit subsystem's `lost` counter, 0 when auditctl cannot say.
audit_lost() {
	auditctl -s 2>/dev/null | awk '$1 == "lost" {n = $2} END {print n + 0}'
}

case "${1:-}" in
--classify)
	classify
	exit $?
	;;
--source)
	choose_source
	exit $?
	;;
--audit-log-file)
	audit_log_file
	exit $?
	;;
esac

# ── The collector, which needs root and real hardware ───────────────────────

BIN=${1:-}
IFACE=${2:-}
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
	printf 'usage: %s <path-to-sipnab> [iface]\n' "$0" >&2
	printf '   or: %s --classify   (judge a streamed log on stdin)\n' "$0" >&2
	printf '   or: %s --source     (auditctl -s on stdin: which log)\n' "$0" >&2
	printf '   or: %s --audit-log-file  (auditd.conf on stdin: its log)\n' "$0" >&2
	exit 64
fi
if [ "$(id -u)" -ne 0 ]; then
	printf 'This half needs root: it reads the kernel or audit log and captures.\n' >&2
	exit 77
fi
if [ -z "$IFACE" ]; then
	IFACE=$(ip -o link show 2>/dev/null | awk -F': ' '$2 !~ /lo/ {print $2; exit}')
fi

SOURCE=$(auditctl -s 2>/dev/null | choose_source)
AUDIT_LOG=""
if [ "$SOURCE" = audit ]; then
	# Two steps, because bash 3.2 (the /bin/bash on macOS) cannot parse a command
	# substitution with a brace group nested in a `${VAR:-...}` default.
	AUDIT_LOG=${SIPNAB_DERIVE_AUDIT_LOG:-}
	if [ -z "$AUDIT_LOG" ]; then
		AUDIT_LOG=$({ cat /etc/audit/auditd.conf 2>/dev/null || true; } | audit_log_file)
	fi
	if [ ! -r "$AUDIT_LOG" ]; then
		printf 'An audit daemon is connected, so the records go to its log,\n' >&2
		printf 'and %s cannot be read. Name it with SIPNAB_DERIVE_AUDIT_LOG.\n' "$AUDIT_LOG" >&2
		exit 66
	fi
	printf 'Records go to the audit daemon; following %s.\n' "$AUDIT_LOG" >&2
else
	printf 'No audit daemon is connected; following the kernel log.\n' >&2
fi

OLD_RATELIMIT=$(cat /proc/sys/kernel/printk_ratelimit 2>/dev/null || echo 5)
WORK=$(mktemp -d)
# Armed BEFORE anything it has to undo. Leaving a host with printk rate
# limiting off is a slow way to fill somebody's disk, and a signal arriving
# between the change and the trap would do exactly that — which a restructure
# of this script introduced and `the_collector_restores_the_rate_limit_it_changed`
# caught within the minute.
trap 'sysctl -q kernel.printk_ratelimit="$OLD_RATELIMIT" 2>/dev/null || true; rm -rf "$WORK"' EXIT INT TERM
# Only the kernel log rate limits seccomp records; the audit path has its own
# loss counter, read per shape below.
if [ "$SOURCE" = kernel ]; then
	sysctl -q kernel.printk_ratelimit=0
fi

# One stream per shape, concatenated with markers afterwards.
#
# NOT one stream with markers appended as it runs: `dmesg --follow` holds that
# file open at its own offset, so anything appended alongside it is overwritten
# the moment the next record arrives. The first version did exactly that and
# every shape's calls landed in the first shape, which made a still-growing set
# look settled — the one verdict this script exists to refuse.
#
# On the audit path `tail -F` follows the log by name, so a rotation during a
# shape is followed rather than lost, and `-n 0` starts at the end so earlier
# records are not read. The rise in the `lost` counter is appended after the
# follower has stopped, when nothing else writes the file.
shape() {
	name=$1
	shift
	if [ "$SOURCE" = audit ]; then
		lost_before=$(audit_lost)
		tail -F -n 0 "$AUDIT_LOG" > "$WORK/$name.log" 2>/dev/null &
	else
		dmesg -C
		dmesg --follow > "$WORK/$name.log" 2>/dev/null &
	fi
	follow=$!
	sleep 1
	# A shape that fails is still a shape: what it managed before failing is
	# evidence, and hiding it would understate the set.
	"$@" > /dev/null 2>&1 || true
	sleep 2
	kill "$follow" 2>/dev/null || true
	wait "$follow" 2>/dev/null || true
	if [ "$SOURCE" = audit ]; then
		printf '== LOST %s\n' "$(($(audit_lost) - lost_before))" >> "$WORK/$name.log"
	fi
	printf '%s\n' "$name" >> "$WORK/order"
}

# The shapes. Every surface that opens a file, a socket or a device belongs
# here, because an unexercised surface is a kill waiting for the operator who
# turns it on: `live-count` added six syscalls that three offline shapes never
# made, and a list derived one shape earlier would have killed every live
# capture.
FIXTURE=${SIPNAB_DERIVE_FIXTURE:-tests/pcap-samples/sip-rtp-g711.pcap}
shape offline-report "$BIN" -N -I "$FIXTURE" --report --seccomp log
shape offline-json "$BIN" -N -I "$FIXTURE" --json --seccomp log
shape offline-output "$BIN" -N -I "$FIXTURE" -O "$WORK/copy.pcap" --seccomp log
shape offline-split "$BIN" -N -I "$FIXTURE" -O "$WORK/split.pcap" --split 1 --seccomp log
shape offline-hexdump "$BIN" -N -I "$FIXTURE" --hexdump --seccomp log
shape offline-audio "$BIN" -N -I "$FIXTURE" --retain-audio --seccomp log
shape offline-vcon "$BIN" -N -I "$FIXTURE" --vcon-out "$WORK/out.vcon" --seccomp log
if [ -n "$IFACE" ]; then
	shape live-count timeout 20 "$BIN" -N -d "$IFACE" --count 200 --seccomp log
	shape live-report timeout 20 "$BIN" -N -d "$IFACE" --count 150 --report --seccomp log
	shape live-sandbox timeout 20 "$BIN" -N -d "$IFACE" --count 150 --sandbox best-effort --seccomp log
	# The server surfaces, which is where the set actually grows. `live-api`
	# added eighteen syscalls that eleven earlier shapes never made — socket,
	# bind, listen, accept and the runtime they pull in. A list derived
	# without them kills every run that turns a server on.
	shape live-api timeout 20 "$BIN" -N -d "$IFACE" --count 50 --api 127.0.0.1:29061 --seccomp log
	shape live-metrics timeout 20 "$BIN" -N -d "$IFACE" --count 50 --metrics 127.0.0.1:29062 --seccomp log
	shape live-hep timeout 20 "$BIN" -N -L 127.0.0.1:29060 --count 50 --seccomp log
	shape live-mcp timeout 20 "$BIN" -N -d "$IFACE" --count 50 --mcp --mcp-transport http --mcp-bind 127.0.0.1:29063 --seccomp log
	shape live-all timeout 20 "$BIN" -N -d "$IFACE" --count 50 --api 127.0.0.1:29064 --metrics 127.0.0.1:29065 --seccomp log
	shape live-repeat timeout 20 "$BIN" -N -d "$IFACE" --count 50 --api 127.0.0.1:29066 --seccomp log
fi

COMBINED="$WORK/combined.log"
: > "$COMBINED"
while IFS= read -r name; do
	printf '== SHAPE %s\n' "$name" >> "$COMBINED"
	cat "$WORK/$name.log" >> "$COMBINED"
done < "$WORK/order"

classify < "$COMBINED"
exit $?
