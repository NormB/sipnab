#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Measure the sipnab LIVE capture path under synthetic load, and say plainly
# whether the 0.5.77 capture changes hold up.
#
# Four changes shipped in 0.5.77 -- the 64 MiB ring default, TPACKET_V3 for
# headless runs, poll(2) off the per-packet path, and the effects-queue lock
# rework -- with REASONED but UNMEASURED throughput claims. This script is what
# turns them into measurements. Refuting them is a success, not a failure: a
# ladder where every rung reports DEGRADED is a result, and it exits 0.
#
# WHAT MAKES A ZERO EVIDENCE RATHER THAN SILENCE
#
#   Two controls run before any rung, and either one failing writes nothing:
#
#   CONTROL 1, observability canary. A veth with the link down, a wrong -d, or
#   a scraper on the wrong side of the namespace all yield packets_total 0 and
#   kernel_dropped 0 -- indistinguishable from a flawless capture. So a known
#   small count is replayed first and packets_total must equal it EXACTLY.
#   Same discipline as tests/offline_never_transmits_test.rs:36-39: "A listener
#   that can never receive anything would pass every no-transmit assertion."
#
#   CONTROL 2, drop-instrument calibration. KERNEL_DROPPED and IFACE_DROPPED
#   are AtomicU64::new(0) (src/capture/live.rs:535, :543) and a failing
#   pcap_stats syscall is swallowed at tracing::debug! (src/capture/live.rs:344)
#   while the default level is info -- a broken stats path reports a flawless
#   capture. So the top rung is run once with a 2 MiB ring and BOTH
#   _quality_degraded == 1 AND kernel_dropped > 0 are required.
#
# SAFETY, STRUCTURAL
#
#   This script takes NO capture path. There is no argument, environment
#   variable or config key through which a pcap can be supplied to sipnab. It
#   generates its own corpus by invoking bench/carrier.py, which is stdlib-only
#   and wholly synthetic (10.1.x.x / 10.2.x.x, locally-administered 02:00:..
#   MACs, Call-IDs call-NNNN@sipnab.bench, payload bytes(160) -- literal
#   silence). Deleting the capability beats blocklisting a path, which a copy
#   or a symlink defeats.
#
# Usage:
#   bench/live-capture.sh --self-test           # no root, no netns, no device
#   sudo bench/live-capture.sh --bin ./sipnab [--runs N] [--rungs LIST]
#        [--headline-only | --ladder-only] [--ladder-seconds S]
#
# See bench/README.md for the operator procedure and the topology figure.

# shellcheck disable=SC2317
# SC2317 file-wide: the self-test cases are dispatched by name out of the
# ST_CASES registry, so ShellCheck 0.9 cannot see the call site and reports
# every line inside them as unreachable. The registry runner asserts instead
# that each registered case exists AND makes at least one assertion.
set -u

# ───────────────────────────────────────────────────────────── constants ───

readonly NS="sipnab-bench"
readonly VETH_TX="snb-tx"
readonly VETH_RX="snb-rx"
readonly API_ADDR="127.0.0.1:8081"
readonly EM_DASH="—"

# carrier.py:47-48, :63-64 -- the generator's clock constants. Everything in
# the rate arithmetic below is derived from these, not assumed.
readonly SIP_PORT=5060
readonly RTP_PORT_BASE=10000
readonly PTIME_USEC=20000
readonly SIGNALLING_STEP_USEC=1000
readonly SIP_PER_CALL=7

# One RTP frame on the wire: 14 eth + 20 ip + 8 udp + 12 rtp + 160 payload
# (carrier.py:274, :281). The pcap record adds a 16-byte header (carrier.py:226)
# and the file opens with a 24-byte header (carrier.py:213-215).
readonly RTP_FRAME_BYTES=214
readonly PCAP_RECHDR_BYTES=16
readonly PCAP_FILEHDR_BYTES=24
readonly RTP_RECORD_BYTES=$(( PCAP_RECHDR_BYTES + RTP_FRAME_BYTES ))  # 230
# SIP records carry a variable text body (carrier.py:157-193). 380 B/record is
# the measured average over a 100-call corpus; it drifts slightly with the call
# index because caller/callee names grow. Treated as an estimate, never exact.
readonly SIP_RECORD_BYTES_EST=380
readonly SIP_RECORD_BYTES_FLOOR=300

# The thirteen rungs whose media-phase rate is EXACT. C must divide 10000, so
# that carrier.py:326's `max(1, PTIME_USEC // (2 * len(state)))` does not
# quantize the clock. C=10000 is the hard ceiling: above it the step clamps to
# 1 us and the per-stream 20 ms cadence breaks.
readonly LADDER_RUNGS="100 125 200 250 400 500 625 1000 1250 2000 2500 5000 10000"
readonly RUNG_CEILING=10000

# pcap_stats is folded on a 1 s timer (src/capture/live.rs:332-334, with
# STATS_INTERVAL at src/capture/live.rs:554) and the FINAL fold happens after
# the capture loop exits (src/capture/live.rs:422-430), where no HTTP scrape
# can ever reach it. The reading therefore has to come from a quiet tail at
# least two intervals after the last packet.
readonly STATS_INTERVAL_S=1
readonly QUIESCE_S=3

readonly EXIT_USAGE=1
readonly EXIT_PREFLIGHT=2
readonly EXIT_UNCALIBRATED=3
readonly EXIT_VOID=4
readonly EXIT_UNEXPLAINED=5

# ────────────────────────────────────────────────────────────── plumbing ───

die() { echo "error: $*" >&2; exit "$EXIT_USAGE"; }

die_code() { # <exit-code> <message...>
  local code="$1"; shift
  echo "error: $*" >&2
  exit "$code"
}

is_uint() { case "${1:-}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

req_int() { # <value> <min> <exit-code> <message>
  if ! is_uint "$1" || [ "$1" -lt "$2" ]; then die_code "$3" "$4"; fi
}

is_num() { # decimal integer or fixed-point; anything else (unavailable/invalid/dash) is not
  case "${1:-}" in
    ''|*[!0-9.]*) return 1 ;;
    *.*.*) return 1 ;;
    *) return 0 ;;
  esac
}

# Every unmeasured cell has to say WHY, with a citation a later reader can
# check. A reason with no file:line is refused outright -- "not supported" is
# how a fabricated zero gets dressed up as a reading.
unavailable() { # <reason carrying a file:line>
  local reason="$1"
  if ! printf '%s' "$reason" | grep -Eq '[A-Za-z0-9_./-]+\.(rs|py|md|toml|sh):[0-9]+'; then
    die_code "$EXIT_USAGE" "unavailable() reason carries no file:line citation: '$reason'"
  fi
  printf 'unavailable(%s)\n' "$reason"
}

invalid() { printf 'invalid(%s)\n' "$1"; }

# ─────────────────────────────────────────────── pure functions: the rate ───

# carrier.py:326 -- the media-phase clock step, in microseconds.
rung_step_usec() { # <concurrency>
  local w="$1" step
  req_int "$w" 1 "$EXIT_PREFLIGHT" "concurrency must be a positive integer, got '$w'"
  step=$(( PTIME_USEC / (2 * w) ))
  [ "$step" -lt 1 ] && step=1
  printf '%d\n' "$step"
}

# The EXACT media-phase aggregate rate for a rung, or a refusal that explains
# the quantization rather than rounding it away.
rung_rate() { # <C> -> pps
  local c="$1" step achieved nominal
  req_int "$c" 1 "$EXIT_PREFLIGHT" "rung: not a positive integer: '$c'"
  if [ "$c" -gt "$RUNG_CEILING" ]; then
    die_code "$EXIT_PREFLIGHT" \
      "rung C=$c is above the hard ceiling $RUNG_CEILING: carrier.py:326 clamps the clock step with max(1, ...), so every C above $RUNG_CEILING replays at the same 1000000 pps and the per-stream 20 ms cadence breaks."
  fi
  if [ $(( 10000 % c )) -ne 0 ]; then
    step=$(rung_step_usec "$c")
    achieved=$(( 1000000 / step ))
    nominal=$(( 100 * c ))
    die_code "$EXIT_PREFLIGHT" \
      "rung C=$c does not divide 10000: carrier.py:326 quantizes the clock to step=$step us by integer division, so the media phase runs at $achieved pps, not the nominal $nominal pps. Valid rungs: $LADDER_RUNGS"
  fi
  printf '%d\n' $(( 100 * c ))
}

# Membership is an explicit published set, not "whatever the arithmetic
# permits". C=50 is exact and still refused, because a rung nobody published
# cannot be compared against anything.
ladder_member() { # <C>
  local c="$1" r
  req_int "$c" 1 "$EXIT_PREFLIGHT" "rung: not a positive integer: '$c'"
  for r in $LADDER_RUNGS; do
    [ "$r" = "$c" ] && { printf '%d\n' "$c"; return 0; }
  done
  if [ "$c" -le "$RUNG_CEILING" ] && [ $(( 10000 % c )) -eq 0 ]; then
    die_code "$EXIT_PREFLIGHT" \
      "C=$c: the arithmetic is exact (10000 % $c == 0, media rate $(( 100 * c )) pps) but $c is not one of the thirteen published rungs. Published rungs: $LADDER_RUNGS"
  fi
  rung_rate "$c" >/dev/null   # produces the specific quantization/ceiling refusal
  die_code "$EXIT_PREFLIGHT" "C=$c is not one of the thirteen published rungs: $LADDER_RUNGS"
}

# carrier.py:287-288 makes the final wave short when calls % concurrency != 0,
# and carrier.py:326 recomputes the step from len(state) -- the ACTUAL wave
# size. A short tail therefore replays at a different rate, and one corpus
# silently carries two offered rates.
waves_are_full() { # <calls> <concurrency> -> wave count
  local calls="$1" conc="$2" tail fullstep tailstep
  req_int "$calls" 1 "$EXIT_PREFLIGHT" "calls must be a positive integer"
  req_int "$conc" 1 "$EXIT_PREFLIGHT" "concurrency must be a positive integer"
  if [ $(( calls % conc )) -ne 0 ]; then
    tail=$(( calls % conc ))
    fullstep=$(rung_step_usec "$conc")
    tailstep=$(rung_step_usec "$tail")
    die_code "$EXIT_PREFLIGHT" \
      "--calls $calls is not a multiple of --concurrency $conc: carrier.py:287-288 makes the final wave $tail calls and carrier.py:326 recomputes the step from len(state), so the tail replays at $(( 1000000 / tailstep )) pps while every full wave replays at $(( 1000000 / fullstep )) pps. One corpus, two offered rates."
  fi
  printf '%d\n' $(( calls / conc ))
}

# carrier.py:238-239 SystemExits on an odd count, because the traffic is
# bidirectional. Catching it here beats discovering it after a 2 GB generation.
require_even_rtp() { # <rtp-per-call>
  local n="$1"
  req_int "$n" 2 "$EXIT_PREFLIGHT" "--rtp-per-call must be a positive even integer, got '$n'"
  if [ $(( n % 2 )) -ne 0 ]; then
    die_code "$EXIT_PREFLIGHT" "--rtp-per-call $n is odd; carrier.py:238-239 raises SystemExit('--rtp-per-call must be even (traffic is bidirectional)')"
  fi
  printf '%d\n' "$n"
}

# The media phase lasts rtp_per_call/100 seconds at EVERY rung: each stream
# emits rtp_per_call/2 packets at a true 20 ms cadence, and the aggregate step
# is scaled so that stays true as C grows.
rtp_per_call_for() { # <media-seconds> -> rtp per call
  local secs="$1"
  req_int "$secs" 1 "$EXIT_PREFLIGHT" "media window must be a positive integer number of seconds"
  require_even_rtp $(( secs * 100 ))
}

# ─────────────────────────────────────── pure functions: the corpus shape ───

corpus_packets()     { printf '%d\n' $(( $1 * (SIP_PER_CALL + $2) )); }   # calls rtp
corpus_sip_records() { printf '%d\n' $(( $1 * SIP_PER_CALL )); }          # calls
corpus_rtp_records() { printf '%d\n' $(( $1 * $2 )); }                    # calls rtp

# The signaling phases run at a FIXED 1000 pps (carrier.py:64, applied at
# :310 and :339), independent of C. This is why the whole-file average rate is
# far below the media rate, and why comparing tcpreplay's achieved rate against
# 100*C marks every row saturated and measures nothing.
sig_span_usec() { # <calls>
  printf '%d\n' $(( $1 * SIP_PER_CALL * SIGNALLING_STEP_USEC ))
}

media_span_usec() { # <calls> <concurrency> <rtp-per-call>
  local step; step=$(rung_step_usec "$2") || return 1
  printf '%d\n' $(( $1 * $3 * step ))
}

# First-to-last-packet span of the generated pcap, exactly as PcapWriter lays
# it out (carrier.py:210-228): every write emits at the current clock and then
# advances it, so the span is the total advance minus the last step, and the
# last packet is a teardown SIP message at the 1000 us signaling step.
corpus_span_usec() { # <calls> <concurrency> <rtp-per-call>
  local calls="$1" conc="$2" rtp="$3" sig media
  waves_are_full "$calls" "$conc" >/dev/null || return 1
  sig=$(sig_span_usec "$calls") || return 1
  media=$(media_span_usec "$calls" "$conc" "$rtp") || return 1
  printf '%d\n' $(( sig + media - SIGNALLING_STEP_USEC ))
}

# A LOWER BOUND on the file size. Exact for RTP records; the SIP part is an
# estimate because the message text varies.
corpus_bytes() { # <sip-records> <rtp-records> <sip-bytes-each>
  printf '%d\n' $(( PCAP_FILEHDR_BYTES + $2 * RTP_RECORD_BYTES + $1 * $3 ))
}

# tcpreplay -K (--preload-pcap) reads the WHOLE corpus into RAM before the
# first packet leaves, so MemTotal is irrelevant -- the guard is MemAvailable.
ram_guard() { # <corpus-bytes> <MemAvailable-kB>
  local bytes="$1" availkb="$2" avail need
  is_uint "$bytes" || die_code "$EXIT_PREFLIGHT" "ram_guard: corpus size is not a number: '$bytes'"
  is_uint "$availkb" || die_code "$EXIT_PREFLIGHT" "ram_guard: MemAvailable is not a number: '$availkb'"
  avail=$(( availkb * 1024 ))
  need=$(( bytes + bytes / 4 ))
  if [ "$need" -gt "$avail" ]; then
    die_code "$EXIT_PREFLIGHT" \
      "corpus is $bytes B and needs $need B with headroom, but MemAvailable is $avail B ($availkb kB). tcpreplay -K preloads the whole corpus into RAM before the first packet leaves, so MemTotal is not the number that matters."
  fi
  printf '%d\n' "$need"
}

# 60 s is HEADLINE-ONLY. A 60 s window at C=10000 is 13.8 GB preloaded into
# RAM; the ladder uses a 10 s media window, which is 2.3 GB at that rung.
duration_policy() { # <rung-id> <ladder-media-seconds> -> media seconds
  local id="$1" ladder="$2"
  case "$id" in
    headline) printf '60\n' ;;
    ladder:*)
      if [ "$ladder" -gt 30 ]; then
        die_code "$EXIT_PREFLIGHT" "ladder rung $id asked for a ${ladder}s media window; 60 s is headline-only (a 60 s window at C=10000 preloads 13.8 GB into RAM under tcpreplay -K)"
      fi
      printf '%d\n' "$ladder" ;;
    *) die_code "$EXIT_PREFLIGHT" "unknown rung id: '$id'" ;;
  esac
}

# ────────────────────────────────────────── pure functions: what to launch ───

# carrier.py:245-248 substitutes `calls` when the pool flag is <= 0. Deriving
# the BPF from the FLAG value instead of the effective pool gives
# `portrange 10000-9999` -- an inverted range that matches nothing, and a run
# that reports a pristine baseline having measured nothing.
effective_pairs() { # <flag> <calls>
  local f="$1" calls="$2"
  if [ "$f" -le 0 ]; then printf '%d\n' "$calls"; else printf '%d\n' "$f"; fi
}

# src/app/bootstrap.rs:337-347 auto-generates a kernel BPF from --portrange
# when none is given on a live source, and the default portrange is 5060-5061.
# Without an explicit filter, 100% of the RTP is dropped in-kernel and the run
# reports a pristine baseline having measured nothing. carrier.py:266-267 puts
# the pairs at RTP_PORT_BASE + 2*pair and +1, so P pairs occupy
# 10000 .. 10000 + 2P - 1 inclusive.
bpf_for() { # <effective-stream-pairs>
  local p="$1"
  req_int "$p" 1 "$EXIT_PREFLIGHT" "bpf_for needs the EFFECTIVE stream-pair pool (>= 1); carrier.py:245-248 normalizes 0 to --calls, and deriving from the flag value inverts the portrange"
  printf 'udp and (port %d or portrange %d-%d)\n' \
    "$SIP_PORT" "$RTP_PORT_BASE" $(( RTP_PORT_BASE + 2 * p - 1 ))
}

# src/capture/live.rs:332-334 folds pcap_stats once per second and the final
# fold at :422-430 lands after the loop exits, where no scrape can see it. So
# --duration must outlast the replay by enough for a quiet-tail scrape, and
# never equal it.
sipnab_duration_for() { # <span-usec> <startup-budget-s> -> seconds
  local span_usec="$1" startup="$2" secs
  secs=$(awk -v u="$span_usec" 'BEGIN { s = u / 1000000.0; printf "%d", (s == int(s) ? s : int(s) + 1) }')
  printf '%d\n' $(( secs + 2 * STATS_INTERVAL_S + 3 + startup ))
}

# One token per line so a caller can scan the argv without re-splitting a
# string that contains spaces.
#
# -N is load-bearing twice over (src/cli.rs:420-421). Without it,
# src/app/bootstrap.rs:503-516 selects RunMode::Tui: immediate_mode_for
# (src/app/bootstrap.rs:1522-1523) then forces TPACKET_V2 at
# src/capture/live.rs:219-220 -- the opposite of the headless-V3 change under
# measurement -- and the TUI takes the terminal over.
#
# -d is the device flag (src/cli.rs:228-232). -i is --ignore-case
# (src/cli.rs:540); `-i snb-rx` would set ignore-case and let clap swallow
# "snb-rx" into the trailing_var_arg BPF positional (src/cli.rs:1483).
argv_sipnab() { # <iface> <duration-s> <api> <bpf> <config> <buffer-mb|""> <budget-mb|""> <report:0|1>
  local iface="$1" dur="$2" api="$3" bpf="$4" cfg="$5" buf="$6" budget="$7" report="$8"
  [ -n "$bpf" ] || die_code "$EXIT_PREFLIGHT" \
    "refusing to build a sipnab argv with an empty BPF filter: src/app/bootstrap.rs:337-347 would auto-generate 'portrange 5060-5061' on a live source, dropping 100% of the RTP in-kernel and reporting a pristine baseline having measured nothing"
  [ -n "$iface" ] || die_code "$EXIT_PREFLIGHT" "refusing to build a sipnab argv with no -d device"
  printf '%s\n' -N
  printf '%s\n' -d "$iface"
  printf '%s\n' --no-cli-print
  printf '%s\n' --no-priv-drop
  printf '%s\n' --config "$cfg"
  printf '%s\n' --api "$api"
  printf '%s\n' --duration "${dur}s"
  [ -n "$buf" ] && printf '%s\n' -B "$buf"
  [ -n "$budget" ] && printf '%s\n' --buffer-budget "$budget"
  [ "$report" = 1 ] && printf '%s\n' --report
  # LAST, always: trailing_var_arg swallows anything placed after it, and
  # src/app/bootstrap.rs:1465 joins the positionals with a single space.
  printf '%s\n' "$bpf"
  return 0
}

# The corpus path is run-scoped by construction. No environment variable can
# redirect it, and there is no argument that supplies one.
argv_carrier() { # <out-dir> <calls> <rtp-per-call> <call-ids> <stream-pairs> <concurrency>
  local outdir="$1"
  [ -n "$outdir" ] || die_code "$EXIT_PREFLIGHT" "argv_carrier: no run-scoped output directory"
  case "$outdir" in
    /tmp/*|/var/tmp/*|/dev/shm/*) ;;
    *) die_code "$EXIT_PREFLIGHT" "argv_carrier: output directory '$outdir' is not under a temporary-filesystem base; the corpus is run-scoped and must not be writable to an arbitrary path" ;;
  esac
  printf '%s\n' --out "$outdir/corpus.pcap"
  printf '%s\n' --calls "$2"
  printf '%s\n' --rtp-per-call "$3"
  printf '%s\n' --call-ids "$4"
  printf '%s\n' --stream-pairs "$5"
  printf '%s\n' --concurrency "$6"
  printf '%s\n' --quiet
}

# ────────────────────────────────────────────── pure functions: the parsers ───

parse_metrics() { # <body> <series-name>
  local body="$1" series="$2" v
  if ! v=$(printf '%s\n' "$body" | awk -v s="$series" '$1 == s && NF == 2 { v = $2; f = 1 } END { if (!f) exit 3; print v }'); then
    unavailable "series $series absent from the scrape; src/output/prometheus.rs:434 emits the capture series unconditionally, so an absent line means the body was truncated or came from another endpoint"
    return 0
  fi
  printf '%s\n' "$v"
}

# HARD ZERO on this route, never a reading. `grep -c CaptureMeter
# src/output/api.rs` returns 0: PrometheusMetrics::for_scrape
# (src/output/prometheus.rs:219) leaves both fields at Default and
# src/output/api.rs:1017 never fills them, while format_metrics emits them
# unconditionally (src/output/prometheus.rs:476, :488). A CaptureMeter reaches
# only the standalone --metrics server (src/output/prometheus_server.rs:114),
# which start_servers now launches for TUI and headless runs alike
# (src/app/servers.rs:190; batch passes the meter at src/app/batch.rs:1879) --
# so the counters ARE measurable headless via --metrics, just never on the
# --api route this harness scrapes.
queue_depth_cell() {
  unavailable "no CaptureMeter is wired into src/output/api.rs:1017, so src/output/prometheus.rs:476 emits a hard zero on the --api route this harness scrapes; a meter reaches only the standalone --metrics server (src/app/servers.rs:190), which this harness does not start"
}

backpressure_cell() {
  unavailable "no CaptureMeter is wired into src/output/api.rs:1017, so src/output/prometheus.rs:488 emits a hard zero on the --api route this harness scrapes; a meter reaches only the standalone --metrics server (src/app/servers.rs:190), which this harness does not start"
}

# tcpreplay's own format strings: "\tSuccessful packets:        %llu",
# "\tFailed packets:            %llu", "Rated: %llu Bps, %.2f Mbps, %llu pps".
parse_tcpreplay_stats() { # <text> -> "<successful> <failed> <pps>"
  local text="$1" ok failed pps
  ok=$(printf '%s\n' "$text" | awk -F: '/Successful packets:/ { gsub(/[^0-9]/, "", $2); v = $2 } END { if (v == "") exit 3; print v }') \
    || ok=$(unavailable "tcpreplay printed no 'Successful packets:' line; the flag probe in bench/live-capture.sh:1 should have caught a build without --stats")
  failed=$(printf '%s\n' "$text" | awk -F: '/Failed packets:/ { gsub(/[^0-9]/, "", $2); v = $2 } END { if (v == "") exit 3; print v }') \
    || failed=$(unavailable "tcpreplay printed no 'Failed packets:' line; see bench/live-capture.sh:1")
  pps=$(printf '%s\n' "$text" | awk '/Rated:/ { for (i = 1; i <= NF; i++) if ($i == "pps") v = $(i-1) } END { if (v == "") exit 3; print v }') \
    || pps=$(unavailable "tcpreplay printed no 'Rated: ... pps' line; see bench/live-capture.sh:1")
  printf '%s %s %s\n' "$ok" "$failed" "$pps"
}

parse_proc_status_vmhwm() { # <text of /proc/<pid>/status> -> peak RSS in kB
  local v
  v=$(printf '%s\n' "$1" | awk '/^VmHWM:/ { print $2; f = 1 } END { if (!f) exit 3 }') \
    || { unavailable "VmHWM absent from /proc/<pid>/status; the process exited before it was read (see bench/live-capture.sh:1)"; return 0; }
  printf '%s\n' "$v"
}

# /proc/<pid>/stat: comm can contain spaces and parentheses, so everything up
# to the LAST ')' is discarded. utime is field 14 and stime field 15 overall,
# which is 12 and 13 in what remains.
parse_proc_stat_cpu() { # <text of /proc/<pid>/stat> -> utime+stime in clock ticks
  local rest="${1##*) }"
  local -a f
  read -r -a f <<< "$rest"
  if [ "${#f[@]}" -lt 13 ]; then
    unavailable "/proc/<pid>/stat had ${#f[@]} fields after the comm, need 13 (see bench/live-capture.sh:1)"
    return 0
  fi
  printf '%d\n' $(( f[11] + f[12] ))
}

# Column 2 of /proc/net/softnet_stat is the per-CPU backlog drop counter, in
# hex. It is SYSTEM-WIDE: softnet_data is per-CPU and global, so this is never
# attributable to one interface.
parse_softnet_dropped() { # <text> -> sum across CPUs
  local total=0 line f2
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    f2=$(printf '%s\n' "$line" | awk '{ print $2 }')
    case "$f2" in
      ''|*[!0-9a-fA-F]*) continue ;;
      *) total=$(( total + 0x$f2 )) ;;
    esac
  done <<< "$1"
  printf '%d\n' "$total"
}

# veth exposes NO rx_dropped counter at all. `ethtool -i <veth>` reports
# `driver: veth` and `ethtool -S <veth> | grep -c rx_dropped` returns 0; the
# only drop-shaped counters are rx_queue_N_drops and three XDP ones. The
# acceptance criterion at docs/research/capture-performance.md:95 is therefore
# unsatisfiable as written, which is a correction that has to land in the doc.
# (:95 is the "Correction to the original acceptance criterion" bullet; the
# criterion sat at :77 before that correction rewrote the surrounding text.)
ethtool_queue_drops() { # <ethtool -S text> -> "<sum> <queue-count>"
  printf '%s\n' "$1" | awk -F: '
    $1 ~ /rx_queue_[0-9]+_drops[ \t]*$/ { gsub(/[^0-9]/, "", $2); s += $2; n++ }
    END { printf "%d %d\n", s + 0, n + 0 }'
}

ethtool_stat() { # <ethtool -S text> <exact key> -> value or unavailable
  local v
  v=$(printf '%s\n' "$1" | awk -F: -v k="$2" '
        { key = $1; gsub(/^[ \t]+|[ \t]+$/, "", key) }
        key == k { gsub(/[^0-9]/, "", $2); v = $2; f = 1 }
        END { if (!f) exit 3; print v }') || {
    if [ "$2" = "rx_dropped" ]; then
      unavailable "veth exposes no rx_dropped counter (ethtool -i reports driver: veth); the acceptance criterion at docs/research/capture-performance.md:95 is unsatisfiable on veth -- rx_queue_N_drops is the counter that exists"
    else
      unavailable "ethtool -S does not expose '$2' on this device; see docs/research/capture-performance.md:95"
    fi
    return 0
  }
  printf '%s\n' "$v"
}

parse_loadavg() { # <text of /proc/loadavg> -> the ONE-minute field
  printf '%s\n' "$1" | awk '{ print $1; exit }'
}

# ────────────────────────────────────── pure functions: gates and verdicts ───

# The design's flat "abort above 0.5" is unsatisfiable on a many-core host
# (14 CPUs here, 11 of them idle at loadavg 2.8), and the first thing an
# operator does with an unsatisfiable gate is delete it. Per-core, with the
# original figure as a floor.
loadavg_gate() { # <load1> <ncpu> -> the threshold used
  local l="$1" n="$2" thr
  thr=$(awk -v n="$n" 'BEGIN { t = 0.1 * n; if (t < 0.5) t = 0.5; printf "%.2f", t }')
  if awk -v l="$l" -v t="$thr" 'BEGIN { exit !(l + 0 > t + 0) }'; then
    die_code "$EXIT_PREFLIGHT" \
      "1-minute load average is $l on $n CPUs, above the $thr gate. This host is not idle; a throughput measurement taken now is a measurement of the other workload."
  fi
  printf '%s\n' "$thr"
}

# Three pairwise-disjoint, non-empty CPU sets, with CPU 0 left to the OS.
cpu_sets() { # <ncpu> -> "<tcpreplay> <sipnab> <sampler>"
  local n="$1"
  is_uint "$n" || die_code "$EXIT_PREFLIGHT" "cpu_sets: '$n' is not a CPU count"
  if [ "$n" -lt 5 ]; then
    die_code "$EXIT_PREFLIGHT" "cpu_sets: $n CPUs is not enough for disjoint tcpreplay / sipnab / sampler sets with CPU 0 left to the OS; 5 is the minimum"
  fi
  printf '1 2-%d %d\n' $(( n - 2 )) $(( n - 1 ))
}

cpulist_expand() { # <list like "2-5,8"> -> one cpu per line
  local list="$1" part lo hi i
  IFS=',' read -r -a _cpl <<< "$list"
  for part in "${_cpl[@]}"; do
    case "$part" in
      *-*) lo="${part%%-*}"; hi="${part##*-}"
           i="$lo"; while [ "$i" -le "$hi" ]; do printf '%d\n' "$i"; i=$(( i + 1 )); done ;;
      *)   printf '%d\n' "$part" ;;
    esac
  done
}

cpu_sets_disjoint() { # <a> <b> <c> -> 0 when pairwise disjoint
  local a b c dup
  a=$(cpulist_expand "$1" | sort -n)
  b=$(cpulist_expand "$2" | sort -n)
  c=$(cpulist_expand "$3" | sort -n)
  [ -n "$a" ] && [ -n "$b" ] && [ -n "$c" ] || return 1
  dup=$(printf '%s\n%s\n%s\n' "$a" "$b" "$c" | sort -n | uniq -d)
  [ -z "$dup" ]
}

assert_links() { # <ip -n <ns> link text> -- EXACT match, not three presence greps
  local got want="lo $VETH_RX $VETH_TX"
  got=$(printf '%s\n' "$1" | awk '/^[0-9]+:/ { n = $2; sub(/:$/, "", n); sub(/@.*/, "", n); print n }' | sort | tr '\n' ' ')
  got="${got% }"
  if [ "$got" != "$want" ]; then
    die_code "$EXIT_PREFLIGHT" \
      "namespace $NS must contain exactly [$want] and contains [$got]; a stray device would put traffic this run did not offer into the delivered-plane counters"
  fi
  printf '%s\n' "$got"
}

assert_routes() { # <ip -n <ns> route show text> -- must be empty
  local trimmed
  trimmed=$(printf '%s' "$1" | tr -d ' \t\n')
  if [ -n "$trimmed" ]; then
    die_code "$EXIT_PREFLIGHT" "namespace $NS has a non-empty route table; the benchmark namespace carries no address and no route by construction: $1"
  fi
  printf '%s\n' "(empty)"
}

check_ns_absent() { # <ip netns list text>
  if printf '%s\n' "$1" | awk '{ print $1 }' | grep -qx "$NS"; then
    die_code "$EXIT_PREFLIGHT" \
      "network namespace $NS already exists. Refusing to start: it is not this run's to delete, and reusing it would inherit whatever is already inside. Remove it yourself with 'ip netns delete $NS' if it is stale."
  fi
  printf 'absent\n'
}

# The disable has to be READ BACK, and it has to happen before the links come
# up: a link-local address assigned first means MLD and RA land in rx_packets
# and identity 3 can never balance exactly.
check_ipv6_disabled() { # <sysctl read-back value>
  local v="${1//[[:space:]]/}"
  if [ "$v" != "1" ]; then
    die_code "$EXIT_PREFLIGHT" \
      "net.ipv6.conf.all.disable_ipv6 reads '$v', not 1, inside $NS. MLD and RA chatter would enter snb-rx rx_packets, and identity 3 (packets_total + kernel_dropped + interface_dropped == rx_packets) could never be exactly zero."
  fi
  printf '1\n'
}

# Read back, never wished. `ethtool -K` on a `[fixed]` feature is a no-op, and
# a run that records the intended state rather than the achieved one records a
# wish.
check_offloads() { # <ethtool -k text>
  local still_on
  still_on=$(printf '%s\n' "$1" | awk -F: '
    $1 ~ /^(generic-receive-offload|large-receive-offload|generic-segmentation-offload|tcp-segmentation-offload)$/ {
      v = $2; gsub(/[ \t]/, "", v)
      if (v ~ /^on/) printf "%s ", $1
    }')
  if [ -n "$still_on" ]; then
    die_code "$EXIT_PREFLIGHT" "offloads still on after ethtool -K on $VETH_RX: ${still_on% }"
  fi
  printf 'all off\n'
}

probe_tcpreplay_flags() { # <tcpreplay --help text>
  local missing="" f
  for f in --stats --preload-pcap --intf1; do
    printf '%s\n' "$1" | grep -q -- "$f" || missing="$missing $f"
  done
  if [ -n "$missing" ]; then
    die_code "$EXIT_PREFLIGHT" \
      "this tcpreplay build does not advertise:$missing. Without --stats the offered plane is unreadable and an empty stats stream would parse as 0 offered packets."
  fi
  printf 'ok\n'
}

probe_sipnab_flags() { # <sipnab --help text>
  local missing="" f
  for f in --api -N --duration --buffer-budget --no-priv-drop; do
    printf '%s\n' "$1" | grep -q -- "$f" || missing="$missing $f"
  done
  if [ -n "$missing" ]; then
    die_code "$EXIT_PREFLIGHT" \
      "this sipnab binary does not advertise:$missing. --api in particular is NOT a default feature (Cargo.toml:219 default = native,tui,audio,metrics; api at Cargo.toml:229) while the flag itself is ungated at src/cli.rs:964-965 and the server arm is cfg-gated at src/app/servers.rs:222-227 -- a plain 'cargo build --release' therefore accepts --api and binds nothing. Use a checksum-verified release artifact, or build with --features api."
  fi
  printf 'ok\n'
}

# A scrape taken less than two STATS_INTERVALs after the last packet
# under-reports kernel drops by up to one interval and manufactures a non-zero
# residual precisely at the loss knee.
scrape_window_valid() { # <replay-end> <last-scrape> <process-exit>
  awk -v r="$1" -v s="$2" -v x="$3" -v q="$(( 2 * STATS_INTERVAL_S ))" 'BEGIN {
    if (s < r + q) { printf "invalid(scrape at %.2f precedes the %.0fs quiesce after the last packet at %.2f; src/capture/live.rs:332-334 folds pcap_stats once per second and the final fold at :422-430 is after the loop, where no scrape can see it)\n", s, q, r; exit }
    if (s > x)     { printf "invalid(scrape at %.2f is after the process exit at %.2f)\n", s, x; exit }
    printf "valid\n" }'
}

canary_check() { # <expected> <observed-or-unavailable> <scrape-ok:0|1>
  local expected="$1" observed="$2" scrape_ok="$3"
  if [ "$scrape_ok" != 1 ]; then
    die_code "$EXIT_VOID" \
      "VOID: the measurement plane never answered. /metrics could not be scraped at all, which most often means the binary was built without the 'api' feature -- Cargo.toml:219 makes it non-default, src/cli.rs:964-965 parses --api regardless, and src/app/servers.rs:222-227 is the cfg-gated arm that would have bound it. It can also mean the scraper ran outside the namespace: --api binds 127.0.0.1 INSIDE $NS and only 'ip netns exec $NS curl' reaches it. Nothing written."
  fi
  if ! is_num "$observed"; then
    die_code "$EXIT_VOID" \
      "VOID: the canary scrape succeeded but sipnab_capture_packets_total read '$observed'. Nothing written."
  fi
  if [ "$observed" -ne "$expected" ]; then
    die_code "$EXIT_VOID" \
      "VOID: the capture point observed $observed packets, not the $expected replayed. A veth with the link down, a wrong -d, or a capture on the transmitting side all report a flawless-looking zero -- this is the check that tells those apart from a real baseline. Nothing written."
  fi
  printf 'canary: %d replayed, %d observed, exact\n' "$expected" "$observed"
}

# BOTH signals. Requiring only _quality_degraded lets a timestamp-only
# degradation stand in for a proven drop counter, which is exactly the reading
# the calibration exists to establish.
calibration_check() { # <degraded> <kernel-dropped>
  local deg="$1" kd="$2"
  if ! is_num "$deg" || ! is_num "$kd"; then
    die_code "$EXIT_UNCALIBRATED" "UNCALIBRATED: calibration scrape read degraded='$deg' kernel_dropped='$kd'. Nothing written."
  fi
  if [ "$deg" -ne 1 ]; then
    die_code "$EXIT_UNCALIBRATED" \
      "UNCALIBRATED: a 2 MiB ring at the top rung did not raise sipnab_capture_quality_degraded (read $deg). The drop instrument is unproven, so a later zero cannot be told from silence. Nothing written."
  fi
  if [ "$kd" -le 0 ]; then
    die_code "$EXIT_UNCALIBRATED" \
      "UNCALIBRATED: sipnab_capture_quality_degraded is 1 but sipnab_capture_kernel_dropped_packets_total is $kd. Degradation was raised by something other than a counted kernel drop (invalid timestamps also raise it), so KERNEL_DROPPED (src/capture/live.rs:535) is still unproven. Nothing written."
  fi
  printf 'calibration: degraded=%d kernel_dropped=%d with a 2 MiB ring at the top rung\n' "$deg" "$kd"
}

residual() { # <rx-packets> <packets-total> <kernel-dropped> <interface-dropped>
  local rx="$1" pt="$2" kd="$3" id="$4"
  if ! is_num "$rx" || ! is_num "$pt" || ! is_num "$kd" || ! is_num "$id"; then
    invalid "one of rx_packets='$rx' packets_total='$pt' kernel_dropped='$kd' interface_dropped='$id' is not a number"
    return 0
  fi
  printf '%d\n' $(( rx - pt - kd - id ))
}

# The offered rate has to come from the corpus's OWN timestamps, not from
# 100*C. carrier.py replays the 7 signaling messages per call at a fixed
# 1000 pps (carrier.py:64, :310, :339) and only the media phase at 100*C, so
# the whole-file average is far below the media rate at every rung -- a 100*C
# comparison marks every row saturated, including the headline, and the
# benchmark reports nothing.
#
# tcpreplay paces from the pcap timestamps, so a shortfall in the whole-file
# rate is attributable to the media phase: the signaling phase at 1000 pps is
# free. Inverting for that fraction is a tighter instrument than the whole-file
# percentage, and it is what the saturation gate uses.
media_achievement_pct() { # <total-packets> <achieved-pps> <sig-span-usec> <media-span-usec>
  awk -v P="$1" -v A="$2" -v S="$3" -v M="$4" 'BEGIN {
    if (A + 0 <= 0) { printf "invalid(achieved rate %s is not positive)\n", A; exit }
    wall = P / A; sig = S / 1000000.0; med = M / 1000000.0
    rem = wall - sig
    if (rem <= 0) { printf "invalid(replay wall clock %.3fs is shorter than the signaling phase alone, %.3fs)\n", wall, sig; exit }
    printf "%.2f\n", 100.0 * med / rem }'
}

# Exactly one verdict per row, always. Precedence, and why:
#   UNEXPLAINED_LOSS    the accounting model is wrong or uncheckable; nothing
#                       on the row can be trusted, so it outranks everything.
#   ARRIVAL_MISMATCH    the rate on the row is fiction; a drop count against a
#                       fictional rate is worse than no number.
#   GENERATOR_SATURATED the rate was never offered. A low drop count at a rate
#                       nobody sent is the most seductive false number here.
#   DEGRADED            the loss knee. A RESULT, not a failure.
#   CLEAN               the only row quotable as a throughput baseline.
classify_row() { # <tcp-ok> <tcp-failed> <tx> <rx> <packets-total> <kernel> <iface> <degraded> <media-pct> <cpu-bound:yes|no|unknown>
  local tok="$1" tfail="$2" tx="$3" rx="$4" pt="$5" kd="$6" ifd="$7" deg="$8" mpct="$9" cpu="${10}"

  if ! is_num "$rx" || ! is_num "$pt" || ! is_num "$kd" || ! is_num "$ifd" || ! is_num "$deg"; then
    printf 'UNEXPLAINED_LOSS\n'; return 0
  fi
  if [ $(( rx - pt - kd - ifd )) -ne 0 ]; then
    printf 'UNEXPLAINED_LOSS\n'; return 0
  fi
  if ! is_num "$tok" || ! is_num "$tx" || [ "$tok" -ne "$tx" ] || [ "$tx" -ne "$rx" ]; then
    printf 'ARRIVAL_MISMATCH\n'; return 0
  fi
  if ! is_num "$tfail" || [ "$tfail" -ne 0 ] || [ "$cpu" = yes ] \
     || ! awk -v p="$mpct" 'BEGIN { exit !(p + 0 >= 99.0) }'; then
    printf 'GENERATOR_SATURATED\n'; return 0
  fi
  if [ "$deg" -ne 0 ]; then
    printf 'DEGRADED\n'; return 0
  fi
  printf 'CLEAN\n'
}

verdict_is_quotable() { [ "$1" = CLEAN ]; }

verdict_rank() { # higher rank wins when several runs of one rung disagree
  case "$1" in
    CLEAN) printf '0\n' ;;
    DEGRADED) printf '1\n' ;;
    GENERATOR_SATURATED) printf '2\n' ;;
    ARRIVAL_MISMATCH) printf '3\n' ;;
    UNEXPLAINED_LOSS) printf '4\n' ;;
    *) die_code "$EXIT_USAGE" "verdict_rank: unknown verdict '$1'" ;;
  esac
}

# N timed runs of one rung can disagree. The row takes the WORST, because a
# rung that lost packets on one run in five is a rung that loses packets.
worst_verdict() { # <verdicts...>
  local v best=CLEAN bestrank=0 rank
  for v in $1; do
    rank=$(verdict_rank "$v")
    if [ "$rank" -gt "$bestrank" ]; then bestrank="$rank"; best="$v"; fi
  done
  printf '%s\n' "$best"
}

# Printed ALWAYS, holding or not: a table that shows its identities only when
# they fail teaches the reader that a silent row was never checked.
identity_lines() { # <tcp-ok> <tx> <rx> <packets-total> <kernel> <iface>
  local tok="$1" tx="$2" rx="$3" pt="$4" kd="$5" ifd="$6" res
  if [ "$tok" = "$tx" ]; then
    printf '  identity 1  tcpreplay successful == %s tx_packets   %s == %s   holds\n' "$VETH_TX" "$tok" "$tx"
  else
    printf '  identity 1  tcpreplay successful == %s tx_packets   %s != %s   FAILS\n' "$VETH_TX" "$tok" "$tx"
  fi
  if [ "$tx" = "$rx" ]; then
    printf '  identity 2  %s tx_packets == %s rx_packets       %s == %s   holds\n' "$VETH_TX" "$VETH_RX" "$tx" "$rx"
  else
    printf '  identity 2  %s tx_packets == %s rx_packets       %s != %s   FAILS\n' "$VETH_TX" "$VETH_RX" "$tx" "$rx"
  fi
  res=$(residual "$rx" "$pt" "$kd" "$ifd")
  if [ "$res" = 0 ]; then
    printf '  identity 3  packets_total + kernel + interface == %s rx_packets   %s + %s + %s == %s   holds\n' \
      "$VETH_RX" "$pt" "$kd" "$ifd" "$rx"
  else
    printf '  identity 3  packets_total + kernel + interface == %s rx_packets   %s + %s + %s vs %s   residual %s   FAILS\n' \
      "$VETH_RX" "$pt" "$kd" "$ifd" "$rx" "$res"
  fi
}

# Every sipnab-sourced cell on a GENERATOR_SATURATED row is an em dash. A low
# drop count at a rate never offered is the number most likely to be quoted and
# most certain to be wrong.
render_sipnab_cell() { # <value> <verdict>
  if [ "$2" = GENERATOR_SATURATED ]; then printf '%s\n' "$EM_DASH"; return 0; fi
  printf '%s\n' "$1"
}

# The closed grammar. A cell is a number, an unavailable() with a citation, an
# invalid() with a reason, or -- only on a saturated row -- an em dash. Never
# "n/a", never blank, and never a 0 standing in for something unmeasured.
cell_is_valid() { # <cell> <dash-allowed:0|1>
  local c="$1" dash="$2"
  case "$c" in
    "$EM_DASH") [ "$dash" = 1 ] ;;
    unavailable\(*\)) [ "${#c}" -gt 14 ] ;;
    invalid\(*\)) [ "${#c}" -gt 10 ] ;;
    *) is_num "$c" ;;
  esac
}

stat_median() { # <values...>
  [ $# -gt 0 ] || { invalid "empty series"; return 0; }
  printf '%s\n' "$@" | sort -g | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'
}

stat_max() { # <values...>
  [ $# -gt 0 ] || { invalid "empty series"; return 0; }
  printf '%s\n' "$@" | awk 'NR == 1 || $1 + 0 > m + 0 { m = $1 } END { print m }'
}

rung_mbps() { # <C>
  awk -v c="$1" -v b="$RTP_FRAME_BYTES" 'BEGIN { printf "%.1f", 100 * c * b * 8 / 1000000.0 }'
}

# The ladder STRADDLES the Phase 2 trigger. 1 Gbps is C ~ 5841, which does not
# divide 10000 and is therefore not a valid rung: C=5000 is 856 Mbps and
# C=10000 is 1712 Mbps. No row may ever be quoted as "1 Gbps".
straddle_note() {
  printf 'Phase 2 trigger (>5%%%% loss on sustained ~1 Gbps RTP): STRADDLED, NOT HIT. 1 Gbps needs C ~ 5841, which does not divide 10000 and is not a valid rung (carrier.py:326). The ladder brackets it at C=5000 = %s Mbps and C=10000 = %s Mbps.\n' \
    "$(rung_mbps 5000)" "$(rung_mbps 10000)"
}

forbidden_phrase_scan() { # <text> -> the offending phrase, or nothing
  local text="$1" p
  for p in "passed at 1 Gbps" "clean at 1 Gbps" "1 Gbps sustained" "sustained 1 Gbps"; do
    case "$text" in *"$p"*) printf '%s\n' "$p"; return 0 ;; esac
  done
  return 0
}

# On a bounded-pool rung 100 calls share one 5-tuple, so SSRC and sequence
# numbers duplicate (carrier.py:266-267, :331-333). The caveat goes on the ROW,
# not in a header a reader can scroll past.
row_caveat() { # <axis: headline|ladder>
  case "$1" in
    headline)
      printf 'reconstruction figures on this row ARE interpretable: --call-ids 0 --stream-pairs 0 give 100 unique Call-IDs and 200 distinct streams (carrier.py:245-248).\n' ;;
    ladder)
      printf 'MOS, jitter and loss on this row are MEANINGLESS: the bounded pools (--call-ids 100 --stream-pairs 100) make many calls share one 5-tuple, so SSRC and sequence numbers duplicate (carrier.py:266-267, :331-333). Only the packet-path counters mean anything here.\n' ;;
    *) die_code "$EXIT_USAGE" "row_caveat: unknown axis '$1'" ;;
  esac
}

# The correction has to land in the DOC, not merely inside this script.
doc_correction_landed() { # <doc text>
  local t="$1"
  case "$t" in *rx_queue_0_drops*) ;; *) printf 'no: rx_queue_0_drops, the counter veth actually exposes, is not named\n'; return 1 ;; esac
  case "$t" in
    *'driver: veth'*|*'exposes no'*|*'no such counter'*|*'no rx_dropped'*) ;;
    *) printf 'no: the veth finding (that no rx_dropped counter exists) is not recorded\n'; return 1 ;;
  esac
  printf 'yes\n'
}

# ────────────────────────────────────────────────────────── record buffer ───

RECORD_FILE=""

record() { printf '%s\n' "$*" >> "$RECORD_FILE"; }
record_raw() { printf '%s\n' "$1" >> "$RECORD_FILE"; }

# UNEXPLAINED_LOSS appends NOTHING and exits non-zero. A row whose accounting
# does not balance is not a worse row, it is an unknown one.
emit_rung_row() { # <verdict> <block text>
  local verdict="$1" block="$2"
  if [ "$verdict" = UNEXPLAINED_LOSS ]; then
    die_code "$EXIT_UNEXPLAINED" \
      "UNEXPLAINED_LOSS: identity 3 residual is not zero (or a required series was unreadable). The accounting model is wrong, so nothing was appended to the record. The block that would have been written:
$block"
  fi
  record_raw "$block"
  printf '%s\n' "$verdict"
}

# =========================================================================
#                                SELF-TEST
# =========================================================================
#
# Needs no root, no namespace and no capture device -- by construction, and
# proven rather than asserted: every case runs with a PATH shim whose ip,
# tcpreplay, sudo, ethtool, sysctl, taskset, nsenter and curl stubs log their
# argv and exit 111. A non-empty log is itself a failure.

ST_TOTAL=0
ST_FAILED=0
ST_ID=""
ST_CASE_N=0
ST_TMP=""
ST_SHIM_LOG=""
ST_OUT=""
ST_RC=0

st_ok()  { ST_TOTAL=$((ST_TOTAL + 1)); ST_CASE_N=$((ST_CASE_N + 1)); printf 'PASS %-5s %s\n' "$ST_ID" "$1"; }
st_bad() {
  ST_TOTAL=$((ST_TOTAL + 1)); ST_CASE_N=$((ST_CASE_N + 1)); ST_FAILED=$((ST_FAILED + 1))
  printf 'FAIL %-5s %s\n' "$ST_ID" "$1"
  printf '           expected: %s\n' "$2"
  printf '           actual:   %s\n' "$3"
}
st_eq()     { if [ "$2" = "$3" ]; then st_ok "$1"; else st_bad "$1" "$2" "$3"; fi; }
st_has()    { case "$3" in *"$2"*) st_ok "$1" ;; *) st_bad "$1" "contains: $2" "$3" ;; esac; }
st_hasnt()  { case "$3" in *"$2"*) st_bad "$1" "must NOT contain: $2" "$3" ;; *) st_ok "$1" ;; esac; }
st_true()   { if "${@:2}"; then st_ok "$1"; else st_bad "$1" "predicate true" "predicate false: ${*:2}"; fi; }
st_false()  { if "${@:2}"; then st_bad "$1" "predicate false" "predicate true: ${*:2}"; else st_ok "$1"; fi; }
st_try()    { ST_OUT=$("$@" 2>&1); ST_RC=$?; return 0; }

# ── the rate ladder ──

st_c_rungs_exact() {
  local c step
  for c in $LADDER_RUNGS; do
    st_eq "S05 rung_rate($c) == 100*C" "$(( 100 * c ))" "$(rung_rate "$c")"
    step=$(rung_step_usec "$c")
    st_eq "S05 rung_rate($c) == 1000000 / (20000/(2*C))" "$(( 1000000 / step ))" "$(rung_rate "$c")"
  done
}

st_c_non_divisor_rejected() {
  st_try rung_rate 300
  st_true "S06 C=300 is refused" test "$ST_RC" -ne 0
  st_has "S06 names the quantized step" "step=33" "$ST_OUT"
  st_has "S06 names the achieved rate" "30303 pps" "$ST_OUT"
  st_has "S06 names the nominal rate" "nominal 30000" "$ST_OUT"
  st_has "S06 cites carrier.py:326" "carrier.py:326" "$ST_OUT"
}

st_c_ceiling_is_hard() {
  st_try rung_rate 10001
  st_true "S07 C=10001 is refused" test "$ST_RC" -ne 0
  st_has "S07 names the max(1, ...) clamp" "max(1, ...)" "$ST_OUT"
  st_has "S07 names the 1 Mpps ceiling" "1000000 pps" "$ST_OUT"
  st_has "S07 names the broken 20 ms cadence" "20 ms cadence" "$ST_OUT"
  st_has "S07 cites carrier.py:326" "carrier.py:326" "$ST_OUT"
}

st_c_membership_is_explicit() {
  st_try ladder_member 50
  st_true "S08 C=50 is refused despite exact arithmetic" test "$ST_RC" -ne 0
  st_has "S08 says the arithmetic is exact" "the arithmetic is exact" "$ST_OUT"
  st_has "S08 says it is not a published rung" "not one of the thirteen published rungs" "$ST_OUT"
  st_eq "S08 C=500 is admitted" "500" "$(ladder_member 500)"
}

st_waves_must_be_full() {
  st_try waves_are_full 150 100
  st_true "S09 150/100 is refused" test "$ST_RC" -ne 0
  st_has "S09 cites the short final wave" "carrier.py:287-288" "$ST_OUT"
  st_has "S09 cites the recomputed step" "carrier.py:326" "$ST_OUT"
  st_has "S09 names the tail rate" "5000 pps" "$ST_OUT"
  st_has "S09 names the full-wave rate" "10000 pps" "$ST_OUT"
  st_eq "S09 100/100 is one full wave" "1" "$(waves_are_full 100 100)"
  st_eq "S09 1000/500 is two full waves" "2" "$(waves_are_full 1000 500)"
}

st_rtp_per_call_even() {
  local s v
  for s in 1 5 10 60; do
    v=$(rtp_per_call_for "$s")
    st_eq "S10 rtp_per_call_for($s) is 100*s" "$(( s * 100 ))" "$v"
    st_eq "S10 rtp_per_call_for($s) is even" "0" "$(( v % 2 ))"
  done
  st_try require_even_rtp 993
  st_true "S10 an odd count is refused" test "$ST_RC" -ne 0
  st_has "S10 cites the generator's own check" "carrier.py:238-239" "$ST_OUT"
}

st_span_is_the_achieved_one() {
  # Exact against the generator's clock: calls=1000 concurrency=1000 rtp=2000
  # lays out 27,000,000 us of advance and the last step is 1000 us.
  st_eq "S11 span(1000,1000,2000) is 26999000 us" "26999000" "$(corpus_span_usec 1000 1000 2000)"
  st_eq "S11 headline span(100,100,6000) is 60699000 us" "60699000" "$(corpus_span_usec 100 100 6000)"
  st_eq "S11 media span is rtp/100 s at C=100" "60000000" "$(media_span_usec 100 100 6000)"
  st_eq "S11 media span is rtp/100 s at C=10000" "60000000" "$(media_span_usec 10000 10000 6000)"
  st_eq "S11 signaling span is 7*calls ms" "700000" "$(sig_span_usec 100)"
}

# ── the BPF ──

st_bpf_derivation() {
  st_eq "S12 P=100 gives 10000-10199" \
    "udp and (port 5060 or portrange 10000-10199)" "$(bpf_for 100)"
  st_eq "S12 P=1 gives 10000-10001" \
    "udp and (port 5060 or portrange 10000-10001)" "$(bpf_for 1)"
}

st_bpf_uses_effective_pool() {
  local p
  p=$(effective_pairs 0 100)
  st_eq "S13 --stream-pairs 0 resolves to --calls" "100" "$p"
  st_eq "S13 the filter follows the effective pool" \
    "udp and (port 5060 or portrange 10000-10199)" "$(bpf_for "$p")"
  st_eq "S13 a positive flag is used as given" "100" "$(effective_pairs 100 5000)"
  st_try bpf_for 0
  st_true "S13 a zero pool is refused, not inverted" test "$ST_RC" -ne 0
  st_has "S13 the refusal cites the normalization" "carrier.py:245-248" "$ST_OUT"
}

st_filter_is_the_trailing_positional() {
  local bpf argv last
  bpf=$(bpf_for 100)
  argv=$(argv_sipnab "$VETH_RX" 66 "$API_ADDR" "$bpf" /tmp/x.toml "" "" 0)
  last=$(printf '%s\n' "$argv" | tail -1)
  st_eq "S14 the BPF is the last argv token" "$bpf" "$last"
  st_eq "S14 the BPF appears exactly once" "1" "$(printf '%s\n' "$argv" | grep -cxF -- "$bpf")"
  st_hasnt "S14 no --bpf-file token" "--bpf-file" "$argv"
  st_has "S14 -N is present (RunMode::Batch, TPACKET_V3)" "-N" "$argv"
  st_has "S14 -d names the capture device" "-d" "$argv"
  st_has "S14 the device is snb-rx" "$VETH_RX" "$argv"
}

st_missing_filter_refused() {
  st_try argv_sipnab "$VETH_RX" 66 "$API_ADDR" "" /tmp/x.toml "" "" 0
  st_true "S15 an empty filter is refused" test "$ST_RC" -ne 0
  st_has "S15 cites the auto-BPF" "src/app/bootstrap.rs:337-347" "$ST_OUT"
  st_has "S15 names portrange 5060-5061" "portrange 5060-5061" "$ST_OUT"
  st_has "S15 says the RTP would be dropped in-kernel" "100% of the RTP in-kernel" "$ST_OUT"
}

# ── verdicts ──

st_one_verdict_per_row() {
  local v n
  local -a rows=(
    "1000 0 1000 1000 1000 0 0 0 100.00 no"          # CLEAN
    "1000 0 1000 1000 990 10 0 1 100.00 no"          # DEGRADED
    "1000 0 1000 1000 1000 0 0 0 80.00 no"           # GENERATOR_SATURATED
    "1000 0 999 999 999 0 0 0 100.00 no"             # ARRIVAL_MISMATCH
    "1000 0 1000 1000 999 0 0 0 100.00 no"           # UNEXPLAINED_LOSS
    "1000 3 1000 1000 1000 0 0 1 80.00 yes"          # overlapping
  )
  for r in "${rows[@]}"; do
    # shellcheck disable=SC2086
    v=$(classify_row $r)
    n=$(printf '%s\n' "$v" | wc -w)
    st_eq "S16 exactly one verdict token for [$r]" "1" "$n"
    case "$v" in
      CLEAN|DEGRADED|GENERATOR_SATURATED|ARRIVAL_MISMATCH|UNEXPLAINED_LOSS) st_ok "S16 token is in the closed set: $v" ;;
      *) st_bad "S16 token is in the closed set" "one of the five" "$v" ;;
    esac
  done
}

st_verdict_precedence() {
  st_eq "S17 residual + mismatch + saturation + degraded => UNEXPLAINED_LOSS" \
    "UNEXPLAINED_LOSS" "$(classify_row 1000 3 999 1000 900 0 0 1 80.00 yes)"
  st_eq "S17 mismatch + saturation + degraded => ARRIVAL_MISMATCH" \
    "ARRIVAL_MISMATCH" "$(classify_row 1000 3 999 999 999 0 0 1 80.00 yes)"
  st_eq "S17 saturation + degraded => GENERATOR_SATURATED" \
    "GENERATOR_SATURATED" "$(classify_row 1000 0 1000 1000 1000 0 0 1 80.00 no)"
}

st_worst_verdict_across_runs() {
  st_eq "S17b five clean runs stay CLEAN" "CLEAN" "$(worst_verdict "CLEAN CLEAN CLEAN CLEAN CLEAN")"
  st_eq "S17b one degraded run degrades the row" "DEGRADED" "$(worst_verdict "CLEAN CLEAN DEGRADED CLEAN CLEAN")"
  st_eq "S17b saturation outranks degradation" "GENERATOR_SATURATED" \
    "$(worst_verdict "DEGRADED GENERATOR_SATURATED CLEAN")"
  st_eq "S17b an unexplained run outranks everything" "UNEXPLAINED_LOSS" \
    "$(worst_verdict "CLEAN DEGRADED GENERATOR_SATURATED ARRIVAL_MISMATCH UNEXPLAINED_LOSS")"
  st_try verdict_rank NOT_A_VERDICT
  st_true "S17b an unknown verdict is refused, not ranked 0" test "$ST_RC" -ne 0
}

st_saturation_blanks_sipnab_cells() {
  local v block
  v=$(classify_row 900012 0 900012 900012 900000 12 0 1 80.00 no)
  st_eq "S18 the row is GENERATOR_SATURATED" "GENERATOR_SATURATED" "$v"
  block=$(printf 'packets_total %s\nkernel_dropped %s\ninterface_dropped %s\ndegraded %s\n' \
    "$(render_sipnab_cell 900000 "$v")" "$(render_sipnab_cell 12 "$v")" \
    "$(render_sipnab_cell 0 "$v")" "$(render_sipnab_cell 1 "$v")")
  st_eq "S18 no digit survives in any sipnab cell" "" "$(printf '%s\n' "$block" | grep -o '[0-9]' | tr -d '\n')"
  st_eq "S18 every sipnab cell is an em dash" "4" "$(printf '%s\n' "$block" | grep -c -- "$EM_DASH")"
  st_eq "S18 offered-plane cells keep their numbers" "900012" "$(render_sipnab_cell 900012 CLEAN)"
}

st_saturation_has_three_triggers() {
  st_eq "S19 (a) achieved 98.9% of nominal" \
    "GENERATOR_SATURATED" "$(classify_row 1000 0 1000 1000 1000 0 0 0 98.90 no)"
  st_eq "S19 (b) tcpreplay reports failed packets" \
    "GENERATOR_SATURATED" "$(classify_row 1000 3 1000 1000 1000 0 0 0 100.00 no)"
  st_eq "S19 (c) tcpreplay pinned to a core, sipnab not" \
    "GENERATOR_SATURATED" "$(classify_row 1000 0 1000 1000 1000 0 0 0 99.60 yes)"
}

st_clean_threshold_is_99() {
  st_eq "S20 98.9% is saturated" "GENERATOR_SATURATED" "$(classify_row 1000 0 1000 1000 1000 0 0 0 98.90 no)"
  st_eq "S20 99.0% is clean" "CLEAN" "$(classify_row 1000 0 1000 1000 1000 0 0 0 99.00 no)"
  st_true "S20 only CLEAN is quotable" verdict_is_quotable CLEAN
  st_false "S20 DEGRADED is not quotable" verdict_is_quotable DEGRADED
  st_false "S20 GENERATOR_SATURATED is not quotable" verdict_is_quotable GENERATOR_SATURATED
}

st_identities_are_exact() {
  st_eq "S21 (A) successful 1000000 vs tx 999999" \
    "ARRIVAL_MISMATCH" "$(classify_row 1000000 0 999999 999999 999999 0 0 0 100.00 no)"
  st_eq "S21 (B) tx 1000000 vs rx 999999" \
    "ARRIVAL_MISMATCH" "$(classify_row 1000000 0 1000000 999999 999999 0 0 0 100.00 no)"
  local lines
  lines=$(identity_lines 1000000 999999 999999 999999 0 0)
  st_has "S21 identity 1 is named as failing" "identity 1" "$lines"
  st_has "S21 both numbers are printed" "1000000 != 999999" "$lines"
}

st_residual_must_be_zero() {
  st_eq "S22 residual 1 is UNEXPLAINED_LOSS" \
    "UNEXPLAINED_LOSS" "$(classify_row 1000000 0 1000000 1000000 999999 0 0 0 100.00 no)"
  st_eq "S22 residual arithmetic" "1" "$(residual 1000000 999999 0 0)"
  st_eq "S22 residual 0 with drops broken out" "0" "$(residual 1000000 999000 900 100)"
  st_eq "S22 a proportional tolerance would have passed this" \
    "CLEAN" "$(classify_row 1000000 0 1000000 1000000 1000000 0 0 0 100.00 no)"
}

st_unexplained_appends_nothing() {
  local before after
  before=$(sha256sum "$RECORD_FILE" | awk '{ print $1 }')
  st_try emit_rung_row UNEXPLAINED_LOSS "rung C=1000 ... would have been written"
  after=$(sha256sum "$RECORD_FILE" | awk '{ print $1 }')
  st_eq "S23 exit code is $EXIT_UNEXPLAINED" "$EXIT_UNEXPLAINED" "$ST_RC"
  st_eq "S23 the record is byte-identical" "$before" "$after"
  st_try emit_rung_row CLEAN "rung C=1000 clean block"
  after=$(sha256sum "$RECORD_FILE" | awk '{ print $1 }')
  st_eq "S23 a CLEAN row does append" "0" "$ST_RC"
  st_true "S23 the record changed for CLEAN" test "$before" != "$after"
}

st_identities_printed_when_holding() {
  local lines
  lines=$(identity_lines 1000 1000 1000 990 8 2)
  st_eq "S24 three identity lines" "3" "$(printf '%s\n' "$lines" | grep -c 'identity ')"
  st_eq "S24 all three say holds" "3" "$(printf '%s\n' "$lines" | grep -c 'holds')"
  st_has "S24 identity 1 shows both sides" "1000 == 1000" "$lines"
}

st_planes_are_never_summed() {
  local block
  block=$(printf '  kernel_dropped      %s\n  interface_dropped   %s\n  invalid_timestamps  %s\n  rx_packets          %s\n  packets_total       %s\n' \
    5 7 3 900000 899988)
  st_hasnt "S25 no summed kernel+interface cell" " 12" "$block"
  st_hasnt "S25 no summed all-drops cell" " 15" "$block"
  st_hasnt "S25 no 'total drops' header" "total drops" "$block"
  st_has "S25 kernel has its own cell" "kernel_dropped      5" "$block"
  st_has "S25 interface has its own cell" "interface_dropped   7" "$block"
  st_has "S25 timestamps have their own cell" "invalid_timestamps  3" "$block"
}

# ── corpus budget ──

st_corpus_budget_is_a_floor() {
  local bytes floor
  bytes=$(corpus_bytes 700 600000 "$SIP_RECORD_BYTES_EST")
  floor=$(corpus_bytes 700 600000 "$SIP_RECORD_BYTES_FLOOR")
  st_eq "S26 estimate is 24 + 600000*230 + 700*380" "$(( 24 + 600000 * 230 + 700 * 380 ))" "$bytes"
  st_true "S26 the estimate is at least 138 MB" test "$bytes" -ge 138000000
  st_true "S26 the floor is below the estimate" test "$floor" -lt "$bytes"
  st_true "S26 the file header is counted" test "$(corpus_bytes 0 1 0)" -eq $(( 24 + 230 ))
  st_eq "S26 headline record counts" "600700" "$(corpus_packets 100 6000)"
  st_eq "S26 headline SIP records" "700" "$(corpus_sip_records 100)"
  st_eq "S26 headline RTP records" "600000" "$(corpus_rtp_records 100 6000)"
}

st_ram_guard_uses_available() {
  st_try ram_guard 13800000000 4194304
  st_eq "S27 exit code is $EXIT_PREFLIGHT" "$EXIT_PREFLIGHT" "$ST_RC"
  st_has "S27 names the corpus size" "13800000000" "$ST_OUT"
  st_has "S27 names MemAvailable" "4194304 kB" "$ST_OUT"
  st_has "S27 names the preload" "tcpreplay -K preloads" "$ST_OUT"
  st_has "S27 says MemTotal is not the number" "MemTotal is not the number" "$ST_OUT"
  st_try ram_guard 138266024 131072000
  st_eq "S27 the headline corpus passes on 125 GiB available" "0" "$ST_RC"
}

st_sixty_seconds_is_headline_only() {
  st_eq "S28 headline is 60 s of media" "60" "$(duration_policy headline 10)"
  st_eq "S28 ladder is the ladder window" "10" "$(duration_policy "ladder:C=10000" 10)"
  st_try duration_policy "ladder:C=10000" 60
  st_true "S28 a 60 s ladder rung is refused" test "$ST_RC" -ne 0
  st_has "S28 the refusal names the 13.8 GB preload" "13.8 GB" "$ST_OUT"
  st_true "S28 the C=10000 ladder corpus is about 2.3 GB" \
    test "$(corpus_bytes "$(corpus_sip_records 10000)" "$(corpus_rtp_records 10000 1000)" "$SIP_RECORD_BYTES_EST")" -lt 2400000000
}

# ── safety ──

st_no_capture_path_accepted() {
  local a
  st_eq "S30 the accepted option surface is pinned" \
    "--self-test|--bin|--runs|--rungs|--ladder-seconds|--headline-only|--ladder-only|-h|--help" \
    "$ACCEPTED_OPTIONS"
  st_try parse_args --bin /srv/pcaps/x.pcap
  st_true "S30 --bin refuses a capture file" test "$ST_RC" -ne 0
  st_has "S30 --bin says it takes no capture path" \
    "this script takes no capture path" "$ST_OUT"
  for a in "--input /srv/pcaps/x.pcap" "-I /srv/pcaps" "--pcap x.pcap" \
           "--corpus x.pcap" "--corpus-file x.pcap" "/srv/pcaps/x.pcap" \
           "--capture x.pcap" "-r x.pcap" "--from x.pcap" "--pcap-dir /srv/pcaps" \
           "--input-name x" "--bpf-file /tmp/f"; do
    # shellcheck disable=SC2086
    st_try parse_args $a
    st_true "S30 refused: $a" test "$ST_RC" -ne 0
    st_has "S30 says it takes no capture path: $a" \
      "this script takes no capture path; it generates its own corpus with bench/carrier.py" "$ST_OUT"
  done
}

st_sipnab_argv_carries_no_input() {
  local argv t
  argv=$(argv_sipnab "$VETH_RX" 66 "$API_ADDR" "$(bpf_for 100)" /tmp/x.toml 64 64 1)
  for t in "-I" "--input" "--input-name" "--bpf-file" "-i"; do
    st_eq "S31 argv carries no $t" "0" "$(printf '%s\n' "$argv" | grep -cx -- "$t")"
  done
  st_eq "S31 argv names the device with -d" "1" "$(printf '%s\n' "$argv" | grep -cx -- "-d")"
  st_eq "S31 the device is $VETH_RX" "1" "$(printf '%s\n' "$argv" | grep -cx -- "$VETH_RX")"
}

st_corpus_path_is_run_scoped() {
  local argv
  export OUT=/srv/pcaps CORPUS=/srv/pcaps/x.pcap SIPNAB_CORPUS=/srv/pcaps/x.pcap
  argv=$(argv_carrier /tmp/sipnab-live.XXXX 100 6000 0 0 100)
  unset OUT CORPUS SIPNAB_CORPUS
  st_has "S32 --out is inside the run-scoped dir" "/tmp/sipnab-live.XXXX/corpus.pcap" "$argv"
  st_hasnt "S32 no environment path leaks in" "/srv/pcaps" "$argv"
  st_try argv_carrier /srv/pcaps 100 6000 0 0 100
  st_true "S32 a non-temporary output base is refused" test "$ST_RC" -ne 0
  st_has "S32 the refusal says run-scoped" "run-scoped" "$ST_OUT"
}

st_config_and_env_cannot_rewrite() {
  local argv cfgidx
  argv=$(argv_sipnab "$VETH_RX" 66 "$API_ADDR" "$(bpf_for 100)" /tmp/run/empty.toml "" "" 0)
  st_eq "S33 argv pins --config" "1" "$(printf '%s\n' "$argv" | grep -cx -- "--config")"
  cfgidx=$(printf '%s\n' "$argv" | grep -nx -- "--config" | cut -d: -f1)
  st_eq "S33 the pinned config is the run-scoped empty one" "/tmp/run/empty.toml" \
    "$(printf '%s\n' "$argv" | sed -n "$(( cfgidx + 1 ))p")"
  st_eq "S33 the launcher scrubs SIPNAB_CONFIG" "unset" "$(launch_env_scrub_plan)"
}

# ── metrics plane ──

st_queue_depth_is_unavailable() {
  local body q b
  body=$(printf '%s\n' \
    "sipnab_capture_packets_total 600700" \
    "sipnab_capture_queue_depth_packets 0" \
    "sipnab_capture_backpressure_blocks_total 0")
  q=$(queue_depth_cell); b=$(backpressure_cell)
  st_hasnt "S35 the queue-depth cell is not a bare 0" "unavailable(0)" "$q"
  st_has "S35 queue depth is unavailable()" "unavailable(" "$q"
  st_has "S35 queue depth cites api.rs:1017" "src/output/api.rs:1017" "$q"
  st_has "S35 queue depth cites the --metrics-only meter wiring" "src/app/servers.rs:190" "$q"
  st_has "S35 backpressure is unavailable()" "unavailable(" "$b"
  st_has "S35 backpressure cites api.rs:1017" "src/output/api.rs:1017" "$b"
  st_eq "S35 the scraped hard zero is never read back" "0" \
    "$(printf '%s\n' "$body" | grep -c "^sipnab_capture_queue_depth_packets $q\$")"
}

st_missing_series_is_not_zero() {
  local body v
  body=$(printf '%s\n' "sipnab_capture_packets_total 600700" "sipnab_capture_quality_degraded 0")
  v=$(parse_metrics "$body" sipnab_capture_kernel_dropped_packets_total)
  st_has "S36 an absent series reads unavailable()" "unavailable(series" "$v"
  st_has "S36 the reason carries a citation" "src/output/prometheus.rs:434" "$v"
  st_eq "S36 the row cannot classify CLEAN" "UNEXPLAINED_LOSS" \
    "$(classify_row 600700 0 600700 600700 600700 "$v" 0 0 100.00 no)"
  st_eq "S36 a present series parses" "600700" "$(parse_metrics "$body" sipnab_capture_packets_total)"
  st_eq "S36 a zero series parses as zero" "0" "$(parse_metrics "$body" sipnab_capture_quality_degraded)"
}

st_cell_grammar_is_closed() {
  st_true "S37 a decimal is a cell" cell_is_valid 12345 0
  st_true "S37 a fixed-point is a cell" cell_is_valid 99.60 0
  st_true "S37 unavailable() is a cell" cell_is_valid "$(unavailable 'src/output/api.rs:1017 hard zero')" 0
  st_true "S37 invalid() is a cell" cell_is_valid "$(invalid 'no reading')" 0
  st_true "S37 an em dash is a cell on a saturated row" cell_is_valid "$EM_DASH" 1
  st_false "S37 an em dash is NOT a cell elsewhere" cell_is_valid "$EM_DASH" 0
  st_false "S37 'n/a' is not a cell" cell_is_valid "n/a" 1
  st_false "S37 an empty cell is not a cell" cell_is_valid "" 1
  st_false "S37 a bare word is not a cell" cell_is_valid "unknown" 1
}

st_unavailable_needs_a_citation() {
  st_try unavailable "not supported"
  st_true "S38 a reason with no citation is refused" test "$ST_RC" -ne 0
  st_has "S38 the refusal says so" "carries no file:line citation" "$ST_OUT"
  st_try unavailable "veth has no such counter, see docs/research/capture-performance.md:95"
  st_eq "S38 a cited reason is accepted" "0" "$ST_RC"
  st_try unavailable "see src/capture/live.rs:535"
  st_eq "S38 a .rs citation is accepted" "0" "$ST_RC"
  st_try unavailable "see carrier.py:326"
  st_eq "S38 a .py citation is accepted" "0" "$ST_RC"
}

# ── controls ──

st_canary_is_exact() {
  st_try canary_check 1000 1000 1
  st_eq "S39 an exact canary passes" "0" "$ST_RC"
  st_has "S39 the canary reading is reported" "1000 replayed, 1000 observed, exact" "$ST_OUT"
  st_try canary_check 1000 999 1
  st_eq "S39 999 of 1000 is VOID" "$EXIT_VOID" "$ST_RC"
  st_try canary_check 1000 0 1
  st_eq "S39 zero observed is VOID" "$EXIT_VOID" "$ST_RC"
  st_has "S39 VOID writes nothing" "Nothing written" "$ST_OUT"
}

st_canary_distinguishes_blind_from_absent() {
  local blind absent
  st_try canary_check 1000 0 1;  blind="$ST_OUT"
  st_try canary_check 1000 "" 0; absent="$ST_OUT"
  st_has "S40 blind capture is named as such" "capture point observed 0 packets" "$blind"
  st_has "S40 blind capture names the -d hazard" "wrong -d" "$blind"
  st_has "S40 absent API names the non-default feature" "Cargo.toml:219" "$absent"
  st_has "S40 absent API names the ungated flag" "src/cli.rs:964-965" "$absent"
  st_has "S40 absent API names the cfg-gated arm" "src/app/servers.rs:222-227" "$absent"
  st_has "S40 absent API names the namespace hazard" "ip netns exec" "$absent"
  st_true "S40 the two messages differ" test "$blind" != "$absent"
}

st_calibration_needs_both_signals() {
  st_try calibration_check 1 418
  st_eq "S41 degraded=1 and drops>0 calibrates" "0" "$ST_RC"
  st_try calibration_check 1 0
  st_eq "S41 degraded=1 with no counted drop is UNCALIBRATED" "$EXIT_UNCALIBRATED" "$ST_RC"
  st_has "S41 it names the other cause of degradation" "invalid timestamps also raise it" "$ST_OUT"
  st_try calibration_check 0 0
  st_eq "S41 neither signal is UNCALIBRATED" "$EXIT_UNCALIBRATED" "$ST_RC"
  st_has "S41 UNCALIBRATED writes nothing" "Nothing written" "$ST_OUT"
}

st_calibration_reading_is_recorded() {
  local block
  block=$(calibration_block "$(argv_sipnab "$VETH_RX" 20 "$API_ADDR" "$(bpf_for 100)" /tmp/x.toml 2 2 0)" 1 418)
  st_has "S42 the calibration argv is written in" "-B" "$block"
  st_has "S42 the 2 MiB ring is written in" "--buffer-budget" "$block"
  st_has "S42 the observed degraded value is written in" "degraded=1" "$block"
  st_has "S42 the observed drop count is written in" "kernel_dropped=418" "$block"
  st_has "S42 later zeros are called readings" "a reading rather than silence" "$block"
  st_has "S42 the AtomicU64 origin is cited" "src/capture/live.rs:535" "$block"
  st_has "S42 the swallowed stats error is cited" "src/capture/live.rs:344" "$block"
  st_has "S42 the inert budget is stated" "--buffer-budget is inert" "$block"
}

st_control_order_is_enforced() {
  local seq
  seq=$(phase_sequence "100 1000 10000")
  st_eq "S43 canary is first" "canary" "$(printf '%s\n' "$seq" | sed -n 1p)"
  st_eq "S43 calibration is second, at the top rung" "calibration:C=10000" "$(printf '%s\n' "$seq" | sed -n 2p)"
  st_eq "S43 then the headline" "headline" "$(printf '%s\n' "$seq" | sed -n 3p)"
  st_eq "S43 rungs ascend" "ladder:C=100" "$(printf '%s\n' "$seq" | sed -n 4p)"
  st_eq "S43 rungs ascend (2)" "ladder:C=1000" "$(printf '%s\n' "$seq" | sed -n 5p)"
  st_eq "S43 rungs ascend (3)" "ladder:C=10000" "$(printf '%s\n' "$seq" | sed -n 6p)"
  seq=$(phase_sequence "10000 100 1000")
  st_eq "S43 an unsorted request still ascends" "ladder:C=100" "$(printf '%s\n' "$seq" | sed -n 4p)"
}

# ── isolation ──

st_link_set_is_exact() {
  local good bad
  good=$(printf '%s\n' \
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT" \
    "2: $VETH_TX@$VETH_RX: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP" \
    "3: $VETH_RX@$VETH_TX: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP")
  bad=$(printf '%s\n%s\n' "$good" "4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN")
  st_try assert_links "$good"
  st_eq "S44 the exact set passes" "0" "$ST_RC"
  st_try assert_links "$bad"
  st_eq "S44 a stray device aborts with $EXIT_PREFLIGHT" "$EXIT_PREFLIGHT" "$ST_RC"
  st_has "S44 the stray device is named" "docker0" "$ST_OUT"
}

st_route_table_must_be_empty() {
  st_try assert_routes ""
  st_eq "S45 an empty table passes" "0" "$ST_RC"
  st_try assert_routes "10.0.0.0/24 dev $VETH_RX proto kernel scope link"
  st_eq "S45 a route aborts with $EXIT_PREFLIGHT" "$EXIT_PREFLIGHT" "$ST_RC"
}

st_isolation_is_evidenced() {
  local links block
  links=$(printf '%s\n' "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536" \
                        "2: $VETH_TX@$VETH_RX: <BROADCAST,UP> mtu 1500" \
                        "3: $VETH_RX@$VETH_TX: <BROADCAST,UP> mtu 1500")
  block=$(isolation_block "$links" "")
  st_has "S46 the link enumeration is copied verbatim" "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536" "$block"
  st_has "S46 the veth pair is copied verbatim" "$VETH_TX@$VETH_RX" "$block"
  st_has "S46 the empty route table is shown as empty" "(empty)" "$block"
  st_hasnt "S46 no bare assertion stands in for the evidence" "isolation: verified" "$block"
}

st_preexisting_namespace_refused() {
  st_try check_ns_absent "$(printf 'other-ns\n%s\n' "$NS")"
  st_eq "S47 a pre-existing namespace aborts" "$EXIT_PREFLIGHT" "$ST_RC"
  st_has "S47 it says it will not delete someone else's" "not this run's to delete" "$ST_OUT"
  st_try check_ns_absent "other-ns"
  st_eq "S47 an absent namespace passes" "0" "$ST_RC"
  st_eq "S47 the teardown is conditional on NS_CREATED" "0" "$NS_CREATED"
}

st_ipv6_disable_is_read_back() {
  st_try check_ipv6_disabled "0"
  st_eq "S48 a read-back of 0 aborts" "$EXIT_PREFLIGHT" "$ST_RC"
  st_has "S48 it names the MLD/RA chatter" "MLD and RA chatter" "$ST_OUT"
  st_has "S48 it names the broken identity" "identity 3" "$ST_OUT"
  st_try check_ipv6_disabled "1"
  st_eq "S48 a read-back of 1 passes" "0" "$ST_RC"
}

# ── timing ──

st_scrape_needs_a_quiesce_window() {
  local a b
  a=$(scrape_window_valid 100.0 100.2 105.0)
  b=$(scrape_window_valid 100.0 102.6 105.0)
  st_has "S49 a scrape 0.2 s after the last packet is invalid" "invalid(" "$a"
  st_has "S49 the reason cites the 1 Hz fold" "src/capture/live.rs:332-334" "$a"
  st_has "S49 the reason cites the post-loop fold" ":422-430" "$a"
  st_eq "S49 a scrape 2.6 s after the last packet is valid" "valid" "$b"
  st_has "S49 a scrape after process exit is invalid" "invalid(" "$(scrape_window_valid 100.0 106.0 105.0)"
}

st_duration_exceeds_the_replay() {
  st_eq "S50 60.07 s replay yields 66 s" "66" "$(sipnab_duration_for 60070000 0)"
  st_eq "S50 an exact 60 s replay yields 65 s" "65" "$(sipnab_duration_for 60000000 0)"
  st_eq "S50 the startup budget is added" "81" "$(sipnab_duration_for 60070000 15)"
  st_true "S50 the duration always exceeds the replay" \
    test "$(sipnab_duration_for 60699000 0)" -gt 61
}

st_one_process_per_rung() {
  local seq n
  seq=$(phase_sequence "100 1000")
  n=$(printf '%s\n' "$seq" | wc -l)
  st_eq "S51 canary + calibration + headline + 2 rungs = 5 phases" "5" "$n"
  st_eq "S51 each phase is its own launch" "5" "$(printf '%s\n' "$seq" | sort -u | wc -l)"
  st_has "S51 the rationale is recorded" "process-global statics" "$(process_per_rung_note)"
  st_has "S51 the rationale cites CAPTURED_PACKETS" "src/capture/mod.rs:84" "$(process_per_rung_note)"
  st_has "S51 the rationale cites the drop statics" "src/capture/live.rs:535" "$(process_per_rung_note)"
}

# ── statistics ──

st_statistic_per_column() {
  st_eq "S52 rates use the median" "11" "$(stat_median 10 12 11 100 10)"
  st_eq "S52 drops use the maximum" "37" "$(stat_max 0 0 0 37 0)"
  st_eq "S52 the mean would have been 28.6" "11" "$(stat_median 10 12 11 100 10)"
  st_has "S52 the rate column names its statistic" "median of 5" "$(stat_label rate 5)"
  st_has "S52 the drop column names its statistic" "max of 5" "$(stat_label drop 5)"
  st_has "S52 the RSS column names its statistic" "max of 5" "$(stat_label rss 5)"
  st_has "S52 an empty series is invalid(), not 0" "invalid(" "$(stat_median)"
}

st_warmup_is_discarded() {
  st_eq "S53 the warm-up is not in the series" "4" "$(stat_max 0 0 0 4 0)"
  st_has "S53 the record says so" "one discarded warm-up, 5 timed runs" "$(stat_label drop 5)"
}

st_governor_is_named() {
  st_has "S54 the governor is copied from the file" "schedutil" "$(env_block schedutil 0.42 14 "1 2-12 13")"
  st_hasnt "S54 nothing is hardcoded to performance" "performance" "$(env_block schedutil 0.42 14 "1 2-12 13")"
}

st_loadavg_gate_reads_field_one() {
  st_eq "S55 the one-minute field is field 1" "0.60" "$(parse_loadavg "0.60 0.30 0.20 1/900 1")"
  st_eq "S55 the one-minute field is field 1 (2)" "0.49" "$(parse_loadavg "0.49 3.00 4.00 1/900 1")"
  st_try loadavg_gate "$(parse_loadavg "0.60 0.30 0.20 1/900 1")" 1
  st_eq "S55 0.60 on 1 CPU refuses" "$EXIT_PREFLIGHT" "$ST_RC"
  st_try loadavg_gate "$(parse_loadavg "0.49 3.00 4.00 1/900 1")" 1
  st_eq "S55 0.49 on 1 CPU proceeds" "0" "$ST_RC"
  st_eq "S55 the gate scales per core" "1.40" "$(loadavg_gate 0.4 14)"
  st_try loadavg_gate 2.81 14
  st_eq "S55 a busy 14-CPU host refuses" "$EXIT_PREFLIGHT" "$ST_RC"
}

st_cpu_sets_are_disjoint() {
  local sets tcp sip smp
  sets=$(cpu_sets 14)
  read -r tcp sip smp <<< "$sets"
  st_eq "S56 tcpreplay gets CPU 1" "1" "$tcp"
  st_eq "S56 sipnab gets the middle" "2-12" "$sip"
  st_eq "S56 the sampler gets the last" "13" "$smp"
  st_true "S56 the three sets are pairwise disjoint" cpu_sets_disjoint "$tcp" "$sip" "$smp"
  st_false "S56 an overlapping assignment is caught" cpu_sets_disjoint "1-3" "2-5" "13"
  st_try cpu_sets 4
  st_eq "S56 four CPUs is refused" "$EXIT_PREFLIGHT" "$ST_RC"
}

st_offloads_are_read_back() {
  local on off
  on=$(printf '%s\n' "generic-receive-offload: on" "large-receive-offload: off [fixed]" \
                     "tcp-segmentation-offload: off" "generic-segmentation-offload: off")
  off=$(printf '%s\n' "generic-receive-offload: off" "large-receive-offload: off [fixed]" \
                      "tcp-segmentation-offload: off" "generic-segmentation-offload: off")
  st_try check_offloads "$on"
  st_eq "S57 a surviving offload aborts" "$EXIT_PREFLIGHT" "$ST_RC"
  st_has "S57 the surviving offload is named" "generic-receive-offload" "$ST_OUT"
  st_try check_offloads "$off"
  st_eq "S57 an all-off read-back passes" "0" "$ST_RC"
  st_has "S57 off [fixed] counts as off" "all off" "$ST_OUT"
}

st_veth_drop_counters() {
  local s drops rxd
  s=$(printf '%s\n' "NIC statistics:" "     peer_ifindex: 3" "     rx_queue_0_xdp_packets: 0" \
                    "     rx_queue_0_drops: 418" "     rx_queue_0_xdp_drops: 0" \
                    "     tx_queue_0_xdp_xmit: 0")
  drops=$(ethtool_queue_drops "$s")
  st_eq "S58 rx_queue_N_drops is read and the queue counted" "418 1" "$drops"
  rxd=$(ethtool_stat "$s" rx_dropped)
  st_has "S58 rx_dropped is unavailable(), not 0" "unavailable(" "$rxd"
  st_has "S58 the reason names the veth driver" "driver: veth" "$rxd"
  st_has "S58 the reason cites the doc criterion" "docs/research/capture-performance.md:95" "$rxd"
  st_hasnt "S58 no fabricated zero" "unavailable(0)" "$rxd"
  st_eq "S58 an XDP drop counter is not mistaken for the queue drop" "418 1" "$drops"
}

st_softnet_is_system_wide() {
  local s block
  s=$(printf '%s\n' "00000123 00000004 00000000 00000000" "00000456 00000007 00000000 00000000")
  st_eq "S59 column 2 is summed across CPUs" "11" "$(parse_softnet_dropped "$s")"
  block=$(delivered_plane_block 1000000 0 0 0 0 "418 1" 11)
  st_has "S59 the cell is labeled system-wide" "system-wide" "$block"
  st_hasnt "S59 it is never attributed to the interface" "$VETH_RX softnet" "$block"
}

st_per_process_resources_are_separate() {
  local block
  block=$(resource_block 812345 4096 1234 56)
  st_has "S60 sipnab has its own peak RSS cell" "sipnab peak RSS" "$block"
  st_has "S60 tcpreplay has its own peak RSS cell" "tcpreplay peak RSS" "$block"
  st_has "S60 sipnab RSS value" "812345" "$block"
  st_has "S60 tcpreplay RSS value" "4096" "$block"
  st_eq "S60 no line carries both processes' numbers" "0" \
    "$(printf '%s\n' "$block" | grep -c '812345.*4096')"
  st_hasnt "S60 no 'total RSS' label" "total RSS" "$block"
  st_hasnt "S60 no 'combined RSS' label" "combined RSS" "$block"
  st_eq "S60 VmHWM parses" "812345" "$(parse_proc_status_vmhwm "VmPeak: 900000 kB
VmHWM:	  812345 kB
VmRSS:	  700000 kB")"
  st_eq "S60 utime+stime parses past a comm with spaces" "1290" \
    "$(parse_proc_stat_cpu "42 (sip nab (x)) S 1 42 42 0 -1 4194304 100 0 0 0 1234 56 0 0 20 0 8 0 900 0 0")"
}

st_tcpreplay_flags_are_probed() {
  st_try probe_tcpreplay_flags "usage: tcpreplay [-i intf] --preload-pcap --intf1"
  st_eq "S61 a build without --stats is refused" "$EXIT_PREFLIGHT" "$ST_RC"
  st_has "S61 the missing flag is named" "--stats" "$ST_OUT"
  st_has "S61 it says why an empty stream is dangerous" "0 offered packets" "$ST_OUT"
  st_try probe_tcpreplay_flags "--stats --preload-pcap --intf1"
  st_eq "S61 a complete build passes" "0" "$ST_RC"
  st_try probe_sipnab_flags "--api -N --duration --buffer-budget"
  st_eq "S61 a sipnab without --no-priv-drop is refused" "$EXIT_PREFLIGHT" "$ST_RC"
  st_try probe_sipnab_flags "-d -N --api --duration --buffer-budget --no-priv-drop"
  st_eq "S61 a complete sipnab passes" "0" "$ST_RC"
  st_try probe_sipnab_flags "-d -N --duration --buffer-budget --no-priv-drop"
  st_has "S61 a missing --api names the non-default feature" "Cargo.toml:219" "$ST_OUT"
}

st_bounded_pool_caveat_on_every_row() {
  local h l
  h=$(row_caveat headline); l=$(row_caveat ladder)
  st_has "S62 the ladder row says MOS is meaningless" "MOS, jitter and loss on this row are MEANINGLESS" "$l"
  st_has "S62 it says calls share one 5-tuple" "share one 5-tuple" "$l"
  st_has "S62 it cites the duplicate SSRC" "carrier.py:266-267" "$l"
  st_has "S63 only the headline is called interpretable" "ARE interpretable" "$h"
  st_hasnt "S63 the ladder row is not called interpretable" "ARE interpretable" "$l"
}

st_straddle_is_stated() {
  local note
  note=$(straddle_note)
  st_has "S64 the summary says straddled, not hit" "STRADDLED, NOT HIT" "$note"
  st_has "S64 C=5000 is named as 856.0 Mbps" "856.0 Mbps" "$note"
  st_has "S64 C=10000 is named as 1712.0 Mbps" "1712.0 Mbps" "$note"
  st_eq "S64 the note carries no forbidden phrase" "" "$(forbidden_phrase_scan "$note")"
  st_eq "S64 'passed at 1 Gbps' is caught" "passed at 1 Gbps" \
    "$(forbidden_phrase_scan "the ladder passed at 1 Gbps with no loss")"
  st_eq "S64 'clean at 1 Gbps' is caught" "clean at 1 Gbps" \
    "$(forbidden_phrase_scan "clean at 1 Gbps")"
  st_eq "S64 '1 Gbps sustained' is caught" "1 Gbps sustained" "$(forbidden_phrase_scan "1 Gbps sustained")"
  st_eq "S64 rung_mbps(100)" "17.1" "$(rung_mbps 100)"
  st_eq "S64 rung_mbps(1000)" "171.2" "$(rung_mbps 1000)"
  st_eq "S64 rung_mbps(2500)" "428.0" "$(rung_mbps 2500)"
}

st_refutation_is_a_success() {
  local s
  s=$(outcome_summary "DEGRADED DEGRADED DEGRADED")
  st_has "S65 refutation is stated plainly" "were NOT reproduced" "$s"
  st_has "S65 the drop planes stay broken out" "kernel, interface and timestamp drops are broken out separately" "$s"
  st_eq "S65 the exit code is 0" "0" "$(outcome_exit_code "DEGRADED DEGRADED DEGRADED")"
  st_eq "S65 an all-clean ladder also exits 0" "0" "$(outcome_exit_code "CLEAN CLEAN")"
  st_has "S65 an all-clean ladder says measured" "were reproduced" "$(outcome_summary "CLEAN CLEAN")"
  st_has "S65 a saturated ladder says the generator was the ceiling" "the generator, not sipnab, was the ceiling" \
    "$(outcome_summary "GENERATOR_SATURATED GENERATOR_SATURATED")"
}

st_media_rate_is_derived_from_the_corpus() {
  # The whole reason the nominal cannot be 100*C: carrier.py replays the seven
  # signaling messages per call at a fixed 1000 pps.
  local span pkts nominal pct
  span=$(corpus_span_usec 100 100 6000)
  pkts=$(corpus_packets 100 6000)
  nominal=$(awk -v p="$pkts" -v s="$span" 'BEGIN { printf "%.2f", p / (s / 1000000.0) }')
  st_eq "S-rate headline whole-file nominal is well below 100*C" "9896.37" "$nominal"
  st_true "S-rate 100*C would have been 10000" test "$(rung_rate 100)" -eq 10000
  pct=$(media_achievement_pct "$pkts" "$nominal" "$(sig_span_usec 100)" "$(media_span_usec 100 100 6000)")
  st_eq "S-rate replaying at the corpus rate is 100% of the media rate" "100.00" "$pct"
  pct=$(media_achievement_pct "$pkts" "$(awk -v p="$pkts" 'BEGIN { printf "%.4f", p / 120.7 }')" \
        "$(sig_span_usec 100)" "$(media_span_usec 100 100 6000)")
  st_eq "S-rate a half-speed media phase reads 50%" "50.00" "$pct"
  st_has "S-rate a non-positive rate is invalid()" "invalid(" \
    "$(media_achievement_pct 600700 0 700000 60000000)"
  st_has "S-rate a wall shorter than signaling is invalid()" "invalid(" \
    "$(media_achievement_pct 600700 999999999 700000 60000000)"
}

st_doc_correction_gate() {
  local old new
  old="- [ ] Benchmark harness: replay a 100+ call sustained-RTP capture; measure
      \`ethtool -S <iface> | grep rx_dropped\`, CPU, RSS; record a baseline."
  new="- [x] **Done:** \`bench/live-capture.sh\` replays a synthetic sustained-RTP
      corpus in a private netns and measures \`ethtool -S snb-rx | grep
      rx_queue_0_drops\` -- veth exposes no rx_dropped counter at all, so the
      criterion as originally written was unsatisfiable."
  st_try doc_correction_landed "$old"
  st_true "S66 the old unsatisfiable criterion fails the gate" test "$ST_RC" -ne 0
  st_has "S66 the failure names the missing counter" "rx_queue_0_drops" "$ST_OUT"
  st_try doc_correction_landed "$new"
  st_eq "S66 the corrected text passes the gate" "0" "$ST_RC"
  st_try doc_correction_landed "measure rx_queue_0_drops"
  st_true "S66 naming the counter without the finding is not enough" test "$ST_RC" -ne 0
  st_has "S66 that failure names the missing finding" "veth finding" "$ST_OUT"
  # A corrected doc necessarily QUOTES the old criterion to explain it. A gate
  # that disqualified on the quote would fail the very text it exists to demand.
  st_try doc_correction_landed "It said to measure \`ethtool -S <iface> | grep rx_dropped\`. That is
    unsatisfiable: \`ethtool -i\` reports \`driver: veth\` and the driver exposes no
    such counter, so the harness reads rx_queue_0_drops instead."
  st_eq "S66 quoting the old criterion while correcting it still passes" "0" "$ST_RC"
}

st_deliberate_failure() {
  if [ "${SELFTEST_INJECT_FAIL:-0}" = 1 ]; then
    st_eq "S04 injected failure (SELFTEST_INJECT_FAIL=1)" "expected-value" "actual-value"
  else
    st_ok "S04 no failure injected (set SELFTEST_INJECT_FAIL=1 to prove the runner propagates one)"
  fi
}

# Runs LAST: everything above has already executed under the shim.
st_shim_log_is_empty() {
  local size
  size=$(wc -c < "$ST_SHIM_LOG")
  st_eq "S01 no privileged call was made during the self-test" "0" "$size"
  if [ "$size" != 0 ]; then
    printf '           shim log:\n'
    sed 's/^/             /' "$ST_SHIM_LOG"
  fi
  st_true "S01 the shims were actually on PATH" test -x "$ST_TMP/shim/ip"
  st_eq "S01 PATH really resolves ip to the shim" "$ST_TMP/shim/ip" "$(command -v ip)"
  st_eq "S01 PATH really resolves tcpreplay to the shim" "$ST_TMP/shim/tcpreplay" "$(command -v tcpreplay)"
}

ST_CASES=(
  "S05:st_c_rungs_exact"
  "S06:st_c_non_divisor_rejected"
  "S07:st_c_ceiling_is_hard"
  "S08:st_c_membership_is_explicit"
  "S09:st_waves_must_be_full"
  "S10:st_rtp_per_call_even"
  "S11:st_span_is_the_achieved_one"
  "S12:st_bpf_derivation"
  "S13:st_bpf_uses_effective_pool"
  "S14:st_filter_is_the_trailing_positional"
  "S15:st_missing_filter_refused"
  "S16:st_one_verdict_per_row"
  "S17:st_verdict_precedence"
  "S17b:st_worst_verdict_across_runs"
  "S18:st_saturation_blanks_sipnab_cells"
  "S19:st_saturation_has_three_triggers"
  "S20:st_clean_threshold_is_99"
  "S21:st_identities_are_exact"
  "S22:st_residual_must_be_zero"
  "S23:st_unexplained_appends_nothing"
  "S24:st_identities_printed_when_holding"
  "S25:st_planes_are_never_summed"
  "S26:st_corpus_budget_is_a_floor"
  "S27:st_ram_guard_uses_available"
  "S28:st_sixty_seconds_is_headline_only"
  "S30:st_no_capture_path_accepted"
  "S31:st_sipnab_argv_carries_no_input"
  "S32:st_corpus_path_is_run_scoped"
  "S33:st_config_and_env_cannot_rewrite"
  "S35:st_queue_depth_is_unavailable"
  "S36:st_missing_series_is_not_zero"
  "S37:st_cell_grammar_is_closed"
  "S38:st_unavailable_needs_a_citation"
  "S39:st_canary_is_exact"
  "S40:st_canary_distinguishes_blind_from_absent"
  "S41:st_calibration_needs_both_signals"
  "S42:st_calibration_reading_is_recorded"
  "S43:st_control_order_is_enforced"
  "S44:st_link_set_is_exact"
  "S45:st_route_table_must_be_empty"
  "S46:st_isolation_is_evidenced"
  "S47:st_preexisting_namespace_refused"
  "S48:st_ipv6_disable_is_read_back"
  "S49:st_scrape_needs_a_quiesce_window"
  "S50:st_duration_exceeds_the_replay"
  "S51:st_one_process_per_rung"
  "S52:st_statistic_per_column"
  "S53:st_warmup_is_discarded"
  "S54:st_governor_is_named"
  "S55:st_loadavg_gate_reads_field_one"
  "S56:st_cpu_sets_are_disjoint"
  "S57:st_offloads_are_read_back"
  "S58:st_veth_drop_counters"
  "S59:st_softnet_is_system_wide"
  "S60:st_per_process_resources_are_separate"
  "S61:st_tcpreplay_flags_are_probed"
  "S62:st_bounded_pool_caveat_on_every_row"
  "S64:st_straddle_is_stated"
  "S65:st_refutation_is_a_success"
  "SR1:st_media_rate_is_derived_from_the_corpus"
  "S66:st_doc_correction_gate"
  "S04:st_deliberate_failure"
  "S01:st_shim_log_is_empty"
)

run_self_test() {
  local t entry id fn before_tree after_tree

  ST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/sipnab-live-capture-selftest.XXXXXX") || die "mktemp failed"
  # shellcheck disable=SC2064
  trap "rm -rf '$ST_TMP'" EXIT

  # Prove unprivilegedness rather than assert it: any call to one of these
  # lands in the log, and S01 fails on a log of non-zero size.
  mkdir -p "$ST_TMP/shim"
  ST_SHIM_LOG="$ST_TMP/privileged-calls.log"
  : > "$ST_SHIM_LOG"
  for t in ip tcpreplay sudo ethtool sysctl taskset nsenter unshare curl tcpdump nft iptables; do
    {
      printf '#!/bin/sh\n'
      printf 'printf "%%s %%s\\n" "%s" "$*" >> "%s"\n' "$t" "$ST_SHIM_LOG"
      printf 'exit 111\n'
    } > "$ST_TMP/shim/$t"
    chmod +x "$ST_TMP/shim/$t"
  done
  PATH="$ST_TMP/shim:$PATH"
  export PATH

  RECORD_FILE="$ST_TMP/record"
  : > "$RECORD_FILE"

  before_tree=$(find "$(dirname "${BASH_SOURCE[0]}")" -maxdepth 1 -printf '%f %s\n' | sort | sha256sum)

  printf 'sipnab live-capture harness self-test\n'
  printf '  no root, no namespace, no capture device -- every privileged tool is shimmed\n'
  printf '  shim: %s\n\n' "$ST_TMP/shim"

  for entry in "${ST_CASES[@]}"; do
    id="${entry%%:*}"; fn="${entry#*:}"
    ST_ID="$id"
    ST_CASE_N=0
    if ! declare -F "$fn" >/dev/null 2>&1; then
      ST_TOTAL=$((ST_TOTAL + 1)); ST_FAILED=$((ST_FAILED + 1))
      printf 'FAIL %-5s registered case has no implementation: %s\n' "$id" "$fn"
      continue
    fi
    "$fn"
    if [ "$ST_CASE_N" -eq 0 ]; then
      ST_TOTAL=$((ST_TOTAL + 1)); ST_FAILED=$((ST_FAILED + 1))
      printf 'FAIL %-5s registered case asserted nothing: %s\n' "$id" "$fn"
    fi
  done

  after_tree=$(find "$(dirname "${BASH_SOURCE[0]}")" -maxdepth 1 -printf '%f %s\n' | sort | sha256sum)
  if [ "$before_tree" = "$after_tree" ]; then
    ST_TOTAL=$((ST_TOTAL + 1)); printf 'PASS %-5s %s\n' "S02" "the self-test wrote nothing into bench/"
  else
    ST_TOTAL=$((ST_TOTAL + 1)); ST_FAILED=$((ST_FAILED + 1))
    printf 'FAIL %-5s %s\n' "S02" "the self-test modified bench/"
  fi

  # Advisory, deliberately not a gate here: docs/research/capture-performance.md
  # is not this script's file, and the fatal gate for the doc correction belongs
  # in tests/docs_drift_test.rs where the rest of the doc drift is enforced.
  local doc
  doc="$(dirname "${BASH_SOURCE[0]}")/../docs/research/capture-performance.md"
  if [ -r "$doc" ]; then
    printf '\nADVISORY  docs/research/capture-performance.md: %s\n' \
      "$(doc_correction_landed "$(cat "$doc")" 2>&1)"
    printf 'ADVISORY  the fatal gate for that correction belongs in tests/docs_drift_test.rs, not here.\n'
  fi

  printf '\n%d assertions across %d cases, %d failed\n' "$ST_TOTAL" "${#ST_CASES[@]}" "$ST_FAILED"
  [ "$ST_FAILED" -eq 0 ] || return 1
  return 0
}

# =========================================================================
#                      BLOCK RENDERERS (pure, self-tested)
# =========================================================================

stat_label() { # <rate|drop|rss> <n>
  case "$1" in
    rate) printf 'median of %d (one discarded warm-up, %d timed runs)\n' "$2" "$2" ;;
    drop|rss) printf 'max of %d (one discarded warm-up, %d timed runs)\n' "$2" "$2" ;;
    *) die_code "$EXIT_USAGE" "stat_label: unknown column '$1'" ;;
  esac
}

env_block() { # <governor> <load1> <ncpu> <cpu-sets>
  printf 'environment\n'
  printf '  scaling_governor    %s   (/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)\n' "$1"
  printf '  loadavg 1-min       %s on %s CPUs\n' "$2" "$3"
  printf '  taskset sets        tcpreplay / sipnab / sampler = %s (pairwise disjoint)\n' "$4"
}

isolation_block() { # <ip link text> <ip route text>
  printf 'isolation, evidenced\n'
  printf '  ip -n %s link\n' "$NS"
  printf '%s\n' "$1" | sed 's/^/    /'
  printf '  ip -n %s route show\n' "$NS"
  if [ -z "$(printf '%s' "$2" | tr -d ' \t\n')" ]; then
    printf '    (empty)\n'
  else
    printf '%s\n' "$2" | sed 's/^/    /'
  fi
}

delivered_plane_block() { # <rx_packets> <rx_dropped> <rx_errors> <rx_missed> <rx_nohandler> <"drops queues"> <softnet>
  local qd qn
  read -r qd qn <<< "$6"
  printf 'plane B, delivered (%s)\n' "$VETH_RX"
  printf '  rx_packets          %s\n' "$1"
  printf '  rx_dropped          %s\n' "$2"
  printf '  rx_errors           %s\n' "$3"
  printf '  rx_missed_errors    %s\n' "$4"
  printf '  rx_nohandler        %s\n' "$5"
  printf '  rx_queue_*_drops    %s   (summed over %s rx queue(s); veth exposes no rx_dropped stat)\n' "$qd" "$qn"
  printf '  softnet dropped     %s   (system-wide: softnet_data is per-CPU and global, summed across CPUs, never attributable to one device)\n' "$7"
}

resource_block() { # <sipnab VmHWM kB> <tcpreplay VmHWM kB> <sipnab ticks> <tcpreplay ticks>
  printf 'resources, per process, never combined\n'
  printf '  sipnab peak RSS     %s kB   (/proc/<pid>/status VmHWM)\n' "$1"
  printf '  tcpreplay peak RSS  %s kB   (GNU time -f %%M)\n' "$2"
  printf '  sipnab CPU          %s ticks (/proc/<pid>/stat utime+stime)\n' "$3"
  printf '  tcpreplay CPU       %s ticks (/proc/<pid>/stat utime+stime)\n' "$4"
}

calibration_block() { # <argv> <degraded> <kernel-dropped>
  printf 'CONTROL 2, drop-instrument calibration\n'
  printf '  argv:\n'
  printf '%s\n' "$1" | sed 's/^/    /'
  printf '  reading: degraded=%s kernel_dropped=%s\n' "$2" "$3"
  printf '  -B 2 shrinks the kernel ring to the 2 MiB floor (buffer_ladder(2) == [2], src/capture/live.rs:509-520).\n'
  printf '  --buffer-budget is inert at this value and is passed only to record the intent:\n'
  printf '    channel_capacity() computes 2 MiB / 2048 = 1024 and clamps UP to MIN_CHANNEL_CAPACITY = 10000\n'
  printf '    (src/capture/native.rs:159-171), so every value at or below 19 MiB yields the same 10000-packet cap.\n'
  printf '  This reading is what makes a later zero a reading rather than silence: KERNEL_DROPPED and\n'
  printf '  IFACE_DROPPED are AtomicU64::new(0) (src/capture/live.rs:535, :543) and a failing pcap_stats\n'
  printf '  syscall is swallowed at tracing::debug! (src/capture/live.rs:344) below the default info level.\n'
}

process_per_rung_note() {
  printf 'One sipnab process per phase, each self-terminating on its own --duration. Required, not incidental:\n'
  printf 'CAPTURED_PACKETS (src/capture/mod.rs:84), KERNEL_DROPPED and IFACE_DROPPED (src/capture/live.rs:535, :543)\n'
  printf 'are process-global statics that are never reset -- a reused process inherits the previous rung s drops.\n'
}

launch_env_scrub_plan() { printf 'unset\n'; }

phase_sequence() { # <space-separated rungs> -> ordered phase ids
  local rungs="$1" sorted top r
  # shellcheck disable=SC2086  # the rung list is split on purpose
  sorted=$(printf '%s\n' $rungs | sort -n | uniq)
  top=$(printf '%s\n' "$sorted" | tail -1)
  printf 'canary\n'
  printf 'calibration:C=%s\n' "$top"
  printf 'headline\n'
  for r in $sorted; do printf 'ladder:C=%s\n' "$r"; done
}

outcome_exit_code() { # <verdicts...>
  case " $1 " in
    *" UNEXPLAINED_LOSS "*) printf '%d\n' "$EXIT_UNEXPLAINED" ;;
    *) printf '0\n' ;;
  esac
}

outcome_summary() { # <verdicts...>
  local v clean=0 degraded=0 saturated=0 mismatch=0
  for v in $1; do
    case "$v" in
      CLEAN) clean=$((clean + 1)) ;;
      DEGRADED) degraded=$((degraded + 1)) ;;
      GENERATOR_SATURATED) saturated=$((saturated + 1)) ;;
      ARRIVAL_MISMATCH) mismatch=$((mismatch + 1)) ;;
    esac
  done
  printf 'outcome\n'
  printf '  %d CLEAN, %d DEGRADED, %d GENERATOR_SATURATED, %d ARRIVAL_MISMATCH\n' \
    "$clean" "$degraded" "$saturated" "$mismatch"
  if [ "$saturated" -gt 0 ] && [ "$clean" -eq 0 ]; then
    printf '  The 0.5.77 capture claims remain UNMEASURED on the saturated rungs: the generator, not sipnab, was the ceiling.\n'
    printf '  No sipnab number on a saturated row is a number; every one of them is an em dash.\n'
  fi
  if [ "$degraded" -gt 0 ]; then
    printf '  The 0.5.77 throughput claims were NOT reproduced on %d rung(s): the loss knee is inside the ladder.\n' "$degraded"
    printf '  That is a RESULT, not a harness failure. The kernel, interface and timestamp drops are broken out separately\n'
    printf '  on every row, never summed, because the remedies differ: a bigger ring cannot recover an interface drop.\n'
  fi
  if [ "$clean" -gt 0 ] && [ "$degraded" -eq 0 ] && [ "$saturated" -eq 0 ] && [ "$mismatch" -eq 0 ]; then
    printf '  The 0.5.77 throughput claims were reproduced across every rung offered. Only the CLEAN rows are quotable.\n'
  fi
  if [ "$mismatch" -gt 0 ]; then
    printf '  %d rung(s) reported ARRIVAL_MISMATCH: the offered rate on those rows is fiction. Check\n' "$mismatch"
    printf '  /proc/sys/net/core/netdev_max_backlog and the softnet dropped column first -- veth attributes a\n'
    printf '  backlog overflow to the TRANSMITTING device, so snb-tx tx_dropped rises while snb-rx rx_packets\n'
    printf '  stays below tcpreplay successful. That is a host limit, not a sipnab capture failure.\n'
  fi
  printf '  %s' "$(straddle_note)"
}

# =========================================================================
#                              ARGUMENT PARSING
# =========================================================================
#
# There is NO route through which a capture file reaches sipnab. Deleting the
# capability beats blocklisting a path, which a copy or a symlink defeats.

# The parser's ENTIRE accepted surface, as data. An option must appear here
# AND have a case arm below; a new arm on its own is unreachable. This is the
# structural half of "no capture path": a future --corpus-file cannot quietly
# become a route for one, because it has to be added here in plain sight and
# the self-test pins this string.
readonly ACCEPTED_OPTIONS="--self-test|--bin|--runs|--rungs|--ladder-seconds|--headline-only|--ladder-only|-h|--help"

option_accepted() {
  local o opts
  IFS='|' read -r -a opts <<< "$ACCEPTED_OPTIONS"
  for o in "${opts[@]}"; do [ "$o" = "$1" ] && return 0; done
  return 1
}

OPT_BIN=""
OPT_RUNS=3
OPT_RUNGS="100 500 1000 2500 5000 10000"
OPT_LADDER_SECONDS=10
OPT_HEADLINE=1
OPT_LADDER=1
NS_CREATED=0

no_capture_path() {
  die_code "$EXIT_USAGE" \
    "this script takes no capture path; it generates its own corpus with bench/carrier.py. Rejected: '$1'"
}

usage() {
  cat <<EOF
Measure the sipnab live capture path under synthetic load.

  bench/live-capture.sh --self-test
  sudo bench/live-capture.sh --bin <sipnab> [options]

  --self-test            run the pure-function gate; no root, no netns, no device
  --bin PATH             sipnab executable to measure (a release artifact, not a dev build)
  --runs N               timed runs per phase after one discarded warm-up (default $OPT_RUNS)
  --rungs LIST           comma-separated ladder rungs (default ${OPT_RUNGS// /,})
                         valid: ${LADDER_RUNGS// /, }
  --ladder-seconds S     media window per ladder rung (default $OPT_LADDER_SECONDS; 60 s is headline-only)
  --headline-only        skip the ladder
  --ladder-only          skip the headline
  -h, --help             this text

This script accepts NO capture path -- no argument, no environment variable and
no config key. It generates its own synthetic corpus with bench/carrier.py.
EOF
}

parse_args() {
  local a
  while [ $# -gt 0 ]; do
    a="$1"
    case "$a" in
      -*) if ! option_accepted "$a"; then
            case "$a" in
              -I|--input|--input-name|--pcap|--corpus|--corpus-file|--capture|--read|-r|--file|-f|--bpf-file|--replay|--pcap-dir|--from)
                no_capture_path "$a" ;;
              *) die_code "$EXIT_USAGE" "unknown argument: $a" ;;
            esac
          fi ;;
      *) no_capture_path "$a" ;;
    esac
    case "$a" in
      --self-test) SELF_TEST=1; shift ;;
      --bin) OPT_BIN="${2:-}"; shift 2 ;;
      --runs) OPT_RUNS="${2:-}"; shift 2 ;;
      --rungs) OPT_RUNGS="${2:-}"; OPT_RUNGS="${OPT_RUNGS//,/ }"; shift 2 ;;
      --ladder-seconds) OPT_LADDER_SECONDS="${2:-}"; shift 2 ;;
      --headline-only) OPT_LADDER=0; shift ;;
      --ladder-only) OPT_HEADLINE=0; shift ;;
      -h|--help) usage; exit 0 ;;
      # Unreachable: the guard above rejects everything not in
      # ACCEPTED_OPTIONS. Present so the loop can never fail to consume an
      # argument -- a guard that stops terminating would otherwise spin here
      # forever, which is worse than a wrong answer.
      *) die_code "$EXIT_USAGE" "internal: '$a' passed the accepted-option guard with no dispatch arm" ;;
    esac
  done
  case "$OPT_BIN" in
    *.pcap|*.pcapng|*.pcap.gz) no_capture_path "$OPT_BIN" ;;
  esac
  req_int "$OPT_RUNS" 1 "$EXIT_USAGE" "--runs must be a positive integer"
  req_int "$OPT_LADDER_SECONDS" 1 "$EXIT_USAGE" "--ladder-seconds must be a positive integer"
  return 0
}

# =========================================================================
#                             ORCHESTRATION
# =========================================================================
#
# Deliberately thin. Every decision above this line is a pure function that the
# self-test can exercise; nothing below can be checked without root, so nothing
# below decides anything.

RUNDIR=""
SAMPLER_PID=""
SIPNAB_PID=""
RUN_VERDICT=""
RUN_SCRAPE_SAMPLES=""
RUN_EXIT_MODE=""
PHASE_VERDICT=""
CARRIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/carrier.py"
CPUS_TCPREPLAY=""
CPUS_SIPNAB=""
CPUS_SAMPLER=""
CORPUS_GEN_S=""
CORPUS_ARGV=""
CORPUS_SHA=""
CORPUS_REAL_BYTES=""

cleanup() {
  local rc=$?
  [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2>/dev/null
  [ -n "$SIPNAB_PID" ] && kill "$SIPNAB_PID" 2>/dev/null
  # ONLY if this run created it. A pre-existing namespace is refused at
  # preflight and must never be deleted by a run that did not make it.
  if [ "$NS_CREATED" = 1 ]; then
    ip netns delete "$NS" 2>/dev/null
  fi
  [ -n "$RUNDIR" ] && rm -rf "$RUNDIR"
  return "$rc"
}

ns() { ip netns exec "$NS" "$@"; }

read_sysfs() { # <iface> <stat>
  ns cat "/sys/class/net/$1/statistics/$2" 2>/dev/null || printf '\n'
}

setup_namespace() {
  check_ns_absent "$(ip netns list 2>/dev/null)" >/dev/null

  ip netns add "$NS" || die_code "$EXIT_PREFLIGHT" "ip netns add $NS failed"
  NS_CREATED=1

  # Before the links come up: an address assigned first means MLD and RA land
  # in rx_packets, and the exact-zero residual is gone.
  ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  ns sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  ns sysctl -qw net.ipv4.conf.all.log_martians=0
  ns sysctl -qw net.ipv4.ip_forward=0

  ip link add "$VETH_TX" type veth peer name "$VETH_RX" \
    || die_code "$EXIT_PREFLIGHT" "creating the veth pair failed"
  ip link set "$VETH_TX" netns "$NS" || die_code "$EXIT_PREFLIGHT" "moving $VETH_TX into $NS failed"
  ip link set "$VETH_RX" netns "$NS" || die_code "$EXIT_PREFLIGHT" "moving $VETH_RX into $NS failed"

  ns sysctl -qw "net.ipv6.conf.$VETH_TX.disable_ipv6=1"
  ns sysctl -qw "net.ipv6.conf.$VETH_RX.disable_ipv6=1"

  # Without these the whole run is the indistinguishable-from-flawless state
  # CONTROL 1 exists to catch, arriving from the setup rather than the operator.
  ns ip link set lo up        || die_code "$EXIT_PREFLIGHT" "bringing lo up in $NS failed"
  ns ip link set "$VETH_TX" up || die_code "$EXIT_PREFLIGHT" "bringing $VETH_TX up failed"
  ns ip link set "$VETH_RX" up || die_code "$EXIT_PREFLIGHT" "bringing $VETH_RX up failed"

  ns ethtool -K "$VETH_RX" gro off lro off gso off tso off >/dev/null 2>&1
  ns ethtool -K "$VETH_TX" gro off lro off gso off tso off >/dev/null 2>&1

  check_ipv6_disabled "$(ns sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" >/dev/null
  check_offloads "$(ns ethtool -k "$VETH_RX" 2>/dev/null)" >/dev/null
  assert_links "$(ip -n "$NS" link 2>/dev/null)" >/dev/null
  assert_routes "$(ip -n "$NS" route show 2>/dev/null)" >/dev/null
}

wait_for_api() { # <deadline-seconds> -> 0 when a real /metrics body answers
  local deadline=$(( SECONDS + $1 )) body
  while [ "$SECONDS" -lt "$deadline" ]; do
    body=$(ns curl -s -m 2 "http://$API_ADDR/metrics" 2>/dev/null)
    case "$body" in *sipnab_capture_packets_total*) return 0 ;; esac
    sleep 1
  done
  return 1
}

scrape() { ns curl -s -m 2 "http://$API_ADDR/metrics" 2>/dev/null; }

snapshot_iface() { # <iface> -> "packets dropped errors missed nohandler queuedrops queues"
  local dir="/sys/class/net/$1/statistics" rx tx qd
  if [ "$1" = "$VETH_TX" ]; then
    printf '%s %s %s\n' "$(ns cat "$dir/tx_packets")" "$(ns cat "$dir/tx_dropped")" "$(ns cat "$dir/tx_errors")"
  else
    rx=$(ns cat "$dir/rx_packets"); tx=$(ns cat "$dir/rx_dropped")
    qd=$(ethtool_queue_drops "$(ns ethtool -S "$1" 2>/dev/null)")
    printf '%s %s %s %s %s %s\n' "$rx" "$tx" \
      "$(ns cat "$dir/rx_errors")" "$(ns cat "$dir/rx_missed_errors")" \
      "$(ns cat "$dir/rx_nohandler")" "$qd"
  fi
}

delta() { # <after> <before> -- a non-numeric either side is invalid(), never 0
  if is_num "$1" && is_num "$2"; then printf '%d\n' $(( $1 - $2 )); else invalid "counter read '$1' minus '$2'"; fi
}

generate_corpus() { # <out-dir> <calls> <rtp> <call-ids> <pairs> <concurrency>
  local argv t0 t1 out
  local argv_text
  argv_text=$(argv_carrier "$@") || exit $?
  mapfile -t argv <<< "$argv_text"
  t0=$(date +%s%N)
  out=$(python3 "$CARRIER" "${argv[@]}" 2>&1) || die_code "$EXIT_PREFLIGHT" "carrier.py failed: $out"
  t1=$(date +%s%N)
  CORPUS_GEN_S=$(awk -v n="$((t1 - t0))" 'BEGIN { printf "%.2f", n / 1000000000 }')
  CORPUS_ARGV="python3 bench/carrier.py ${argv[*]}"
  CORPUS_SHA=$(sha256sum "$1/corpus.pcap" | awk '{ print $1 }')
  CORPUS_REAL_BYTES=$(stat -c %s "$1/corpus.pcap")
}

# One timed run. Sets RUN_* globals; echoes the verdict.
run_once() { # <phase-id> <bpf> <duration> <buffer-mb> <budget-mb> <report> <packets> <sig-usec> <media-usec>
  local phase="$1" bpf="$2" dur="$3" buf="$4" budget="$5" report="$6"
  local packets="$7" sigus="$8" medus="$9"
  local -a argv
  local argv_text tx0 rx0 tx1 rx1 sn0 sn1 body tstats tok tfail tpps t_end t_scrape comm
  local a b c

  argv_text=$(argv_sipnab "$VETH_RX" "$dur" "$API_ADDR" "$bpf" "$RUNDIR/empty.toml" "$buf" "$budget" "$report") || exit $?
  mapfile -t argv <<< "$argv_text"

  local scrapedir="$RUNDIR/scrapes.$phase"
  rm -rf "$scrapedir"; mkdir -p "$scrapedir"

  tx0=$(snapshot_iface "$VETH_TX"); rx0=$(snapshot_iface "$VETH_RX")
  sn0=$(parse_softnet_dropped "$(ns cat /proc/net/softnet_stat)")

  taskset -c "$CPUS_SIPNAB" ip netns exec "$NS" "$OPT_BIN" "${argv[@]}" \
    > "$RUNDIR/sipnab.$phase.out" 2>&1 &
  SIPNAB_PID=$!

  if ! wait_for_api 20; then
    kill "$SIPNAB_PID" 2>/dev/null; wait "$SIPNAB_PID" 2>/dev/null; SIPNAB_PID=""
    canary_check 1 "" 0   # exits 4 with the API-never-bound message
  fi

  # 1 Hz sampler, inside the namespace: --api binds 127.0.0.1 in there and no
  # scrape from the host loopback can ever reach it.
  ( n=0
    while :; do
      n=$((n + 1))
      if taskset -c "$CPUS_SAMPLER" ip netns exec "$NS" \
           curl -s -m 2 -o "$scrapedir/scrape.$n" "http://$API_ADDR/metrics" 2>/dev/null; then
        date +%s.%N > "$scrapedir/scrape.$n.t"
      fi
      sleep 1
    done ) &
  SAMPLER_PID=$!

  tstats=$(/usr/bin/time -f '%M' -o "$RUNDIR/tcpreplay.rss" \
             taskset -c "$CPUS_TCPREPLAY" ip netns exec "$NS" \
             tcpreplay -K --intf1 "$VETH_TX" --stats 1 "$RUNDIR/corpus.pcap" 2>&1)
  t_end=$(date +%s.%N)

  # The reading comes from a deliberate quiet-tail scrape, never from "whatever
  # the 1 Hz sampler last got": src/capture/live.rs:332-334 folds pcap_stats
  # once per second and the final fold at :422-430 is after the loop exits.
  sleep "$QUIESCE_S"
  body=$(scrape)
  t_scrape=$(date +%s.%N)

  comm=$(cat "/proc/$SIPNAB_PID/comm" 2>/dev/null)
  if [ "$comm" = sipnab ]; then
    RUN_SIPNAB_RSS=$(parse_proc_status_vmhwm "$(cat "/proc/$SIPNAB_PID/status" 2>/dev/null)")
    RUN_SIPNAB_CPU=$(parse_proc_stat_cpu "$(cat "/proc/$SIPNAB_PID/stat" 2>/dev/null)")
  else
    RUN_SIPNAB_RSS=$(unavailable "/proc/<pid>/comm read '$comm', not sipnab; the launched pid is not the measured process (see bench/live-capture.sh:1)")
    RUN_SIPNAB_CPU="$RUN_SIPNAB_RSS"
  fi

  kill "$SAMPLER_PID" 2>/dev/null; wait "$SAMPLER_PID" 2>/dev/null; SAMPLER_PID=""

  # The 1 Hz series is evidence that the plane stayed up for the whole run; the
  # READING is the quiesce scrape above, and the two are labeled apart.
  RUN_SCRAPE_SAMPLES=$(find "$scrapedir" -name 'scrape.*' ! -name '*.t' -size +0 | wc -l)

  # Bounded: sipnab self-terminates on --duration, but a capture that stops
  # answering must not hang the harness, and being forced is a fact the record
  # carries rather than one that disappears.
  local deadline=$(( SECONDS + dur + 30 ))
  RUN_EXIT_MODE=self-terminated
  while kill -0 "$SIPNAB_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      RUN_EXIT_MODE="forced (SIGTERM after --duration ${dur}s + 30s grace)"
      kill "$SIPNAB_PID" 2>/dev/null; sleep 5
      if kill -0 "$SIPNAB_PID" 2>/dev/null; then
        RUN_EXIT_MODE="forced (SIGKILL; SIGTERM was ignored)"
        kill -9 "$SIPNAB_PID" 2>/dev/null
      fi
      break
    fi
    sleep 1
  done
  wait "$SIPNAB_PID" 2>/dev/null; SIPNAB_PID=""

  tx1=$(snapshot_iface "$VETH_TX"); rx1=$(snapshot_iface "$VETH_RX")
  sn1=$(parse_softnet_dropped "$(ns cat /proc/net/softnet_stat)")

  read -r a b c <<< "$tx0"; local tx_p0="$a" tx_d0="$b" tx_e0="$c"
  read -r a b c <<< "$tx1"; local tx_p1="$a" tx_d1="$b" tx_e1="$c"
  local rp0 rd0 re0 rm0 rn0 rq0 rqn0 rp1 rd1 re1 rm1 rn1 rq1 rqn1
  # shellcheck disable=SC2034  # rqn0 is the pre-run queue count; only the post-run one is reported
  read -r rp0 rd0 re0 rm0 rn0 rq0 rqn0 <<< "$rx0"
  read -r rp1 rd1 re1 rm1 rn1 rq1 rqn1 <<< "$rx1"

  RUN_TX_PACKETS=$(delta "$tx_p1" "$tx_p0")
  RUN_TX_DROPPED=$(delta "$tx_d1" "$tx_d0")
  RUN_TX_ERRORS=$(delta "$tx_e1" "$tx_e0")
  RUN_RX_PACKETS=$(delta "$rp1" "$rp0")
  RUN_RX_DROPPED=$(delta "$rd1" "$rd0")
  RUN_RX_ERRORS=$(delta "$re1" "$re0")
  RUN_RX_MISSED=$(delta "$rm1" "$rm0")
  RUN_RX_NOHANDLER=$(delta "$rn1" "$rn0")
  RUN_RX_QDROPS="$(delta "$rq1" "$rq0") $rqn1"
  RUN_SOFTNET=$(delta "$sn1" "$sn0")

  read -r tok tfail tpps <<< "$(parse_tcpreplay_stats "$tstats")"
  RUN_TCP_OK="$tok"; RUN_TCP_FAILED="$tfail"; RUN_TCP_PPS="$tpps"
  RUN_TCP_RSS=$(tail -1 "$RUNDIR/tcpreplay.rss" 2>/dev/null)
  is_num "$RUN_TCP_RSS" ||
    RUN_TCP_RSS=$(unavailable "GNU time wrote no %M line for tcpreplay (see bench/live-capture.sh:1)")
  RUN_TCP_CPU=$(unavailable "tcpreplay exits before /proc/<pid>/stat can be read; only peak RSS survives via GNU time (see bench/live-capture.sh:1)")

  RUN_PACKETS_TOTAL=$(parse_metrics "$body" sipnab_capture_packets_total)
  RUN_KERNEL_DROPPED=$(parse_metrics "$body" sipnab_capture_kernel_dropped_packets_total)
  RUN_IFACE_DROPPED=$(parse_metrics "$body" sipnab_capture_interface_dropped_packets_total)
  RUN_INVALID_TS=$(parse_metrics "$body" sipnab_capture_invalid_timestamps_total)
  RUN_DEGRADED=$(parse_metrics "$body" sipnab_capture_quality_degraded)
  RUN_QUEUE_DEPTH=$(queue_depth_cell)
  RUN_BACKPRESSURE=$(backpressure_cell)

  RUN_SCRAPE_WINDOW=$(scrape_window_valid "$t_end" "$t_scrape" "$(date +%s.%N)")
  RUN_MEDIA_PCT=$(media_achievement_pct "$packets" "$RUN_TCP_PPS" "$sigus" "$medus")

  # tcpreplay saturating a core while sipnab does not is the third, independent
  # saturation trigger. Ticks are not comparable across differing run lengths,
  # so this is left explicitly unknown rather than guessed.
  RUN_CPU_BOUND=unknown

  if [ "$RUN_SCRAPE_WINDOW" != valid ]; then
    RUN_PACKETS_TOTAL=$(invalid "reading taken outside the quiesce window: $RUN_SCRAPE_WINDOW")
  fi

  RUN_VERDICT=$(classify_row "$RUN_TCP_OK" "$RUN_TCP_FAILED" "$RUN_TX_PACKETS" "$RUN_RX_PACKETS" \
    "$RUN_PACKETS_TOTAL" "$RUN_KERNEL_DROPPED" "$RUN_IFACE_DROPPED" "$RUN_DEGRADED" \
    "$RUN_MEDIA_PCT" "$RUN_CPU_BOUND")
}

rung_row_block() { # <phase-id> <axis> <C> <verdict> <plan text>
  local phase="$1" axis="$2" c="$3" verdict="$4" plan="$5"
  printf 'rung %s   verdict %s\n' "$phase" "$verdict"
  printf '%s\n' "$plan" | sed 's/^/  /'
  printf '  %s\n' "$(row_caveat "$axis")"
  printf 'plane A, offered\n'
  printf '  tcpreplay successful  %s\n' "$RUN_TCP_OK"
  printf '  tcpreplay failed      %s\n' "$RUN_TCP_FAILED"
  printf '  tcpreplay rated       %s pps\n' "$RUN_TCP_PPS"
  printf '  offered media rate    %s pps (%s Mbps) -- the media phase only; carrier.py replays signaling at a fixed 1000 pps (carrier.py:64)\n' \
    "$(rung_rate "$c")" "$(rung_mbps "$c")"
  printf '  media achievement     %s %% of the offered media rate\n' "$RUN_MEDIA_PCT"
  printf '  %s tx_packets      %s\n' "$VETH_TX" "$RUN_TX_PACKETS"
  printf '  %s tx_dropped      %s\n' "$VETH_TX" "$RUN_TX_DROPPED"
  printf '  %s tx_errors       %s\n' "$VETH_TX" "$RUN_TX_ERRORS"
  delivered_plane_block "$RUN_RX_PACKETS" "$RUN_RX_DROPPED" "$RUN_RX_ERRORS" \
    "$RUN_RX_MISSED" "$RUN_RX_NOHANDLER" "$RUN_RX_QDROPS" "$RUN_SOFTNET"
  printf 'plane C, what sipnab lost (never summed with A or B)\n'
  printf '  packets_total       %s\n' "$(render_sipnab_cell "$RUN_PACKETS_TOTAL" "$verdict")"
  printf '  kernel_dropped      %s\n' "$(render_sipnab_cell "$RUN_KERNEL_DROPPED" "$verdict")"
  printf '  interface_dropped   %s\n' "$(render_sipnab_cell "$RUN_IFACE_DROPPED" "$verdict")"
  printf '  invalid_timestamps  %s\n' "$(render_sipnab_cell "$RUN_INVALID_TS" "$verdict")"
  printf '  quality_degraded    %s\n' "$(render_sipnab_cell "$RUN_DEGRADED" "$verdict")"
  printf '  queue_depth         %s\n' "$RUN_QUEUE_DEPTH"
  printf '  backpressure_blocks %s\n' "$RUN_BACKPRESSURE"
  printf '  scrape window       %s\n' "$RUN_SCRAPE_WINDOW"
  printf '  1 Hz samples        %s   (liveness of the measurement plane; the READING above is the quiesce scrape, not a sample)\n' "$RUN_SCRAPE_SAMPLES"
  printf '  sipnab exit         %s\n' "$RUN_EXIT_MODE"
  printf 'identities, printed whether they hold or not\n'
  identity_lines "$RUN_TCP_OK" "$RUN_TX_PACKETS" "$RUN_RX_PACKETS" \
    "$RUN_PACKETS_TOTAL" "$RUN_KERNEL_DROPPED" "$RUN_IFACE_DROPPED"
  resource_block "$RUN_SIPNAB_RSS" "$RUN_TCP_RSS" "$RUN_SIPNAB_CPU" "$RUN_TCP_CPU"
}

# One phase = one corpus, one warm-up, OPT_RUNS timed runs, one row.
run_phase() { # <phase-id> <axis> <C> <rtp> <call-ids> <stream-pairs> <buffer> <budget> <report>
  local phase="$1" axis="$2" c="$3" rtp="$4" cid="$5" sp="$6" buf="$7" budget="$8" report="$9"
  local pairs bpf span sig med packets sipn rtpn bytes dur plan v i
  local verdicts="" rates=() kdrops=() idrops=() rsss=()

  waves_are_full "$c" "$c" >/dev/null
  require_even_rtp "$rtp" >/dev/null
  pairs=$(effective_pairs "$sp" "$c")
  bpf=$(bpf_for "$pairs")
  span=$(corpus_span_usec "$c" "$c" "$rtp")
  sig=$(sig_span_usec "$c")
  med=$(media_span_usec "$c" "$c" "$rtp")
  packets=$(corpus_packets "$c" "$rtp")
  sipn=$(corpus_sip_records "$c")
  rtpn=$(corpus_rtp_records "$c" "$rtp")
  bytes=$(corpus_bytes "$sipn" "$rtpn" "$SIP_RECORD_BYTES_EST")
  ram_guard "$bytes" "$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)" >/dev/null
  dur=$(sipnab_duration_for "$span" 20)

  printf '  generating %s: %s packets, ~%s B estimated, MemAvailable %s kB\n' \
    "$phase" "$packets" "$bytes" "$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)" >&2
  generate_corpus "$RUNDIR" "$c" "$rtp" "$cid" "$sp" "$c"

  plan=$(printf 'axis %s, C=%s, --rtp-per-call %s, --call-ids %s, --stream-pairs %s (effective %s)\n' \
                "$axis" "$c" "$rtp" "$cid" "$sp" "$pairs"
         printf 'corpus %s packets (%s SIP, %s RTP), %s B on disk, estimate %s B, sha256 %s\n' \
                "$packets" "$sipn" "$rtpn" "$CORPUS_REAL_BYTES" "$bytes" "$CORPUS_SHA"
         printf 'corpus argv: %s\n' "$CORPUS_ARGV"
         printf 'generation took %s s (carrier.py is pure-Python struct.pack per packet)\n' "$CORPUS_GEN_S"
         printf 'span %s us (signaling %s us at a fixed 1000 pps, media %s us), sipnab --duration %ss\n' \
                "$span" "$sig" "$med" "$dur"
         printf 'BPF (mandatory, trailing positional): %s\n' "$bpf"
         printf 'method: one discarded warm-up, %s timed runs; rates are the median, drops and peak RSS the maximum\n' "$OPT_RUNS")

  run_once "$phase-warmup" "$bpf" "$dur" "$buf" "$budget" "$report" "$packets" "$sig" "$med"

  i=0
  while [ "$i" -lt "$OPT_RUNS" ]; do
    i=$((i + 1))
    run_once "$phase-$i" "$bpf" "$dur" "$buf" "$budget" "$report" "$packets" "$sig" "$med"
    verdicts="$verdicts $RUN_VERDICT"
    rates+=("$RUN_TCP_PPS")
    if is_num "$RUN_KERNEL_DROPPED"; then kdrops+=("$RUN_KERNEL_DROPPED"); fi
    if is_num "$RUN_IFACE_DROPPED"; then idrops+=("$RUN_IFACE_DROPPED"); fi
    if is_num "$RUN_SIPNAB_RSS"; then rsss+=("$RUN_SIPNAB_RSS"); fi
  done

  v=$(worst_verdict "$verdicts")
  # The last timed run's cells are what the block prints; the aggregates are
  # named beside them so nobody mistakes one for the other.
  PHASE_VERDICT=$(emit_rung_row "$v" "$(rung_row_block "$phase" "$axis" "$c" "$v" "$plan")
aggregates across the timed runs, statistic named per column
  tcpreplay rated     $(stat_median "${rates[@]}") pps   [$(stat_label rate "$OPT_RUNS")]
  kernel_dropped      $(stat_max ${kdrops[@]+"${kdrops[@]}"})   [$(stat_label drop "$OPT_RUNS")]
  interface_dropped   $(stat_max ${idrops[@]+"${idrops[@]}"})   [$(stat_label drop "$OPT_RUNS")]
  sipnab peak RSS     $(stat_max ${rsss[@]+"${rsss[@]}"}) kB   [$(stat_label rss "$OPT_RUNS")]
  per-run verdicts   $verdicts   -> row takes the worst
") || exit $?
  record ""
}

main() {
  SELF_TEST=0
  parse_args "$@"

  if [ "$SELF_TEST" = 1 ]; then
    run_self_test
    exit $?
  fi

  [ "$(id -u)" = 0 ] || die_code "$EXIT_PREFLIGHT" \
    "this harness needs root: it creates a network namespace and a veth pair, and opens a live capture."
  [ -n "$OPT_BIN" ] || die_code "$EXIT_USAGE" "--bin <sipnab> is required (run --self-test for the unprivileged gate)"
  [ -x "$OPT_BIN" ] || die_code "$EXIT_USAGE" "not executable: $OPT_BIN"

  local t
  for t in ip tcpreplay ethtool taskset curl python3 sha256sum /usr/bin/time; do
    command -v "$t" >/dev/null 2>&1 || die_code "$EXIT_PREFLIGHT" "missing tool: $t"
  done
  probe_tcpreplay_flags "$(tcpreplay --help 2>&1)" >/dev/null
  probe_sipnab_flags "$("$OPT_BIN" --help 2>&1)" >/dev/null

  local ncpu governor load1 sets
  ncpu=$(nproc)
  governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || printf 'unavailable(no cpufreq on this host; see bench/live-capture.sh:1)\n')
  load1=$(parse_loadavg "$(cat /proc/loadavg)")
  loadavg_gate "$load1" "$ncpu" >/dev/null
  sets=$(cpu_sets "$ncpu")
  read -r CPUS_TCPREPLAY CPUS_SIPNAB CPUS_SAMPLER <<< "$sets"
  cpu_sets_disjoint "$CPUS_TCPREPLAY" "$CPUS_SIPNAB" "$CPUS_SAMPLER" \
    || die_code "$EXIT_PREFLIGHT" "the taskset assignments are not pairwise disjoint: $sets"
  [ -r "$CARRIER" ] || die_code "$EXIT_PREFLIGHT" "cannot read the corpus generator: $CARRIER"

  RUNDIR=$(mktemp -d /tmp/sipnab-live-capture.XXXXXX) || die "mktemp failed"
  trap cleanup EXIT INT TERM
  RECORD_FILE="$RUNDIR/record.txt"
  : > "$RECORD_FILE"
  # Pinned so no stray ~/.config/sipnab/sipnab.toml rewrites the very knobs
  # under measurement (src/config.rs:251-269 carries buffer and buffer_budget_mb;
  # the explicit path short-circuits the search at src/config.rs:660-673).
  : > "$RUNDIR/empty.toml"
  unset SIPNAB_CONFIG

  record "sipnab live-capture measurement"
  record "  binary   $("$OPT_BIN" --version 2>&1 | head -1)"
  record "  host     $(uname -sm), $ncpu cores"
  record "  date     $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  record ""
  record_raw "$(env_block "$governor" "$load1" "$ncpu" "$sets")"
  record ""
  record_raw "$(process_per_rung_note)"

  setup_namespace
  record ""
  record_raw "$(isolation_block "$(ip -n "$NS" link 2>/dev/null)" "$(ip -n "$NS" route show 2>/dev/null)")"

  # Phases, in the mandated order: canary, then calibration at the TOP rung,
  # then the headline, then the ladder ascending. No rung may precede a control.
  local rungs top phases verdicts="" v bad r
  for r in $OPT_RUNGS; do ladder_member "$r" >/dev/null; done
  # shellcheck disable=SC2086
  rungs=$(printf '%s\n' $OPT_RUNGS | sort -n | uniq | tr '\n' ' ')
  # shellcheck disable=SC2086
  top=$(printf '%s\n' $rungs | sort -n | tail -1)
  phases=$(phase_sequence "$rungs")
  record ""
  record "phase order (controls first, rungs ascending):"
  record_raw "$(printf '%s\n' "$phases" | sed 's/^/  /')"
  record ""

  # ── CONTROL 1, observability canary ─────────────────────────────────────
  # A small corpus at a low rate. packets_total must equal it EXACTLY, or the
  # capture point is blind and every zero below would be silence, not a reading.
  local canary_calls=100 canary_rtp=20 canary_packets
  canary_packets=$(corpus_packets "$canary_calls" "$canary_rtp")
  generate_corpus "$RUNDIR" "$canary_calls" "$canary_rtp" 0 0 "$canary_calls"
  run_once canary "$(bpf_for "$canary_calls")" \
    "$(sipnab_duration_for "$(corpus_span_usec "$canary_calls" "$canary_calls" "$canary_rtp")" 20)" \
    "" "" 0 "$canary_packets" "$(sig_span_usec "$canary_calls")" \
    "$(media_span_usec "$canary_calls" "$canary_calls" "$canary_rtp")" >/dev/null
  record "CONTROL 1, observability canary"
  record_raw "  $(canary_check "$canary_packets" "$RUN_PACKETS_TOTAL" 1)"
  record "  corpus argv: $CORPUS_ARGV"
  record "  sha256 $CORPUS_SHA"
  record "  A veth with the link down, a wrong -d, or a scraper outside the namespace would all"
  record "  report packets_total 0 and kernel_dropped 0 -- indistinguishable from a flawless capture."
  record "  Same discipline as tests/offline_never_transmits_test.rs:36-39."
  record ""

  # ── CONTROL 2, drop-instrument calibration ──────────────────────────────
  local cal_rtp cal_bpf cal_dur cal_argv
  cal_rtp=$(rtp_per_call_for "$OPT_LADDER_SECONDS")
  cal_bpf=$(bpf_for "$(effective_pairs 100 "$top")")
  cal_dur=$(sipnab_duration_for "$(corpus_span_usec "$top" "$top" "$cal_rtp")" 20)
  ram_guard "$(corpus_bytes "$(corpus_sip_records "$top")" "$(corpus_rtp_records "$top" "$cal_rtp")" "$SIP_RECORD_BYTES_EST")" \
    "$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)" >/dev/null
  generate_corpus "$RUNDIR" "$top" "$cal_rtp" 100 100 "$top"
  run_once calibration "$cal_bpf" "$cal_dur" 2 2 0 \
    "$(corpus_packets "$top" "$cal_rtp")" "$(sig_span_usec "$top")" \
    "$(media_span_usec "$top" "$top" "$cal_rtp")" >/dev/null
  cal_argv=$(argv_sipnab "$VETH_RX" "$cal_dur" "$API_ADDR" "$cal_bpf" "$RUNDIR/empty.toml" 2 2 0)
  calibration_check "$RUN_DEGRADED" "$RUN_KERNEL_DROPPED" >/dev/null
  record_raw "$(calibration_block "$cal_argv" "$RUN_DEGRADED" "$RUN_KERNEL_DROPPED")"
  record ""

  # ── HEADLINE: the Phase 1 item, literally ───────────────────────────────
  # 100 concurrent calls, 100 unique Call-IDs, 200 streams, 60 s of media.
  if [ "$OPT_HEADLINE" = 1 ]; then
    run_phase headline headline 100 "$(rtp_per_call_for "$(duration_policy headline "$OPT_LADDER_SECONDS")")" 0 0 "" "" 1
    verdicts="$verdicts $PHASE_VERDICT"
  fi

  # ── LADDER: bounded pools, so state is held constant while pps varies ────
  if [ "$OPT_LADDER" = 1 ]; then
    for r in $rungs; do
      run_phase "ladder:C=$r" ladder "$r" \
        "$(rtp_per_call_for "$(duration_policy "ladder:C=$r" "$OPT_LADDER_SECONDS")")" 100 100 "" "" 0
      verdicts="$verdicts $PHASE_VERDICT"
    done
  fi

  record_raw "$(outcome_summary "$verdicts")"

  bad=$(forbidden_phrase_scan "$(cat "$RECORD_FILE")")
  [ -z "$bad" ] || die_code "$EXIT_PREFLIGHT" \
    "the record contains a forbidden claim -- '$bad'. 1 Gbps is C ~ 5841, which is not a valid rung; the ladder straddles the Phase 2 trigger at 856 and 1712 Mbps and never hits it."

  cat "$RECORD_FILE"
  exit "$(outcome_exit_code "$verdicts")"
}

main "$@"
