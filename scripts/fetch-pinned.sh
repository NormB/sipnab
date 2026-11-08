#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# fetch-pinned.sh: put the pinned bytes of one file at a destination.
#
#   fetch-pinned.sh --url URL --sha256 HEX --dest FILE
#                   [--budget S] [--first-delay S] [--max-delay S]
#                   [--attempt-timeout S] [--connect-timeout S]
#   fetch-pinned.sh --print-schedule [--budget S] [--first-delay S] [--max-delay S]
#
# THE ONE RULE (CI-TOOL-DOWNLOAD-RESILIENCE). Every pinned tool archive CI
# installs from a GitHub release goes through this script, either through
# .github/actions/pinned-download (which restores and saves the actions cache
# around it) or, in release.yml, directly. tests/workflow_supply_chain_test.rs
# fails a workflow step that downloads a release asset any other way.
#
# On 2026-11-08 github.com answered release downloads with HTTP 504 from at
# least 08:57Z to at least 09:48Z. Each install step was one
# `curl --retry 5 --retry-delay 5`, about 25 s of retries, so main's Pages
# deploy and three jobs of two pull requests failed on the first minute of an
# outage of most of an hour.
#
# What it does, in order:
#
# 1. A file already at FILE (a restored cache entry) is hashed. If it matches
#    HEX it is used and nothing is fetched. If it does not, it is deleted with
#    a warning and treated as a miss: a cache entry is data another run wrote,
#    and it is trusted no more than a download.
# 2. On a miss, URL is fetched into a temporary file beside FILE. HTTP 408,
#    429 and 5xx, timeouts, refused or reset connections and transfers cut
#    short are retried after a delay that starts at --first-delay and doubles
#    up to --max-delay. A retry is made only while the time spent so far plus
#    the next delay stays within --budget. Each attempt is bounded by
#    --attempt-timeout, so the worst case is about budget + attempt-timeout.
# 3. The downloaded bytes are hashed. A match is moved to FILE; anything else
#    is deleted, and FILE is never left holding unverified bytes.
#
# Exit status:
#   0  FILE holds the pinned bytes
#   1  every attempt failed transiently: a re-run may pass
#   2  the arguments are wrong
#   3  the bytes served do not match HEX: do not re-run, check the pin
#   4  a permanent refusal (HTTP 4xx other than 408 and 429, a missing file,
#      an unsupported URL): fix the URL or the pin
#
# Times are seconds with up to three decimals. The defaults allow 8 attempts,
# 5, 10, 20, 40, 60, 60 and 60 s apart (255 s of waiting, inside 300 s).
# Runs under bash 3.2 (macOS) as well as bash 5: no associative arrays, and no
# expansion of an empty array. curl sends its default User-Agent, which names
# curl and its version and nothing else.
# Tested by scripts/tests/test_fetch_pinned.py against a local HTTP server.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: fetch-pinned.sh --url URL --sha256 HEX --dest FILE
                       [--budget S] [--first-delay S] [--max-delay S]
                       [--attempt-timeout S] [--connect-timeout S]
       fetch-pinned.sh --print-schedule [--budget S] [--first-delay S] [--max-delay S]
EOF
}

die_usage() {
  echo "::error::fetch-pinned: $*" >&2
  usage >&2
  exit 2
}

# Seconds with up to three decimals to whole milliseconds, or fail.
to_ms() {
  local v=$1 int frac=""
  case $v in
    '' | . | *[!0-9.]* | *.*.*) return 1 ;;
  esac
  int=${v%%.*}
  if [ "$int" != "$v" ]; then frac=${v#*.}; fi
  [ ${#frac} -le 3 ] || return 1
  while [ ${#frac} -lt 3 ]; do frac="${frac}0"; done
  [ -n "$int" ] || int=0
  echo $((10#$int * 1000 + 10#$frac))
}

# Whole milliseconds to seconds, with no trailing zeros: 50 -> 0.05.
from_ms() {
  local s=$(($1 / 1000)) f
  f=$(printf '%03d' $(($1 % 1000)))
  while [ -n "$f" ] && [ "${f%0}" != "$f" ]; do f=${f%0}; done
  if [ -n "$f" ]; then echo "$s.$f"; else echo "$s"; fi
}

# The delays before each retry, in ms, one per line: doubling from FIRST,
# capped at CAP, and stopping before their sum would pass BUDGET.
schedule_ms() {
  local d=$1 cap=$2 budget=$3 total=0
  if [ "$d" -gt "$cap" ]; then d=$cap; fi
  while [ $((total + d)) -le "$budget" ]; do
    echo "$d"
    total=$((total + d))
    d=$((d * 2))
    if [ "$d" -gt "$cap" ]; then d=$cap; fi
  done
}

# Milliseconds since the epoch; whole seconds where date has no %N (macOS).
now_ms() {
  local t
  t=$(date +%s%3N 2>/dev/null || true)
  case $t in
    '' | *[!0-9]*) echo $(($(date +%s) * 1000)) ;;
    *) echo "$t" ;;
  esac
}

# One bounded attempt. Prints the HTTP status; the bytes go to $tmp. No
# --retry: the loop below owns the retries and the budget.
fetch_once() {
  curl --silent --show-error --location --fail \
    --proto '=https,http,file' --proto-redir '=https,http' \
    --connect-timeout "$connect_timeout" --max-time "$attempt_timeout" \
    --write-out '%{http_code}' --output "$tmp" -- "$url"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum <"$1" | cut -d' ' -f1
  else
    shasum -a 256 <"$1" | cut -d' ' -f1
  fi
}

url="" sha="" dest="" print_schedule=0
budget=300 first_delay=5 max_delay=60 attempt_timeout=180 connect_timeout=20
while [ $# -gt 0 ]; do
  opt=$1
  case $opt in
    --print-schedule) print_schedule=1; shift; continue ;;
    --url | --sha256 | --dest | --budget | --first-delay | --max-delay | --attempt-timeout | --connect-timeout)
      [ $# -ge 2 ] || die_usage "$opt needs a value"
      ;;
    *) die_usage "unknown option $opt" ;;
  esac
  case $opt in
    --url) url=$2 ;;
    --sha256) sha=$2 ;;
    --dest) dest=$2 ;;
    --budget) budget=$2 ;;
    --first-delay) first_delay=$2 ;;
    --max-delay) max_delay=$2 ;;
    --attempt-timeout) attempt_timeout=$2 ;;
    --connect-timeout) connect_timeout=$2 ;;
  esac
  shift 2
done

budget_ms=$(to_ms "$budget") || die_usage "--budget '$budget' is not a number of seconds"
first_ms=$(to_ms "$first_delay") || die_usage "--first-delay '$first_delay' is not a number of seconds"
cap_ms=$(to_ms "$max_delay") || die_usage "--max-delay '$max_delay' is not a number of seconds"
to_ms "$attempt_timeout" >/dev/null || die_usage "--attempt-timeout '$attempt_timeout' is not a number of seconds"
to_ms "$connect_timeout" >/dev/null || die_usage "--connect-timeout '$connect_timeout' is not a number of seconds"
[ "$first_ms" -gt 0 ] || die_usage "--first-delay must be more than 0"
[ "$cap_ms" -gt 0 ] || die_usage "--max-delay must be more than 0"
[ "$(to_ms "$attempt_timeout")" -gt 0 ] || die_usage "--attempt-timeout must be more than 0"
[ "$(to_ms "$connect_timeout")" -gt 0 ] || die_usage "--connect-timeout must be more than 0"

if [ "$print_schedule" = 1 ]; then
  schedule_ms "$first_ms" "$cap_ms" "$budget_ms" | while read -r d; do from_ms "$d"; done
  exit 0
fi

[ -n "$url" ] || die_usage "--url is required"
[ -n "$sha" ] || die_usage "--sha256 is required"
[ -n "$dest" ] || die_usage "--dest is required"
case $sha in
  *[!0-9a-f]*) die_usage "--sha256 must be 64 lowercase hex digits, not '$sha'" ;;
esac
[ ${#sha} -eq 64 ] || die_usage "--sha256 must be 64 lowercase hex digits; '$sha' has ${#sha}"
[ ! -d "$dest" ] || die_usage "--dest '$dest' is a directory; name the file"

dir=$(dirname -- "$dest")
mkdir -p -- "$dir"

# 1. A restored cache entry is verified before it is used.
if [ -e "$dest" ]; then
  actual=$(sha256_of "$dest")
  if [ "$actual" = "$sha" ]; then
    echo "fetch-pinned: $dest already holds the pinned bytes (restored from the cache); sha256 verified"
    exit 0
  fi
  echo "::warning::fetch-pinned: $dest does not match the pin (sha256 $actual, pinned $sha); deleting it and fetching $url. If it came from the actions cache, delete that entry: an entry is never overwritten." >&2
  rm -f -- "$dest"
fi

# 2. Fetch, retrying transient failures inside the budget.
tmp=$(mktemp "$dir/.fetch-pinned.XXXXXX")
err=$(mktemp "$dir/.fetch-pinned-err.XXXXXX")
trap 'rm -f -- "$tmp" "$err"' EXIT

delays=()
while read -r d; do delays+=("$d"); done < <(schedule_ms "$first_ms" "$cap_ms" "$budget_ms")

start=$(now_ms)
attempt=0
next=0
last=""
while :; do
  attempt=$((attempt + 1))
  rc=0
  code=$(fetch_once 2>"$err") || rc=$?
  if [ "$rc" = 0 ]; then
    break
  fi
  msg=$(tr '\n' ' ' <"$err" | sed 's/ *$//')
  case $rc in
    22)
      last="HTTP $code"
      case $code in
        408 | 429 | 5??) ;;
        *)
          echo "::error::fetch-pinned: $url answered $last on attempt $attempt. A permanent refusal, not an outage: check the URL and the pinned version." >&2
          exit 4
          ;;
      esac
      ;;
    1 | 3 | 37)
      echo "::error::fetch-pinned: $url cannot be fetched (curl exit $rc: $msg). A permanent failure, not an outage: check the URL." >&2
      exit 4
      ;;
    28) last="curl exit 28, timed out: $msg" ;;
    *) last="curl exit $rc: $msg" ;;
  esac
  elapsed=$(($(now_ms) - start))
  if [ "$next" -ge ${#delays[@]} ] || [ $((elapsed + delays[next])) -gt "$budget_ms" ]; then
    noun=attempts
    if [ "$attempt" = 1 ]; then noun=attempt; fi
    echo "::error::fetch-pinned: $url failed after $attempt $noun over $(from_ms "$elapsed") s (budget $(from_ms "$budget_ms") s); the last was $last. A transient outage, not a build failure: re-run the job once the host answers." >&2
    exit 1
  fi
  d=$(from_ms "${delays[next]}")
  next=$((next + 1))
  echo "::warning::fetch-pinned: attempt $attempt for $url failed ($last); retrying in $d s" >&2
  sleep "$d"
done

# 3. Only verified bytes reach the destination.
actual=$(sha256_of "$tmp")
if [ "$actual" != "$sha" ]; then
  size=$(wc -c <"$tmp" | tr -d ' ')
  echo "::error::fetch-pinned: $url served $size bytes with sha256 $actual, not the pinned $sha. The archive is truncated or substituted: do NOT re-run; check the pin against the release." >&2
  exit 3
fi
chmod 0644 "$tmp"
mv -f -- "$tmp" "$dest"
echo "fetch-pinned: downloaded $url on attempt $attempt to $dest; sha256 verified"
