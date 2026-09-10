#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prove that a PUBLISHED sipnab artifact can load and attach its eBPF program.
#
# # Why this is a script and not a test
#
# `src/capture/uprobe/bpf.rs` loads an eBPF program. Loading needs privileges
# the test suite does not have and must not acquire, so the suite covers
# building the object and nothing else -- and building was never the half that
# broke. Through four releases the object built on every run, the suite was
# green, and the verifier rejected the program on every kernel that had it.
#
# So this runs out of band, by hand, on a host that has BTF and root. What it
# does NOT do is trust a build: it downloads the artifact a user would install,
# checks it against the checksum published beside it, and runs that.
#
# # The two halves
#
#   verify-bpf-load.sh              download, run, and judge
#   verify-bpf-load.sh --classify   judge text on stdin, and nothing else
#
# The second exists so the judgement is testable. Deciding whether a run
# attached is pure text handling, it is the only part a machine reads, and
# `tests/bpf_load_verification_test.rs` drives it with the real strings from a
# real attach and a real rejection. Without that split the verdict would be the
# one thing in this path nothing checks.
#
# # Usage
#
#   sudo scripts/verify-bpf-load.sh [VERSION] [TARGET]
#
# VERSION defaults to the release the website currently advertises, because
# that is the one a user installs. TARGET defaults to x86_64-unknown-linux-gnu.
# `bpf` ships on the *-linux-gnu artifacts only; a musl build refuses by name,
# which proves nothing about the kernel.
set -euo pipefail

# ── The verdict ─────────────────────────────────────────────────────────────
#
# Three outcomes, and the third is the point. "Nothing recognizable" is not a
# pass: a run that printed neither an attach nor a refusal is a run nobody can
# say anything about, and treating that as success is how a feature stays
# broken while looking exercised.
#
#   0  ATTACHED    the program loaded and attached
#   1  REFUSED     sipnab said why it could not
#   2  NO VERDICT  the output does not answer the question
classify() {
    local text
    text=$(cat)

    # Refusal first. A rejection can be followed by ordinary shutdown logging,
    # and a capture summary printed after a failure must not outvote it.
    local refusal
    refusal=$(printf '%s\n' "$text" | grep -m1 -E \
        'verifier rejected|BPF_PROG_LOAD|refus(ed|ing)|not supported|Permission denied' || true)
    if [ -n "$refusal" ]; then
        printf 'REFUSED: %s\n' "$refusal"
        return 1
    fi

    local attach
    attach=$(printf '%s\n' "$text" | grep -m1 -F 'BPF capture attached to' || true)
    if [ -n "$attach" ]; then
        printf 'ATTACHED: %s\n' "$attach"
        return 0
    fi

    printf 'NO VERDICT: the run said neither that it attached nor why it could not\n'
    return 2
}

if [ "${1:-}" = "--classify" ]; then
    classify
    exit $?
fi

# ── The run ─────────────────────────────────────────────────────────────────

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version=${1:-$(sed -n 's/^published_version = "\(.*\)"/\1/p' "$repo_root/website/config.toml")}
target=${2:-x86_64-unknown-linux-gnu}

if [ -z "$version" ]; then
    echo "could not read published_version from website/config.toml" >&2
    exit 3
fi

# Refuse early rather than produce a verdict about the wrong thing. A musl
# artifact has no `bpf` feature, so `--uprobe-backend bpf` refuses by name and
# the refusal says nothing about the kernel under test.
case "$target" in
*-linux-gnu) ;;
*)
    echo "the bpf feature ships on the *-linux-gnu artifacts only; $target would" >&2
    echo "refuse by name and prove nothing about this host" >&2
    exit 3
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "loading an eBPF program needs root (or CAP_SYS_ADMIN + CAP_PERFMON)" >&2
    exit 3
fi

if [ ! -r /sys/kernel/btf/vmlinux ]; then
    echo "this kernel has no BTF (/sys/kernel/btf/vmlinux); the bpf backend" >&2
    echo "cannot attach here and a refusal would say nothing about the object" >&2
    exit 3
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

base="https://github.com/NormB/sipnab/releases/download/v${version}"
tarball="sipnab-${version}-${target}.tar.gz"

echo "==> downloading $tarball"
curl -fsSLO "$base/$tarball"
curl -fsSLO "$base/${tarball}.sha256"

# The checksum published beside the artifact. Running an artifact without
# checking it would make this a test of whatever the network returned.
echo "==> verifying the checksum"
sha256sum -c "${tarball}.sha256"

tar xzf "$tarball"
bin="$work/sipnab-${version}-${target}/sipnab"

echo "==> $($bin --version)"
if ! "$bin" --version | grep -q 'bpf'; then
    echo "this artifact was built without the bpf feature" >&2
    exit 3
fi

# `-N` because a TUI cannot run without a terminal, and the point is the load,
# not the display. The timeout bounds a run that would otherwise capture until
# interrupted; the program has attached or failed long before it expires.
echo "==> loading and attaching (25s)"
out=$(timeout 25 "$bin" -N --uprobe-tls --uprobe-backend bpf -v 2>&1 || true)
printf '%s\n' "$out"

echo "==> verdict"
printf '%s\n' "$out" | classify
verdict=$?

if [ "$verdict" -eq 0 ]; then
    echo
    echo "Record this in docs/internals/uprobe-capture.md, section 8:"
    echo "  version $version, artifact $target, $(uname -m), kernel $(uname -r), $(date -u +%Y-%m-%d)"
fi
exit "$verdict"
