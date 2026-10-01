#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build sipnab's release binary so that the same commit gives the same bytes,
# and check that it does.
#
# Usage:
#   reproducible-build.sh --rustflags
#       the rustc path remaps, to APPEND to RUSTFLAGS
#   reproducible-build.sh --cflags
#       the same remaps as C compiler -ffile-prefix-map flags
#   reproducible-build.sh build <target-triple> <features> [cargo|cross]
#       the release build: `cargo build --release --locked` (or `cross build`)
#       of the sipnab binary for <target-triple> with exactly <features>, with
#       the symbol-split flags and the remaps appended to RUSTFLAGS, the C
#       prefix maps appended to CFLAGS, and SOURCE_DATE_EPOCH set to the
#       commit time. release.yml builds through this.
#   reproducible-build.sh check <target-triple> <features> <workdir> [<rev>]
#       clone <rev> (default HEAD; a release tag works) into <workdir>/a and <workdir>/b, build each with `build`,
#       the second with its own CARGO_HOME, split each with the same stem, and
#       compare the stripped binaries and symbol files byte for byte. Exits
#       non-zero, with evidence, when they differ. <workdir> is deleted on
#       success; kept on failure for inspection.
#   reproducible-build.sh compare <file-a> <file-b>
#       the verdict `check` uses: exit 0 when identical, else 1 and evidence
#
# Why: OpenSSF Silver `build_repeatable` asks that the project can repeat the
# build of a release and get the same bytes. Measured 2026-09-30 on aarch64,
# two release builds of one commit in two directories differed, from four
# causes this script and build.rs now remove:
#
#   1. mimalloc's C source embeds __DATE__ and __TIME__. SOURCE_DATE_EPOCH,
#      set to the commit time, fixes both.
#   2. The eBPF object build.rs embeds keeps its debug info (the loader needs
#      the BTF), and the BTF named the checkout, `$CARGO_HOME` and the nightly's
#      rust-src by absolute path. Remapped: the remaps below reach the nested
#      eBPF build because build.rs forwards them (build_script/bpf_flags.rs).
#   3. Rust panic locations in registry crates name `$CARGO_HOME/registry/src`,
#      and every C object (ring, mimalloc) names it in its DWARF. The DWARF is
#      stripped from what ships, but the GNU build ID the linker writes into
#      the binary is a hash over the whole output, DWARF included, and the
#      symbol file's CRC is in `.gnu_debuglink`. Remapped for rustc here and
#      for the C compiler through CFLAGS.
#   4. The eBPF object's mangled symbols carried a hash of the absolute path of
#      crates/sipnab-bpf-types, because cargo hashes a path dependency outside
#      the workspace root by absolute path. bpf/Cargo.toml reaches it through
#      the symlink bpf/sipnab-bpf-types instead, inside its workspace root.
#
# Not causes, checked: sipnab's Rust code embeds no build time and no absolute
# path of its own (`file!()` in the workspace is relative); the commit hash and tag it
# embeds are the same for every build of one commit, provided the build runs
# in a git checkout of that commit (a tarball without .git embeds none).
#
# What a rebuild must hold fixed besides the source: the Rust toolchain
# (1.98.1), the eBPF nightly (bpf/rust-toolchain.toml), bpf-linker (0.11.0,
# pinned by sha256 in release.yml), and the linker and C compiler, which for
# the gnu targets come from the rust:1-bookworm image release.yml pins by
# digest. docs/internals/build-ci-release.md "Reproducible builds" says how.

set -euo pipefail

die() { printf 'reproducible-build: %s\n' "$*" >&2; exit 1; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# THE rule: every prefix that varies between builders, and the fixed name it
# is rewritten to. Both flag forms below derive from this list, so the Rust
# and C halves cannot disagree. The checkout is `pwd -P` because rustc sees
# the directory cargo runs in as the kernel reports it, symlinks resolved.
# `$CARGO_HOME` exactly as cargo will read it from the environment.
remap_pairs() {
  local cargo_home="${CARGO_HOME:-$HOME/.cargo}" p
  for p in "$ROOT" "$cargo_home"; do
    case "$p" in
      *[[:space:]]*) die "cannot remap '$p': a path containing whitespace cannot travel in RUSTFLAGS, which cargo splits on whitespace. Build from a path without it." ;;
    esac
  done
  # The checkout is listed LAST: rustc applies the last matching remap, so a
  # checkout inside CARGO_HOME (or the reverse) still gets its own name.
  printf '%s=/cargo\n' "$cargo_home"
  printf '%s=/sipnab\n' "$ROOT"
}

rustflags() {
  local pairs out="" p
  pairs=$(remap_pairs)
  for p in $pairs; do out="${out:+$out }--remap-path-prefix=$p"; done
  printf '%s\n' "$out"
}

cflags() {
  local pairs out="" p
  pairs=$(remap_pairs)
  for p in $pairs; do out="${out:+$out }-ffile-prefix-map=$p"; done
  printf '%s\n' "$out"
}

cmd_build() {
  [ $# -ge 2 ] && [ $# -le 3 ] || die "usage: $0 build <target-triple> <features> [cargo|cross]"
  local target="$1" features="$2" tool="${3:-cargo}" split remap cmap
  case "$tool" in cargo|cross) ;; *) die "unknown build tool '$tool' (cargo or cross)" ;; esac
  split=$(bash "$ROOT/scripts/split-debuginfo.sh" --rustflags "$target")
  remap=$(rustflags)
  cmap=$(cflags)
  cd "$ROOT"
  # mimalloc's options.c prints __DATE__ and __TIME__, the wall clock of the
  # compile, into the binary. GCC takes both from SOURCE_DATE_EPOCH when it is
  # set, and the commit's own time is the one every rebuild of it agrees on.
  # A value already in the environment is kept, as the convention asks.
  if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct HEAD 2>/dev/null) \
      || die "$ROOT is not a git checkout, so there is no commit time for SOURCE_DATE_EPOCH (and no commit for sipnab --version). Build from a checkout, or set SOURCE_DATE_EPOCH."
  fi
  export SOURCE_DATE_EPOCH
  # APPENDED to RUSTFLAGS, never replacing it: ci.yml sets -Dwarnings
  # workflow-wide, and a set RUSTFLAGS replaces build.rustflags entirely.
  export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }$split $remap"
  export CFLAGS="${CFLAGS:+$CFLAGS }$cmap"
  if [ "$tool" = cross ]; then
    # cross may not forward RUSTFLAGS into its container, so the split flags
    # also go as --config (see split-debuginfo.sh). The container mounts its
    # own fixed paths, so the remaps there are belt and braces.
    cross build --release --locked \
      --config "$(bash "$ROOT/scripts/split-debuginfo.sh" --cargo-config "$target")" \
      --target "$target" --no-default-features --features "$features" --bin sipnab
  else
    cargo build --release --locked \
      --target "$target" --no-default-features --features "$features" --bin sipnab
  fi
}

cmd_compare() {
  [ $# -eq 2 ] || die "usage: $0 compare <file-a> <file-b>"
  local a="$1" b="$2"
  [ -f "$a" ] || die "no such file: $a"
  [ -f "$b" ] || die "no such file: $b"
  if cmp -s "$a" "$b"; then
    printf 'identical: %s  %s\n' "$(sha256sum "$a" | cut -d' ' -f1)" "$a"
    return 0
  fi
  printf 'NOT reproducible: %s and %s differ\n' "$a" "$b"
  sha256sum "$a" "$b"
  printf 'differing bytes: %s (first ones: offset, octal a, octal b)\n' \
    "$(cmp -l "$a" "$b" | wc -l | tr -d ' ')"
  cmp -l "$a" "$b" | head -10 || true
  printf 'strings that differ (< a, > b):\n'
  diff <(strings -n 6 "$a") <(strings -n 6 "$b") | head -40 || true
  return 1
}

cmd_check() {
  [ $# -eq 3 ] || [ $# -eq 4 ] || die "usage: $0 check <target-triple> <features> <workdir> [<rev>]"
  local target="$1" features="$2" work="$3" head d ok=0 cargo_home
  [ ! -e "$work" ] || die "$work exists; give check a fresh directory"
  head=$(git -C "$ROOT" rev-parse --verify "${4:-HEAD}^{commit}")
  mkdir -p "$work"
  work=$(cd "$work" && pwd -P)
  for d in a b; do
    git clone --quiet --no-checkout "$ROOT" "$work/$d"
    git -C "$work/$d" checkout --quiet --detach "$head"
    # Different CARGO_HOMEs, so the registry path varies as well as the
    # checkout's. rustup's toolchains are found through RUSTUP_HOME and stay.
    if [ "$d" = a ]; then cargo_home="${CARGO_HOME:-$HOME/.cargo}"; else cargo_home="$work/cargo-home-b"; fi
    printf '== build %s in %s (CARGO_HOME=%s)\n' "$d" "$work/$d" "$cargo_home"
    CARGO_HOME="$cargo_home" bash "$work/$d/scripts/reproducible-build.sh" build "$target" "$features"
    mkdir -p "$work/$d-dist"
    cp "$work/$d/target/$target/release/sipnab" "$work/$d-dist/sipnab"
    # One stem for both, since the symbol file's name is in .gnu_debuglink.
    (cd "$work/$d-dist" && bash "$work/$d/scripts/split-debuginfo.sh" sipnab sipnab)
  done
  cmd_compare "$work/a-dist/sipnab" "$work/b-dist/sipnab" || ok=1
  cmd_compare "$work/a-dist/sipnab.debug" "$work/b-dist/sipnab.debug" || ok=1
  if [ "$ok" -ne 0 ]; then
    printf 'kept %s for inspection\n' "$work" >&2
    return 1
  fi
  rm -rf "$work"
}

main() {
  case "${1:-}" in
    --rustflags) [ $# -eq 1 ] || die "usage: $0 --rustflags"; rustflags ;;
    --cflags) [ $# -eq 1 ] || die "usage: $0 --cflags"; cflags ;;
    build) shift; cmd_build "$@" ;;
    check) shift; cmd_check "$@" ;;
    compare) shift; cmd_compare "$@" ;;
    *) die "usage: $0 --rustflags | --cflags | build <target> <features> [cargo|cross] | check <target> <features> <workdir> [<rev>] | compare <a> <b>" ;;
  esac
}

main "$@"
