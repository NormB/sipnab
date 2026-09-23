#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Split the debug symbols out of a release binary, so the release can ship the
# binary stripped and publish the symbols beside it.
#
# Usage:
#   split-debuginfo.sh <binary> <output-stem>
#       ELF:    strips <binary> in place and writes <output-stem>.debug
#       Mach-O: strips nothing (rustc already did) and zips <binary>.dSYM
#               into <output-stem>.dSYM.zip
#   split-debuginfo.sh --cargo-config <target-triple>
#       prints the `cargo --config` value the build of <target-triple> needs
#       so that the symbols survive until this script runs
#
# Why: every published binary is stripped, so a crash report or a core dump
# from a user names no functions. The symbols come from the SAME compile as the
# binary and are matched to it by the GNU build ID (ELF) or the Mach-O UUID.
# A rebuild later does not reproduce them byte for byte, so they are published
# with the release or they are gone.
#
# Why rustflags and not `profile.release.strip = false`: cargo hashes the
# profile into every crate's `-C metadata`, which reseeds symbol hashes and
# perturbs codegen (8,064 bytes of `.text` on an aarch64 build, measured).
# Cargo keeps rustflags out of that hash, and rustc takes the LAST `-C strip`,
# so `-C strip=none` appended after cargo's `-C strip=symbols` produces the
# same code as today's linker-stripped build, byte for byte in `.text`.
# A RUSTFLAGS variable in the environment would override build.rustflags; the
# build would then strip at link time and the split below refuses it loudly.
#
# ELF: the build appends `-C strip=none`, so the linker keeps `.symtab` and
# the DWARF line tables `[profile.release] debug = "line-tables-only"` asks
# for. This script copies them into the .debug file (sections compressed),
# strips the binary the same way the linker would have, and adds a
# `.gnu_debuglink` naming the .debug file. The binary's code and data are
# untouched: only non-allocated sections are removed.
#
# llvm-objcopy is preferred because it reads every architecture. The host's GNU
# objcopy cannot read an aarch64 binary on an x86_64 runner, which is how the
# release's old `strip || true` step failed on every cross build unseen.
#
# Mach-O: the build keeps rustc's own strip and appends
# `-C split-debuginfo=packed`, so rustc runs dsymutil BEFORE it strips and
# leaves <binary>.dSYM beside the binary. This script checks that the bundle's
# UUID is the binary's and zips it.
#
# Exit status is non-zero, with the reason on stderr, whenever the result would
# be a symbol file that cannot be paired with the binary or has nothing in it.

set -euo pipefail

die() { printf 'split-debuginfo: %s\n' "$*" >&2; exit 1; }

cargo_config() {
  case "$1" in
    *-linux-*) printf '%s\n' 'build.rustflags=["-C","strip=none"]' ;;
    *-apple-darwin) printf '%s\n' 'build.rustflags=["-C","split-debuginfo=packed"]' ;;
    *) die "no symbol-split rule for target '$1'" ;;
  esac
}

# The objcopy to use: $OBJCOPY, else the llvm-objcopy of the active Rust
# toolchain (rustup component llvm-tools), else one on PATH, else GNU objcopy.
find_objcopy() {
  if [ -n "${OBJCOPY:-}" ]; then printf '%s\n' "$OBJCOPY"; return; fi
  local sysroot host
  if sysroot=$(rustc --print sysroot 2>/dev/null) \
     && host=$(rustc -vV 2>/dev/null | sed -n 's/^host: //p') \
     && [ -x "$sysroot/lib/rustlib/$host/bin/llvm-objcopy" ]; then
    printf '%s\n' "$sysroot/lib/rustlib/$host/bin/llvm-objcopy"; return
  fi
  if command -v llvm-objcopy >/dev/null 2>&1; then command -v llvm-objcopy; return; fi
  if command -v objcopy >/dev/null 2>&1; then command -v objcopy; return; fi
  die "no objcopy: install the llvm-tools rustup component or binutils"
}

# Lowercase hex GNU build ID of an ELF file, empty when it has none.
elf_build_id() {
  readelf -n "$1" 2>/dev/null | sed -n 's/.*Build ID: *\([0-9a-fA-F]*\).*/\1/p' | head -1 \
    | tr 'A-F' 'a-f'
}

# Section names of an ELF file, one per line.
elf_sections() {
  # stderr dropped: on a .debug file readelf complains that the NOBITS
  # .interp holds no interpreter name, which is expected there.
  readelf -S -W "$1" 2>/dev/null | sed -n 's/^ *\[ *[0-9]*\] *\([^ ]*\).*/\1/p'
}

split_elf() {
  local bin="$1" stem="$2" debug objcopy id
  debug="${stem}.debug"
  command -v readelf >/dev/null 2>&1 || die "readelf is required (binutils)"

  id=$(elf_build_id "$bin")
  [ -n "$id" ] || die "$bin has no GNU build ID, so no symbol file could ever be matched to it. Link with -Wl,--build-id (build.rs adds it for Linux)."
  elf_sections "$bin" | grep -qx '\.debug_line' \
    || die "$bin has no .debug_line line table: it was stripped at link time, so there is nothing to split. Build with --config '$(cargo_config x86_64-unknown-linux-gnu)'"
  elf_sections "$bin" | grep -qx '\.symtab' \
    || die "$bin has no .symtab; it was stripped before the split"

  objcopy=$(find_objcopy)
  mkdir -p "$(dirname "$debug")"
  rm -f "$debug"
  "$objcopy" --only-keep-debug --compress-debug-sections=zlib "$bin" "$debug"
  # Same result the linker's own strip produced before: every non-allocated
  # symbol and debug section removed. The loaded image does not change.
  "$objcopy" --strip-all "$bin"
  # After the .debug file is final: the link records its CRC.
  "$objcopy" --add-gnu-debuglink="$debug" "$bin"

  # Verify the pairing rather than trust the tools.
  local secs dsecs did
  secs=$(elf_sections "$bin")
  dsecs=$(elf_sections "$debug")
  # .debug_gdb_scripts is the one exception: rustc puts it in an ALLOCATED
  # section (a pointer to gdb's pretty-printers), so it is part of the loaded
  # image and the linker-stripped binaries always carried it too.
  if printf '%s\n' "$secs" | grep -v -x '\.debug_gdb_scripts' \
       | grep -qE '^(\.symtab|\.debug_.*)$'; then
    die "$bin still carries symbols or DWARF after the strip"
  fi
  printf '%s\n' "$secs" | grep -qx '\.note\.gnu\.build-id' \
    || die "the strip removed .note.gnu.build-id from $bin"
  printf '%s\n' "$secs" | grep -qx '\.gnu_debuglink' \
    || die "$bin has no .gnu_debuglink after the split"
  readelf -p .gnu_debuglink "$bin" | grep -qF "$(basename "$debug")" \
    || die ".gnu_debuglink in $bin does not name $(basename "$debug")"
  printf '%s\n' "$dsecs" | grep -qx '\.debug_line' \
    || die "$debug has no .debug_line line table"
  printf '%s\n' "$dsecs" | grep -qx '\.symtab' \
    || die "$debug has no .symtab"
  did=$(elf_build_id "$debug")
  [ "$did" = "$id" ] || die "build ID mismatch: $bin is $id, $debug is ${did:-none}"

  printf 'split %s: build ID %s\n' "$bin" "$id"
  printf '  shipped binary %s bytes, symbol file %s (%s bytes)\n' \
    "$(wc -c < "$bin" | tr -d ' ')" "$debug" "$(wc -c < "$debug" | tr -d ' ')"
}

# Mach-O UUID as printed by dwarfdump, uppercase with dashes.
macho_uuid() {
  dwarfdump --uuid "$1" | awk '/^UUID:/ { print $2; exit }'
}

split_macho() {
  local bin="$1" stem="$2" dsym zip bid did
  dsym="${bin}.dSYM"
  zip="${stem}.dSYM.zip"
  [ -d "$dsym" ] || die "no $dsym: rustc runs dsymutil only with split-debuginfo=packed, so build with --config '$(cargo_config aarch64-apple-darwin)'"
  command -v dwarfdump >/dev/null 2>&1 || die "dwarfdump is required (Xcode command line tools)"
  bid=$(macho_uuid "$bin")
  did=$(macho_uuid "$dsym")
  [ -n "$bid" ] || die "$bin has no LC_UUID"
  [ "$bid" = "$did" ] || die "UUID mismatch: $bin is $bid, $dsym is ${did:-none}"
  dwarfdump --debug-line "$dsym" | grep -q 'debug_line\[' \
    || die "$dsym carries no line table"
  mkdir -p "$(dirname "$zip")"
  rm -f "$zip"
  ditto -c -k --keepParent "$dsym" "$zip"
  printf 'packaged %s: UUID %s\n' "$zip" "$bid"
  printf '  shipped binary %s bytes, symbol bundle %s bytes zipped\n' \
    "$(wc -c < "$bin" | tr -d ' ')" "$(wc -c < "$zip" | tr -d ' ')"
}

main() {
  if [ "${1:-}" = "--cargo-config" ]; then
    [ $# -eq 2 ] || die "usage: $0 --cargo-config <target-triple>"
    cargo_config "$2"
    return
  fi
  [ $# -eq 2 ] || die "usage: $0 <binary> <output-stem> | --cargo-config <target-triple>"
  local bin="$1" stem="$2" magic
  [ -f "$bin" ] || die "no such binary: $bin"
  magic=$(head -c 4 "$bin" | od -An -tx1 | tr -d ' \n')
  case "$magic" in
    7f454c46) split_elf "$bin" "$stem" ;;
    cffaedfe|cefaedfe) split_macho "$bin" "$stem" ;;
    *) die "$bin is neither ELF nor Mach-O (magic $magic)" ;;
  esac
}

main "$@"
