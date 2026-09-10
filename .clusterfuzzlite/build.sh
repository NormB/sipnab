#!/bin/bash -eu
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build every fuzz target. ONE build, two consumers.
#
# Runs INSIDE `gcr.io/oss-fuzz-base/base-builder-rust`, which supplies the
# instrumented toolchain, `$OUT`, and the sanitizer flags. Do not set those
# here: the builder image owns them, and a script that overrides them is
# fuzzing something other than what the runner thinks it built.
#
# # Why this is the only copy
#
# ClusterFuzzLite runs it directly, from this path in this repository. If
# sipnab is ever accepted into OSS-Fuzz, the `projects/sipnab/build.sh` in
# `google/oss-fuzz` is a two-line shim that execs this same file -- see
# `ops/oss-fuzz/`. The target list, the corpus layout and the build flags all
# change here, and a second copy in another repository would drift the first
# time a target is added, silently, because nothing compares them.
#
# # The target list is DERIVED
#
# `cargo fuzz list` reads `fuzz/Cargo.toml`, so a new `[[bin]]` is fuzzed
# without touching this script. A hardcoded list would mean a target that
# builds, passes CI, and is never fuzzed -- which looks exactly like a target
# that is fuzzed and finds nothing.

cd "$SRC/sipnab/fuzz"

# `-O` for optimized targets, `--debug-assertions` because a panic OSS-Fuzz can
# report is worth more than the cycles: an overflow that wraps silently in
# release is a bug nobody sees.
cargo fuzz build -O --debug-assertions

host="$(rustc -vV | sed -n 's|^host: ||p')"
target_dir="$SRC/sipnab/fuzz/target/$host/release"

# The runner image is not the builder image.
#
# `bad_build_check` runs every target inside `gcr.io/oss-fuzz-base/base-runner`,
# which has none of the packages installed above. sipnab's fuzz targets link
# libpcap through the `native` feature that `hep` requires, so all eighteen
# came back as "error while loading shared libraries: libpcap.so.0.8" --- built,
# copied, and unable to start anywhere but the machine that built them.
#
# The fix OSS-Fuzz documents is to ship the libraries beside the binaries and
# point the loader at them with an rpath relative to the executable. `$ORIGIN`
# rather than an absolute path because the checker MOVES `$OUT` somewhere else
# before running anything, precisely to catch a build that hardcoded a path.
#
# What gets copied is derived from the binary, not listed here: whatever `ldd`
# resolves, minus the C runtime every runner already has. Add another system
# library to `Cargo.toml` and it ships without anyone remembering to edit this.
mkdir -p "$OUT/lib"

# The one hand-written list, and the reason it is safe to write by hand: it is
# the glibc/toolchain ABI, which is a property of the base images rather than
# of sipnab. Copying these would override the runner's own C library with the
# builder's, which is a worse failure than the one being fixed.
runtime_provided() {
    case "$1" in
    libc.so.* | libm.so.* | libdl.so.* | libpthread.so.* | librt.so.* | \
        libgcc_s.so.* | libstdc++.so.* | ld-linux*.so.* | linux-vdso.so.*)
        return 0
        ;;
    esac
    return 1
}

built=0
seeded=0
for target in $(cargo fuzz list); do
    cp "$target_dir/$target" "$OUT/"
    built=$((built + 1))

    # Read the dependencies BEFORE the rpath is set, so this sees what the
    # loader saw on this machine rather than what it will see after the patch.
    for lib in $(ldd "$OUT/$target" | awk '/=> \//{print $3}'); do
        runtime_provided "$(basename "$lib")" && continue
        cp -n "$lib" "$OUT/lib/"
    done
    patchelf --set-rpath '$ORIGIN/lib' "$OUT/$target"

    # Seed corpora, where one exists. The directory drops the `fuzz_` prefix
    # the binary carries, so `fuzz_sip_parser` seeds from `corpus/sip_parser`.
    seed="$SRC/sipnab/fuzz/corpus/${target#fuzz_}"
    if [ -d "$seed" ] && [ -n "$(ls -A "$seed" 2>/dev/null)" ]; then
        zip -j -q "$OUT/${target}_seed_corpus.zip" "$seed"/*
        seeded=$((seeded + 1))
    fi
done

# A build that produced nothing is a build that failed quietly. OSS-Fuzz would
# accept an empty $OUT and report a project that never finds anything.
if [ "$built" -eq 0 ]; then
    echo "ERROR: cargo fuzz list produced no targets; nothing was built" >&2
    exit 1
fi

# This repository tracks seed corpora, so packing none means they did not reach
# the image -- almost certainly a `.dockerignore` pattern, which excludes them
# without any error anyone would see. Fuzzing would then start from an empty
# corpus every run and look exactly like fuzzing that has found nothing yet.
if [ "$seeded" -eq 0 ]; then
    echo "ERROR: no seed corpus was packed. fuzz/corpus/ is tracked in this" >&2
    echo "       repository, so an empty result means the seeds are missing" >&2
    echo "       from the build context, not that there are none." >&2
    exit 1
fi
shipped=$(find "$OUT/lib" -type f | wc -l)
echo "built $built fuzz target(s); $seeded seeded; $shipped shared librar(y|ies) shipped"
