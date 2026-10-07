#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Print the Rust target for the OTHER Linux architecture than the given
# machine name (default: `uname -m`), so a gate can compile the code that
# `#[cfg(target_arch = ...)]` hides from the host. Exits 1, printing nothing,
# for a machine it does not know. Tested by tests/pre_push_cross_arch_test.rs.
machine="${1:-$(uname -m)}"
case "$machine" in
	aarch64 | arm64) echo "x86_64-unknown-linux-gnu" ;;
	x86_64 | amd64) echo "aarch64-unknown-linux-gnu" ;;
	*) exit 1 ;;
esac
