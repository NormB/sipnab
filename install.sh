#!/usr/bin/env bash
#
# Build, install, and grant live-capture capabilities to sipnab.
#
# `cargo install` has no post-install hook, so this wrapper performs the two
# steps a packaged install would: build+install the binary, then a one-time
# `setcap` (Linux only) so live capture works without sudo. Extra arguments are
# forwarded to `cargo install` (e.g. `./install.sh --features full`).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ">> cargo install --path ${here} $*"
cargo install --path "${here}" "$@"

bin="$(command -v sipnab || true)"
if [ -z "${bin}" ]; then
	echo "sipnab installed but not on PATH; ensure ~/.cargo/bin is on PATH." >&2
	exit 0
fi

case "$(uname -s)" in
Linux)
	echo ">> Granting live-capture capabilities (may prompt for sudo): ${bin}"
	# Delegate to the binary's own helper so the capability set lives in one place.
	if ! "${bin}" --setup-caps; then
		echo "Capability setup skipped/failed. Run live capture with sudo, or grant manually:" >&2
		echo "  sudo setcap cap_net_raw,cap_net_admin+ep ${bin}" >&2
	fi
	;;
*)
	echo ">> Non-Linux platform: run live capture under sudo (file capabilities unavailable)."
	;;
esac

echo ">> Installed:"
"${bin}" --version
