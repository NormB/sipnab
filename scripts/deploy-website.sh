#!/usr/bin/env bash
# Build the sipnab Zola site and rsync it to a static-hosting target.
#
# This script is environment-agnostic. The deploy target is passed via
# environment variables so the same script works for any operator's
# infrastructure (a single host, a CDN edge, a jumpbox-fronted nginx,
# etc.). Save your specific values in a `.envrc` (direnv) or shell
# function — do not commit them.
#
# Required:
#   DEPLOY_HOST   SSH target the rsync runs against, e.g. `user@host`
#                 or an SSH config alias. Must be a host where the
#                 logged-in user has sudo (rsync is invoked via
#                 `--rsync-path="sudo rsync"` so files land owned by
#                 root and the chown step that follows is privileged).
#
# Optional:
#   DEPLOY_PATH   Remote directory served by nginx/Caddy/etc.
#                 Default: /var/www/sipnab
#   DEPLOY_OWNER  user:group for the deployed files.
#                 Default: www-data:www-data
#   ZOLA_BIN      Path to the zola binary. Default: zola (PATH lookup).
#   SKIP_BUILD    Set to any non-empty value to skip `zola build` and
#                 sync the existing website/public/ directory as-is.
#
# Example:
#   DEPLOY_HOST=deploy@web01.example.com scripts/deploy-website.sh
#   DEPLOY_HOST=web01 DEPLOY_PATH=/srv/www/sipnab scripts/deploy-website.sh
#
# Exit codes:
#   0  success
#   1  missing required env / pre-flight failure
#   2  build failed
#   3  rsync failed
#   4  remote chown failed

set -euo pipefail

DEPLOY_PATH="${DEPLOY_PATH:-/var/www/sipnab}"
DEPLOY_OWNER="${DEPLOY_OWNER:-www-data:www-data}"
ZOLA_BIN="${ZOLA_BIN:-zola}"

if [ -z "${DEPLOY_HOST:-}" ]; then
    echo "error: DEPLOY_HOST is required (e.g. user@host)" >&2
    echo "       see comments in $0 for full options" >&2
    exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
site_root="$repo_root/website"

if [ ! -d "$site_root" ]; then
    echo "error: $site_root does not exist" >&2
    exit 1
fi

cd "$site_root"

if [ -z "${SKIP_BUILD:-}" ]; then
    if ! command -v "$ZOLA_BIN" >/dev/null 2>&1; then
        echo "error: zola not found in PATH (set ZOLA_BIN=/path/to/zola)" >&2
        exit 1
    fi
    # ---- The version is part of the build, not a detail -------------------
    #
    # This printed whatever `zola --version` said and built with it, which is
    # the same defect the Vale gate in .githooks/pre-push had: a pinned tool in
    # CI and an unpinned one locally, reported confidently either way.
    #
    # .github/workflows/pages.yml and quality.yml both pin ZOLA_VERSION and
    # verify a SHA256 before installing it, because zola's markdown renderer
    # and heading slugger change between releases -- `slug_zola` in
    # tests/link_integrity_test.rs and `zola_slug` in
    # scripts/build-site-internals.py are hand-ports of that exact algorithm,
    # and `generated_site_anchors_resolve_under_zola` is a gate on it. A deploy
    # built by a different renderer can therefore publish anchors that no gate
    # in this repository ever agreed to.
    #
    # Measured 2026-08-19 on macOS/aarch64: Homebrew ships zola 0.23.0; the
    # workflows pin 0.19.2. Four minor versions apart, and nothing said so.
    #
    # It stays a WARNING rather than a hard stop: this is an operator's deploy
    # script for their own infrastructure, not a merge gate, and refusing to
    # publish over a version skew would be the wrong trade for someone pushing
    # a hotfix. But it must not be silent, and it must name both numbers.
    #
    # `|| true` on both, and it is load-bearing under this script's
    # `set -euo pipefail`: `VAR=$(cmd)` propagates cmd's status, and with
    # pipefail a grep that matches nothing makes the whole pipeline non-zero.
    # Without it a missing pin would kill the script one line before the branch
    # written to report a missing pin. Verified 2026-08-19: the same assignment
    # against a file with no match exits 1 and never reaches the next line.
    ZOLA_HAVE=$("$ZOLA_BIN" --version 2>/dev/null | awk '{print $2}' || true)
    ZOLA_PIN=$(grep -oE "ZOLA_VERSION: '[0-9.]+'" \
        "$repo_root/.github/workflows/pages.yml" 2>/dev/null \
        | grep -oE '[0-9.]+' | head -1 || true)
    if [ -z "$ZOLA_PIN" ]; then
        echo "warning: no ZOLA_VERSION pin found in .github/workflows/pages.yml," >&2
        echo "         so this build cannot be compared against what CI publishes." >&2
    elif [ "$ZOLA_HAVE" != "$ZOLA_PIN" ]; then
        echo "warning: local zola ${ZOLA_HAVE:-unknown}, but CI publishes with ${ZOLA_PIN}." >&2
        echo "         Renderer and heading-slug behavior differ between releases, so" >&2
        echo "         this deploy may not match what the Pages workflow would produce." >&2
        echo "         Set ZOLA_BIN to a v${ZOLA_PIN} binary to publish the same bytes CI does." >&2
    fi
    echo "→ Building Zola site (zola ${ZOLA_HAVE:-unknown}, CI pins ${ZOLA_PIN:-unknown})..."
    if ! "$ZOLA_BIN" build; then
        echo "error: zola build failed" >&2
        exit 2
    fi
fi

if [ ! -d "$site_root/public" ]; then
    echo "error: $site_root/public does not exist (build skipped or failed?)" >&2
    exit 2
fi

echo "→ Syncing $site_root/public/ → $DEPLOY_HOST:$DEPLOY_PATH/"
if ! rsync -avz --delete --rsync-path="sudo rsync" \
        "$site_root/public/" "$DEPLOY_HOST:$DEPLOY_PATH/"; then
    echo "error: rsync failed" >&2
    exit 3
fi

echo "→ chown -R $DEPLOY_OWNER $DEPLOY_PATH"
if ! ssh "$DEPLOY_HOST" "sudo chown -R $DEPLOY_OWNER $DEPLOY_PATH"; then
    echo "error: remote chown failed" >&2
    exit 4
fi

echo "✓ Deployed. Verify with:"
echo "    curl -sI https://sipnab.com | grep -i last-modified"
