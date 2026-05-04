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
    echo "→ Building Zola site (zola $($ZOLA_BIN --version | awk '{print $2}'))..."
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
echo "    curl -sI https://www.sipnab.com | grep -i last-modified"
