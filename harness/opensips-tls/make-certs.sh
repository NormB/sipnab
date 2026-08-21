#!/bin/sh
# Self-signed cert for the harness TLS listener.
#
# Regenerated rather than committed: see .gitignore. Short-lived on purpose --
# this exists to make an encrypted call against a container on loopback, and
# nothing should be tempted to reuse it.
set -eu
dir="$(dirname "$0")/tls"
mkdir -p "$dir"
[ -f "$dir/cert.pem" ] && [ -f "$dir/key.pem" ] && exit 0
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$dir/key.pem" -out "$dir/cert.pem" \
    -days 30 -subj "/CN=opensips-tls-harness" 2>/dev/null
chmod 600 "$dir/key.pem"
echo "generated $dir/cert.pem"
