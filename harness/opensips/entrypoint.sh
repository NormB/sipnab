#!/bin/sh
# Render opensips.cfg from the template and launch OpenSIPS in the foreground.
set -eu

IFACE="${IFACE:-eth0}"

# Resolve this container's IP on the bridge (default to env override).
DETECTED_IP="$(ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
OPENSIPS_IP="${OPENSIPS_IP:-$DETECTED_IP}"
UAS_TARGET="${UAS_TARGET:-172.28.0.20:5060}"
RTPENGINE_SOCK="${RTPENGINE_SOCK:-udp:127.0.0.1:22222}"

# Locate the installed module directory (path differs by libdir layout).
MPATH="$(dirname "$(find /usr/local/lib /usr/local/lib64 -name tm.so 2>/dev/null | head -1)")/"
if [ "$MPATH" = "./" ] || [ -z "$MPATH" ]; then
    echo "FATAL: could not locate OpenSIPS modules dir" >&2
    exit 1
fi

sed -e "s|@OPENSIPS_IP@|${OPENSIPS_IP}|g" \
    -e "s|@UAS_TARGET@|${UAS_TARGET}|g" \
    -e "s|@RTPENGINE_SOCK@|${RTPENGINE_SOCK}|g" \
    -e "s|@MPATH@|${MPATH}|g" \
    /etc/opensips/opensips.cfg.tmpl > /etc/opensips/opensips.cfg

echo "opensips-1: ip=${OPENSIPS_IP} uas=${UAS_TARGET} rtpengine=${RTPENGINE_SOCK} mpath=${MPATH}"

OPENSIPS_BIN="$(command -v opensips || echo /usr/local/sbin/opensips)"

# Validate config before launching (fails fast with a clear error).
"$OPENSIPS_BIN" -C -f /etc/opensips/opensips.cfg

# -D: run in the foreground with the normal worker model (stderr logging via the
# config's stderror_enabled=yes). NOT -F: in this 4.1-dev build -F busy-spins the
# attendant at ~100% CPU and never binds the SIP socket. OpenSIPS 4.1 has no -E.
exec "$OPENSIPS_BIN" -f /etc/opensips/opensips.cfg -D
