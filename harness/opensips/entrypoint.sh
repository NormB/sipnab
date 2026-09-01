#!/bin/sh
# Render opensips.cfg from the template and launch OpenSIPS in the foreground.
set -eu

IFACE="${IFACE:-eth0}"

# Resolve this container's IP on the bridge (default to env override).
DETECTED_IP="$(ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
OPENSIPS_IP="${OPENSIPS_IP:-$DETECTED_IP}"
UAS_TARGET="${UAS_TARGET:-172.28.0.20:5060}"
RTPENGINE_SOCK="${RTPENGINE_SOCK:-udp:127.0.0.1:22222}"
RTPPROXY_SOCK="${RTPPROXY_SOCK:-udp:127.0.0.1:22223}"

# ---- Media anchor selection ------------------------------------------------
# ONE variable picks the relay. The three anchors differ in more than an
# address: module name, control-socket parameter name and teardown function
# name all change, so each is rendered as a whole statement rather than as a
# socket string dropped into a fixed call. rtpengine tears down with
# rtpengine_delete(); rtpproxy with rtpproxy_unforce() -- read from the
# module's own cmd_export table, not from a manual.
#
# `none` is a first-class value, not a failure mode: OpenSIPS loads no relay
# module and rewrites no SDP, so media flows endpoint-to-endpoint. It is the
# control the anchored runs are measured against.
MEDIA_ANCHOR="${MEDIA_ANCHOR:-rtpengine}"

case "$MEDIA_ANCHOR" in
    rtpengine)
        ANCHOR_LOADMODULE='loadmodule "rtpengine.so"'
        ANCHOR_MODPARAM="modparam(\"rtpengine\", \"rtpengine_sock\", \"${RTPENGINE_SOCK}\")"
        ANCHOR_OFFER='rtpengine_offer();'
        ANCHOR_ON_BYE='if (is_method("BYE")) { rtpengine_delete(); }'
        ANCHOR_ON_REPLY='if (has_body("application/sdp")) { rtpengine_answer(); }'
        ANCHOR_CTL="$RTPENGINE_SOCK"
        ;;
    rtpproxy)
        ANCHOR_LOADMODULE='loadmodule "rtpproxy.so"'
        ANCHOR_MODPARAM="modparam(\"rtpproxy\", \"rtpproxy_sock\", \"${RTPPROXY_SOCK}\")"
        ANCHOR_OFFER='rtpproxy_offer();'
        ANCHOR_ON_BYE='if (is_method("BYE")) { rtpproxy_unforce(); }'
        ANCHOR_ON_REPLY='if (has_body("application/sdp")) { rtpproxy_answer(); }'
        ANCHOR_CTL="$RTPPROXY_SOCK"
        ;;
    none)
        ANCHOR_LOADMODULE='# MEDIA_ANCHOR=none: no relay module loaded'
        ANCHOR_MODPARAM='# MEDIA_ANCHOR=none: no relay control socket'
        ANCHOR_OFFER='# MEDIA_ANCHOR=none: offer SDP forwarded untouched'
        ANCHOR_ON_BYE='# MEDIA_ANCHOR=none: no relay session to tear down on BYE'
        # `return;` and not a bare comment: OpenSIPS rejects an EMPTY
        # onreply_route with "invalid onreply_route statement", so the block
        # needs a real statement. `return` ends script processing for the
        # reply; tm still forwards it, SDP untouched.
        ANCHOR_ON_REPLY='return;   # MEDIA_ANCHOR=none: no SDP to rewrite'
        ANCHOR_CTL="(none)"
        ;;
    *)
        echo "FATAL: MEDIA_ANCHOR='${MEDIA_ANCHOR}' is not one of: rtpengine, rtpproxy, none" >&2
        exit 1
        ;;
esac

# Locate the installed module directory (path differs by libdir layout).
MPATH="$(dirname "$(find /usr/local/lib /usr/local/lib64 -name tm.so 2>/dev/null | head -1)")/"
if [ "$MPATH" = "./" ] || [ -z "$MPATH" ]; then
    echo "FATAL: could not locate OpenSIPS modules dir" >&2
    exit 1
fi

sed -e "s|@OPENSIPS_IP@|${OPENSIPS_IP}|g" \
    -e "s|@UAS_TARGET@|${UAS_TARGET}|g" \
    -e "s|@ANCHOR_LOADMODULE@|${ANCHOR_LOADMODULE}|g" \
    -e "s|@ANCHOR_MODPARAM@|${ANCHOR_MODPARAM}|g" \
    -e "s|@ANCHOR_OFFER@|${ANCHOR_OFFER}|g" \
    -e "s|@ANCHOR_ON_BYE@|${ANCHOR_ON_BYE}|g" \
    -e "s|@ANCHOR_ON_REPLY@|${ANCHOR_ON_REPLY}|g" \
    -e "s|@MPATH@|${MPATH}|g" \
    /etc/opensips/opensips.cfg.tmpl > /etc/opensips/opensips.cfg

echo "opensips-1: ip=${OPENSIPS_IP} uas=${UAS_TARGET} anchor=${MEDIA_ANCHOR} ctl=${ANCHOR_CTL} mpath=${MPATH}"

# A placeholder that survived rendering means the template grew a knob the
# entrypoint does not set. OpenSIPS would reject it with a parse error naming
# a line number, not a cause, so name the cause here.
#
# Comment lines are excluded, and on principle rather than to get to green: the
# parser never sees them, and the template's own header documents the
# convention with a literal "@NAME@" that this check flagged on its first run.
if grep -vE '^[[:space:]]*#' /etc/opensips/opensips.cfg | grep -q '@[A-Z_]*@'; then
    echo "FATAL: unsubstituted placeholder(s) in rendered config:" >&2
    grep -nE '@[A-Z_]*@' /etc/opensips/opensips.cfg | grep -vE ':[[:space:]]*#' >&2
    exit 1
fi

OPENSIPS_BIN="$(command -v opensips || echo /usr/local/sbin/opensips)"

# Validate config before launching (fails fast with a clear error).
"$OPENSIPS_BIN" -C -f /etc/opensips/opensips.cfg

# -D: run in the foreground with the normal worker model (stderr logging via the
# config's stderror_enabled=yes). NOT -F: in this 4.1-dev build -F busy-spins the
# attendant at ~100% CPU and never binds the SIP socket. OpenSIPS 4.1 has no -E.
exec "$OPENSIPS_BIN" -f /etc/opensips/opensips.cfg -D
