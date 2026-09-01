# rtpproxy media relay -- the SECOND anchor, so "swap the relay" is a thing the
# harness can actually do rather than a claim about a variable.
#
# Alpine, not the trixie base every other image here uses, and that is a
# measured constraint rather than a preference: `rtpproxy` is not in Debian
# trixie at all (`apt-cache search rtpproxy` on the pinned base returns
# nothing) and `asterisk` has no installation candidate there either. Alpine
# 3.22 carries rtpproxy for aarch64, which is what this harness runs on.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN apk add --no-cache rtpproxy iproute2
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
