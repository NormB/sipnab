# Roadmap

This page says where sipnab is going from October 2026 to September 2027:
what we intend to work on, and what we have decided not to build. It is a
statement of intent, not a promise. Plans change when a measurement or a user's
report shows we were wrong, and some of this may not happen at all. The
maintainer ([MAINTAINERS.md](MAINTAINERS.md)) edits this page as priorities
move, and what actually shipped is always in [CHANGELOG.md](CHANGELOG.md). If
something here matters to you, or something missing should be here, tell us:
[How to influence it](#how-to-influence-it) says where.

## What we intend to do

### Close the known security gaps

[Threat model: residual risks and known gaps](docs/threat-model.md#residual-risks-and-known-gaps)
lists what sipnab does not protect against today. We intend to work down that
list, starting with the network-facing ones:

- **TLS for MCP over HTTP and for the metrics endpoint.** Today neither can
  serve TLS itself, so you must keep them on loopback or put a TLS-terminating
  reverse proxy in front. The REST API already serves HTTPS.
- **Safer sandbox defaults.** The Landlock sandbox and the seccomp system-call
  filter exist but are off by default
  ([seccomp and Landlock](docs/design/syscall-sandbox.md)). We want turning
  them on to be the easy, documented path, and we change a default only once
  it works on hosts other than the one we measured it on.

### Decide what 1.0 means

sipnab is pre-1.0: the CLI, the configuration and the Rust library can change
in any release, and the changelog calls out each breaking change
([The changelog](docs/internals/build-ci-release.md#the-changelog)). Before
promising stability, we need to decide which surfaces a 1.0 would freeze and
how we would announce a later break. We intend to write that decision down
this year. We do not promise a 1.0 release by any date.

### Prove shipped features against real traffic

Tests exercise some features only against synthetic captures and simulated
peers. We intend to run them against real servers, and keep the resulting
captures and expected results as tests:

- vCon export against a running vCon server ([vCon export](docs/vcon.md)).
- TFPS, the attack-blocking tool sipnab can feed, as a real peer in CI
  ([Add TFPS to your voice stack](docs/tfps.md)).
- Mobile-core (GTP-U) decoding on real, not synthetic, headers.

### Guides for the rest of the voice stack

Step-by-step guides already cover [OpenSIPS](docs/opensips.md),
[Kamailio](docs/kamailio.md), [rtpengine](docs/rtpengine.md),
[Homer](docs/homer.md) and [Prometheus](docs/prometheus.md), each followed by
how sipnab connects to it. Next are fail2ban, SIP over TLS, the rtpproxy media
relay, and an Asterisk or a FreeSWITCH PBX behind the proxy. We run every
step of a guide on Debian 13 and Ubuntu 24.04 before it ships.

### Reading more of what a call carries

- **SIP over TLS on a live server you cannot restart.** sipnab can already
  decrypt with keys you supply ([Capture SIP over TLS](docs/tls-capture.md)).
  We intend to let it obtain those keys from the running server itself
  ([Deferred and declined work](docs/design/deferred-and-declined.md)).
- **Media relays.** Better visibility into rtpengine and rtpproxy, such as
  matching recorded streams to calls from rtpengine's own recording metadata.
- **Bad actors.** sipnab already names scanners and fraud attempts from the
  signaling. We intend to read the media as well, such as DTMF bursts or held
  silence, to tell kinds of fraud apart. sipnab recommends; you decide what to
  block.
- **Reach across nodes.** Correlate one call across several capture points
  without a central database
  ([What the position demands](docs/design/positioning.md#3-what-the-position-demands)).

### Documentation in other languages

The first step is the website in Italian, built so that later languages cost
less ([Internationalization](docs/design/i18n.md)). Translating the CLI and
TUI themselves is a separate, larger project that we have not committed to.

### Higher security-practice badges

sipnab holds the OpenSSF Best Practices
[passing badge and OpenSSF Baseline level 3](https://www.bestpractices.dev/projects/13931).
We are working toward the silver level now. Gold needs a second maintainer
who reviews changes, so it waits until someone joins. See
[MAINTAINERS.md](MAINTAINERS.md).

## What we do not intend to do

Each of these is a decision recorded in the repository, with the reasons:

- **Run as a service you have to operate.** No database, no web UI, no
  multi-user accounts, no dashboards and no alert history. Retention stays
  bounded and file-based. If a feature means you have to operate sipnab rather
  than just run it, it is out of scope
  ([What the position forbids](docs/design/positioning.md#4-what-the-position-forbids)).
- **Faster capture through DPDK, PF_RING, AF_XDP, XDP filters or forked
  workers.** We evaluated each one and declined it for a specific reason
  ([Declined capture technologies](docs/design/deferred-and-declined.md#5-declined-capture-technologies)).
- **Bundle AMR, AMR-WB or EVS audio decoders** in the released packages, for
  patent reasons
  ([Decoding AMR, AMR-WB and EVS](docs/design/deferred-and-declined.md#7-decoding-amr-amr-wb-and-evs--declined-for-the-shipped-artifacts-2026-09-09)).
- **Sign, encrypt or claim consent in vCon exports.** sipnab observes a call;
  it does not record it, so its vCons say only what it saw
  ([The five refusals, and the one role](docs/design/vcon.md#2-the-five-refusals-and-the-one-role)).
- **Choose `X-` header names for you.** Correlation headers are yours to
  configure, following [RFC 6648](https://www.rfc-editor.org/rfc/rfc6648)
  ([`xcid_headers`](docs/config-reference.md)).

## How to influence it

- **Ask or propose** in [Discussions](https://github.com/NormB/sipnab/discussions).
  A use case that a roadmap item does not cover is the most useful input we get.
- **Request a feature or report a bug** through
  [an issue](https://github.com/NormB/sipnab/issues/new/choose).
  [SUPPORT.md](SUPPORT.md) explains which channel fits which question.
- **Contribute.** Open an issue before anything structural, then follow
  [CONTRIBUTING.md](CONTRIBUTING.md).
