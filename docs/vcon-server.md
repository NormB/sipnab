# Add a vCon server to an OpenSIPS voice stack

A [vCon](glossary.md#vcon) is a JSON container that holds one conversation:

- who took part,
- the recording,
- anything a later tool adds, such as a transcript.

This guide stands up a vCon server beside an OpenSIPS proxy. OpenSIPS then
records every call into it.

- This guide does not use sipnab.
- When you have this working,
  [Send sipnab's vCons to a vCon server](vcon-sipnab.md) adds sipnab as a
  second source.

Kamailio cannot record calls this way. It has no SIPREC module.
[With Kamailio](#with-kamailio-a-gap) says what that means. It also says what a
Kamailio stack can send the vCon server instead.

The parts, and what each one does:

| Part | Role |
|---|---|
| **vcon-server** | Receives vCons over HTTP, runs them through a processing chain, and stores them. Its worker process is the *conserver*. |
| **Valkey** | The conserver's working store: queues and cached vCons. Valkey is the open-source fork of Redis and speaks the same protocol. |
| **PostgreSQL** | Keeps the finished vCons. |
| **OpenSIPS** | Your SIP proxy. Its `siprec` module starts a recording for each call. |
| **rtpengine** | Relays each call's media and sends a copy of it to the recorder. |
| **vcon-siprec-adapter** | The recorder. It receives the copy over SIPREC, turns each finished call into a vCon, and posts it to vcon-server. |

SIPREC ([RFC 7866](https://www.rfc-editor.org/rfc/rfc7866.html)) is the
standard way for a SIP server to hand a copy of a call to a recorder.

- The proxy opens a second SIP session to the recorder.
- It sends the recorder both directions of the audio.

Everything below runs on one machine. That keeps the example short. The
[last section](#put-the-parts-on-different-machines) says what changes when the
parts live on different machines.

## Tested on

Every block on this page ran as written, in order, on 2026-09-28.

- Machines: clean x86_64 virtual machines with 2 cores and 3 GB of memory.
- Systems: Debian 13 (kernel 6.12.63) and Ubuntu 24.04.5 (kernel 6.8.0).

On each, it ran:

- With OpenSIPS built from source on a machine with nothing installed.
- With the OpenSIPS 4.0 packages.
- [On different machines](#put-the-parts-on-different-machines), with the
  vCon server on its own machine.

More:

- [With Kamailio](#with-kamailio-a-gap) ran with
  [the sipnab page](vcon-sipnab.md).
- On Debian 13, causing each fault under
  [When something does not work](#when-something-does-not-work) produced what
  it describes.
- The commands pin the components to the versions below.
  - Newer commits may behave differently.
  - Pinning them keeps the guide describing what you get.

| Software | Version or commit |
|---|---|
| Docker Engine / Compose | 29.8.1 / v5.5.1, from the Docker apt repository |
| vcon-server | [`d441470b`](https://github.com/vcon-dev/vcon-server/commit/d441470b), main on 2026-09-20 |
| Valkey / PostgreSQL | `valkey/valkey:9.1.2-alpine` / `postgres:17.11-alpine` |
| OpenSIPS, built here | [`f46ef9337b`](https://github.com/OpenSIPS/opensips/commit/f46ef9337b), master, 4.1.0-dev |
| OpenSIPS, from packages | 4.0.2, installed as [the OpenSIPS guide](opensips.md) installs it |
| rtpengine | [`8da4be3355`](https://github.com/sipwise/rtpengine/commit/8da4be3355), master, packaged as 26.3.0.0 |
| vcon-siprec-adapter | [`fa09b939d3`](https://github.com/vcon-dev/vcon-siprec-adapter/commit/fa09b939d3), main |
| SIPp (for the test call) | the distribution's `sip-tester`: 3.7.3 on Debian, 3.7.2 on Ubuntu |

The whole vCon stack used about 165 MiB of memory while idle.

The examples use `192.0.2.10` as the machine's address. Replace it with yours
everywhere it appears.

## Before you start: your SIP server

Find your case, and follow the steps it names:

- **No SIP server yet.** Follow every step.
  - The step "Install OpenSIPS's recording module" builds OpenSIPS for you.
  - You may rather run the OpenSIPS 4.0 packages. Then install them with
    [Install OpenSIPS](opensips.md#install-opensips) in the OpenSIPS guide.
  - Then take the packages' route in "Install OpenSIPS's recording module".
- **OpenSIPS already runs, from the packages or built from source.**
  - The step "Install OpenSIPS's recording module" adds the `siprec` module.
  - The step "Configure OpenSIPS to record every call" finds your
    configuration file and replaces it.
  - On a machine whose script you want to keep, add the lines that step marks
    to your own script instead.
  - rtpengine may already relay your calls, as
    [Add rtpengine to your voice stack](rtpengine-relay.md) sets it up. Then
    skip the step "Build rtpengine".
- **Kamailio.** Kamailio cannot record over SIPREC. Read
  [With Kamailio](#with-kamailio-a-gap) first.
- **Both OpenSIPS and Kamailio on one machine.**
  - OpenSIPS records the calls that pass through it.
  - Kamailio's calls go unrecorded.
  - [With Kamailio](#with-kamailio-a-gap) says how to get vCons for both.

## Install Docker

vcon-server runs as containers. Install Docker Engine and the Compose plugin
from the Docker repository:

```bash
# Run all of these, in order.
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
. /etc/os-release
sudo curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
```

Log out and back in. Your account's new `docker` group then takes effect.
Then check:

```bash
docker compose version
```

## Install the vCon server

Check out vcon-server at the tested commit:

```bash
# Run all of these, in order.
sudo mkdir -p /opt/vcon && sudo chown "$USER": /opt/vcon
cd /opt/vcon
git clone https://github.com/vcon-dev/vcon-server.git
git -C vcon-server checkout d441470b
```

The `docker-compose.yml` in the checkout runs Redis and development tooling.
Write a smaller one beside the checkout. It runs Valkey and PostgreSQL instead:

```bash
cat > /opt/vcon/compose.yml <<'EOF'
name: vcon

services:
  valkey:
    image: valkey/valkey:9.1.2-alpine
    command: ["valkey-server", "--save", "20", "1", "--notify-keyspace-events", "Ex",
              "--appendonly", "yes", "--dir", "/data"]
    volumes: [valkey_data:/data]
    healthcheck:
      test: ["CMD-SHELL", "valkey-cli ping | grep -q PONG"]
      interval: 10s
      retries: 12
    restart: unless-stopped

  postgres:
    image: postgres:17.11-alpine
    environment:
      POSTGRES_DB: vcon
      POSTGRES_USER: vcon
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
    volumes: [postgres_data:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vcon -d vcon"]
      interval: 10s
      retries: 12
    restart: unless-stopped

  conserver:
    build: {context: ./vcon-server, dockerfile: ./docker/Dockerfile}
    command: ["python", "/app/conserver/main.py"]
    volumes:
      - ./vcon-server:/app
      - ./config.yml:/app/config.yml:ro
    env_file: [.env]
    depends_on:
      valkey: {condition: service_healthy}
      postgres: {condition: service_healthy}
    restart: unless-stopped

  api:
    build: {context: ./vcon-server, dockerfile: ./docker/Dockerfile}
    command: ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
    volumes:
      - ./vcon-server:/app
      - ./config.yml:/app/config.yml:ro
    ports: ["8000:8000"]
    env_file: [.env]
    depends_on:
      valkey: {condition: service_healthy}
    restart: unless-stopped

volumes:
  valkey_data: {}
  postgres_data: {}
EOF
```

Create the two files that hold secrets.

- `umask 077` makes both readable by you alone.
- Each secret is a fresh random value:

```bash
# Run all of these, in order.
cd /opt/vcon
umask 077
cat > .env <<EOF
REDIS_URL=redis://valkey
CONSERVER_CONFIG_FILE=/app/config.yml
CONSERVER_API_TOKEN=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
EOF
. ./.env
cat > config.yml <<EOF
ingress_auth:
  siprec: "$(openssl rand -hex 32)"

links:
  mark_recorder:
    module: links.tag
    options:
      tags: [vcon_role:recorder]

storages:
  postgres_recorded:
    module: storage.postgres
    options:
      host: postgres
      port: 5432
      database: vcon
      user: vcon
      password: "$POSTGRES_PASSWORD"
      table_name: vcons_recorded

chains:
  siprec_recorder:
    links: [mark_recorder]
    ingress_lists: [siprec]
    storages: [postgres_recorded]
    enabled: 1
EOF
umask 022
```

What that configuration says:

- **`ingress_auth`** gives the ingress list `siprec` its own key.
  - A producer that holds this key can post to `siprec` and nothing else.
  - The full `CONSERVER_API_TOKEN` in `.env` is for reading vCons back.
  - Keep it off the producers.
- **`chains`** routes everything that arrives on `siprec`:
  - through the `mark_recorder` link, which tags each vCon
    `vcon_role:recorder`,
  - into the `vcons_recorded` table.
  - PostgreSQL creates the table on the first write.

Start it and check that the API answers:

```bash
# Run all of these, in order.
cd /opt/vcon
docker compose up -d --build
until curl -sf localhost:8000/health; do sleep 2; done; echo
until docker compose logs conserver | grep -q 'Worker-1 started'; do sleep 2; done
until docker compose exec -T postgres pg_isready -q -h 127.0.0.1 -U vcon -d vcon; do sleep 2; done
docker compose ps
```

What those wait lines are for:

- The API takes a few seconds to start. So the first `until` line waits for
  `/health` to answer. It answers a JSON object whose `status` is `healthy`,
  beside a `version` object that holds `version`, `git_commit` and
  `build_time` (vcon-server's `health_check` in `api/api.py`).
- The conserver stores what the API queues. It starts later.
  - On a fresh machine its worker came up about 15 seconds after the API
    answered.
  - The second `until` line waits for it.
- On its first start PostgreSQL creates its database with a temporary server.
  Then it stops that server and starts the real one.
  - So the third `until` line waits for the real one to answer on the network.
  - The temporary server never listens there.

All four services then show `running`. `valkey` and `postgres` also show
`healthy`.

### Prove it stores what it accepts

The ingress route answers `204` when it has *queued* a vCon. It does not wait
until it has stored it. Post a small one and look for it in PostgreSQL:

```bash
# Run all of these, in order.
cd /opt/vcon
KEY=$(sed -n 's/^  siprec: "\(.*\)"/\1/p' config.yml)
UUID=$(cat /proc/sys/kernel/random/uuid)
printf '{"vcon":"0.0.1","uuid":"%s","created_at":"%s","parties":[{"tel":"+15551230001"},{"tel":"+15551230002"}],"dialog":[],"analysis":[],"attachments":[]}' \
  "$UUID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /tmp/test.vcon.json
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  "localhost:8000/vcon/external-ingress?ingress_list=siprec" \
  -H "x-conserver-api-token: $KEY" -H "Content-Type: application/json" \
  --data-binary @/tmp/test.vcon.json
rm /tmp/test.vcon.json
sleep 3
docker compose exec -T postgres psql -U vcon -d vcon -c \
  "select id, vcon_json->'attachments' from vcons_recorded where id='$UUID'"
```

The `curl` prints `204`. The query returns one row. Its attachment is the
`["vcon_role:recorder"]` tag. A wrong key gets `403` instead.

## Build rtpengine

rtpengine's own documentation recommends building Debian packages from the
source tree. That gives you:

- a systemd unit,
- a configuration file,
- a clean uninstall.

The build:

- installs its dependencies from the tree's `debian/control`,
- then runs rtpengine's test suite, which takes a while:

```bash
# Run all of these, in order.
sudo apt-get install -y --no-install-recommends build-essential devscripts equivs fakeroot
sudo mkdir -p /usr/local/src/voice && sudo chown "$USER": /usr/local/src/voice
cd /usr/local/src/voice
git clone https://github.com/sipwise/rtpengine.git
cd rtpengine
git checkout 8da4be3355
sudo mk-build-deps -i -r -t "apt-get -y --no-install-recommends" debian/control
dpkg-buildpackage -us -uc -b -j2
cd ..
sudo apt-get install -y ./ngcp-rtpengine-daemon_26.3.0.0+0~mr26.3.0.0_amd64.deb \
  ./ngcp-rtpengine-utils_26.3.0.0+0~mr26.3.0.0_all.deb
```

The package's configuration asks for rtpengine's kernel forwarding module. This
guide does not install that module. Tell rtpengine to forward in userspace, and
restart it:

```bash
# Run all of these, in order.
sudo sed -i '0,/^table = 0/s//table = -1/' /etc/rtpengine/rtpengine.conf
sudo systemctl restart ngcp-rtpengine-daemon
systemctl is-active ngcp-rtpengine-daemon
```

It listens for OpenSIPS on `127.0.0.1:2223`. It relays media on ports
30000-39999.

## Install OpenSIPS's recording module

OpenSIPS records with its `siprec` module.

**With the OpenSIPS packages,** it comes in a package of its own. The
`uac_auth` module comes in another. The step "Configure OpenSIPS to record
every call" loads that module:

```bash
sudo apt-get install -y opensips-siprec-module opensips-auth-modules
```

**Or build OpenSIPS with it.** Skip this if you installed the packages.

- OpenSIPS master builds with compiler optimizations turned off.
  - That is right for OpenSIPS's own developers.
  - It is wrong for a proxy carrying calls.
- Turn them back on before you build.
- Add the `siprec` module. The default build leaves it out.
- You may already have built OpenSIPS from source by one of these guides.
  - Then the block reuses that tree, `/usr/local/src/voice/opensips`.
  - It rebuilds it with `siprec`.
- With a tree of your own, change `/usr/local/src/voice` in the block to the
  directory that holds it:

```bash
# Run all of these, in order.
sudo apt-get install -y --no-install-recommends bison flex uuid-dev pkg-config libncurses-dev
cd /usr/local/src/voice
[ -d opensips ] || git clone https://github.com/OpenSIPS/opensips.git
cd opensips
git checkout f46ef9337b
make Makefile.conf
sed -i 's/^DEFS+= -DCC_O0/#DEFS+= -DCC_O0/' Makefile.conf
make -j2 all include_modules="siprec"
sudo make install include_modules="siprec"
/usr/local/sbin/opensips -V | head -2
```

The second line of `opensips -V` lists the build flags. `CC_O0` is no longer
among them.

Leave `DBG_MALLOC` as it is.

- With both it and `CC_O0` switched off, this commit of master does not
  compile.
- `net/tcp_conn_defs.h` calls `get_ticks()` without including the header that
  declares it.
- Only `DBG_MALLOC`'s headers happen to supply it.

The build installs under `/usr/local`:

- the binary is `/usr/local/sbin/opensips`,
- modules are in `/usr/local/lib64/opensips/modules/`,
- OpenSIPS reads its configuration from `/usr/local/etc/opensips/`.

The packages install under `/usr`, with the configuration in `/etc/opensips/`.

## Configure OpenSIPS to record every call

This configuration is a minimal proxy with recording added.

- Your own script does much more (registration, authentication, routing to
  carriers).
- The recording part is the block marked below, and the `loadmodule` lines it
  needs.

### Write the configuration

The packages and the source build keep their configuration and their modules in
different places. The first two lines find them:

- `C` is your configuration file.
- `M` is the directory your install loads modules from. The script's `mpath`
  names it.

```bash
# Run all of these, in order.
for f in /etc/opensips/opensips.cfg /usr/local/etc/opensips/opensips.cfg; do sudo test -f "$f" && C=$f && break; done
for d in /usr/lib/*/opensips/modules /usr/local/lib64/opensips/modules; do [ -f "$d/tm.so" ] && M=$d && break; done
echo "configuration: $C   modules: $M"
sudo tee "$C" >/dev/null <<'EOF'
# OpenSIPS as a SIP proxy that records every call over SIPREC.
log_level=3
stderror_enabled=no
syslog_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=2
open_files_limit=4096

socket=udp:192.0.2.10:5060   # the address your phones and carriers reach

mpath="MODULES/"

loadmodule "proto_udp.so"   # built into the core, but still loaded by name
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/run/opensips/opensips_fifo")

# Recording: siprec needs dialog, b2b_entities and rtp_relay, loaded first.
loadmodule "dialog.so"
loadmodule "uac_auth.so"
loadmodule "b2b_entities.so"
loadmodule "siprec.so"
loadmodule "rtp_relay.so"
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")

route {
	if (!mf_process_maxfwd_header(10)) {
		send_reply(483, "Too Many Hops");
		exit;
	}

	if (has_totag()) {
		if (is_method("ACK") && t_check_trans()) {
			t_relay();
			exit;
		}
		if (!loose_route()) {
			send_reply(404, "Not here");
			exit;
		}
		t_relay();
		exit;
	}

	if (is_method("CANCEL")) {
		if (t_check_trans())
			t_relay();
		exit;
	}
	t_check_trans();

	if (!is_method("INVITE")) {
		send_reply(405, "Method Not Allowed");
		exit;
	}

	record_route();

	# --- recording starts here ---
	create_dialog();
	rtp_relay_engage("rtpengine");
	siprec_start_recording("sip:127.0.0.1:5090");
	# --- recording ends here ---

	# Where the call goes. Here, a test callee on this machine; in your
	# stack, lookup("location"), dispatcher or a carrier.
	$du = "sip:127.0.0.1:5070";
	t_relay();
}
EOF
sudo sed -i "s|^mpath=\"MODULES/\"|mpath=\"$M/\"|" "$C"
sudo grep '^mpath=' "$C"
```

What the recording block does, line by line:

- `create_dialog()` makes OpenSIPS track the call.
  - So it knows when the call ends.
  - It can end the recording with it.
- `rtp_relay_engage("rtpengine")` puts rtpengine in the media path.
  - The recorder can only receive a copy of audio that passes through
    rtpengine.
- `siprec_start_recording("sip:127.0.0.1:5090")` opens the SIPREC session to
  the recorder.
  - It starts only when the callee's SDP arrives, usually in the `200 OK`.

`loadmodule "uac_auth.so"` is there because `b2b_entities` asks for it at
startup. Leaving it out works. But it then logs a warning on every start.

### If you built OpenSIPS while installing its recording module: give it a user and a unit

The packages come with an `opensips` user and a systemd unit.

- Did you install them? Or does your source build already run as a service?
  Then skip to
  [Check the configuration and start OpenSIPS](#check-the-configuration-and-start-opensips).
- A fresh build has neither. Run OpenSIPS as its own user, under systemd:

```bash
# Run all of these, in order.
sudo useradd --system --home-dir /run/opensips --shell /usr/sbin/nologin opensips
sudo chown root:opensips /usr/local/etc/opensips
sudo chmod 750 /usr/local/etc/opensips
sudo tee /etc/systemd/system/opensips.service >/dev/null <<'EOF'
[Unit]
Description=OpenSIPS SIP server
After=network.target ngcp-rtpengine-daemon.service

[Service]
Type=forking
User=opensips
Group=opensips
RuntimeDirectory=opensips
RuntimeDirectoryMode=775
PIDFile=/run/opensips/opensips.pid
ExecStart=/usr/local/sbin/opensips -P /run/opensips/opensips.pid -f /usr/local/etc/opensips/opensips.cfg -m 64 -M 8
Restart=always
TimeoutStopSec=30s
LimitNOFILE=262144

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
```

### Check the configuration and start OpenSIPS

```bash
# Run all of these, in order.
for f in /etc/opensips/opensips.cfg /usr/local/etc/opensips/opensips.cfg; do sudo test -f "$f" && C=$f && break; done
sudo chown root:opensips "$C"
sudo chmod 640 "$C"
sudo opensips -C -f "$C"
sudo systemctl enable opensips
sudo systemctl restart opensips
systemctl is-active opensips
```

`opensips -C` checks the configuration before you start anything. It prints
`config file ok`.

## Install the recorder

vcon-siprec-adapter runs as a container.

- It uses the host's network directly.
  - A call's audio arrives on a range of UDP ports.
  - Publishing a range through Docker is slow.
- Its ports stay clear of everything else on this machine:
  - SIP on `127.0.0.1:5090`,
  - audio on 40000-40999,
  - its health check on `127.0.0.1:8081`.

```bash
# Run all of these, in order.
sudo mkdir -p /opt/siprec && sudo chown "$USER": /opt/siprec
cd /opt/siprec
git clone https://github.com/vcon-dev/vcon-siprec-adapter.git
git -C vcon-siprec-adapter checkout fa09b939d3
mkdir -p vcons dlq logs
KEY=$(sed -n 's/^  siprec: "\(.*\)"/\1/p' /opt/vcon/config.yml)
umask 077
cat > config.yaml <<EOF
server:
  listen_address: "127.0.0.1"
  sip_port_udp: 5090
  sip_port_tcp: 5090
  sip_port_tls: 5091
  tls_cert: null
  tls_key: null
  user_agent: "SIPREC-SRS/1.0"
  max_sessions: 100
  session_timeout: 3600

storage:
  local_path: "/app/vcons"
  filename_pattern: "{timestamp}_{call_id}.vcon.json"
  create_directories: true
  cleanup_temp_files: true

webhooks:
  enabled: true
  dlq_path: "/app/dlq"
  endpoints:
    - url: "http://127.0.0.1:8000/vcon/external-ingress?ingress_list=siprec"
      headers:
        x-conserver-api-token: "$KEY"
      retry_attempts: 3
      timeout: 30
      backoff_factor: 2.0
      hmac_secret: null

media:
  mode: "inline"
  publisher: "none"

signing:
  enabled: false

health:
  enabled: true
  host: "127.0.0.1"
  port: 8081

rtp:
  buffer_size: 65536
  supported_codecs: ["PCMU/8000", "PCMA/8000", "G722/8000", "opus/48000"]
  audio_format: "wav"
  sample_rate: 8000
  channels: 1
  port_range_start: 40000
  port_range_end: 40999

lawful_basis:
  enabled: true
  lawful_basis: "legitimate_interests"
  purposes: ["recording"]
  expiration: null
  justification: "Recorded by the operator of this SIP service."

logging:
  level: "INFO"
  file: "/app/logs/siprec-srs.log"
  max_size: "10MB"
  backup_count: 5
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
EOF
umask 022
cat > compose.yml <<'EOF'
name: siprec

services:
  srs:
    build: ./vcon-siprec-adapter
    network_mode: host
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./vcons:/app/vcons
      - ./dlq:/app/dlq
      - ./logs:/app/logs
    environment:
      SIPREC_PUBLIC_IP: 127.0.0.1
    restart: unless-stopped
EOF
docker compose up -d --build
until curl -fs 127.0.0.1:8081/healthz; do sleep 2; done; echo
```

The recorder takes a few seconds to start after its container does. So the
last line waits until the health check answers. It answers a JSON object whose
`status` is `ok`, beside a `timestamp` that holds the current time in ISO 8601
form (vcon-siprec-adapter's `_healthz` in `siprec_srs/health_server.py`).

Four settings deserve a word:

- **`sip_port_tls: 5091` with no certificate.** TLS stays off.
  - The adapter's own `config.yaml` points at certificate files that do not
    exist.
  - It does not start with them.
  - Its validator also refuses a TLS port of `null`.
- **`webhooks`** posts each finished vCon to the `siprec` ingress list with
  that list's key.
  - If every attempt fails, the vCon goes to `dlq/` (dead-letter queue)
    instead.
  - So it is not lost.
- **`storage.local_path`** keeps a copy of every vCon, audio included, in
  `/opt/siprec/vcons`.
  - That copy is call data.
  - The [operating section](#operate-it) says how to clear it.
- **`signing: enabled: false`.** A signed (JWS) vCon does not match the shape
  vcon-server's ingress route accepts.

## Place a test call

SIPp plays both ends:

- a callee that echoes audio back,
- a caller that dials through OpenSIPS and plays a recorded G.711 sample.

SIPp's built-in caller ignores the `Record-Route` header OpenSIPS adds.

- So its `BYE` would miss the proxy and draw `404 Not here`.
- The three `sed` lines make it honor the route set, the way a real phone
  does.
- They also drop the DTMF clip the recorder cannot store:

```bash
# Run all of these, in order.
sudo apt-get install -y sip-tester
mkdir -p ~/sipp/pcap && cd ~/sipp
ln -sf /usr/share/sip-tester/*.pcap pcap/
sipp -sd uac_pcap > uac_rr.xml
sed -i 's|<recv response="200" rtd="true" crlf="true">|<recv response="200" rtd="true" crlf="true" rrs="true">|' uac_rr.xml
sed -i -E 's#^( *)(ACK|BYE) sip:\[service\]@\[remote_ip\]:\[remote_port\] SIP/2.0#\1\2 [next_url] SIP/2.0\n\1[routes]#' uac_rr.xml
sed -i '/dtmf_2833_1.pcap/d' uac_rr.xml
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -timeout 90s
```

The caller needs `sudo` because it plays the audio sample through a raw socket.
At the end SIPp's statistics screen shows `Successful call` at 1.

## Find the call's vCon

When the call ends, the recorder builds the vCon and posts it. Its log names
the vCon's UUID:

```bash
# Run all of these, in order.
cd /opt/siprec
docker compose logs --since 5m srs | grep -E "Vcon object initialized|delivered vCon"
```

Look it up in PostgreSQL, with the UUID from that log line:

```bash
# Run all of these, in order.
cd /opt/vcon
docker compose exec -T postgres psql -U vcon -d vcon -c \
  "select id, jsonb_array_length(vcon_json->'parties') as parties,
          jsonb_array_length(vcon_json->'dialog') as recordings
     from vcons_recorded order by created_at desc limit 1"
```

The test call produced one vCon with:

- 2 parties,
- 2 recordings, one for each direction of the audio.
  - Each is an `audio/wav` of about 150 KB.

## Operate it

**Check health.**

```bash
# Run all of these, in order.
curl -s -w '\n' localhost:8000/health          # vcon-server API
curl -s -w '\n' 127.0.0.1:8081/healthz         # recorder
systemctl is-active opensips ngcp-rtpengine-daemon
cd /opt/vcon && docker compose ps
```

**Read the logs.**

```bash
# Run all of these, in order.
cd /opt/vcon && docker compose logs --tail 50 conserver
cd /opt/siprec && docker compose logs --tail 50 srs
sudo journalctl -u opensips -n 50
sudo journalctl -u ngcp-rtpengine-daemon -n 50
```

The conserver logs one line for every vCon it stores:
`Completed processing vCon <uuid> in <seconds> seconds - Chain: siprec_recorder`
(vcon-server's `conserver/main.py`).

**Restart after a configuration change.** vcon-server reads `config.yml` on
each request. But restart it anyway, so that both processes agree:

```bash
# Run all of these, in order.
cd /opt/vcon && docker compose restart conserver api
sudo systemctl restart opensips
```

**Clear the recorder's local copies.**

- Once a vCon is in PostgreSQL, the copy in `/opt/siprec/vcons` is a second
  copy of the call.
- The container writes it as root. So remove it with `sudo`.
- This deletes copies more than a day old:

```bash
sudo find /opt/siprec/vcons -name '*.vcon.json' -mtime +1 -delete
```

Check `/opt/siprec/dlq` as well. Anything there is a vCon that never reached
vcon-server.

**Back up the store.** Everything worth keeping is in PostgreSQL:

```bash
# Run all of these, in order.
cd /opt/vcon
docker compose exec -T postgres pg_dump -U vcon vcon | gzip > vcon-$(date +%F).sql.gz
```

**Uninstall.**

- `docker compose down -v` removes the containers *and* their volumes.
  - The volumes hold every stored vCon.
- The rtpengine build installed its build dependencies through one package,
  `ngcp-rtpengine-build-deps`.
  - Purging it and running `autoremove` removes them.
- `autoremove` also removes any other package that nothing depends on any
  more.
  - So on a machine that runs other software, drop `-y` and read its list
    first.


```bash
# Run all of these, in order.
cd /opt/siprec && docker compose down
cd /opt/vcon && docker compose down -v
sudo systemctl disable --now opensips ngcp-rtpengine-daemon
sudo apt-get purge -y ngcp-rtpengine-daemon ngcp-rtpengine-utils ngcp-rtpengine-build-deps
sudo apt-get autoremove -y
```

## With Kamailio: a gap

Kamailio has no SIPREC module.

- So it cannot hand a copy of a call to a recorder the way the step
  "Configure OpenSIPS to record every call" has OpenSIPS do.
- Neither Kamailio 6.1 nor its development branch has one.
  - None of the 256 modules in Kamailio 6.1's source tree implements SIPREC.
  - None of the 258 on its `master` branch does either.
- The recorder in this guide, vcon-siprec-adapter, takes SIPREC only.
  - So with Kamailio it receives nothing.

What a Kamailio stack can send the vCon server is sipnab's own vCons.

- sipnab reads the calls off the wire, beside Kamailio.
- It writes a vCon for each. The vCon holds:
  - the parties,
  - the signaling,
  - with the media in its capture, the audio.
- It is an observer's record, not a party's.
  - A packet the capture missed is not in it.
- [Send sipnab's vCons to a vCon server](vcon-sipnab.md) sets it up.
  - It keeps those vCons apart from recorded ones.

With Kamailio:

- Follow the first two steps here, "Install Docker" and "Install the vCon
  server". Skip the rest of the steps, from "Build rtpengine" to "Find the
  call's vCon": the recorder and its test.
- Follow [Send sipnab's vCons to a vCon server](vcon-sipnab.md). Its
  [With Kamailio](vcon-sipnab.md#with-kamailio) section places the test call.

With OpenSIPS and Kamailio on one machine:

- Follow every step here for OpenSIPS's calls.
- Then follow the sipnab guide. Its
  [same section](vcon-sipnab.md#with-kamailio) widens sipnab's capture to
  Kamailio's port.

## Put the parts on different machines

**The vCon server on its own machine.**

- The vCon server, Valkey and PostgreSQL can have a machine to themselves,
  here `192.0.2.20`.
- The recorder stays beside the SIP proxy and rtpengine. They send it the
  audio.

The steps:

- Follow "Install Docker" and "Install the vCon server" on that machine.
- On the proxy's machine, do the steps from "Build rtpengine" to "Configure
  OpenSIPS to record every call".
- Then fetch the recorder's key before "Install the recorder".
  - "Install the recorder" reads it from `/opt/vcon/config.yml`.
  - So this writes that file with the key and nothing else, not the database
    password:

```bash
# Run all of these, in order.
sudo mkdir -p /opt/vcon && sudo chown "$USER": /opt/vcon
ssh 192.0.2.20 "grep '^  siprec: ' /opt/vcon/config.yml" > /opt/vcon/config.yml
chmod 600 /opt/vcon/config.yml
grep -c '^  siprec: "' /opt/vcon/config.yml
```

It prints 1. Then do "Install the recorder". Send the recorder's vCons to the
vCon server's address in place of the loopback one:

```bash
# Run all of these, in order.
cd /opt/siprec
sed -i 's|url: "http://127.0.0.1:8000/|url: "http://192.0.2.20:8000/|' config.yaml
grep -n 'url:' config.yaml
docker compose up -d --force-recreate
```

"Place a test call" and "Find the call's vCon" then work as written.

- Run the database query from "Find the call's vCon" on the vCon server's
  machine.
- Port 8000 on it is now reachable from the network. So allow it only from
  the machines that post vCons.

This guide covers that split only.

- The recorder receives the audio from rtpengine.
- So moving either one to another machine changes the addresses both of them
  and OpenSIPS use.
- This guide has not run that.

## When something does not work

- **`ERROR:core:main: no transport protocol loaded`.**
  - `loadmodule
    "proto_udp.so"` is missing.
  - The OpenSIPS binary contains the module.
  - But the script must still name it.
- **`ERROR:core:parse_opensips_cfg: loading config file
  /usr/local/etc/opensips/opensips.cfg: Permission denied`.**
  - OpenSIPS runs as `opensips` and cannot read its configuration.
  - `make install` creates `/usr/local/etc/opensips` readable by root alone.
  - So give the group both the directory and the file, as in the step
    "Configure OpenSIPS to record every call".
  - The packages set this up themselves.
  - But a file you wrote as root keeps root's group until that step changes
    it.
- **The test call's `BYE` gets `404 Not here`.**
  - The caller ignored the route set.
  - Use the edited `uac_rr.xml`, not SIPp's built-in `uac_pcap`.
- **`/health` answers but nothing reaches PostgreSQL.**
  - A `204` from the ingress route means queued.
  - Read `docker compose logs conserver`. The conserver logs a storage failure
    there.
- **rtpengine logs `FAILED TO OPEN KERNEL TABLE 0`.** One of these happened:
  - `table = -1` was not set,
  - the service was not restarted after setting it.
