# Add Homer to an OpenSIPS voice stack

[Homer](https://github.com/sipcapture/homer) keeps a searchable history of
your SIP traffic. Your SIP servers send it a copy of every message they handle,
wrapped in HEP (the Homer Encapsulation Protocol), and Homer stores each one
and shows you any past call as a ladder of messages. It answers "what happened
to that call yesterday" without anyone having run a capture at the time.

This guide stands up Homer beside an OpenSIPS proxy and has OpenSIPS send it
every call. This guide does not use sipnab. When you have this working,
[Connect sipnab to Homer](homer-sipnab.md) adds sipnab as a second receiver
and as another source.

The parts, and what each one does:

| Part | Role |
|---|---|
| **heplify-server** | Receives HEP on UDP port 9060 and writes each message into PostgreSQL. |
| **PostgreSQL** | Stores the messages, one table per message type and day. |
| **homer-app** | The web interface and its API, on port 9080. It reads what heplify-server stored. |
| **OpenSIPS** | Your SIP proxy. Its `tracer` module copies every message of a call to heplify-server over HEP. |

Everything below runs on one machine, which keeps the example short. The
[last section](#put-the-parts-on-different-machines) says what changes when
they are apart.

## Tested on

Every command on this page ran as written, in order, on 2026-09-26 on two
x86_64 virtual machines with 2 cores and 4 GB of memory: a clean Debian 13
(kernel 6.12.63), and Ubuntu 24.04.5 (kernel 6.8.0). The commands pin the
components to the versions below.

| Software | Version or commit |
|---|---|
| Docker Engine / Compose | from the Docker apt repository |
| heplify-server | `ghcr.io/sipcapture/heplify-server:1.60.9` |
| homer-app | `ghcr.io/sipcapture/homer-app:1.5.21` |
| PostgreSQL | `postgres:17.11-alpine` |
| OpenSIPS | [`f46ef9337b`](https://github.com/OpenSIPS/opensips/commit/f46ef9337b), master, 4.1.0-dev |
| SIPp (for the test call) | the distribution's `sip-tester` |

The examples use `192.0.2.10` as the machine's address. Replace it with yours
everywhere it appears.

## 1. Install Docker

Homer runs as containers. Install Docker Engine and the Compose plugin from
the Docker repository:

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

Log out and back in so that your account's new `docker` group takes effect,
then check:

```bash
docker compose version
```

## 2. Start Homer

The three services below are the ones in the sipcapture project's own
[homer7-docker](https://github.com/sipcapture/homer7-docker) recipe, without
the Prometheus, Grafana and Loki it also bundles. Choose a database password
and put it in `.env`, where Compose reads it:

```bash
# Run all of these, in order.
sudo mkdir -p /opt/homer && sudo chown "$USER": /opt/homer
cd /opt/homer
echo "DB_PASS=$(openssl rand -hex 16)" > .env
chmod 600 .env
cat > init-user-db.sh <<'EOF'
#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE DATABASE homer_config;
EOSQL
EOF
cat > docker-compose.yml <<'EOF'
services:
  db:
    image: postgres:17.11-alpine
    environment:
      POSTGRES_USER: root
      POSTGRES_PASSWORD: ${DB_PASS}
    volumes:
      - ./init-user-db.sh:/docker-entrypoint-initdb.d/init-user-db.sh:ro
      - db-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "psql -h localhost -U root -c '\\l'"]
      interval: 2s
      timeout: 3s
      retries: 30
    restart: unless-stopped

  heplify-server:
    image: ghcr.io/sipcapture/heplify-server:1.60.9
    command: ["./heplify-server"]
    ports:
      - "9060:9060/udp"
    environment:
      HEPLIFYSERVER_HEPADDR: "0.0.0.0:9060"
      HEPLIFYSERVER_DBSHEMA: homer7
      HEPLIFYSERVER_DBDRIVER: postgres
      HEPLIFYSERVER_DBADDR: "db:5432"
      HEPLIFYSERVER_DBUSER: root
      HEPLIFYSERVER_DBPASS: ${DB_PASS}
      HEPLIFYSERVER_DBDATATABLE: homer_data
      HEPLIFYSERVER_DBCONFTABLE: homer_config
      HEPLIFYSERVER_DBROTATE: "true"
      HEPLIFYSERVER_DBDROPDAYS: "7"
      HEPLIFYSERVER_LOGLVL: info
      HEPLIFYSERVER_LOGSTD: "true"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  homer-app:
    image: ghcr.io/sipcapture/homer-app:1.5.21
    environment:
      DB_HOST: db
      DB_USER: root
      DB_PASS: ${DB_PASS}
    ports:
      - "9080:80"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

volumes:
  db-data:
EOF
docker compose up -d
```

`HEPLIFYSERVER_DBDROPDAYS` is how long Homer keeps messages: heplify-server
drops each day's tables after 7 days here.

The first start creates the tables, which takes a few seconds. Wait until the
web interface answers:

```bash
until curl -fs -o /dev/null localhost:9080; do sleep 2; done; echo ready
```

Open `http://192.0.2.10:9080` and log in as `admin`, password `sipcapture`.
Change that password under the user settings before anything else can reach
the port.

## 3. Build OpenSIPS

OpenSIPS master builds with compiler optimizations turned off, which is right
for OpenSIPS's own developers and wrong for a proxy carrying calls. Turn them
back on before you build. The `proto_hep` and `tracer` modules are part of the
default build:

```bash
# Run all of these, in order.
sudo apt-get install -y --no-install-recommends build-essential bison flex uuid-dev pkg-config libncurses-dev libssl-dev
sudo mkdir -p /usr/local/src/voice && sudo chown "$USER": /usr/local/src/voice
cd /usr/local/src/voice
git clone https://github.com/OpenSIPS/opensips.git
cd opensips
git checkout f46ef9337b
make Makefile.conf
sed -i 's/^DEFS+= -DCC_O0/#DEFS+= -DCC_O0/' Makefile.conf
make -j2 all
sudo make install
/usr/local/sbin/opensips -V | head -2
```

Leave `DBG_MALLOC` as it is. With both it and `CC_O0` switched off, this commit
of master does not compile: `net/tcp_conn_defs.h` calls `get_ticks()` without
including the header that declares it, and only `DBG_MALLOC`'s headers happen
to supply it.

## 4. Configure OpenSIPS to send every call to Homer

This configuration is a minimal proxy with tracing added. Your own script does
much more. The tracing part is the block marked below, and the `loadmodule`
lines it needs.

```bash
sudo tee /usr/local/etc/opensips/opensips.cfg >/dev/null <<'EOF'
# OpenSIPS as a SIP proxy that sends every call to Homer over HEP.
log_level=3
stderror_enabled=no
syslog_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=2
open_files_limit=4096

socket=udp:192.0.2.10:5060   # the address your phones and carriers reach
socket=hep_udp:127.0.0.1:6061   # HEP to Homer leaves through this socket

mpath="/usr/local/lib64/opensips/modules/"

loadmodule "proto_udp.so"   # built into the core, but still loaded by name
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"
loadmodule "dialog.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/run/opensips/opensips_fifo")

# Tracing: where HEP goes, and a name for it that trace() uses.
loadmodule "proto_hep.so"
modparam("proto_hep", "hep_id", "[homer] 127.0.0.1:9060; transport=udp; version=3")
modparam("proto_hep", "hep_capture_id", 101)
loadmodule "tracer.so"
modparam("tracer", "trace_id", "[tid]uri=hep:homer")

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

	# --- tracing starts here ---
	create_dialog();
	trace("tid", "d");
	# --- tracing ends here ---

	# Where the call goes. Here, a test callee on this machine; in your
	# stack, lookup("location"), dispatcher or a carrier.
	$du = "sip:127.0.0.1:5070";
	t_relay();
}
EOF
```

What the tracing lines do:

- `socket=hep_udp:...` gives OpenSIPS a socket to send HEP from. Without it,
  OpenSIPS refuses to start: `No binding found for protocol proto_hep`.
- `hep_id` names a HEP destination, `homer`: heplify-server on this machine,
  HEP version 3 over UDP. Without `transport=udp`, OpenSIPS sends version 3
  over TCP, which this heplify-server does not listen on.
- `hep_capture_id` is the number Homer shows as the source of these messages.
  Give each SIP server its own.
- `trace_id` defines `tid` as "send to `homer`".
- `create_dialog()` makes OpenSIPS track the call, and `trace("tid", "d")`
  sends every message of that dialog, both legs, until it ends.

Run OpenSIPS as its own user, under systemd:

```bash
# Run all of these, in order.
sudo useradd --system --home-dir /run/opensips --shell /usr/sbin/nologin opensips
sudo chown root:opensips /usr/local/etc/opensips /usr/local/etc/opensips/opensips.cfg
sudo chmod 750 /usr/local/etc/opensips
sudo chmod 640 /usr/local/etc/opensips/opensips.cfg
sudo tee /etc/systemd/system/opensips.service >/dev/null <<'EOF'
[Unit]
Description=OpenSIPS SIP server
After=network.target docker.service

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
sudo /usr/local/sbin/opensips -C -f /usr/local/etc/opensips/opensips.cfg
sudo systemctl daemon-reload
sudo systemctl enable --now opensips
systemctl is-active opensips
```

## 5. Place a test call

SIPp plays both ends: a callee on this machine, and a caller that dials through
OpenSIPS. SIPp's built-in caller ignores the `Record-Route` header OpenSIPS
adds, so its `BYE` would miss the proxy and draw `404 Not here`. The two `sed`
lines make it honor the route set, the way a real phone does:

```bash
# Run all of these, in order.
sudo apt-get install -y sip-tester
mkdir -p ~/sipp && cd ~/sipp
sipp -sd uac > uac_rr.xml
sed -i 's|<recv response="200" rtd="true">|<recv response="200" rtd="true" rrs="true">|' uac_rr.xml
sed -i -E 's#^( *)(ACK|BYE) sip:\[service\]@\[remote_ip\]:\[remote_port\] SIP/2.0#\1\2 [next_url] SIP/2.0\n\1[routes]#' uac_rr.xml
sipp -sn uas -i 127.0.0.1 -p 5070 -m 1 -bg
sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -d 2000 -timeout 30s \
  -trace_msg -message_file uac.msg
grep -m1 -i '^Call-ID:' uac.msg
```

At the end SIPp's statistics screen shows `Successful call` at 1. The last
line prints the call's Call-ID.

## 6. Find the call in Homer

The web interface at `http://192.0.2.10:9080` searches what heplify-server
stored. To check from the command line, query the database heplify-server
writes. heplify-server writes in batches, at least every 4 seconds, so the
first line waits for the last batch. Each row is one message, and OpenSIPS sent
most of them twice, as it arrived and as it left:

```bash
# Run all of these, in order.
sleep 5
cd ~/sipp
CALL=$(grep -m1 -i '^Call-ID:' uac.msg | awk '{print $2}' | tr -d '\r')
cd /opt/homer
docker compose exec -T db psql -U root -d homer_data -c \
  "select create_date, data_header->>'method' as method
     from hep_proto_1_call where data_header->>'callid' = '$CALL' order by create_date"
```

## 7. Operate it

**Check health and read the logs.**

```bash
# Run all of these, in order.
cd /opt/homer && docker compose ps
docker compose logs --tail 20 heplify-server
systemctl is-active opensips
```

heplify-server logs a line of statistics every five minutes, counting the HEP
packets it received and any it filtered or failed to store.

**Keep more or fewer days.** Change `HEPLIFYSERVER_DBDROPDAYS` in
`/opt/homer/docker-compose.yml` and recreate heplify-server:

```bash
# Run all of these, in order.
cd /opt/homer
sed -i 's/HEPLIFYSERVER_DBDROPDAYS: "7"/HEPLIFYSERVER_DBDROPDAYS: "14"/' docker-compose.yml
docker compose up -d heplify-server
```

**Restart.** A restart of heplify-server loses the HEP packets sent while it
is down: HEP over UDP is not retried.

```bash
# Run all of these, in order.
cd /opt/homer && docker compose restart
sudo systemctl restart opensips
```

**Uninstall.** `docker compose down -v` removes the containers *and* the
database volume, which is every stored message:

```bash
# Run all of these, in order.
cd /opt/homer && docker compose down -v
sudo systemctl disable --now opensips
```

## Put the parts on different machines

- **Homer on its own machine.** In `hep_id`, replace `127.0.0.1` with that
  machine's address, and bind the `hep_udp` socket to an address that can
  reach it, such as `socket=hep_udp:192.0.2.10:6061`. Open UDP 9060 on it to your SIP servers only, and port
  9080 to the people who use the interface.
- **Several SIP servers.** Give each one the same `hep_id` destination and its
  own `hep_capture_id`, so that Homer shows which server saw each message.

## When something does not work

- **OpenSIPS does not start: `No binding found for protocol proto_hep`.** The
  configuration loads `proto_hep` but has no `socket=hep_udp:...` line.
- **The search finds nothing.** Check that heplify-server received anything:
  `docker compose logs heplify-server`. If it logged no packets, check the
  `hep_id` address and `transport=udp`.
- **`hep_id` without `transport=udp`.** OpenSIPS sends HEP version 3 over TCP
  by default, and this heplify-server listens on UDP only.
- **The test call's `BYE` gets `404 Not here`.** The caller ignored the route
  set. Use the edited `uac_rr.xml`, not SIPp's built-in `uac`.
