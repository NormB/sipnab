# Manage many sipnab instances

`sipnab fleet inventory` asks every sipnab instance you list for its
inventory, and prints one table of the fleet. Use it to answer "which build
and which configuration does each instance run, and which ones are down?"
before and after an upgrade or a configuration change.

The table shows, for each instance:

- the build it runs, and the SHA-256 of its binary,
- the digest of its effective configuration: the file it loaded and its
  command line,
- the user it runs as, and how long it has been up.

Below the table it names the instances that did not answer, the instances on
a different build from the rest, the HEP senders a collector receives from
that are not in your list, and the listed instances whose HEP a listed
collector refuses for authentication. Each instance also reports when each of
its key, token and password files was last replaced, so you can check that a
rotation took effect. It reports. It changes nothing on any instance.

`sipnab fleet serve` is the other direction: a fleet center that members
report to. Each member pushes a heartbeat, the center keeps the newest one per
member, and it says which members went silent, including members the
controller cannot reach. See [Run a fleet center](#run-a-fleet-center).

Some upgrades need every sender and its collector on the same build, such as
the HEP HMAC version 2 change in
[Upgrade a fleet that uses HMAC authentication](config-reference.md#upgrade-a-fleet-that-uses-hmac-authentication).
The report shows which instances are still on the old build.

The commands and output on this page come from a run on 2026-11-03: four
instances in containers on the network `192.0.2.0/24`, and the controller on
the host. The instances ran a development build of 0.5.232 with this feature,
and one ran release 0.5.130. The output of
[A listed sender the collector refuses](#a-listed-sender-the-collector-refuses)
and [Check that a key rotation took effect](#check-that-a-key-rotation-took-effect)
comes from a run on 2026-11-07 on one host, with a development build of
0.5.236: the collector `hub` on `127.0.0.2` and the sender `edge-a` on
`127.0.0.1`.

## How it works

- Each instance serves `GET /v1/inventory` on its REST API (`--api`). See
  [GET /v1/inventory](rest-api.md#get-v1inventory) for every field.
- `sipnab fleet inventory` runs on one machine, the controller. It reads a
  hosts file and asks every instance in it at once. The instances never
  connect to the controller.
- Each request carries a bearer token with scope `inventory`. That token reads
  the inventory and nothing else: no dialogs, no messages, no audio.
- The answer holds no configuration value and no command-line argument, only
  their SHA-256 digests.
- The command reads at most 16 KiB of each answer's status line and headers
  (`MAX_HEAD_BYTES`) and at most 4 MiB of its body (`MAX_ANSWER_BYTES`). The
  inventories in this page's run were under 2 KB each.

## Before you start

- **sipnab on each instance.** A build whose `sipnab --version` lists the
  `api` feature, and that serves `GET /v1/inventory`. An older build answers
  `404` there, and the report marks it `refused`.
- **sipnab on the controller.** Any build with the `api` feature. It needs no
  capture privilege: it opens no capture.
- **TLS for each instance's API.** A certificate whose subject alternative
  name is the address or name in the instance's URL, its key readable by the
  sipnab user only, and the certificate of the issuing CA on the controller.
  Plain `http://` works too, and sends the token in clear text.
- **A signing key on each instance**, in a file only the sipnab user can read.
  [Set up authentication](auth.md) shows how to create one.
- **Network.** The controller reaches each instance's API port over TCP, 8443
  in this page's examples. Open that port to the controller's address only.
  The instances need no route to the controller.
- **Other systems.** No change. OpenSIPS, Kamailio, Homer and a HEP collector
  keep their configuration. A collector that runs sipnab joins the list like
  any other instance.

## Step 1: run each instance with the REST API over TLS

- **[each instance]** Add `--api`, the TLS certificate and key, the signing key
  and a node name to the instance's command line. This is the instance
  `edge-a` from the run, which reads a capture file and sends HEP to the
  collector `hub`:

  ```bash
  sipnab -N -I /var/lib/sipnab/sample.pcap --config /etc/sipnab/edge-a.toml \
    --hep-send 192.0.2.10:9060 --hep-auth-mode hmac --hep-auth-file /etc/sipnab/hep.key \
    --api 192.0.2.11:8443 --api-tls-cert /etc/sipnab/edge-a.crt --api-tls-key /etc/sipnab/edge-a.key \
    --api-signing-key-file /etc/sipnab/edge-a.signing --node-name edge-a
  ```

  The collector ran with the same API flags and its HEP listener:

  ```bash
  sipnab -N --config /etc/sipnab/hub.toml \
    --hep-listen 192.0.2.10:9060 --hep-auth-mode hmac --hep-auth-file /etc/sipnab/hep.key \
    --api 192.0.2.10:8443 --api-tls-cert /etc/sipnab/hub.crt --api-tls-key /etc/sipnab/hub.key \
    --api-signing-key-file /etc/sipnab/hub.signing --node-name hub
  ```

  Each instance logs `REST API listening on <address>` when its API is up.

## Step 2: mint an inventory token on each instance

- **[each instance]** Mint a token with that instance's signing key:

  ```bash
  sipnab --mint-token --token-scope inventory --token-id fleet-controller \
    --api-signing-key-file /etc/sipnab/edge-a.signing --api-token-ttl 2592000
  ```

  It prints one token, starting `s2.`, and exits. `--api-token-ttl 2592000`
  makes it valid for 30 days.

- **[controller]** Save each token in its own file, readable by the
  controller's user only:

  ```bash
  install -m 600 /dev/null /etc/sipnab/fleet/edge-a.token
  ```

  Then paste the token into it. sipnab refuses a token file that other users
  can read.

## Step 3: write the hosts file

- **[controller]** Write `/etc/sipnab/fleet/fleet.toml`, one `[[host]]` table
  per instance. This is the file from the run:

  ```toml
  [[host]]
  name = "hub"
  url = "https://192.0.2.10:8443"
  token_file = "/etc/sipnab/fleet/hub.token"
  ca_file = "/etc/sipnab/fleet/internal-ca.pem"

  [[host]]
  name = "edge-a"
  url = "https://192.0.2.11:8443"
  token_file = "/etc/sipnab/fleet/edge-a.token"
  ca_file = "/etc/sipnab/fleet/internal-ca.pem"

  [[host]]
  name = "edge-b"
  url = "https://192.0.2.12:8443"
  token_file = "/etc/sipnab/fleet/edge-b.token"
  ca_file = "/etc/sipnab/fleet/internal-ca.pem"
  ```

  - `name` is the name the report shows. Each name appears once.
  - `url` is the instance's REST API, `https://` or `http://`.
  - `token_file` holds the instance's `inventory` token on one line.
  - `ca_file` is optional: a PEM CA file to trust instead of the host's CA
    bundle.

  sipnab refuses an unknown key, an empty name, an empty URL and a name used
  twice, with exit `2`.

## Step 4: read the fleet

- **[controller]** Run:

  ```bash
  sipnab fleet inventory --hosts /etc/sipnab/fleet/fleet.toml
  ```

  Output from the run:

  ```text
  NAME             STATE        VERSION      COMMIT       BINARY       CONFIG          UID   UPTIME_S
  hub              ok           0.5.232      29204db7     6bba53867ecd ec09522b49b4   1000         54
  edge-a           ok           0.5.232      29204db7     6bba53867ecd 6a434df0c5e2   1000         40
  edge-b           ok           0.5.232      29204db7     6bba53867ecd f63dfdce2c9d   1000         39
  ```

  It exited `0`.

  - `BINARY` and `CONFIG` are the first 12 hex digits of `binary.sha256` and
    `config.effective_sha256`. The three instances run one binary and three
    configurations: each has its own config file and node name.
  - `--json` prints the whole report, with every instance's full inventory.
  - `--timeout <SECS>` sets how long each instance has to answer. Default `10`.

## Verify

- **Every instance is `ok`, and there is no `finding` line.** That is exit
  `0`.
- **Two instances you expect to match show one `CONFIG`.** Two instances with
  the same `CONFIG` loaded the same configuration values and run the same
  command line. A different `--node-name` alone gives a different `CONFIG`.
- **The exit status** says the same for a script:

  | Code | Meaning |
  |---|---|
  | `0` | Every instance answered and there is no finding. |
  | `1` | An instance did not answer, refused the token, or sent an inventory this build cannot read; or there is a finding. |
  | `2` | sipnab cannot read or use the hosts file. |

## Troubleshoot

Each output below comes from the same run, with one thing changed.

- **`unreachable` and `connection timed out`.** Nothing answered at that
  address within `--timeout`: the instance is down, the URL names the wrong
  address or port, or a firewall drops the controller's packets. The other
  instances are still listed:

  ```text
  edge-c           unreachable  192.0.2.14:8443: connection timed out
  ```

  `Connection refused` instead means the host answered and nothing listens on
  that port: check `--api` on the instance.

- **`unreachable` and `invalid peer certificate: UnknownIssuer`.** The
  controller does not trust the CA that issued the instance's certificate. Set
  `ca_file` for that host:

  ```text
  hub              unreachable  sending: invalid peer certificate: UnknownIssuer
  ```

- **`refused` with HTTP `401`.** The instance did not accept the token: it was
  minted with another instance's signing key, it expired, someone revoked it, or
  its scope is not `inventory`, `full`, `actions` or `admin`. Mint a new one
  on that instance (step 2). This run gave `edge-b` the hub's token:

  ```text
  edge-b           refused      the instance answered HTTP 401
  ```

- **`refused` with HTTP `404`.** The instance runs a build without
  `GET /v1/inventory`. Upgrade it. Release 0.5.130 answered:

  ```text
  edge-old         refused      the instance answered HTTP 404
  ```

  Release 0.5.130 also refuses `--token-scope inventory` at mint time, with
  `invalid value 'inventory' for '--token-scope <SCOPE>'`.

- **`unreachable` and `can be read or written by other users`.** The token
  file's mode lets other users read it. Run `chmod 600` on it:

  ```text
  edge-a           unreachable  token_file '/etc/sipnab/fleet/open.token' can be read or written by other users (mode 0644); chmod 600 it
  ```

- **`finding hep_sender_refused`.** A collector in the list refuses the HEP of
  an instance in the list for authentication. See
  [A listed sender the collector refuses](#a-listed-sender-the-collector-refuses).

- **`finding unlisted_hep_sender`.** A collector in the list receives HEP
  from an address that no listed instance's URL resolves to. Add that sender
  to the hosts file, or find out why it sends. With `edge-b` left out of the
  file:

  ```text
  finding unlisted_hep_sender: hub receives HEP from 192.0.2.12, which is no instance in the hosts file
  ```

  The check compares addresses only. A sender whose packets leave from a
  different address than its API URL names shows up as unlisted.

- **`incompatible` and a `schema_version`.** The instance answered an
  inventory format newer than the controller reads. Upgrade the controller's
  sipnab. No release answers a newer format yet, so this output comes from a
  test server that answered `schema_version` 2:

  ```text
  edge-next        incompatible the instance answered inventory schema_version 2; this sipnab reads up to 1
  ```

## A listed sender the collector refuses

A collector that refuses a sender's HEP drops every packet it refuses. The
sender counts them as sent, because UDP reports no delivery, so neither end
fails. The report names that sender, and exits `1`, while the collector
refused the latest packet it received from it.

- **[controller]** Run the report. In this run `edge-a` sent with a key the
  collector `hub` does not hold:

  ```bash
  sipnab fleet inventory --hosts /etc/sipnab/fleet/fleet.toml
  ```

  ```text
  NAME             STATE        VERSION      COMMIT       BINARY       CONFIG          UID   UPTIME_S
  hub              ok           0.5.236      fd7d466e     d7cd2b7e5769 a5dc546e4913   1000          5
  edge-a           ok           0.5.236      fd7d466e     d7cd2b7e5769 79480fa13223   1000          3
  finding hep_sender_refused: hub refused 7 HEP packets from edge-a (127.0.0.1): refused: authentication (wrong key or HMAC version); the collector's reasons: hmac_bad_mac 7
  ```

  It exited `1`.

  - The finding names the collector, every listed instance whose URL resolves
    to the refused address, the address, and the authentication refusals only.
  - `refused: authentication (wrong key or HMAC version)` names both causes and
    claims neither. A sender with the wrong key, and a sender on a different
    HEP HMAC version, can both arrive as a MAC that does not verify, depending
    on which build each end runs.
  - `the collector's reasons` are the collector's own refusal reasons, with
    the names `GET /v1/hep/senders` uses: `hmac_bad_mac` for a MAC that does
    not verify, `hmac_unsupported_version` for a version-1 token on a collector
    on 0.5.131 or later, `auth_mismatch` for a wrong `plain` key, and
    `auth_missing`, `hmac_bad_format`, `hmac_timestamp_out_of_window` and
    `hmac_replay`. Refusals for other reasons, such as the rate limit or the
    allowlist, are not this finding.

- **[controller]** See the collector's refusals, from the same report:

  ```bash
  sipnab fleet inventory --hosts /etc/sipnab/fleet/fleet.toml --json \
    | jq -c '.hosts[] | {name, refused: .inventory.hep_listener.refused_sources}'
  ```

  ```text
  {"name":"hub","refused":[{"by_reason":{"hmac_bad_mac":7},"last_seen":"2026-11-07T12:52:30.675Z","packets":7,"peer":"127.0.0.1"}]}
  {"name":"edge-a","refused":[]}
  ```

- **[sender]** Fix the sender. Give it the collector's key, or upgrade it to
  the collector's build when the reason is `hmac_unsupported_version`, as
  [Upgrade a fleet that uses HMAC authentication](config-reference.md#upgrade-a-fleet-that-uses-hmac-authentication)
  describes. Restart it.

- **[controller]** Verify. The collector keeps counting the old refusals for as
  long as it runs, but it has admitted the sender since its last refusal, so
  the report has no finding and exits `0`:

  ```bash
  sipnab fleet inventory --hosts /etc/sipnab/fleet/fleet.toml --json \
    | jq -c '.hosts[0].inventory.hep_listener | {senders: [.senders[] | {peer, last_seen}], refused: [.refused_sources[] | {peer, packets, last_seen}]}'
  ```

  ```text
  {"senders":[{"peer":"127.0.0.1","last_seen":"2026-11-07T12:52:43.016Z"}],"refused":[{"peer":"127.0.0.1","packets":7,"last_seen":"2026-11-07T12:52:30.675Z"}]}
  ```

**Troubleshoot:**

- **The collector refuses the sender, and there is no finding.** The refused address is no
  listed instance's: the check compares addresses, as `unlisted_hep_sender`
  does. A sender whose packets leave from another address than its API URL
  names is not matched. Read the collector's `refused_sources` as above.
- **No `refused_sources` at all.** A collector on a build before this check
  does not report them. Its `packets_refused` still counts every refusal.
- **The finding stays after the fix.** The collector has not admitted a packet
  from that address since its last refusal: the sender is not sending yet, or
  is still refused. Its `last_seen` in `senders` must be later than in
  `refused_sources`.

## Check that a key rotation took effect

The configuration digests cover a key file's path only, so replacing the key
in it changes no digest. Each instance therefore reports, for every secret or
credential file it named, the file's inode and modification time when it
started, under the setting that named it. The answer holds nothing derived
from the key. See [GET /v1/inventory](rest-api.md#get-v1inventory) for the
fields.

- **[each instance]** Rotate the key the usual way: write the new key to a new
  file, rename it over the old one, and restart sipnab. This run fixed
  `edge-a`'s HEP key:

  ```bash
  install -m 600 hep.key edge-hep.key.new && mv edge-hep.key.new edge-hep.key
  ```

- **[controller]** Before and after the restart, read each instance's stamps:

  ```bash
  sipnab fleet inventory --hosts /etc/sipnab/fleet/fleet.toml --json \
    | jq -c '.hosts[] | {name, secrets: [.inventory.config.secret_files[] | {setting, inode, mtime}]}'
  ```

  Before:

  ```text
  {"name":"hub","secrets":[{"setting":"--api-signing-key-file","inode":6849703,"mtime":"2026-11-07T12:41:19.472148552Z"},{"setting":"--hep-auth-file","inode":6849697,"mtime":"2026-11-07T12:41:19.472148552Z"}]}
  {"name":"edge-a","secrets":[{"setting":"--api-signing-key-file","inode":6849705,"mtime":"2026-11-07T12:41:19.476148542Z"},{"setting":"--hep-auth-file","inode":6852341,"mtime":"2026-11-07T12:52:28.642390890Z"}]}
  ```

  After:

  ```text
  {"name":"hub","secrets":[{"setting":"--api-signing-key-file","inode":6849703,"mtime":"2026-11-07T12:41:19.472148552Z"},{"setting":"--hep-auth-file","inode":6849697,"mtime":"2026-11-07T12:41:19.472148552Z"}]}
  {"name":"edge-a","secrets":[{"setting":"--api-signing-key-file","inode":6849705,"mtime":"2026-11-07T12:41:19.476148542Z"},{"setting":"--hep-auth-file","inode":6817841,"mtime":"2026-11-07T12:52:41.958355975Z"}]}
  ```

**Verify:** the rotated file's `inode` or `mtime` changed on the instance you
rotated, and on no other. `CONFIG` did not change: the path is the same.

**Troubleshoot:**

- **Nothing changed.** The instance has not restarted: sipnab takes the stamp
  at start, and it describes the file the run read. Restart it.
- **Only `mtime` changed.** The key was rewritten in place rather than
  replaced. That is a rotation too.
- **`error` holds a reason.** The instance could not stat the file at start, for
  example `No such file or directory (os error 2)`. The reason never names the
  path.

## Run a fleet center

A fleet center is a sipnab, `sipnab fleet serve`, that fleet members push
heartbeats to. Each heartbeat carries the member's inventory, the record
`GET /v1/inventory` answers. The center keeps the newest heartbeat of each
member, and answers "which members are there, what do they run, and which went
silent" on `GET /v1/fleet/members`, without asking any member.

Use it when the controller cannot reach every member, such as members behind
NAT, or to learn that a member stopped without polling it. It is phase P1 of
the fleet center: heartbeats only, no traffic. A capture run becomes a member
with `--fleet-report-url` (or `[fleet] report_url`), as
[Make an instance a fleet member](#make-an-instance-a-fleet-member) shows.
Step 3 sends one heartbeat by hand, in the format a member sends.

The output in this section comes from a run on 2026-11-07 on one host, with a
development build of 0.5.236: the center on `127.0.0.1:8444` over HTTPS, and
one instance, `edge-a`, on `127.0.0.1:18080`. The run kept its files in one
working directory. The commands name them as a deployment would, under
`/etc/sipnab` and `/var/lib/sipnab`, and the log lines show the names the run
used.

### Before you start a center

- **sipnab on the center.** A build with the `api` feature. It opens no
  capture and needs no capture privilege.
- **A TLS certificate for the center**, whose subject alternative name is the
  address or name members use, its key readable by the center's user only, and
  the certificate of the issuing CA on each member. The center refuses plain HTTP on
  any address but loopback, because members send their token and their
  inventory.
- **A signing key for the center**, in a file only the center's user can read.
  The center mints and verifies member tokens with it. It is not any member's
  REST API key.
- **A store key for the center**, in a file only the center's user can read.
  The center encrypts its store under it, and does not start without it.
  Step 1 creates it. [Encrypt the center's store](#encrypt-the-centers-store)
  covers backup and rotation.
- **Network.** Each member reaches the center's port over TCP, 8444 in this
  section. The center needs no route to the members.
- **Disk.** The store file holds the newest heartbeat of each member: 1,884
  and 1,883 bytes of JSON for the two members of this run. Encryption adds 21
  bytes to each record and 120 bytes to the file.
- **Bounds.** The center reads at most 4 MiB of one request
  (`MAX_INGEST_BYTES`) and answers `413` past it. Its rate limit counts at most
  4096 addresses in one second (`MAX_TRACKED_PEERS`); a further address in
  that second gets `503`, with `--rate-limit-per-peer` above `0`.
- **Other systems.** No change. OpenSIPS, Kamailio, Homer and any HEP collector
  keep their configuration.

### Step 1: start the center

- **[center]** Create the signing key, readable by the center's user only:

  ```bash
  # Run all of these, in order.
  install -m 600 /dev/null /etc/sipnab/center.signing
  head -c 32 /dev/urandom | base64 > /etc/sipnab/center.signing
  ```

- **[center]** Create the store key, and copy it to your backup. The
  command writes the file with mode `0600` and prints the key's id:

  ```bash
  sipnab fleet keygen --out /etc/sipnab/center.storekey
  ```

  ```text
  store.key: key id ac7b02adecf75d31
  ```

- **[center]** Start it:

  ```bash
  sipnab fleet serve --listen 127.0.0.1:8444 --store /var/lib/sipnab/center.store \
    --store-key-file /etc/sipnab/center.storekey \
    --signing-key-file /etc/sipnab/center.signing \
    --tls-cert /etc/sipnab/center.crt --tls-key /etc/sipnab/center.key
  ```

  ```text
  INFO sipnab::app::fleet_center: fleet center store 'center.store': 0 member(s), 0 past --retention-hours 72 removed
  INFO sipnab::app::fleet_center: fleet center serving HTTPS on 127.0.0.1:8444
  INFO sipnab::output::api: REST API serves HTTPS only (TLS 1.2/1.3, ALPN http/1.1)
  INFO sipnab::output::api: REST API listening on 127.0.0.1:8444
  ```

  A center after 0.5.242 also logs the key it encrypts the store under,
  before the store line. This line is from a run on 2026-11-10:

  ```text
  INFO sipnab::app::fleet_center: fleet center store encryption sealed, key id ac7b02adecf75d31, 0 old key(s)
  ```

  It creates the store with mode `0600`, encrypted. It removes a member it has not heard
  from for `--retention-hours` (default 72), at start and every minute.
  `--silent-after-missed` (default 3) sets how many of a member's heartbeat
  intervals may pass before it is silent. Members reaching the center by a name
  need that name in `--allowed-host`. [The CLI reference](cli-reference.md#fleet-inventory-sipnab-fleet)
  lists every flag.

- **[center]** To refuse any member without a certificate from your own CA,
  as well as its token, add `--tls-client-ca /etc/sipnab/members-ca.pem`.
  [Require member certificates on a fleet center](mtls.md#require-member-certificates-on-a-fleet-center)
  makes the CA and the member certificates, and says how a member presents
  one.

### Step 2: mint a token for each member and for each reader

- **[center]** A member's token has scope `fleet-report`, and its id is the
  member's name. The center vouches for that name, and for nothing else the
  member says:

  ```bash
  sipnab --mint-token --token-scope fleet-report --token-id edge-a \
    --api-signing-key-file /etc/sipnab/center.signing --api-token-ttl 2592000
  ```

  It prints one token, starting `s2.`. A `fleet-report` token reaches the
  center's ingest and nothing else, on the center and on every other sipnab.
  Give each member its own token, so revoking one leaves the others working.

- **[center]** A token that reads the members list has scope `inventory`, as
  for `sipnab fleet inventory`:

  ```bash
  sipnab --mint-token --token-scope inventory --token-id fleet-reader \
    --api-signing-key-file /etc/sipnab/center.signing --api-token-ttl 2592000
  ```

### Make an instance a fleet member

A member writes its inventory as a heartbeat every `[fleet] heartbeat_secs`
(default 30) into its spool directory, and sends the spool to the center,
oldest first. While the center is away the heartbeats wait, and the capture
goes on: the member runs on a thread of its own and the capture never waits
on it. The spool keeps at most `[fleet] spool_max_files` (default 2880, a day
at 30 s) and drops the oldest past that. A heartbeat the center refuses for
good (`400`, `413`) moves to `failed/` in the spool.

The output below comes from a second run on 2026-11-07 on one host: the
center on `127.0.0.1:8444` over HTTPS, and `edge-a` reading a capture file
with its REST API on `127.0.0.1:18080`, reporting every 5 seconds.

- **Other systems.** The member opens TCP connections to the center's port:
  open it outbound from each member. Nothing else changes.

- **[member]** Put the token minted in step 2 in a file only the sipnab user
  can read, then add a `[fleet]` section to the member's configuration:

  ```toml
  [fleet]
  report_url = "https://127.0.0.1:8444"
  report_token_file = "/etc/sipnab/fleet/edge-a.report.token"
  report_ca_file = "/etc/sipnab/fleet/internal-ca.pem"
  spool_dir = "/var/lib/sipnab/fleet-spool"
  heartbeat_secs = 5
  ```

  The flags `--fleet-report-url`, `--fleet-report-token-file`,
  `--fleet-report-ca-file` and `--fleet-spool-dir` set the same and override
  the keys. `report_url` takes `http://` only to loopback: sipnab refuses
  plain HTTP to another machine and does not start (exit `2` for a flag, `1`
  for a key).

- **[member]** Start the run as usual. It logs where it reports:

  ```text
  INFO sipnab::app::fleet_member: fleet member reporting to https://127.0.0.1:8444/ every 5 s, spool 'fleet-spool'
  ```

- **[controller]** The center lists the member, with the member's own
  inventory under `self_reported`:

  ```text
  {"member":"edge-a","silent":false,"seconds_since_heartbeat":3,"verified":{"heartbeats":2,"peer":"127.0.0.1","received_at":"2026-11-07T18:31:28Z"},"node":"edge-a","interval":5,"seq":2}
  ```

  That line comes from the members list through
  `jq -c '.members[] | {member, silent, seconds_since_heartbeat, verified, node: .self_reported.inventory.node_name, interval: .self_reported.heartbeat_secs, seq: .self_reported.seq}'`.

**Verify the member:**

- **The center goes away.** This run stopped the center for 12 seconds. The
  member logged it once, its REST API still answered `200`, and two
  heartbeats waited in the spool (`00000000000000000005.json` and
  `00000000000000000006.json`):

  ```text
  WARN sipnab::app::fleet_member: fleet member: heartbeats wait in the spool: the center did not answer: 127.0.0.1:8444: Connection refused (os error 111)
  ```

- **The center returns.** The spool drained, and the center counted every
  heartbeat once: `heartbeats` 8 for `seq` 8.

  ```text
  INFO sipnab::app::fleet_member: fleet member: the center takes heartbeats again (was: the center did not answer: 127.0.0.1:8444: Connection refused (os error 111))
  ```

  The returned center first reported `edge-a` silent, from the time of its last
  heartbeat before the outage, then `heard again` once the spool drained.

- **The member stops.** This run killed `edge-a`. The center reported it
  silent three 5 s intervals later:

  ```text
  WARN sipnab::app::fleet_center: fleet member 'edge-a' is silent: no heartbeat for 15 s, more than 3 of its 5 s intervals
  ```

**Troubleshoot the member:**

- **`the center refused this member's token (HTTP 401)`.** The token was not
  minted with this center's key, it expired, or the center revoked its id.
  The heartbeats wait in the spool. Mint a new token on the center (step 2),
  put it in the token file, and restart the member: the member reads the
  token once, at start.
- **`the center did not answer`.** The center is down, or a firewall drops
  the member's connections. The heartbeats wait; nothing needs doing on the
  member once the center is back.
- **`the center did not answer: sending: invalid peer certificate: UnknownIssuer`.**
  The member does not trust the center's certificate. Set `report_ca_file` to
  the certificate of the issuing CA.
- **`the spool holds [fleet] spool_max_files`.** The center was away long
  enough to fill the spool, and the member dropped the oldest heartbeats. A newer
  heartbeat says everything an older one did.

### Step 3: send a heartbeat by hand

A heartbeat is one JSON record per line, `POST`ed to `/v1/fleet/ingest` with
the member's token:

| Field | Meaning |
|---|---|
| `schema_version` | `1`. |
| `kind` | `heartbeat`. |
| `stream` | The member's delivery stream: 1 to 64 letters, digits, `.`, `_` or `-`, chosen once. |
| `seq` | The record's place in the stream, from `1`. |
| `sent_at` | When the member wrote it, [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html). |
| `heartbeat_secs` | How often the member sends one, 1 to 3600. |
| `inventory` | The member's `GET /v1/inventory` answer. |

The center counts a record once. In the same stream a record is new when its
`seq` is past the newest one the center accepted. A record of another stream
is new when its `sent_at` is later: a member that recreates its spool starts
a new stream. The center counts a batch sent twice once, also after it
restarts.

- **[member]** Send `edge-a`'s inventory as a heartbeat:

  ```bash
  # Run all of these, in order.
  curl -s -H "Authorization: Bearer $EDGE_A_INVENTORY_TOKEN" http://127.0.0.1:18080/v1/inventory \
    | jq -c '{schema_version: 1, kind: "heartbeat", stream: "edge-a-manual", seq: 1, sent_at: (now | todate), heartbeat_secs: 30, inventory: .}' \
    > heartbeat.ndjson
  curl -s --cacert /etc/sipnab/fleet/internal-ca.pem -H "Authorization: Bearer $EDGE_A_REPORT_TOKEN" \
    -H 'Content-Type: application/x-ndjson' --data-binary @heartbeat.ndjson \
    https://127.0.0.1:8444/v1/fleet/ingest
  ```

  ```text
  {"accepted":1,"duplicate":0,"member":"edge-a"}
  ```

  Sent again, the same file is a duplicate:

  ```text
  {"accepted":0,"duplicate":1,"member":"edge-a"}
  ```

### Verify the center

- **[controller]** Read the members:

  ```bash
  curl -s --cacert /etc/sipnab/fleet/internal-ca.pem -H "Authorization: Bearer $FLEET_READER_TOKEN" \
    https://127.0.0.1:8444/v1/fleet/members | jq 'del(.members[].self_reported.inventory)'
  ```

  ```json
  {
    "members": [
      {
        "member": "edge-a",
        "seconds_since_heartbeat": 0,
        "self_reported": {
          "heartbeat_secs": 30,
          "sent_at": "2026-11-07T15:41:36Z",
          "seq": 1,
          "stream": "edge-a-manual"
        },
        "silent": false,
        "verified": {
          "heartbeats": 1,
          "peer": "127.0.0.1",
          "received_at": "2026-11-07T15:41:36Z"
        }
      }
    ],
    "now": "2026-11-07T15:41:36Z",
    "retention_hours": 72,
    "schema_version": 1,
    "silent_after_missed": 3
  }
  ```

  - `member` is the id of the token the heartbeat came with. The center
    verified it.
  - `verified` is what the center saw: when the newest heartbeat arrived, on
    the center's clock, from which address, and how many heartbeats it
    accepted from this member.
  - `self_reported` is what the member says about itself: its stream, place,
    send time, interval and `inventory`, the record in
    [GET /v1/inventory](rest-api.md#get-v1inventory). A member that is not
    honest can put anything there.
  - `silent` is `true` once more than `silent_after_missed` of the member's
    intervals passed with no heartbeat, measured on the center's clock.

- **[center]** The center logs a member going silent, and coming back. In this run
  `edge-b` sent one heartbeat with a 1 s interval:

  ```text
  WARN sipnab::app::fleet_center: fleet member 'edge-b' is silent: no heartbeat for 3 s, more than 3 of its 1 s intervals
  INFO sipnab::app::fleet_center: fleet member 'edge-b' is heard again
  ```

### Revoke a member

- **[center]** Start the center with `--revoked-file`, and add the member's
  token id to that file, one per line. sipnab re-reads the file when it
  changes, so the center keeps running. This run revoked `edge-a`:

  ```bash
  echo edge-a >> /etc/sipnab/center.revoked
  ```

  `edge-a`'s next heartbeat gets `401`, and `edge-b`'s still gets `200`. The
  members list keeps `edge-a`'s last heartbeat until retention removes it.

### Encrypt the center's store

**Purpose.** The center's store holds every member's inventory: node names,
versions, configuration digests, addresses. The center never writes it in
clear. It seals the store file with AES-256-GCM under a key that you keep in
a file, and it refuses to start without that key. A center cannot run with
encryption off.

The outputs below come from a run on 2026-11-10 on one host, with a
development build after 0.5.242 and the files in one working directory.

**Before you start.**

- **A sipnab after 0.5.242 on the center.** Members need no change, and no
  other system does: OpenSIPS, Kamailio, Homer and any HEP collector keep
  their configuration.
- **A place to back up one small file**, apart from the center's disk. Whoever
  holds the key file can read the store. Without the key file nobody can.
- **A center from 0.5.237 to 0.5.242** wrote its store in clear and took no
  key. After the upgrade it does not start until you give it
  `--store-key-file`. On the first start with a key it reads the old store,
  writes it encrypted and replaces the file. The old bytes may stay on the
  disk's free space until the file system reuses it.

**Steps.**

1. **[center]** Create the key. The file gets mode `0600`. The id it prints
   is not secret: the center logs it, and a refusal names it.

   ```bash
   sipnab fleet keygen --out /etc/sipnab/center.storekey
   ```

   ```text
   store.key: key id ac7b02adecf75d31
   ```

2. **[center]** Copy `/etc/sipnab/center.storekey` to your backup, and note
   the key id beside it.

3. **[center]** Start the center with `--store-key-file`, as
   [Step 1](#step-1-start-the-center) shows, or add the flag to the service
   unit of a center you upgraded.

4. **To replace the key**, create a second key file, and start the center
   once with the new file as `--store-key-file` and the old one as
   `--store-old-key-file`:

   ```bash
   # Run all of these, in order.
   sipnab fleet keygen --out /etc/sipnab/center.storekey.2
   sipnab fleet serve --listen 127.0.0.1:8444 --store /var/lib/sipnab/center.store \
     --store-key-file /etc/sipnab/center.storekey.2 \
     --store-old-key-file /etc/sipnab/center.storekey \
     --signing-key-file /etc/sipnab/center.signing \
     --tls-cert /etc/sipnab/center.crt --tls-key /etc/sipnab/center.key
   ```

   ```text
   INFO sipnab::app::fleet_center: fleet center store encryption sealed, key id dd70bddbd340fae5, 1 old key(s)
   ```

   The center rewrites the store under the new key as it starts. From the
   next start on, leave `--store-old-key-file` out, back up the new key file
   and destroy the old one.

**Verify.**

- The center's first log line names the key id that `keygen` printed.
- The store is a sealed file. Its first four bytes are `SNFS`, and no
  member's name is in it:

  ```bash
  # Run all of these, in order.
  head -c 4 /var/lib/sipnab/center.store; echo
  grep -c edge-a /var/lib/sipnab/center.store
  ```

  ```text
  SNFS
  0
  ```

- `GET /v1/fleet/members` lists the same members after a restart.

**What it covers and what it does not.** The center seals the store file and
the file it stages a rewrite in, and writes no other file. It authenticates
each record with the record's position in the file, so a changed byte, a
moved record or a store cut short inside the records of its last rewrite
stops the center at start. Two things it cannot detect: someone deleting the
whole store, and someone removing records from the end of the file that the
center appended after its last rewrite. The center rewrites the store at
start and every minute. `--store-encryption` names how the center encrypts
the store. This release has one mechanism, `sealed`, and refuses the values
`modular` and `both`.

**Troubleshoot.** Each message stops the center with exit `2`, and none
shows a key.

- **`--store-key-file is required`.** The center has no key. Create one and
  pass it:

  ```text
  sipnab fleet serve: --store-key-file is required: the center encrypts everything it stores. Create a key with `sipnab fleet keygen --out FILE` and pass --store-key-file FILE
  ```

- **`which is not loaded`, after a key id.** The store is under
  another key than the one given. Give the file of the key with that id as
  `--store-key-file`, or as `--store-old-key-file` beside a new key. The
  center leaves the store as it found it:

  ```text
  sipnab fleet serve: --store 'center.store': sealed layer: the file was written under key id ac7b02adecf75d31, which is not loaded; give that key's file with --store-old-key-file
  ```

- **`did not authenticate`, or `was truncated`.** Something changed the
  store or cut it short after the center wrote it. The center leaves it as it
  found it. Restore the store from a copy, or move it away and start with an
  empty store: the members report again within one heartbeat interval each,
  and the list loses only a member that is silent now.

  ```text
  sipnab fleet serve: --store 'center.store': sealed layer: the file has a header that did not authenticate (the file was modified, or the key is wrong)
  ```

- **`can be read or written by other users`**, naming the key file. Run
  `chmod 600` on it:

  ```text
  sipnab fleet serve: --store-key-file 'store.key' can be read or written by other users (mode 0644); chmod 600 it
  ```

- **`is not a key`.** The file does not hold 32 bytes in base64. Use the file
  `keygen` wrote, unchanged:

  ```text
  sipnab fleet serve: --store-key-file 'bad.key' is not a key: it holds 3 bytes, and a key is 32; create a key with `sipnab fleet keygen --out FILE`
  ```

- **`File exists`, from `keygen`.** `keygen` never overwrites a file, because
  it may be the only copy of a key. Name a new file:

  ```text
  sipnab fleet keygen: --out 'store.key': File exists (os error 17)
  ```

- **`this build cannot read or write Parquet modular encryption`.** Leave
  `--store-encryption` out, or set it to `sealed`:

  ```text
  sipnab fleet serve: --store-encryption modular: this build cannot read or write Parquet modular encryption; `sealed` is the one value it runs under
  ```

### Troubleshoot the center

Each output below comes from the same run.

- **`401` on the ingest.** The token is not a `fleet-report` token this
  center's key signed, it expired, or its id is in the revocation file. A `full`, `admin` or
  `inventory` token gets `401` there too: only a member's token reports.
  Mint one as in step 2.

  ```text
  401 {"status":401,"title":"Unauthorized","type":"https://sipnab.com/problems/unauthorized"}
  ```

- **`401` on the members list.** The token is a member's token, which reads
  nothing. Use an `inventory` token.

- **`403` and `the token's id names no member`.** The token's `--token-id` has
  characters a member name cannot have. This run minted one with the id
  `edge a`:

  ```text
  403 {"detail":"the token's id names no member: mint it with --token-id of 1 to 64 letters, digits, '.', '_' or '-'","status":403,"title":"Forbidden","type":"https://sipnab.com/problems/forbidden"}
  ```

- **`400` and a line number.** A record in the batch is not one the center
  reads, and the center accepted none of the batch. The detail names the line
  and the field:

  ```text
  400 {"detail":"line 2: not a record: expected ident at line 1 column 2","status":400,"title":"Bad Request","type":"https://sipnab.com/problems/bad-request"}
  ```

- **`plain HTTP is refused except on loopback`.** The command line names an
  address other than loopback and no `--tls-cert` and `--tls-key`. It exits
  `2` before it creates the store:

  ```text
  sipnab fleet serve: --listen 192.0.2.10:8444 without --tls-cert and --tls-key would take members' tokens and inventories in plain HTTP; plain HTTP is refused except on loopback
  ```

- **`can be read or written by other users`.** Other users can read the store
  file. Run `chmod 600` on it. It exits `2`:

  ```text
  sipnab fleet serve: --store 'center.store' can be read or written by other users (mode 0644); chmod 600 it
  ```

- **A member stays `silent`.** The center has had no heartbeat from it for
  more than `silent_after_missed` of its intervals: the member is down, cannot
  reach the center, or the center refuses its token. `seconds_since_heartbeat` says
  how long ago the last one arrived.

[docs/errors.md](errors.md#fleet-center-sipnab-fleet-serve) lists every message
the center prints.

## States and findings

**State of each instance:**

| State | Meaning |
|---|---|
| `ok` | It answered with an inventory. |
| `refused` | It answered with an HTTP status other than 200, such as `401` for a wrong, expired or narrower token, or `404` for a build without the inventory. |
| `unreachable` | No answer: no connection, a timeout, a TLS failure, a token file sipnab would not read, or an answer that is not JSON. |
| `incompatible` | Its inventory has a `schema_version` newer than this build reads, or none. Upgrade the controller's sipnab. |

**Findings across the fleet:**

| Finding | Meaning |
|---|---|
| `version_mismatch` | The instances that answered do not all run the same build. The finding names each build and the instances on it. |
| `unlisted_hep_sender` | A HEP collector in the list receives from an address that no listed instance's URL resolves to. |
| `hep_sender_refused` | A HEP collector in the list refused packets from a listed instance's address for authentication, and has not admitted a packet from it since. |

## Check a binary against its release

Every instance reports `signature.state` as `unverified`. A process cannot
prove which binary it is, and one that someone had tampered with would report
"verified" too.

- Download `SHA256SUMS.txt` from the release the instance claims, and verify
  it:

  ```bash
  gh attestation verify SHA256SUMS.txt --repo NormB/sipnab
  ```

- Compare the instance's `binary.sha256` with the line for its artifact. On
  Linux the instance hashes `/proc/self/exe`, so after an upgrade replaces the
  file the digest still names the binary that is running.

## What it cannot tell you

- Every field is the instance's own claim. An attacker who controls a host can make
  it report anything.
- For a secret held in a file, the digests cover its path only. Replacing the
  contents of such a file, for example rotating the key in
  `--api-signing-key-file`, changes no digest; it changes the file's `inode` or
  `mtime` in `config.secret_files` once the instance restarts. Two instances
  that hold different keys at the same path look the same: the answer holds
  nothing derived from a key. A secret given as a value, such as
  `--api-signing-key` or a `${NAME}` the configuration expands, changes
  `config.effective_sha256`.
- It reads only the instances in your hosts file. An instance nobody listed is
  invisible to it, unless it sends HEP to a listed collector.
- It changes nothing. Pushing a configuration, upgrading and restarting are not
  part of it.
