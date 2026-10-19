# Ban SIP scanners with fail2ban

[fail2ban](https://github.com/fail2ban/fail2ban) reads your servers' logs. It
bans the addresses that show up in them for the wrong reasons. It does that by
adding them to a firewall rule.

- Make your SIP server write one log line for each scanner request and each
  wrong password.
- fail2ban then bans SIP scanners and password guessers.

It is the firewall alternative to [TFPS](tfps.md):

- TFPS reads the SIP traffic itself and drops attackers with an XDP program.
- fail2ban acts on what your SIP server logged. It bans with an ordinary
  nftables rule.

This guide does the following:

- It sets up OpenSIPS as a registrar that logs scanners and failed passwords.
- It has fail2ban ban on those lines.
- It proves it from this machine with:
  - a scanner,
  - a password guesser,
  - a phone that keeps working.

This guide does not use sipnab. When fail2ban is working,
[Feed fail2ban from sipnab](fail2ban-sipnab.md) adds sipnab as a second source
of bans.

Three terms used below:

- **Filter**: the patterns that pick the failure lines out of a log, and the
  address in each.
- **Jail**: one filter put to work. A jail sets:
  - which log it reads,
  - how many failures within how long earn a ban (`maxretry`, `findtime`),
  - how long a ban lasts (`bantime`),
  - what a ban blocks.
- **Ban action**: what fail2ban runs to ban and unban.
  - Here it adds the address to an nftables set.
  - A rule beside the set refuses that set's SIP traffic.

## Tested on

Every block on this page ran as written, in order, on 2026-10-01. So did every
command in the table in "Operate it".

- The machines were clean x86_64 virtual machines with 2 cores and 3 GB of
  memory.
- They ran Debian 13 (kernel 6.12.111) and Ubuntu 24.04 (kernel 6.8.0).
- The scanner and the phone were on the same machine, as
  "Give this machine a scanner and a phone to test with"
  sets them up.
- On Debian 13, each fault under
  [When something does not work](#when-something-does-not-work) happened
  during these runs, with the message it quotes.

| Software | Version |
|---|---|
| fail2ban | the distribution's: 1.1.0 on Debian 13, 1.0.2 on Ubuntu 24.04 |
| OpenSIPS | 4.0.2, from the OpenSIPS project's packages |
| SIPp (for the test call) | the distribution's `sip-tester` |

The examples use `192.0.2.10` as the SIP server's address. Replace it with
yours everywhere it appears.

- The scanner (`198.51.100.60`) and the phone (`203.0.113.70`) are test
  addresses.
- The section "Give this machine a scanner and a phone to test with"
  creates them on this machine.

## Before you start: OpenSIPS

- Run [Install OpenSIPS](opensips.md#install-opensips) in the guide "Use OpenSIPS as your voice stack's SIP server".
  - It installs the 4.0 packages.
- Then come back here.
- The section "Make OpenSIPS log scanners and wrong passwords" below replaces that guide's configuration.
  - The new configuration authenticates phones.
  - It logs what fail2ban needs.

## Make OpenSIPS log scanners and wrong passwords

Password checks need OpenSIPS's `auth` module. It is in its own package. The
configuration below does three things:

- It registers one test account, `1001`.
- It routes its calls to a test callee on this machine.
- It writes a log line for two things:
  - a request whose `User-Agent` names a known scanner tool.
    - OpenSIPS answers it with nothing.
  - a request whose credentials are wrong: a wrong password, or a user that
    does not exist.
    - OpenSIPS does not log a request that carries no credentials yet. Such a
      request is the normal first half of a login.

```bash
# Run all of these, in order.
sudo apt-get install -y opensips-auth-modules
sudo tee /etc/opensips/opensips.cfg >/dev/null <<'EOF'
# OpenSIPS as a registrar that logs what fail2ban bans on.
log_level=3
stderror_enabled=no
syslog_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=2

socket=udp:192.0.2.10:5060

mpath="/usr/lib/x86_64-linux-gnu/opensips/modules/"

loadmodule "proto_udp.so"
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"
loadmodule "usrloc.so"
modparam("usrloc", "working_mode_preset", "single-instance-no-db")
loadmodule "registrar.so"
loadmodule "auth.so"
modparam("auth", "username_spec", "$var(username)")
modparam("auth", "password_spec", "$var(password)")
modparam("auth", "calculate_ha1", 1)

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/run/opensips/opensips_fifo")

route {
	if (!mf_process_maxfwd_header(10)) {
		send_reply(483, "Too Many Hops");
		exit;
	}

	# Scanner tools that name themselves: log, and answer nothing.
	if ($ua =~ "friendly-scanner|sipvicious|sipcli|VaxSIPUserAgent") {
		xlog("L_WARN", "SIP scanner from $si: User-Agent \"$ua\"\n");
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

	if (is_method("OPTIONS")) {
		send_reply(200, "OK");
		exit;
	}

	# The one test account. Your registrar reads its accounts from a database.
	$var(username) = "1001";
	$var(password) = "correct-horse-1001";

	if (is_method("REGISTER")) {
		if (!pv_www_authorize("")) {
			$var(rc) = $rc;
			# -1: no such user, -2: wrong password
			if ($var(rc) == -1 || $var(rc) == -2)
				xlog("L_WARN", "SIP auth failure from $si for \"$au\"\n");
			www_challenge("", "auth");
			exit;
		}
		consume_credentials();
		if (!save("location"))
			sl_reply_error();
		exit;
	}

	if (is_method("INVITE")) {
		if (!pv_proxy_authorize("")) {
			$var(rc) = $rc;
			if ($var(rc) == -1 || $var(rc) == -2)
				xlog("L_WARN", "SIP auth failure from $si for \"$au\"\n");
			proxy_challenge("", "auth");
			exit;
		}
		consume_credentials();
		record_route();
		# Where the call goes. Here, a test callee on this machine.
		$du = "sip:127.0.0.1:5070";
		t_relay();
		exit;
	}

	send_reply(405, "Method Not Allowed");
}
EOF
sudo opensips -C -f /etc/opensips/opensips.cfg
sudo systemctl restart opensips
systemctl is-active opensips
```

OpenSIPS writes these lines to the systemd journal. `journalctl -u opensips`
shows each one after the date and the host name, here `sip-proxy`:

```text
Oct 06 14:03:07 sip-proxy /usr/sbin/opensips[15830]: WARNING:SIP scanner from 198.51.100.60: User-Agent "friendly-scanner"
Oct 06 14:03:09 sip-proxy /usr/sbin/opensips[15830]: WARNING:SIP auth failure from 198.51.100.60 for "1001"
```

## Install fail2ban

```bash
# Run all of these, in order.
sudo apt-get install -y fail2ban nftables
fail2ban-client --version
```

The jail below bans with nftables, so the command installs it too.

## Tell fail2ban what to look for, and what to ban

The filter reads OpenSIPS's lines from the journal. The jail bans an address
after 3 matching lines within 10 minutes.

- The ban lasts for an hour.
- It covers the SIP ports only.
  - Its rule names ports 5060 and 5061.
  - So a banned address can still reach your other services, SSH included:

```bash
# Run all of these, in order.
sudo tee /etc/fail2ban/filter.d/opensips.conf >/dev/null <<'EOF'
[INCLUDES]
before = common.conf

[Definition]
_daemon = \S*opensips
failregex = ^%(__prefix_line)sWARNING:SIP scanner from <HOST>: User-Agent
            ^%(__prefix_line)sWARNING:SIP auth failure from <HOST> for
ignoreregex =
journalmatch = _SYSTEMD_UNIT=opensips.service
EOF
sudo tee /etc/fail2ban/jail.d/opensips.local >/dev/null <<'EOF'
[opensips]
enabled   = true
filter    = opensips
backend   = systemd
banaction = nftables[type=multiport]
port      = 5060,5061
protocol  = udp,tcp
maxretry  = 3
findtime  = 10m
bantime   = 1h
EOF
sudo systemctl restart fail2ban
sleep 3
sudo fail2ban-client status opensips
```

- The status shows the jail with
  `Journal matches: _SYSTEMD_UNIT=opensips.service`.
- It shows nobody banned yet.
- When it starts, the jail also reads the last `findtime` of the journal.
  - So failures logged before it ran can earn a ban.

`_daemon` matches the program name the journal records. For the packages, that
is `/usr/sbin/opensips`.

## Give this machine a scanner and a phone to test with

Each test address lives in a network namespace.

- A network namespace is a separate network stack on this machine with its own
  address.
- A virtual cable links it to this one.
- Its requests reach OpenSIPS from that address, as if from another machine:

```bash
# Run all of these, in order.
for n in scanner:198.51.100 phone:203.0.113; do
  ns=${n%%:*} net=${n#*:}
  sudo ip netns add $ns
  sudo ip link add f2b-$ns type veth peer name eth0 netns $ns
  sudo ip addr add $net.1/24 dev f2b-$ns
  sudo ip link set f2b-$ns up
  sudo ip -n $ns link set lo up
  sudo ip -n $ns link set eth0 up
done
sudo ip -n scanner addr add 198.51.100.60/24 dev eth0
sudo ip -n scanner route add default via 198.51.100.1
sudo ip -n phone addr add 203.0.113.70/24 dev eth0
sudo ip -n phone route add default via 203.0.113.1
```

A small SIP client sends the test requests and prints each answer. It uses
only Python's standard library:

```bash
# Run all of these, in order.
mkdir -p ~/f2b-test
cat > ~/f2b-test/sipreq.py <<'EOF'
"""Send SIP requests and print each final answer.
usage: sipreq.py SERVER METHOD COUNT [USER-AGENT] [USER PASSWORD]"""
import hashlib, re, socket, sys, uuid

srv, method, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
ua = sys.argv[4] if len(sys.argv) > 4 else "sipreq"
user, pw = (sys.argv[5], sys.argv[6]) if len(sys.argv) > 6 else (None, None)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((srv, 5060))
me, port = s.getsockname()


def request(n, ext, auth=""):
    return (f"{method} sip:{srv} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {me}:{port};branch=z9hG4bK{uuid.uuid4().hex}\r\n"
            f"Max-Forwards: 70\r\nFrom: <sip:{ext}@{srv}>;tag={n}\r\n"
            f"To: <sip:{ext}@{srv}>\r\nCall-ID: {cid}\r\nCSeq: {n} {method}\r\n"
            f"Contact: <sip:{ext}@{me}:{port}>\r\nExpires: 300\r\n"
            f"User-Agent: {ua}\r\n{auth}Content-Length: 0\r\n\r\n").encode()


def answer(data):
    s.send(data)
    while True:
        try:
            reply = s.recv(65535).decode(errors="replace")
        except socket.timeout:
            return "no answer"
        except ConnectionRefusedError:
            return "refused"
        if int(reply.split(" ", 2)[1]) >= 200:
            return reply


for i in range(count):
    cid = uuid.uuid4().hex
    ext = user or str(100 + i)
    reply = answer(request(1, ext))
    if reply.startswith("SIP/2.0 401") and user:
        c = dict(re.findall(r'(\w+)="([^"]*)"', reply.split("WWW-Authenticate:", 1)[1].split("\r\n", 1)[0]))
        ha1 = hashlib.md5(f"{user}:{c['realm']}:{pw}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:sip:{srv}".encode()).hexdigest()
        resp = hashlib.md5(f"{ha1}:{c['nonce']}:00000001:0a4f113b:auth:{ha2}".encode()).hexdigest()
        auth = (f'Authorization: Digest username="{user}", realm="{c["realm"]}", '
                f'nonce="{c["nonce"]}", uri="sip:{srv}", response="{resp}", '
                f'qop=auth, nc=00000001, cnonce="0a4f113b", algorithm=MD5\r\n')
        reply = answer(request(2, ext, auth))
    print(f"{method} {ext}: " + reply.split("\r\n", 1)[0])
EOF
```

## Check that a phone registers and calls

The phone at `203.0.113.70` registers as `1001` with the right password:

```bash
sudo ip netns exec phone python3 ~/f2b-test/sipreq.py 192.0.2.10 REGISTER 1 MicroSIP 1001 correct-horse-1001
```

It prints `REGISTER 1001: SIP/2.0 200 OK`.

Then it places a call through OpenSIPS. SIPp plays both ends:

- a callee on this machine,
- the phone, which answers OpenSIPS's challenge with its password:

```bash
# Run all of these, in order.
sudo apt-get install -y sip-tester
cd ~/f2b-test
cat > call.xml <<'EOF'
<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="Call with digest authentication">
  <send retrans="500">
    <![CDATA[
      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:1001@[remote_ip]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 INVITE
      Contact: <sip:1001@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
      s=-
      c=IN IP[media_ip_type] [media_ip]
      t=0 0
      m=audio [media_port] RTP/AVP 0
      a=rtpmap:0 PCMU/8000
    ]]>
  </send>
  <recv response="100" optional="true"/>
  <recv response="407" auth="true"/>
  <send>
    <![CDATA[
      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:1001@[remote_ip]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 1 ACK
      Max-Forwards: 70
      Content-Length: 0
    ]]>
  </send>
  <send retrans="500">
    <![CDATA[
      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:1001@[remote_ip]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 2 INVITE
      Contact: <sip:1001@[local_ip]:[local_port]>
      [authentication]
      Max-Forwards: 70
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
      s=-
      c=IN IP[media_ip_type] [media_ip]
      t=0 0
      m=audio [media_port] RTP/AVP 0
      a=rtpmap:0 PCMU/8000
    ]]>
  </send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200" rtd="true" rrs="true"/>
  <send>
    <![CDATA[
      ACK [next_url] SIP/2.0
      [routes]
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:1001@[remote_ip]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 2 ACK
      Max-Forwards: 70
      Content-Length: 0
    ]]>
  </send>
  <pause milliseconds="2000"/>
  <send retrans="500">
    <![CDATA[
      BYE [next_url] SIP/2.0
      [routes]
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:1001@[remote_ip]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 3 BYE
      Max-Forwards: 70
      Content-Length: 0
    ]]>
  </send>
  <recv response="200" crlf="true"/>
</scenario>
EOF
sipp -sn uas -i 127.0.0.1 -p 5070 -m 1 -bg
sudo ip netns exec phone sipp -sf call.xml 192.0.2.10:5060 -i 203.0.113.70 -p 5080 -s 2000 \
  -au 1001 -ap correct-horse-1001 -m 1 -timeout 20s -trace_screen -screen_file call.screen >/dev/null
grep -E 'Successful call|Failed call' call.screen
```

The output shows these events:

- OpenSIPS challenged the call.
- The phone answered the challenge.
- The callee answered.
- The phone hung up:

```text
  Successful call        |        0                  |        1
  Failed call            |        0                  |        0
```

The phone's first `INVITE` drew a challenge. That is the normal first half of
a login. So OpenSIPS logged nothing for it.

## Watch fail2ban ban a scanner

The scanner walks extensions the way SIPVicious's `svwar` does. It announces
itself as `friendly-scanner`. Then it tries once more:

```bash
# Run all of these, in order.
sudo ip netns exec scanner python3 ~/f2b-test/sipreq.py 192.0.2.10 REGISTER 5 friendly-scanner
sleep 2
sudo fail2ban-client status opensips
sudo nft list set inet f2b-table addr-set-opensips
sudo ip netns exec scanner python3 ~/f2b-test/sipreq.py 192.0.2.10 OPTIONS 1
```

OpenSIPS answered none of the scanner's `REGISTER`s.

- Each prints `no answer`.
- Or it prints `refused` if the ban was already in place.

The jail lists the scanner:

```text
   `- Banned IP list:	198.51.100.60
```

nftables holds it in the jail's set:

```text
table inet f2b-table {
	set addr-set-opensips {
		type ipv4_addr
		elements = { 198.51.100.60 }
	}
}
```

The jail's chain in the same table refuses SIP traffic from every address in
that set, with the rule
`udp dport { 5060, 5061 } ip saddr @addr-set-opensips reject with icmp port-unreachable`.
`sudo nft list table inet f2b-table` prints the set, the chain and the rule
together.

The last request prints `OPTIONS 100: refused`.

- The firewall answered with an ICMP port unreachable.
- OpenSIPS never saw it.

The phone is not affected. It still registers:

```bash
sudo ip netns exec phone python3 ~/f2b-test/sipreq.py 192.0.2.10 REGISTER 1 MicroSIP 1001 correct-horse-1001
```

## Lift a ban

```bash
# Run all of these, in order.
sudo fail2ban-client set opensips unbanip 198.51.100.60
sudo ip netns exec scanner python3 ~/f2b-test/sipreq.py 192.0.2.10 OPTIONS 1
```

- `unbanip` prints `1`, the number of addresses it unbanned.
- The scanner's `OPTIONS` gets an answer again: `OPTIONS 100: SIP/2.0 200 OK`.

## Watch a password guesser get banned, and the ban run out

A password guesser uses an ordinary `User-Agent` and a real user name.

- You can see a ban end on its own without waiting an hour.
  - Shorten this jail's `bantime` to 60 seconds while it runs.
  - Then put it back.
- `fail2ban-client set` changes the running jail only.
  - The jail file still says an hour:

```bash
# Run all of these, in order.
sudo fail2ban-client set opensips bantime 60
sudo ip netns exec scanner python3 ~/f2b-test/sipreq.py 192.0.2.10 REGISTER 4 MicroSIP 1001 wrong-password
sleep 2
sudo fail2ban-client get opensips banip --with-time
sleep 70
sudo fail2ban-client status opensips
sudo ip netns exec scanner python3 ~/f2b-test/sipreq.py 192.0.2.10 OPTIONS 1
sudo fail2ban-client set opensips bantime 3600
```

- Each guess prints `REGISTER 1001: SIP/2.0 401 Unauthorized`.
- A guess or two past the third can still get an answer.
  - fail2ban acts on the log line after OpenSIPS has written it.
- `banip --with-time` shows when the ban started and ends, 60 seconds later:

```text
198.51.100.60 	2026-10-01 03:47:03 + 60 = 2026-10-01 03:48:03
```

The ban starts from the time of the failure that earned it. After the wait:

- `Banned IP list:` is empty.
- The `OPTIONS` gets an answer again.

## Operate it

The commands below do these things, in this order:

- ban a test address by hand,
- look at it,
- restart fail2ban,
- lift the ban.

| Command | What it does |
|---|---|
| `sudo fail2ban-client set opensips banip 198.51.100.61` | ban an address by hand, for the jail's `bantime`, and print how many it banned |
| `sudo fail2ban-client status opensips` | the jail's failures and its banned addresses |
| `sudo fail2ban-client get opensips banip --with-time` | each banned address, when its ban started and when it ends |
| `sudo systemctl restart fail2ban` | apply a change to the filter or the jail. Bans survive it, because fail2ban keeps them in its database and restores them |
| `sudo fail2ban-client set opensips unbanip 198.51.100.61` | lift a ban |
| `sudo fail2ban-regex systemd-journal opensips` | count the journal lines the filter matches, without banning anything |
| `sudo journalctl -u fail2ban -n 20` | the fail2ban service's messages, including a jail that failed to start |
| `sudo tail -n 20 /var/log/fail2ban.log` | fail2ban's own log: every ban and unban, by jail and address |

**Remove the test addresses** when you finish testing:

```bash
# Run all of these, in order.
sudo ip netns del scanner
sudo ip netns del phone
rm -rf ~/f2b-test
```

**Uninstall.** Stopping fail2ban removes its nftables table. So no ban
outlives it:

```bash
# Run all of these, in order.
sudo systemctl disable --now fail2ban
sudo rm -f /etc/fail2ban/filter.d/opensips.conf /etc/fail2ban/jail.d/opensips.local
sudo apt-get purge -y fail2ban
```

This keeps the OpenSIPS configuration from
"Make OpenSIPS log scanners and wrong passwords".
To uninstall OpenSIPS too, see [its guide](opensips.md#operate-it).

## When something does not work

- **The jail never bans.**
  - Check what the filter matches.
    `sudo fail2ban-regex systemd-journal opensips` reports `Failregex: 0 total`
    when it matches nothing.
  - OpenSIPS may run under another unit or another program name.
    - Then `journalmatch` or `_daemon` does not fit it.
    - See how the journal records the program with
      `sudo journalctl -u opensips -n 5`.
- **fail2ban does not start.**
  - `sudo journalctl -u fail2ban -n 20` names the jail and the reason.
  - One jail that fails stops fail2ban.
    - Every jail stops with it, SSH's included.
