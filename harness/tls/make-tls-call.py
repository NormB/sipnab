#!/usr/bin/env python3
"""A real TLS 1.3 SIP call on loopback, with a keylog sipnab can be fed.

Deterministic on purpose: this exists to reproduce sipnab's client-direction
decrypt failure, so every property that might matter is chosen here rather
than left to a stack.

  * TLS 1.3, TLS_AES_256_GCM_SHA384 -- the suite in Dan's capture.
  * The INVITE is written in TWO sends, so it lands in TWO records: headers,
    then the SDP body. That is how the real trunk framed it.
  * The keylog is written by Python itself (ssl.SSLContext.keylog_filename),
    so the keys are correct by construction and the run is not also testing
    an extraction tool.
"""

import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CERT = HERE / "srv.pem"
KEY = HERE / "srv.key"
HOST = "127.0.0.1"
PORT = 15061

INVITE_HEAD = (
    "INVITE sip:echo@127.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/TLS 127.0.0.1:15062;branch=z9hG4bK-tlstest-1\r\n"
    "From: <sip:uac@127.0.0.1>;tag=uac-tag-1\r\n"
    "To: <sip:echo@127.0.0.1>\r\n"
    "Call-ID: tls-split-invite-1@127.0.0.1\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:uac@127.0.0.1:15062;transport=tls>\r\n"
    "Content-Type: application/sdp\r\n"
    "Max-Forwards: 70\r\n"
)
SDP = (
    "v=0\r\n"
    "o=uac 1 1 IN IP4 127.0.0.1\r\n"
    "s=tls-test\r\n"
    "c=IN IP4 127.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 40000 RTP/AVP 8 101\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=sendrecv\r\n"
)
TRYING = "SIP/2.0/TLS"


def make_cert():
    if CERT.exists() and KEY.exists():
        return
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(KEY), "-out", str(CERT), "-days", "2",
         "-subj", "/CN=tls-test"],
        check=True, capture_output=True,
    )


def response(code, reason, with_sdp=False):
    body = SDP.replace("m=audio 40000", "m=audio 40002") if with_sdp else ""
    head = (
        f"SIP/2.0 {code} {reason}\r\n"
        "Via: SIP/2.0/TLS 127.0.0.1:15062;branch=z9hG4bK-tlstest-1\r\n"
        "From: <sip:uac@127.0.0.1>;tag=uac-tag-1\r\n"
        "To: <sip:echo@127.0.0.1>;tag=uas-tag-1\r\n"
        "Call-ID: tls-split-invite-1@127.0.0.1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:echo@127.0.0.1:15061;transport=tls>\r\n"
    )
    if with_sdp:
        head += f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n"
    else:
        head += "Content-Length: 0\r\n\r\n"
    return (head + body).encode()


def server(ready):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(CERT), str(KEY))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(1)
        ready.set()
        conn, _ = sock.accept()
        with ctx.wrap_socket(conn, server_side=True) as tls:
            tls.recv(65535)                      # INVITE (both records)
            tls.sendall(response(100, "Trying"))
            time.sleep(0.05)
            tls.sendall(response(180, "Ringing"))
            time.sleep(0.05)
            tls.sendall(response(200, "OK", with_sdp=True))
            tls.recv(65535)                      # ACK
            tls.recv(65535)                      # BYE
            tls.sendall(response(200, "OK"))
            time.sleep(0.2)


def client(keylog):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.keylog_filename = str(keylog)
    with socket.create_connection((HOST, PORT)) as raw:
        with ctx.wrap_socket(raw, server_hostname="tls-test") as tls:
            print(f"    negotiated {tls.version()} {tls.cipher()[0]}", flush=True)
            head = INVITE_HEAD + f"Content-Length: {len(SDP)}\r\n\r\n"
            # TWO sends => TWO records. This is the split that loses the SDP.
            tls.sendall(head.encode())
            time.sleep(0.05)
            tls.sendall(SDP.encode())
            tls.recv(65535)
            time.sleep(0.15)
            tls.sendall(
                ("ACK sip:echo@127.0.0.1 SIP/2.0\r\n"
                 "Via: SIP/2.0/TLS 127.0.0.1:15062;branch=z9hG4bK-tlstest-2\r\n"
                 "From: <sip:uac@127.0.0.1>;tag=uac-tag-1\r\n"
                 "To: <sip:echo@127.0.0.1>;tag=uas-tag-1\r\n"
                 "Call-ID: tls-split-invite-1@127.0.0.1\r\n"
                 "CSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n").encode()
            )
            time.sleep(0.05)
            tls.sendall(
                ("BYE sip:echo@127.0.0.1 SIP/2.0\r\n"
                 "Via: SIP/2.0/TLS 127.0.0.1:15062;branch=z9hG4bK-tlstest-3\r\n"
                 "From: <sip:uac@127.0.0.1>;tag=uac-tag-1\r\n"
                 "To: <sip:echo@127.0.0.1>;tag=uas-tag-1\r\n"
                 "Call-ID: tls-split-invite-1@127.0.0.1\r\n"
                 "CSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n").encode()
            )
            tls.recv(65535)
            time.sleep(0.2)


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE
    out.mkdir(parents=True, exist_ok=True)
    pcap, keylog = out / "tlscall.pcap", out / "tlscall.keylog"
    for stale in (pcap, keylog):
        stale.unlink(missing_ok=True)
    make_cert()

    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-w", str(pcap), "-U", f"tcp port {PORT}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.2)
    try:
        ready = threading.Event()
        t = threading.Thread(target=server, args=(ready,), daemon=True)
        t.start()
        ready.wait(5)
        client(keylog)
        t.join(timeout=5)
    finally:
        time.sleep(0.7)
        tcpdump.terminate()
        tcpdump.wait(timeout=10)

    print(f"    pcap={pcap} ({pcap.stat().st_size} bytes)")
    print(f"    keylog={keylog} ({len(keylog.read_text().splitlines())} lines)")


if __name__ == "__main__":
    main()
