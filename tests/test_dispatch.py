#!/usr/bin/env python3
"""Dispatcher routing tests: stub backends + the real sniff.py.

One public port must split traffic by content: SSH banner -> sshd
(only when SSH support is enabled; off by default it falls to the
mux), TLS ClientHello -> the REALITY backend, 0x05 -> SOCKS (only
when the public SOCKS5 branch is enabled; off by default it falls
to the mux),
CONNECT / absolute-form HTTP -> HTTP proxy inbound, WebSocket upgrade
-> Xray mux, origin-form HTTP (a browser) -> the admin console,
anything else -> mux. Each stub backend answers with its own name, so
the client's received bytes prove the routing.
"""
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""))


BASE = 19100
PORTS = {"mux": BASE, "http": BASE + 1, "socks": BASE + 2,
         "ssh": BASE + 3, "admin": BASE + 4, "reality": BASE + 5}
PUBLIC = BASE + 9


def stub(name, port, stop):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    srv.settimeout(0.3)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(2)
            try:
                conn.recv(4096)
            except OSError:
                pass
            try:
                conn.sendall(name.encode())
            except OSError:
                pass
    srv.close()


def probe(payload):
    with socket.create_connection(("127.0.0.1", PUBLIC), timeout=5) as c:
        c.sendall(payload)
        c.settimeout(3)
        try:
            return c.recv(64)
        except (socket.timeout, ConnectionResetError):
            return b""


def unit_checks():
    """In-process checks of the dispatcher's pure-Python pieces: the
    AES block cipher, VMess AuthID recognition against a rendered
    config, and the HTTP-proxy on/off read from the same config."""
    sys.path.insert(0, ROOT)
    import sniff

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    check("AES-128 encrypt passes the FIPS-197 vector",
          sniff._aes128_encrypt_block(key, plain) == cipher)
    check("AES-128 decrypt passes the FIPS-197 vector",
          sniff._aes128_decrypt_block(key, cipher) == plain)

    vector_uuid = "22222222-3333-4444-5555-666666666666"
    vector_ts = 1794000000
    authid = bytes.fromhex("fb691713b812d08fcd4c12625ec8ab25")

    tmp = tempfile.mkdtemp(prefix="xmagic-sniff-unit-")

    def use_config(cfg):
        path = os.path.join(tmp, f"cfg-{len(os.listdir(tmp))}.json")
        with open(path, "w") as f:
            json.dump(cfg, f)
        os.environ["XMAGIC_XRAY_CONFIG"] = path
        sniff._CONFIG_CACHE["key"] = None
        return path

    def vmess_cfg(tag, uuid):
        return {"inbounds": [{
            "tag": tag, "protocol": "vmess",
            "settings": {"clients": [{"id": uuid}]}}]}

    use_config(vmess_cfg("vmess", vector_uuid))
    check("vmess ids come from the bare inbound",
          sniff._vmess_ids() == {vector_uuid})
    check("AuthID vector accepted for its user at its timestamp",
          sniff._looks_vmess(authid, now=vector_ts))
    check("AuthID vector rejected once stale",
          not sniff._looks_vmess(authid, now=vector_ts + 10000))
    flipped = bytes([authid[0] ^ 1]) + authid[1:]
    check("AuthID vector with a flipped byte rejected",
          not sniff._looks_vmess(flipped, now=vector_ts))
    check("dispatcher waits for a full AuthID before deciding",
          not sniff._decidable(b"\x09" * 8)
          and sniff._decidable(b"\x09" * 16))

    use_config(vmess_cfg("vmess", "33333333-4444-5555-6666-777777777777"))
    check("AuthID vector rejected for a different user",
          not sniff._looks_vmess(authid, now=vector_ts))

    use_config(vmess_cfg("vmess-ws-0", vector_uuid))
    check("vmess-ws inbounds alone do not arm recognition",
          sniff._vmess_ids() == set()
          and not sniff._looks_vmess(authid, now=vector_ts))

    connect = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"
    check("CONNECT fails closed at the mux while HTTP is off",
          sniff.classify(connect) == "mux")
    with_http = vmess_cfg("vmess-ws-0", vector_uuid)
    with_http["inbounds"].append({"tag": "http-in", "protocol": "http"})
    use_config(with_http)
    check("CONNECT routes to the HTTP inbound while HTTP is on",
          sniff.classify(connect) == "http")
    os.environ["XMAGIC_XRAY_CONFIG"] = os.path.join(tmp, "missing.json")
    sniff._CONFIG_CACHE["key"] = None
    check("unreadable config keeps the legacy HTTP routing",
          sniff.classify(connect) == "http")
    del os.environ["XMAGIC_XRAY_CONFIG"]

    def ws_frame(op, payload, mask=b"\x01\x02\x03\x04"):
        n = len(payload)
        hdr = bytes([0x80 | op, 0x80 | n]) if n < 126 else \
            bytes([0x80 | op, 0x80 | 126]) + n.to_bytes(2, "big")
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return hdr + mask + body

    ws_head = b"GET /xmagic HTTP/1.1\r\nHost: h\r\n\r\n"
    payload = bytes(range(50))
    check("frame parser: binary frame after the head",
          sniff._first_data_frame(ws_head + ws_frame(2, payload))
          == (2, 50, payload))
    check("frame parser: control frame skipped",
          sniff._first_data_frame(
              ws_head + ws_frame(9, b"hi") + ws_frame(1, b"abc"))
          == (1, 3, b"abc"))
    check("frame parser: truncated frame undecidable",
          sniff._first_data_frame(ws_head + ws_frame(2, payload)[:5])
          is None)
    check("frame parser: skip_head at a frame boundary",
          sniff._first_data_frame(ws_frame(2, payload), skip_head=True)
          == (2, 50, payload))


def main():
    unit_checks()
    stop = threading.Event()
    threads = [threading.Thread(target=stub, args=(n, p, stop), daemon=True)
               for n, p in PORTS.items()]
    for t in threads:
        t.start()
    env = dict(os.environ, XRAY_PORT=str(PUBLIC),
               XRAY_MUX_PORT=str(PORTS["mux"]), BE_HTTP_PORT=str(PORTS["http"]),
               BE_SOCKS_PORT=str(PORTS["socks"]), SSH_BE_PORT=str(PORTS["ssh"]),
               ADMIN_BE_PORT=str(PORTS["admin"]),
               XRAY_REALITY_PORT=str(PORTS["reality"]))
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "sniff.py")],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PUBLIC), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.1)

        cases = [
            ("SSH banner -> mux (SSH off by default)",
             b"SSH-2.0-probe\r\n", b"mux"),
            ("SOCKS5 greeting -> mux (public SOCKS off by default)",
             b"\x05\x01\x00", b"mux"),
            ("CONNECT -> http proxy", b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", b"http"),
            ("absolute-form GET -> http proxy",
             b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", b"http"),
            ("websocket upgrade -> mux",
             b"GET /vless-ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n", b"mux"),
            ("browser GET / -> admin", b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", b"admin"),
            ("console API POST -> admin",
             b"POST /api/users HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}", b"admin"),
            ("TLS ClientHello bytes -> reality",
             b"\x16\x03\x01\x00\x80\x01\x03", b"reality"),
        ]
        for name, payload, want in cases:
            got = probe(payload)
            check(name, got == want, f"got {got!r} want {want!r}")

        frag_cases = [
            ("fragmented browser GET -> admin",
             [b"GE", b"T / HTTP/1.1\r\nHost: h\r\n\r\n"], b"admin"),
            ("fragmented WS upgrade -> mux",
             [b"GET /vless-ws HTTP/1.1\r\nHost: h\r\nUpg",
              b"rade: websocket\r\n\r\n"], b"mux"),
            ("fragmented SSH banner -> mux (SSH off by default)",
             [b"SS", b"H-2.0-probe\r\n"], b"mux"),
            ("fragmented TLS ClientHello -> reality",
             [b"\x16", b"\x03\x01\x00\x80\x01\x03"], b"reality"),
            ("fragmented SOCKS greeting -> mux (off by default)",
             [b"\x05", b"\x01\x00"], b"mux"),
            ("SS salt starting 0x05, bogus greeting -> mux",
             [b"\x05\x40" + bytes(range(64))], b"mux"),
            ("SS salt 0x05 + junk method bytes -> mux",
             [b"\x05\x02\x07\x09" + bytes(range(60))], b"mux"),
        ]
        for name, chunks, want in frag_cases:
            with socket.create_connection(("127.0.0.1", PUBLIC), timeout=5) as c:
                for ch in chunks:
                    c.sendall(ch)
                    time.sleep(0.05)
                c.settimeout(3)
                try:
                    got = c.recv(64)
                except socket.timeout:
                    got = b""
            check(name, got == want, f"got {got!r} want {want!r}")

        # phase 2: with the opt-ins set, both branches come back
        proc.terminate()
        proc.wait(timeout=5)
        for _ in range(50):  # wait until the old listener is really gone
            try:
                socket.create_connection(("127.0.0.1", PUBLIC),
                                         timeout=0.3).close()
                time.sleep(0.1)
            except OSError:
                break
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "sniff.py")],
            env=dict(env, XMAGIC_ENABLE_SOCKS5="1",
                     XMAGIC_ENABLE_SSH="1"),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PUBLIC),
                                         timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.1)
        got = probe(b"\x05\x01\x00")
        check("SOCKS5 greeting -> socks (XMAGIC_ENABLE_SOCKS5=1)",
              got == b"socks", f"got {got!r}")
        got = probe(b"SSH-2.0-probe\r\n")
        check("SSH banner -> sshd (XMAGIC_ENABLE_SSH=1)",
              got == b"ssh", f"got {got!r}")

        # phase 3: admin backend down -> a browser request is
        # answered 503 (not dropped); other protocols still drop.
        proc.terminate()
        proc.wait(timeout=5)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PUBLIC),
                                         timeout=0.3).close()
                time.sleep(0.1)
            except OSError:
                break
        dead = str(BASE + 60)
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "sniff.py")],
            env=dict(env, ADMIN_BE_PORT=dead, BE_HTTP_PORT=dead),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PUBLIC),
                                         timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.1)
        got = probe(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
        check("browser GET with admin down -> 503, not a drop",
              got.startswith(b"HTTP/1.1 503"), f"got {got!r}")
        got = probe(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        check("CONNECT with http backend down -> dropped, no 503",
              got == b"", f"got {got!r}")

        # phase 4: WS early-data normalization. The mux stub records
        # exactly what the dispatcher forwards, so the rewritten head
        # and the reframed early data are asserted byte for byte.
        proc.terminate()
        proc.wait(timeout=5)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PUBLIC),
                                         timeout=0.3).close()
                time.sleep(0.1)
            except OSError:
                break
        captured = []

        def recorder(port):
            srv = socket.socket()
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(8)
            srv.settimeout(0.3)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(1.5)
                    buf = b""
                    replied = False
                    try:
                        while True:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            buf += chunk
                            if not replied and b"\r\n\r\n" in buf:
                                # a fake 101 so the dispatcher's
                                # gated early-data injection fires
                                conn.sendall(b"HTTP/1.1 101 Switching "
                                             b"Protocols\r\n\r\n")
                                replied = True
                    except OSError:
                        pass
                    captured.append(buf)
            srv.close()

        rec_port = BASE + 70
        threading.Thread(target=recorder, args=(rec_port,),
                         daemon=True).start()
        proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "sniff.py")],
            env=dict(env, XRAY_MUX_PORT=str(rec_port)),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PUBLIC),
                                         timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.1)

        def ws_probe(head, tail=b""):
            n0 = len(captured)
            with socket.create_connection(("127.0.0.1", PUBLIC),
                                          timeout=5) as c:
                c.sendall(head)
                if tail:
                    time.sleep(0.3)
                    c.sendall(tail)
                for _ in range(30):
                    if len(captured) > n0:
                        break
                    time.sleep(0.1)
            return captured[-1] if len(captured) > n0 else b""

        marker = b"\x82\x84\x01\x02\x03\x04mark"
        payload = bytes(range(64))
        ed = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        head = (f"GET /ss-ws HTTP/1.1\r\nHost: h\r\n"
                f"Upgrade: websocket\r\n"
                f"Sec-WebSocket-Protocol: {ed}\r\n\r\n").encode()
        got = ws_probe(head, marker)
        stripped, _, rest = got.partition(b"\r\n\r\n")
        ok = (b"sec-websocket-protocol" not in got.lower()
              and stripped.startswith(b"GET /ss-ws HTTP/1.1"))
        if ok and len(rest) >= 6 and rest[0] == 0x82 and rest[1] & 0x80:
            ln = rest[1] & 0x7F
            mask = rest[2:6]
            frame = bytes(b ^ mask[i % 4]
                          for i, b in enumerate(rest[6:6 + ln]))
            ok = (ln == len(payload) and frame == payload
                  and rest[6 + ln:] == marker)
        else:
            ok = False
        check("WS early data: header stripped, payload reframed first",
              ok, f"got {got!r}")

        head = (b"GET /ss-ws HTTP/1.1\r\nHost: h\r\n"
                b"Upgrade: websocket\r\n"
                b"Sec-WebSocket-Protocol: shadowsocks\r\n\r\n")
        got = ws_probe(head, marker)
        want = (b"GET /ss-ws HTTP/1.1\r\nHost: h\r\n"
                b"Upgrade: websocket\r\n\r\n" + marker)
        check("WS subprotocol token: stripped, stream untouched",
              got == want, f"got {got!r} want {want!r}")

        head = (b"GET /ss-ws HTTP/1.1\r\nHost: h\r\n"
                b"Upgrade: websocket\r\n\r\n")
        got = ws_probe(head, marker)
        check("WS without the header: forwarded byte-identical",
              got == head + marker, f"got {got!r}")
    finally:
        proc.terminate()
        stop.set()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
