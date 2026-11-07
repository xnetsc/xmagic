#!/usr/bin/env python3
"""Dispatcher routing tests: stub backends + the real sniff.py.

One public port must split traffic by content: SSH banner -> sshd,
TLS ClientHello -> the REALITY backend, 0x05 -> SOCKS (only when the
public SOCKS5 branch is enabled; off by default it falls to the mux),
CONNECT / absolute-form HTTP -> HTTP proxy inbound, WebSocket upgrade
-> Xray mux, origin-form HTTP (a browser) -> the admin console,
anything else -> mux. Each stub backend answers with its own name, so
the client's received bytes prove the routing.
"""
import os
import socket
import subprocess
import sys
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
        except socket.timeout:
            return b""


def main():
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
            ("SSH banner -> sshd", b"SSH-2.0-probe\r\n", b"ssh"),
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
            ("fragmented SSH banner -> sshd",
             [b"SS", b"H-2.0-probe\r\n"], b"ssh"),
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

        # phase 2: with XMAGIC_ENABLE_SOCKS5=1 the branch comes back
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
            env=dict(env, XMAGIC_ENABLE_SOCKS5="1"),
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
    finally:
        proc.terminate()
        stop.set()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
