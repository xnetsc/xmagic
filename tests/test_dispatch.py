#!/usr/bin/env python3
"""Dispatcher routing tests: stub backends + the real sniff.py.

One public port must split traffic by content: SSH banner -> sshd,
0x05 -> SOCKS, CONNECT / absolute-form HTTP -> HTTP proxy inbound,
WebSocket upgrade -> Xray mux, origin-form HTTP (a browser) -> the
admin console, anything else -> mux. Each stub backend answers with
its own name, so the client's received bytes prove the routing.
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
         "ssh": BASE + 3, "admin": BASE + 4}
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
               ADMIN_BE_PORT=str(PORTS["admin"]))
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
            ("SOCKS5 greeting -> socks", b"\x05\x01\x00", b"socks"),
            ("CONNECT -> http proxy", b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", b"http"),
            ("absolute-form GET -> http proxy",
             b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", b"http"),
            ("websocket upgrade -> mux",
             b"GET /vless-ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n", b"mux"),
            ("browser GET / -> admin", b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", b"admin"),
            ("console API POST -> admin",
             b"POST /api/users HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}", b"admin"),
            ("binary protocol bytes -> mux", b"\x16\x03\x01\x00\x80\x01\x03", b"mux"),
        ]
        for name, payload, want in cases:
            got = probe(payload)
            check(name, got == want, f"got {got!r} want {want!r}")
    finally:
        proc.terminate()
        stop.set()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
