#!/usr/bin/env python3
"""First-byte protocol dispatcher for the single public port.

Every protocol this node serves is client-speaks-first, so the opening
bytes identify the protocol unambiguously:

  "SSH-" banner                      -> sshd            (SSH_BE_PORT)
  0x05                               -> SOCKS5 inbound  (BE_SOCKS_PORT)
  "CONNECT ..."                      -> HTTP inbound    (BE_HTTP_PORT)
  other HTTP + "Upgrade: websocket"  -> Xray mux        (XRAY_MUX_PORT)
  other HTTP (absolute-form proxying)-> HTTP inbound    (BE_HTTP_PORT)
  anything else (VLESS-TCP, bare SS) -> Xray mux        (XRAY_MUX_PORT)

The mux itself then dispatches WebSocket paths to the VLESS/Trojan
backends and everything else to the bare-Shadowsocks backend.

Environment:
  XRAY_PORT      public listen port      (default 8080)
  XRAY_MUX_PORT  Xray fallback mux       (default 18080)
  BE_HTTP_PORT   Xray http inbound       (default 18081)
  BE_SOCKS_PORT  Xray socks inbound      (default 18082)
  SSH_BE_PORT    sshd port               (default 12222)
  SNIFF_PEEK_TIMEOUT  seconds to wait for the client's first bytes (5)

Python 3 stdlib only. One thread pair per connection; logging to stdout.
"""
import os
import select
import socket
import sys
import threading

LISTEN_PORT = int(os.environ.get("XRAY_PORT", "8080"))
TARGETS = {
    "mux": ("127.0.0.1", int(os.environ.get("XRAY_MUX_PORT", "18080"))),
    "http": ("127.0.0.1", int(os.environ.get("BE_HTTP_PORT", "18081"))),
    "socks": ("127.0.0.1", int(os.environ.get("BE_SOCKS_PORT", "18082"))),
    "ssh": ("127.0.0.1", int(os.environ.get("SSH_BE_PORT", "12222"))),
}
PEEK_TIMEOUT = float(os.environ.get("SNIFF_PEEK_TIMEOUT", "5"))
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                b"OPTIONS ", b"PATCH ", b"TRACE ")


def log(*a):
    print(*a, file=sys.stdout, flush=True)


def classify(data: bytes) -> str:
    if data.startswith(b"SSH-"):
        return "ssh"
    if data[:1] == b"\x05":
        return "socks"
    if data.startswith(b"CONNECT "):
        return "http"
    if data.startswith(HTTP_METHODS):
        head = data.split(b"\r\n\r\n", 1)[0].lower()
        if b"upgrade: websocket" in head or b"upgrade:websocket" in head:
            return "mux"
        return "http"
    return "mux"


def pipe(src, dst):
    try:
        while True:
            r, _, _ = select.select([src], [], [], 300)
            if not r:
                break
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except (OSError, ValueError):
        # ValueError: the sibling thread closed the socket under our select.
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, addr):
    try:
        client.settimeout(PEEK_TIMEOUT)
        try:
            data = client.recv(4096, socket.MSG_PEEK)
        except socket.timeout:
            log(f"{addr}: no first bytes within {PEEK_TIMEOUT}s, closing")
            client.close()
            return
        if not data:
            client.close()
            return
        kind = classify(data)
        host, port = TARGETS[kind]
        try:
            backend = socket.create_connection((host, port), timeout=10)
        except OSError as e:
            log(f"{addr}: backend {kind} ({host}:{port}) unreachable: {e}")
            client.close()
            return
        client.settimeout(None)
        log(f"{addr}: -> {kind} ({host}:{port})")
        t = threading.Thread(target=pipe, args=(client, backend), daemon=True)
        t.start()
        pipe(backend, client)
        backend.close()
    except OSError:
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(128)
    log(f"sniff dispatcher on 0.0.0.0:{LISTEN_PORT} -> {TARGETS}")
    while True:
        c, addr = srv.accept()
        threading.Thread(target=handle, args=(c, addr), daemon=True).start()


if __name__ == "__main__":
    main()
