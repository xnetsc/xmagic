#!/usr/bin/env python3
"""First-byte protocol dispatcher for the single public port.

Every protocol this node serves is client-speaks-first, so the opening
bytes identify the protocol unambiguously:

  "SSH-" banner                      -> sshd            (SSH_BE_PORT)
  well-formed SOCKS5 greeting        -> SOCKS5 inbound  (BE_SOCKS_PORT;
                                        only with XMAGIC_ENABLE_SOCKS5=1,
                                        off by default: SOCKS5 is plaintext)
  "CONNECT ..."                      -> HTTP inbound    (BE_HTTP_PORT)
  other HTTP + "Upgrade: websocket"  -> Xray mux        (XRAY_MUX_PORT)
  other HTTP, absolute-form target   -> HTTP inbound    (BE_HTTP_PORT)
  other HTTP, origin-form target     -> admin console   (ADMIN_BE_PORT)
  anything else (VLESS-TCP, bare SS) -> Xray mux        (XRAY_MUX_PORT)

The mux itself then dispatches WebSocket paths to the VLESS/Trojan
backends and everything else to the bare-Shadowsocks backend.

Origin-form vs absolute-form is what separates the console from proxy
traffic on this one port: a browser talking to the console asks for
"/..." on this host, while a client using the HTTP proxy asks for
"http://..." (or CONNECT). Explicit-proxy clients never send
origin-form, so the split is unambiguous.

Environment:
  XRAY_PORT      public listen port      (default 8080)
  XRAY_MUX_PORT  Xray fallback mux       (default 18080)
  BE_HTTP_PORT   Xray http inbound       (default 18081)
  BE_SOCKS_PORT  Xray socks inbound      (default 18082)
  SSH_BE_PORT    sshd port               (default 12222)
  ADMIN_BE_PORT  admin console backend   (default 18090)
  SNIFF_PEEK_TIMEOUT  seconds to wait for the client's first bytes (5)

Python 3 stdlib only. One thread pair per connection; logging to stdout.
"""
import os
import select
import socket
import sys
import threading
import time

LISTEN_PORT = int(os.environ.get("XRAY_PORT", "8080"))
TARGETS = {
    "mux": ("127.0.0.1", int(os.environ.get("XRAY_MUX_PORT", "18080"))),
    "http": ("127.0.0.1", int(os.environ.get("BE_HTTP_PORT", "18081"))),
    "socks": ("127.0.0.1", int(os.environ.get("BE_SOCKS_PORT", "18082"))),
    "ssh": ("127.0.0.1", int(os.environ.get("SSH_BE_PORT", "12222"))),
    "admin": ("127.0.0.1", int(os.environ.get("ADMIN_BE_PORT", "18090"))),
}
PEEK_TIMEOUT = float(os.environ.get("SNIFF_PEEK_TIMEOUT", "5"))
# SOCKS5 has no encryption of its own and, not being HTTP, cannot ride
# the outer HTTPS endpoint either - the public SOCKS5 branch stays off
# unless the operator explicitly enables it.
SOCKS_PUBLIC = os.environ.get(
    "XMAGIC_ENABLE_SOCKS5", "").lower() in ("1", "true", "yes", "on")
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                b"OPTIONS ", b"PATCH ", b"TRACE ")


def log(*a):
    print(*a, file=sys.stdout, flush=True)


def _looks_socks(data: bytes) -> bool:
    """True only for a complete, well-formed SOCKS5 greeting.

    A bare-Shadowsocks stream starts with random salt bytes, so keying
    on the first byte alone (0x05) would misroute ~1/256 of SS
    connections here. Requiring the whole greeting shape - plausible
    method count, the greeting fully present, every offered method a
    known one - makes a random stream matching it negligible.
    """
    if len(data) < 3 or data[0] != 0x05:
        return False
    n = data[1]
    if not 1 <= n <= 16 or len(data) < 2 + n:
        return False
    return all(m in (0x00, 0x01, 0x02, 0xFF) for m in data[2:2 + n])


def classify(data: bytes) -> str:
    if data.startswith(b"SSH-"):
        return "ssh"
    if SOCKS_PUBLIC and _looks_socks(data):
        return "socks"
    if data.startswith(b"CONNECT "):
        return "http"
    if data.startswith(HTTP_METHODS):
        head = data.split(b"\r\n\r\n", 1)[0].lower()
        if b"upgrade: websocket" in head or b"upgrade:websocket" in head:
            return "mux"
        first_line = data.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ")
        target = parts[1] if len(parts) > 1 else b""
        if target.startswith(b"/"):
            return "admin"
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


SPECIALS = (b"SSH-", b"CONNECT ") + HTTP_METHODS


def _decidable(data: bytes) -> bool:
    """Can classify() trust this peek, or might more bytes change it?

    TCP may deliver a protocol head split across segments; deciding on
    a fragment ("GE", "SS", half a SOCKS greeting) would misroute it.
    Wait until the bytes either match a special prefix in full (HTTP
    then needs its whole head for the Upgrade decision), provably
    cannot match any special any more, or complete a SOCKS greeting.
    """
    if not data:
        return False
    if data[0] == 0x05 and SOCKS_PUBLIC:
        if len(data) < 2:
            return False
        return data[1] > 16 or len(data) >= 2 + data[1]
    for tok in SPECIALS:
        if data.startswith(tok):
            return b"\r\n\r\n" in data or len(data) >= 4096
        if tok.startswith(data):
            return False
    return True


def _peek_head(client) -> bytes:
    """MSG_PEEK until the head is decidable (1s accumulation cap).

    Polling is deliberate: MSG_PEEK does not consume, so the socket
    stays readable while any peeked byte remains - select() cannot
    signal "more arrived". A 20ms poll exits as soon as the head
    becomes decidable; complete heads (the norm) never wait at all.
    """
    data = client.recv(4096, socket.MSG_PEEK)
    deadline = time.monotonic() + 1.0
    while data and not _decidable(data) and time.monotonic() < deadline:
        time.sleep(0.02)
        data = client.recv(4096, socket.MSG_PEEK)
    return data


def handle(client, addr):
    try:
        client.settimeout(PEEK_TIMEOUT)
        try:
            data = _peek_head(client)
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
