#!/usr/bin/env python3
"""First-byte protocol dispatcher for the single public port.

Every protocol this node serves is client-speaks-first, so the opening
bytes identify the protocol unambiguously:

  "SSH-" banner                      -> sshd            (SSH_BE_PORT;
                                        only with XMAGIC_ENABLE_SSH=1,
                                        off by default)
  TLS ClientHello (0x16 0x03 ...)    -> REALITY inbound (XRAY_REALITY_PORT)
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

One header is rewritten on the way to the mux. v2ray-plugin clients
(Shadowrocket's among them) may open a WebSocket with "early data":
the first chunk of the tunneled stream rides base64-encoded in the
Sec-WebSocket-Protocol handshake header and only the remainder
follows in frames. Xray's WS server mishandles that split - unless
the header carries the client's whole first flight, the stream head
arrives corrupted and the backend rejects it (a Shadowsocks inbound
reports "failed to match an user" for a stream whose password is in
fact right). A value that is not early data at all (a subprotocol
token) is worse: Xray still decodes and prepends it. So for mux-bound
upgrades the dispatcher strips the header, holds the client's stream
until the backend's handshake response has gone by (the frame must
not coalesce with the request head - the mux's path sniffing would
trip over it), and re-injects content that decodes to a plausible
stream head (>= 32 bytes) as the first WebSocket frame, ahead of the
client's own frames: exactly the stream the client would have sent
without early data. Everything else stays a raw splice.

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
  XRAY_REALITY_PORT  Xray REALITY inbound (default 18083)
  SSH_BE_PORT    sshd port               (default 12222)
  ADMIN_BE_PORT  admin console backend   (default 18090)
  SNIFF_PEEK_TIMEOUT  seconds to wait for the client's first bytes (5)

Python 3 stdlib only. One thread pair per connection; logging to stdout.
"""
import base64
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
    "reality": ("127.0.0.1", int(os.environ.get("XRAY_REALITY_PORT", "18083"))),
    "ssh": ("127.0.0.1", int(os.environ.get("SSH_BE_PORT", "12222"))),
    "admin": ("127.0.0.1", int(os.environ.get("ADMIN_BE_PORT", "18090"))),
}
PEEK_TIMEOUT = float(os.environ.get("SNIFF_PEEK_TIMEOUT", "5"))
# SOCKS5 has no encryption of its own and, not being HTTP, cannot ride
# the outer HTTPS endpoint either - the public SOCKS5 branch stays off
# unless the operator explicitly enables it.
SOCKS_PUBLIC = os.environ.get(
    "XMAGIC_ENABLE_SOCKS5", "").lower() in ("1", "true", "yes", "on")
# SSH support is off by default, opt-in with XMAGIC_ENABLE_SSH=1 (the
# same environment decides whether the entrypoint starts sshd at
# all). While off, an "SSH-" banner is not routed anywhere: it falls
# through to the mux like any other stream and fails there.
SSH_ENABLED = os.environ.get(
    "XMAGIC_ENABLE_SSH", "").lower() in ("1", "true", "yes", "on")
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
    if SSH_ENABLED and data.startswith(b"SSH-"):
        return "ssh"
    if len(data) >= 2 and data[0] == 0x16 and data[1] == 0x03:
        # A TLS record opening a handshake: the REALITY inbound (a
        # bare-Shadowsocks stream hitting both bytes at random is
        # ~1/65536 and just fails its REALITY handshake).
        return "reality"
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


# Shortest Sec-WebSocket-Protocol payload still treated as early
# data. A stream head shorter than this cannot carry even a salt and
# one sealed record of any protocol the mux serves; a value that
# decodes shorter is a subprotocol token, not data, and is dropped.
ED_MIN = 32


def _b64_decode_loose(value: bytes):
    """Decode base64 in either alphabet, padded or not; None if not."""
    v = value.strip().rstrip(b"=")
    if not v:
        return None
    v += b"=" * (-len(v) % 4)
    for alt in (b"-_", None):
        try:
            return base64.b64decode(v, altchars=alt, validate=True)
        except ValueError:
            continue
    return None


def normalize_ws_head(head: bytes):
    """Split a WS upgrade head into (head to forward, early data).

    Returns None when the head carries no Sec-WebSocket-Protocol
    header (the common case - forward it untouched). Otherwise the
    returned head has every such header removed, and the second
    element is the decoded early data to re-inject as the first
    frame, or None when the value was a token / undecodable and is
    simply dropped.
    """
    lines = head[:-4].split(b"\r\n")  # caller guarantees the \r\n\r\n
    kept, values = [], []
    for line in lines:
        name, sep, val = line.partition(b":")
        if sep and name.strip().lower() == b"sec-websocket-protocol":
            values.append(val)
            continue
        kept.append(line)
    if not values:
        return None
    data = _b64_decode_loose(values[0])
    if data is not None and len(data) < ED_MIN:
        data = None
    return b"\r\n".join(kept) + b"\r\n\r\n", data


def _ws_client_frame(payload: bytes) -> bytes:
    """One masked binary frame, as a WS client would send it."""
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        hdr = bytes([0x82, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x82, 0x80 | 126]) + n.to_bytes(2, "big")
    else:
        hdr = bytes([0x82, 0x80 | 127]) + n.to_bytes(8, "big")
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return hdr + mask + body


def _ws_rewrite(client, data: bytes):
    """Plan the early-data normalization for a mux-bound connection.

    Pure inspection of peeked bytes: returns (head_len, new_head,
    early_data) when the connection's request head is complete in
    the peek and carries the header, else None (raw splice). The
    caller consumes exactly head_len bytes, forwards new_head, and
    when early_data is not None reframes it via _forward_gated.
    """
    if not data.startswith(HTTP_METHODS):
        return None
    big = client.recv(65536, socket.MSG_PEEK)
    if len(big) < len(data):
        big = data
    end = big.find(b"\r\n\r\n")
    if end < 0:
        return None
    head = big[:end + 4]
    if b"sec-websocket-protocol" not in head.lower():
        return None
    plan = normalize_ws_head(head)
    if plan is None:
        return None
    new_head, early = plan
    return end + 4, new_head, early


def _recv_exact(client, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = client.recv(n - len(out))
        if not chunk:
            raise ConnectionError("client closed mid-head")
        out += chunk
    return out


def pipe(src, dst, bell=None):
    tail = b""
    try:
        while True:
            r, _, _ = select.select([src], [], [], 300)
            if not r:
                break
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
            if bell is not None and not bell.is_set():
                window = tail + chunk
                if b"\r\n\r\n" in window:
                    bell.set()
                tail = window[-3:]
    except (OSError, ValueError):
        # ValueError: the sibling thread closed the socket under our select.
        pass
    finally:
        if bell is not None:
            bell.set()
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _forward_gated(client, backend, frame, bell) -> bool:
    """Hold the client's stream until the handshake response passes.

    The reframed early data must reach the backend as a WebSocket
    frame in its own right: sent together with the request head it
    lands in the mux's path-sniffing read and corrupts the routing,
    so the client's own bytes wait in the kernel buffer (a real WS
    client sends nothing before the 101 anyway). The grace period
    bounds the wait when the backend never answers with an HTTP head;
    the frame then goes out regardless, which is no worse than the
    unnormalized connection would have been.
    """
    bell.wait(10)
    try:
        backend.sendall(frame)
    except OSError:
        return False
    pipe(client, backend)
    return True


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
    if data[0] == 0x16:
        # TLS classification needs the record version byte too.
        return len(data) >= 2
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
        plan = _ws_rewrite(client, data) if kind == "mux" else None
        host, port = TARGETS[kind]
        try:
            backend = socket.create_connection((host, port), timeout=10)
        except OSError as e:
            log(f"{addr}: backend {kind} ({host}:{port}) unreachable: {e}")
            if kind == "admin":
                # The client sent a plain-HTTP browser request whose
                # bytes are still unconsumed (peek only). Answer 503
                # instead of dropping the connection: the platform in
                # front (and the browser) then sees a backend that is
                # still starting, not a dead process. On
                # invoke-driven runtimes a dropped connection is
                # reported as the process having exited mid-request,
                # which gets the instance recycled before the admin
                # has finished starting - a starvation loop.
                try:
                    # Consume the request head first: closing a
                    # socket with unread received data resets the
                    # connection, which would destroy the 503
                    # before the client reads it.
                    client.recv(4096)
                    body = b"xmagic admin is starting; retry in a moment.\n"
                    client.sendall(
                        b"HTTP/1.1 503 Service Unavailable\r\n"
                        b"Content-Type: text/plain; charset=utf-8\r\n"
                        b"Retry-After: 2\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: " + str(len(body)).encode()
                        + b"\r\n\r\n" + body)
                except OSError:
                    pass
            client.close()
            return
        log(f"{addr}: -> {kind} ({host}:{port})")
        if plan is not None:
            head_len, new_head, early = plan
            try:
                _recv_exact(client, head_len)
                backend.sendall(new_head)
            except OSError:
                backend.close()
                return
            client.settimeout(None)
            if early is None:
                log(f"{addr}: ws subprotocol header stripped")
            else:
                bell = threading.Event()
                t = threading.Thread(target=pipe,
                                     args=(backend, client, bell),
                                     daemon=True)
                t.start()
                if _forward_gated(client, backend,
                                  _ws_client_frame(early), bell):
                    log(f"{addr}: ws early data reframed "
                        f"({len(early)} bytes)")
                backend.close()
                return
        client.settimeout(None)
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
