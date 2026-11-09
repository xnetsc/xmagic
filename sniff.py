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
  "CONNECT ..."                      -> HTTP inbound    (BE_HTTP_PORT;
                                        only while the node's HTTP
                                        proxy is on - an "http" inbound
                                        in the rendered config; else
                                        the mux, failing closed there)
  other HTTP + "Upgrade: websocket"  -> Xray mux        (XRAY_MUX_PORT)
  other HTTP, absolute-form target   -> HTTP inbound    (BE_HTTP_PORT;
                                        same HTTP-on condition)
  other HTTP, origin-form target     -> admin console   (ADMIN_BE_PORT)
  VMess AEAD AuthID (validated)      -> VMess inbound   (VMESS_BE_PORT)
  anything else (VLESS-TCP, bare SS) -> Xray mux        (XRAY_MUX_PORT)

The mux itself then dispatches WebSocket paths to the VLESS/Trojan/
Shadowsocks/VMess backends and everything else to the
bare-Shadowsocks backend.

A bare VMess stream is random-looking AEAD ciphertext, so no prefix
identifies it - but its first 16 bytes are an AuthID the node can
verify: an AES-128 block over (timestamp, random, CRC32) under a key
derived from the user's id. The dispatcher validates that block
against the user ids of the rendered config's bare "vmess" inbound
(XMAGIC_XRAY_CONFIG, else $DATA_DIR/config.json). That inbound is
rendered only while bare VMess is enabled, so with it off the id set
is empty, recognition is inert, and a VMess stream falls through to
the mux like any other unknown traffic. Recognition is routing only:
the VMess backend still performs the full authentication.

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

v2ray-plugin's other default is multiplexing: many SS connections
share one WebSocket connection, each framed Mux.Cool-style as
[2B meta length][meta][2B data length][data]. The SS inbound cannot
demultiplex that - a muxed stream dies there as an unmatched user.
So on upgrade paths the rendered config maps to an SS-WS inbound,
the dispatcher watches the first frame: when it opens with an exact
Mux.Cool session frame (the meta length must equal the serialized
target length - not a pattern a random SS salt can pass), the
dispatcher takes the connection over from the mux, terminates the
mux itself and gives every session its own WebSocket connection to
the SS backend. Any other stream on those paths keeps the raw
splice through the mux, byte for byte.

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
  VMESS_BE_PORT  Xray bare-VMess inbound (default 18084)
  SSH_BE_PORT    sshd port               (default 12222)
  ADMIN_BE_PORT  admin console backend   (default 18090)
  XMAGIC_XRAY_CONFIG  rendered Xray config the bare-VMess user ids
                 and the HTTP-proxy on/off state (an "http" inbound's
                 presence) are read from (default:
                 $DATA_DIR/config.json, DATA_DIR defaulting to /data)
  SNIFF_PEEK_TIMEOUT  seconds to wait for the client's first bytes (5)

Python 3 stdlib only. One thread pair per connection; logging to stdout.
"""
import base64
import hashlib
import json
import os
import select
import socket
import struct
import sys
import threading
import time
import uuid
import zlib

LISTEN_PORT = int(os.environ.get("XRAY_PORT", "8080"))
TARGETS = {
    "mux": ("127.0.0.1", int(os.environ.get("XRAY_MUX_PORT", "18080"))),
    "http": ("127.0.0.1", int(os.environ.get("BE_HTTP_PORT", "18081"))),
    "socks": ("127.0.0.1", int(os.environ.get("BE_SOCKS_PORT", "18082"))),
    "reality": ("127.0.0.1", int(os.environ.get("XRAY_REALITY_PORT", "18083"))),
    "vmess": ("127.0.0.1", int(os.environ.get("VMESS_BE_PORT", "18084"))),
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


# ------------------------------------------------------------ VMess AuthID
# A bare VMess stream opens with a 16-byte AuthID: AES-128-ECB of
# (timestamp int64 BE, 4 random bytes, CRC32 BE of the first 12) under
# a per-user key, KDF16(cmd_key, "AES Auth ID Encryption") with
# cmd_key = MD5(uuid bytes || "c48619fe-...") and KDF the recursive
# HMAC-SHA256 construction of v2ray-core's proxy/vmess/aead. Only one
# block per user is ever decrypted here, so a small pure-Python
# AES-128 (both directions - encrypt exists for the tests) is plenty.


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p


def _build_sboxes():
    def rotl(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xFF

    sbox = []
    for x in range(256):
        inv = 0
        if x:
            inv, base, e = 1, x, 254  # x**254 is the GF(2^8) inverse
            while e:
                if e & 1:
                    inv = _gf_mul(inv, base)
                base = _gf_mul(base, base)
                e >>= 1
        sbox.append(inv ^ rotl(inv, 1) ^ rotl(inv, 2) ^ rotl(inv, 3)
                    ^ rotl(inv, 4) ^ 0x63)
    inv_sbox = [0] * 256
    for i, s in enumerate(sbox):
        inv_sbox[s] = i
    return sbox, inv_sbox


_SBOX, _INV_SBOX = _build_sboxes()
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _aes_expand_key(key):
    """AES-128 key schedule: the 11 round keys, 16 bytes each."""
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // 4 - 1], _SBOX[t[2]],
                 _SBOX[t[3]], _SBOX[t[0]]]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(b for word in w[4 * r:4 * r + 4] for b in word)
            for r in range(11)]


def _shift_rows(s):
    return [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]


def _inv_shift_rows(s):
    return [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]]


def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c:4 * c + 4] = [
            _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3],
            a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3],
            a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3),
            _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)]
    return out


def _inv_mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c:4 * c + 4] = [
            _gf_mul(a[0], 14) ^ _gf_mul(a[1], 11)
            ^ _gf_mul(a[2], 13) ^ _gf_mul(a[3], 9),
            _gf_mul(a[0], 9) ^ _gf_mul(a[1], 14)
            ^ _gf_mul(a[2], 11) ^ _gf_mul(a[3], 13),
            _gf_mul(a[0], 13) ^ _gf_mul(a[1], 9)
            ^ _gf_mul(a[2], 14) ^ _gf_mul(a[3], 11),
            _gf_mul(a[0], 11) ^ _gf_mul(a[1], 13)
            ^ _gf_mul(a[2], 9) ^ _gf_mul(a[3], 14)]
    return out


def _aes128_encrypt_block(key, block):
    rk = _aes_expand_key(key)
    s = [b ^ k for b, k in zip(block, rk[0])]
    for rnd in range(1, 10):
        s = _mix_columns(_shift_rows([_SBOX[b] for b in s]))
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    s = _shift_rows([_SBOX[b] for b in s])
    return bytes(b ^ k for b, k in zip(s, rk[10]))


def _aes128_decrypt_block(key, block):
    rk = _aes_expand_key(key)
    s = [b ^ k for b, k in zip(block, rk[10])]
    for rnd in range(9, 0, -1):
        s = [_INV_SBOX[b] for b in _inv_shift_rows(s)]
        s = [b ^ k for b, k in zip(s, rk[rnd])]
        s = _inv_mix_columns(s)
    s = [_INV_SBOX[b] for b in _inv_shift_rows(s)]
    return bytes(b ^ k for b, k in zip(s, rk[0]))


class _ChainHash:
    """One link of the VMess KDF: an HMAC-SHA256 whose hash function
    is the previous link (the Go original builds hmac.New over a
    factory returning the chained hash; this mirrors its semantics:
    the inner pad feeds a copy of the chain, the outer pad the chain
    itself)."""

    def __init__(self, key, inner):
        self._in = bytes(b ^ 0x36 for b in key.ljust(64, b"\x00"))
        self._out = bytes(b ^ 0x5C for b in key.ljust(64, b"\x00"))
        self._inner = inner.copy()
        self._outer = inner
        self._inner.update(self._in)

    def copy(self):
        dup = object.__new__(type(self))
        dup._in, dup._out = self._in, self._out
        dup._inner, dup._outer = self._inner.copy(), self._outer.copy()
        return dup

    def update(self, data):
        self._inner.update(data)

    def digest(self):
        inner_result = self._inner.digest()[:32]
        self._outer.update(self._out)
        self._outer.update(inner_result)
        return self._outer.digest()


def _kdf(key, path):
    cur = _ChainHash(b"VMess AEAD KDF", hashlib.sha256())
    for item in path:
        cur = _ChainHash(item, cur)
    cur.update(key)
    return cur.digest()


def _kdf16(key, path):
    return _kdf(key, path)[:16]


def _cmd_key(uuid_bytes):
    return hashlib.md5(
        uuid_bytes + b"c48619fe-8f02-49e0-b9e9-edf763e17e21").digest()


_AUTH_KEYS = {}


def _auth_key(uid_str):
    key = _AUTH_KEYS.get(uid_str)
    if key is None:
        try:
            raw = uuid.UUID(uid_str).bytes
        except ValueError:
            return None
        key = _kdf16(_cmd_key(raw), [b"AES Auth ID Encryption"])
        _AUTH_KEYS[uid_str] = key
    return key


_CONFIG_CACHE = {"key": None, "ids": frozenset(), "http": True}


def _vmess_config_path():
    path = os.environ.get("XMAGIC_XRAY_CONFIG")
    if path:
        return path
    return os.path.join(os.environ.get("DATA_DIR", "/data"),
                        "config.json")


def _load_rendered_config():
    """(bare-vmess ids, http inbound present) from the rendered
    config, or None when the file cannot be read at all.

    Cached on (path, mtime, size); callers pick their own fallback
    for None (VMess: the last good id set; HTTP: enabled, the legacy
    behavior in deployments without the config wiring). Only the
    inbound tagged "vmess" contributes ids - the vmess-ws inbounds
    carry the same ids but must not arm recognition on their own:
    the bare inbound exists in the render only while bare VMess is
    enabled, so a WS-only render leaves the set empty and AuthID
    recognition inert."""
    path = _vmess_config_path()
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_mtime_ns, st.st_size)
    if _CONFIG_CACHE["key"] == key:
        return _CONFIG_CACHE["ids"], _CONFIG_CACHE["http"]
    ids, http = set(), False
    try:
        with open(path) as f:
            cfg = json.load(f)
        for inbound in cfg.get("inbounds", []):
            if inbound.get("protocol") == "http":
                http = True
            if (inbound.get("protocol") == "vmess"
                    and inbound.get("tag") == "vmess"):
                clients = (inbound.get("settings") or {}).get(
                    "clients") or []
                for client in clients:
                    cid = str(client.get("id") or "").strip().lower()
                    if cid:
                        ids.add(cid)
    except (OSError, ValueError, AttributeError):
        return None
    _CONFIG_CACHE["key"] = key
    _CONFIG_CACHE["ids"] = frozenset(ids)
    _CONFIG_CACHE["http"] = http
    return _CONFIG_CACHE["ids"], http


def _vmess_ids():
    """User ids of the BARE vmess inbound in the rendered config
    (empty while bare VMess is off or the config is unreadable -
    the last good set survives a transient read error)."""
    loaded = _load_rendered_config()
    if loaded is None:
        return _CONFIG_CACHE["ids"]
    return loaded[0]


def _http_enabled():
    """The node's HTTP proxy is on iff the rendered config holds an
    "http" inbound. An unreadable config means a deployment without
    the config wiring - keep the legacy behavior and route HTTP."""
    loaded = _load_rendered_config()
    if loaded is None:
        return True
    return loaded[1]


_SS_WS_CACHE = {"key": None, "routes": {}}


def _ss_ws_routes():
    """{ws path: backend port} of the rendered config's SS-WS
    inbounds, for Mux.Cool demultiplexing. Empty when the config
    cannot be read - demultiplexing then stays off and SS-WS
    traffic takes the plain mux path, the behavior of deployments
    without the config wiring."""
    path = _vmess_config_path()
    try:
        st = os.stat(path)
    except OSError:
        return {}
    key = (path, st.st_mtime_ns, st.st_size)
    if _SS_WS_CACHE["key"] == key:
        return _SS_WS_CACHE["routes"]
    routes = {}
    try:
        with open(path) as f:
            cfg = json.load(f)
        for inbound in cfg.get("inbounds", []):
            tag = str(inbound.get("tag") or "")
            if inbound.get("protocol") != "shadowsocks" \
                    or not tag.startswith("ss-ws"):
                continue
            ws = ((inbound.get("streamSettings") or {})
                  .get("wsSettings") or {})
            p = str(ws.get("path") or "").split("?", 1)[0]
            port = inbound.get("port")
            if p and isinstance(port, int):
                routes[p] = port
    except (OSError, ValueError, AttributeError):
        return _SS_WS_CACHE["routes"]
    _SS_WS_CACHE["key"] = key
    _SS_WS_CACHE["routes"] = routes
    return routes


def _authid_match(data, ids, now):
    """True when data opens with a valid VMess AuthID for one of ids.

    The same two checks the VMess server itself applies first: the
    CRC32 over the decrypted head must match, and the embedded
    timestamp must sit within the +/-120s window."""
    head = data[:16]
    for uid in ids:
        key = _auth_key(uid)
        if key is None:
            continue
        plain = _aes128_decrypt_block(key, head)
        ts = struct.unpack(">q", plain[:8])[0]
        crc = struct.unpack(">I", plain[12:16])[0]
        if ts < 0 or abs(ts - now) > 120:
            continue
        if zlib.crc32(plain[:12]) & 0xFFFFFFFF == crc:
            return True
    return False


def _looks_vmess(data, now=None):
    if len(data) < 16:
        return False
    ids = _vmess_ids()
    if not ids:
        return False
    return _authid_match(data, ids,
                         time.time() if now is None else now)


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
        # The HTTP proxy is opt-in on the node; while its inbound is
        # absent from the render, CONNECT fails closed at the mux.
        return "http" if _http_enabled() else "mux"
    if data.startswith(HTTP_METHODS):
        head = data.split(b"\r\n\r\n", 1)[0].lower()
        if b"upgrade: websocket" in head or b"upgrade:websocket" in head:
            return "mux"
        first_line = data.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ")
        target = parts[1] if len(parts) > 1 else b""
        if target.startswith(b"/"):
            return "admin"
        return "http" if _http_enabled() else "mux"
    if _looks_vmess(data):
        # A bare-VMess stream: random-looking, but its AuthID
        # validates against a user id, which no other protocol's
        # opening bytes do (CRC32 + a live timestamp inside an
        # AES block keyed per user).
        return "vmess"
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


def _mask_xor(data: bytes, mask: bytes) -> bytes:
    """WebSocket masking: XOR with a repeating 4-byte key.

    Computed as one big-integer XOR instead of a per-byte Python
    loop. The loop was the demultiplexer's dominant CPU cost -
    on a 0.5-vCPU function it throttled bulk transfers to a
    crawl and tore them down midway."""
    n = len(data)
    if not n:
        return data
    key = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "little")
            ^ int.from_bytes(key, "little")).to_bytes(n, "little")


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
    return hdr + mask + _mask_xor(payload, mask)


def _ws_rewrite(client, data: bytes):
    """Plan the early-data normalization for a mux-bound connection.

    Pure inspection of peeked bytes: returns (plan, info). plan is
    (head_len, new_head, early_data) when the connection's request
    head is complete in the peek and carries the header, else None
    (raw splice); the caller consumes exactly head_len bytes,
    forwards new_head, and when early_data is not None reframes it
    via _forward_gated. info is a one-line summary of the upgrade
    request for the log (request line, the header's disposition,
    User-Agent) - what a client actually sent is otherwise invisible
    from the node's side when a dialect mismatch is suspected.
    """
    if not data.startswith(HTTP_METHODS):
        return None, None
    big = client.recv(65536, socket.MSG_PEEK)
    if len(big) < len(data):
        big = data
    end = big.find(b"\r\n\r\n")
    if end < 0:
        return None, None
    head = big[:end + 4]
    lines = head[:-4].split(b"\r\n")
    request = lines[0].decode("latin-1", "replace")
    sp, ua = None, ""
    for line in lines[1:]:
        name, sep, val = line.partition(b":")
        if not sep:
            continue
        lname = name.strip().lower()
        if lname == b"sec-websocket-protocol" and sp is None:
            sp = val.strip()
        elif lname == b"user-agent":
            ua = val.strip().decode("latin-1", "replace")[:60]
    if sp is None:
        disp = "absent"
    else:
        decoded = _b64_decode_loose(sp)
        disp = (f"data:{len(decoded)}"
                if decoded is not None and len(decoded) >= ED_MIN
                else "token")
    info = f"{request} sp={disp}" + (f" ua={ua}" if ua else "")
    if sp is None:
        return None, info
    plan = normalize_ws_head(head)
    if plan is None:
        return None, info
    new_head, early = plan
    return (end + 4, new_head, early), info


def _first_data_frame(buf: bytes, skip_head: bool = False):
    """First WebSocket data frame in a client stream, for the log.

    The stream starts with the HTTP upgrade head (already consumed
    by the caller when skip_head is set), then masked frames.
    Returns (opcode, payload_length, payload_prefix) with the
    prefix unmasked and capped at 64 bytes - enough to identify
    what protocol a rejected stream actually carries - or None
    while the bytes buffered so far cannot decide.
    """
    if skip_head:
        i = 0
    else:
        end = buf.find(b"\r\n\r\n")
        if end < 0:
            return None
        i = end + 4
    for _ in range(8):  # skip at most a few control frames
        if len(buf) < i + 2:
            return None
        b0, b1 = buf[i], buf[i + 1]
        opcode = b0 & 0x0F
        ln = b1 & 0x7F
        j = i + 2
        if ln == 126:
            if len(buf) < j + 2:
                return None
            ln = int.from_bytes(buf[j:j + 2], "big")
            j += 2
        elif ln == 127:
            if len(buf) < j + 8:
                return None
            ln = int.from_bytes(buf[j:j + 8], "big")
            j += 8
        mask = None
        if b1 & 0x80:
            if len(buf) < j + 4:
                return None
            mask = buf[j:j + 4]
            j += 4
        if opcode in (0x0, 0x1, 0x2):
            take = min(ln, 64)
            if len(buf) < j + take:
                return None
            payload = buf[j:j + take]
            if mask:
                payload = bytes(b ^ mask[k % 4]
                                for k, b in enumerate(payload))
            return opcode, ln, payload
        if len(buf) < j + ln:
            return None
        i = j + ln
    return None


def _pipe_c2b_snoop(src, dst, tag, skip_head=False):
    """pipe() client->backend, logging the first data frame's head.

    Observation only: every chunk is forwarded the moment it
    arrives; a copy is parsed on the side until the first data
    frame is identified (or a sane cap is passed).
    """
    buf = b""
    logged = False
    try:
        while True:
            r, _, _ = select.select([src], [], [], 300)
            if not r:
                break
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
            if not logged and len(buf) <= 1 << 20:
                buf += chunk
                got = _first_data_frame(buf, skip_head)
                if got is not None:
                    opcode, ln, payload = got
                    log(f"{tag}: ws first frame op={opcode} len={ln} "
                        f"head={payload.hex()}")
                    logged = True
    except (OSError, ValueError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


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


# --- Mux.Cool demultiplexing on SS-WS paths ---------------------------
# Frame layout (v2ray-plugin mux mode): [2B meta length][meta]
# [2B data length][data]; meta = session id(2B) + status(1B) +
# option(1B) + target on a New session, serialized as network(1B) +
# port(2B) + address type(1B) + address. Statuses: 1 New, 2 Keep,
# 3 End, 4 KeepAlive.

_MUX_NEW, _MUX_KEEP, _MUX_END = 1, 2, 3


def _mux_open_state(buf):
    """True/False/None: does buf open with a Mux.Cool session frame?

    None while more bytes could still decide. False is final: the
    meta length must be plausible, the status must be New with a
    target option, and the target must serialize to exactly the
    announced meta length."""
    if len(buf) < 2:
        return None
    meta_len = int.from_bytes(buf[0:2], "big")
    if meta_len < 8 or meta_len > 32:
        return False
    if len(buf) < 2 + meta_len:
        return None
    meta = buf[2:2 + meta_len]
    if meta[2] != _MUX_NEW or meta[3] not in (0x00, 0x01, 0x03):
        return False
    if meta[4] not in (0x01, 0x02):       # network: TCP / UDP
        return False
    atyp = meta[7]
    if atyp == 0x01:
        addr = 4
    elif atyp == 0x03:
        addr = 16
    elif atyp == 0x02:
        if meta_len < 9:
            return False
        addr = 1 + meta[8]
    else:
        return False
    return 8 + addr == meta_len


def _frames_payload(buf):
    """(payload, consumed) of the complete WebSocket frames in buf.

    Data-frame payloads are concatenated - the mux layer sees only
    the byte stream; control frames are skipped. A trailing partial
    frame stays unconsumed."""
    out = bytearray()
    pos = 0
    while True:
        if len(buf) - pos < 2:
            break
        b0, b1 = buf[pos], buf[pos + 1]
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        p = pos + 2
        if length == 126:
            if len(buf) - p < 2:
                break
            length = int.from_bytes(buf[p:p + 2], "big")
            p += 2
        elif length == 127:
            if len(buf) - p < 8:
                break
            length = int.from_bytes(buf[p:p + 8], "big")
            p += 8
        mask = None
        if b1 & 0x80:
            if len(buf) - p < 4:
                break
            mask = buf[p:p + 4]
            p += 4
        if len(buf) - p < length:
            break
        payload = bytes(buf[p:p + length])
        if mask is not None:
            payload = _mask_xor(payload, mask)
        if opcode in (0x0, 0x1, 0x2):
            out += payload
        pos = p + length
    return bytes(out), pos


def _ws_server_frame(opcode, payload):
    """One unmasked frame, as a WS server would send it."""
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n <= 0xFFFF:
        head += bytes([126]) + n.to_bytes(2, "big")
    else:
        head += bytes([127]) + n.to_bytes(8, "big")
    return head + payload


class _WSReader:
    """Streaming WebSocket message reader over a socket.

    read_message() returns one complete data message (fragmentation
    reassembled); control frames are handled inline - a ping is
    answered through the on_ping callback, a close raises EOFError.

    Consumption is offset-based: the buffer is not memmoved per
    message (the old delete-from-the-front made a busy stream
    quadratic in the buffered size, which a throttled CPU feels
    immediately)."""

    def __init__(self, sock, buf=b"", on_ping=None):
        self.sock = sock
        self.buf = bytearray(buf)
        self.off = 0
        self.on_ping = on_ping
        self.frag = None

    def _avail(self):
        return len(self.buf) - self.off

    def _compact(self):
        if self.off == len(self.buf):
            self.buf.clear()
            self.off = 0
        elif self.off >= 65536:
            del self.buf[:self.off]
            self.off = 0

    def _fill(self, n):
        while self._avail() < n:
            if self.off == len(self.buf):
                self.buf.clear()
                self.off = 0
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("socket closed")
            self.buf += chunk

    def read_head(self):
        """Consume an HTTP head (through CRLFCRLF) and return it."""
        while True:
            idx = self.buf.find(b"\r\n\r\n", self.off)
            if idx >= 0:
                head = bytes(self.buf[self.off:idx + 4])
                self.off = idx + 4
                self._compact()
                return head
            if self._avail() > 65536:
                raise ConnectionError("http head too large")
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("socket closed during head")
            self.buf += chunk

    def next_message_len(self):
        """Buffered size of the next complete data message, or
        None while any of it is still missing - lets a caller
        drain already-arrived messages without ever blocking."""
        pos = self.off
        while True:
            avail = len(self.buf) - pos
            if avail < 2:
                return None
            b0, b1 = self.buf[pos], self.buf[pos + 1]
            opcode = b0 & 0x0F
            length = b1 & 0x7F
            p = pos + 2
            if length == 126:
                if avail < 4:
                    return None
                length = int.from_bytes(self.buf[p:p + 2], "big")
                p += 2
            elif length == 127:
                if avail < 10:
                    return None
                length = int.from_bytes(self.buf[p:p + 8], "big")
                p += 8
            if b1 & 0x80:
                p += 4
            if len(self.buf) - p < length:
                return None
            p += length
            if opcode in (0x8, 0x9, 0xA):   # close/ping/pong: walk on
                if opcode == 0x8:
                    return p - self.off
                pos = p
                continue
            if b0 & 0x80:                   # FIN: message complete
                return p - self.off
            pos = p                         # fragment: keep walking

    def read_message(self):
        while True:
            self._fill(2)
            base = self.off
            b0, b1 = self.buf[base], self.buf[base + 1]
            fin = b0 & 0x80
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            length = b1 & 0x7F
            pos = base + 2
            if length == 126:
                self._fill(4)
                length = int.from_bytes(
                    self.buf[base + 2:base + 4], "big")
                pos = base + 4
            elif length == 127:
                self._fill(10)
                length = int.from_bytes(
                    self.buf[base + 2:base + 10], "big")
                pos = base + 10
            if length > 1 << 24:
                raise ConnectionError("websocket message too large")
            mask = None
            if masked:
                self._fill(pos - base + 4)
                mask = bytes(self.buf[pos:pos + 4])
                pos += 4
            self._fill(pos - base + length)
            payload = bytes(self.buf[pos:pos + length])
            self.off = pos + length
            self._compact()
            if mask is not None:
                payload = _mask_xor(payload, mask)
            if opcode == 0x9:                       # ping
                if self.on_ping is not None:
                    self.on_ping(payload)
                continue
            if opcode == 0xA:                       # pong
                continue
            if opcode == 0x8:                       # close
                raise EOFError("websocket close frame")
            if opcode in (0x1, 0x2):
                if self.frag is not None:
                    raise ConnectionError("new message mid-fragment")
                self.frag = bytearray(payload)
            elif opcode == 0x0:
                if self.frag is None:
                    raise ConnectionError(
                        "continuation without a start")
                self.frag += payload
            else:
                raise ConnectionError("bad websocket opcode")
            if fin:
                out = bytes(self.frag)
                self.frag = None
                return out


class _MuxSession:
    """One mux session: a dedicated WebSocket connection to the
    SS-WS backend, its byte stream wrapped in mux frames."""

    def __init__(self, demux, sid, be_sock, reader):
        self.demux = demux
        self.sid = sid
        self.be = be_sock
        self.reader = reader
        self.dead = False

    def run(self):
        try:
            while not self.dead:
                payload = self.reader.read_message()
                # Coalesce whatever has already arrived into the
                # same mux frame: in a bulk transfer the backend
                # emits many small messages, and one frame per
                # message costs a lock, a send and two headers
                # each - on a throttled CPU that tax dominates.
                # Only complete messages already buffered (or a
                # frame already in flight on the socket) join in,
                # so a lone message is never delayed.
                while len(payload) < 262144:
                    if self.reader.next_message_len() is None:
                        r, _, _ = select.select([self.be], [], [], 0)
                        if not r:
                            break
                    payload += self.reader.read_message()
                self.demux.send_frame(self.sid, _MUX_KEEP, payload)
        except (EOFError, ConnectionError, OSError):
            pass
        finally:
            self.dead = True
            try:
                self.demux.send_frame(self.sid, _MUX_END, b"")
            except (ConnectionError, OSError):
                pass
            self.demux.drop(self.sid, self)
            try:
                self.be.close()
            except OSError:
                pass

    def write(self, data):
        self.be.sendall(_ws_client_frame(data))

    def close(self):
        self.dead = True
        try:
            self.be.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.be.close()
        except OSError:
            pass


class _SSDemux:
    """Terminates one muxed client WebSocket and fans its sessions
    out to per-session WebSocket connections on the SS-WS backend."""

    def __init__(self, client, be_port, path):
        self.client = client
        self.be_port = be_port
        self.path = path
        self.lock = threading.Lock()
        self.sessions = {}

    # -- client side ------------------------------------------------
    def _send_ws(self, opcode, payload):
        with self.lock:
            self.client.sendall(_ws_server_frame(opcode, payload))

    def send_frame(self, sid, status, data):
        # Mux.Cool option bit 0x01 = OptionData (a data segment
        # follows); 0x02 is OptionError. Data frames must carry
        # 0x01 - without it the peer treats the frame as meta-only
        # and the return stream desynchronizes.
        option = 0x01 if data else 0x00
        meta = sid.to_bytes(2, "big") + bytes([status, option])
        chunks = [data[i:i + 60000]
                  for i in range(0, len(data), 60000)] or [b""]
        for chunk in chunks:
            frame = (len(meta).to_bytes(2, "big") + meta
                     + len(chunk).to_bytes(2, "big") + chunk)
            try:
                self._send_ws(0x2, frame)
            except OSError:
                raise ConnectionError("client write failed")

    def drop(self, sid, session):
        with self.lock:
            if self.sessions.get(sid) is session:
                del self.sessions[sid]

    # -- backend side ------------------------------------------------
    def _open_session(self, sid):
        be = socket.create_connection(("127.0.0.1", self.be_port),
                                      timeout=10)
        be.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            be.sendall(
                (f"GET {self.path} HTTP/1.1\r\n"
                 f"Host: 127.0.0.1:{self.be_port}\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 f"Sec-WebSocket-Key: {key}\r\n"
                 "Sec-WebSocket-Version: 13\r\n\r\n").encode())
            reader = _WSReader(be)
            head = reader.read_head()
            if b" 101 " not in head.split(b"\r\n", 1)[0]:
                raise ConnectionError("backend refused the upgrade")
            be.settimeout(None)
            return _MuxSession(self, sid, be, reader)
        except (OSError, EOFError, ConnectionError):
            try:
                be.close()
            except OSError:
                pass
            raise

    # -- the mux stream ----------------------------------------------
    def serve(self, mux_prefix, raw_rest):
        def on_ping(payload):
            try:
                self._send_ws(0xA, payload)
            except OSError:
                pass

        reader = _WSReader(self.client, raw_rest, on_ping=on_ping)
        buf = bytearray(mux_prefix)
        try:
            while True:
                self._drain(buf)
                buf += reader.read_message()
        except (EOFError, ConnectionError, OSError):
            pass
        finally:
            with self.lock:
                sessions = list(self.sessions.values())
                self.sessions.clear()
            for s in sessions:
                s.close()

    def _drain(self, buf):
        # Cursor-based: the consumed prefix is deleted once, not
        # memmoved per frame. A frame split across WebSocket
        # messages simply waits for the rest - the old code read
        # the meta past the buffered end in that case and died on
        # an index error, taking the whole mux connection down.
        pos = 0
        try:
            while True:
                if len(buf) - pos < 2:
                    return
                meta_len = int.from_bytes(buf[pos:pos + 2], "big")
                if meta_len < 4 or meta_len > 4096:
                    raise ConnectionError("mux meta length implausible")
                if len(buf) - pos < 2 + meta_len:
                    return
                meta = bytes(buf[pos + 2:pos + 2 + meta_len])
                if meta[3] & 0x01:        # OptionData: a segment follows
                    if len(buf) - pos < 2 + meta_len + 2:
                        return
                    data_len = int.from_bytes(
                        buf[pos + 2 + meta_len:pos + 4 + meta_len],
                        "big")
                    total = 2 + meta_len + 2 + data_len
                    if len(buf) - pos < total:
                        return
                    data = bytes(buf[pos + 2 + meta_len + 2:
                                         pos + total])
                else:
                    total = 2 + meta_len
                    data = b""
                pos += total
                self._frame(meta, data)
        finally:
            if pos:
                del buf[:pos]

    def _frame(self, meta, data):
        sid = int.from_bytes(meta[0:2], "big")
        status = meta[2]
        if status == _MUX_NEW:
            with self.lock:
                old = self.sessions.pop(sid, None)
            if old is not None:
                old.close()
            try:
                session = self._open_session(sid)
            except (OSError, EOFError, ConnectionError):
                self.send_frame(sid, _MUX_END, b"")
                return
            with self.lock:
                self.sessions[sid] = session
            threading.Thread(target=session.run, daemon=True).start()
            if data:
                self._deliver(session, data)
        elif status == _MUX_KEEP:
            with self.lock:
                session = self.sessions.get(sid)
            if session is not None and data:
                self._deliver(session, data)
        elif status == _MUX_END:
            with self.lock:
                session = self.sessions.pop(sid, None)
            if session is not None:
                session.close()
        # KeepAlive and unknown statuses carry nothing to do.

    def _deliver(self, session, data):
        try:
            session.write(data)
        except OSError:
            session.close()
            self.drop(session.sid, session)
            try:
                self.send_frame(session.sid, _MUX_END, b"")
            except (ConnectionError, OSError):
                pass


def _serve_ss_ws(client, mux, addr, be_port, path, head_done):
    """One SS-WS connection: a raw splice through the mux, unless
    the client speaks v2ray-plugin mux - then demultiplex.

    The mux backend answers the upgrade as usual. When the
    demultiplexer takes over it closes that connection and speaks
    WebSocket to the client itself, so the backend-to-client pump
    must leave the client socket alone once takeover is signalled.
    At takeover the backend has sent nothing but the handshake head,
    and the pump is joined before the demultiplexer writes."""
    takeover = threading.Event()

    def pump_b2c():
        try:
            while not takeover.is_set():
                r, _, _ = select.select([mux], [], [], 0.5)
                if not r:
                    continue
                chunk = mux.recv(65536)
                if not chunk:
                    break
                client.sendall(chunk)
        except (OSError, ValueError):
            # ValueError: the demultiplexer closed the mux socket
            # under our select.
            pass
        finally:
            if not takeover.is_set():
                try:
                    client.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

    t = threading.Thread(target=pump_b2c, daemon=True)
    t.start()

    rawbuf = bytearray()
    if not head_done:
        # Forward the request head to the mux byte for byte;
        # anything already read past it stays buffered for the
        # classification below.
        try:
            pending = bytearray()
            while b"\r\n\r\n" not in pending:
                chunk = client.recv(65536)
                if not chunk:
                    mux.close()
                    return
                pending += chunk
                if len(pending) > 65536:
                    break
            head, _, rest = bytes(pending).partition(b"\r\n\r\n")
            mux.sendall(head + b"\r\n\r\n")
            rawbuf = bytearray(rest)
        except OSError:
            try:
                mux.close()
            except OSError:
                pass
            return

    # Classify the first data message's payload: an exact Mux.Cool
    # session-open frame, or not mux at all.
    verdict = None
    deadline = time.monotonic() + 3.0
    while verdict is None:
        payload, _ = _frames_payload(bytes(rawbuf))
        verdict = _mux_open_state(payload)
        if verdict is not None:
            break
        if len(rawbuf) > 1 << 16 or time.monotonic() > deadline:
            verdict = False
            break
        r, _, _ = select.select(
            [client], [], [],
            max(0.0, deadline - time.monotonic()))
        if not r:
            verdict = False
            break
        try:
            chunk = client.recv(65536)
        except OSError:
            chunk = b""
        if not chunk:
            try:
                mux.close()
            except OSError:
                pass
            return
        rawbuf += chunk

    if not verdict:
        # A raw SS stream: flush what classification buffered, then
        # splice exactly like the generic path.
        try:
            if rawbuf:
                mux.sendall(bytes(rawbuf))
        except OSError:
            pass
        pipe(client, mux)
        try:
            mux.close()
        except OSError:
            pass
        t.join(timeout=2)
        return

    payload, consumed = _frames_payload(bytes(rawbuf))
    takeover.set()
    try:
        # Mux frames are small and latency-sensitive; Nagle
        # batching stalls each one behind the previous ACK,
        # which reads as uniform slowness on the client.
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        mux.close()
    except OSError:
        pass
    t.join(timeout=5)
    log(f"{addr}: v2ray-plugin mux on {path} - demultiplexing")
    _SSDemux(client, be_port, path).serve(payload,
                                          bytes(rawbuf[consumed:]))


def _ws_path(data):
    """The request path (query stripped) of a peeked WS upgrade."""
    parts = data.split(b"\r\n", 1)[0].split(b" ")
    if len(parts) < 2:
        return None
    return parts[1].decode("latin-1").split("?", 1)[0]


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
    if len(data) < 16 and _vmess_ids():
        # A random-looking stream may be a VMess head split across
        # segments: wait for the full 16-byte AuthID before letting
        # it fall through to the mux.
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
        plan = None
        ws_info = None
        ss_path = None
        ss_be = None
        if kind == "mux":
            plan, ws_info = _ws_rewrite(client, data)
            if ws_info:
                log(f"{addr}: ws {ws_info}")
                ss_path = _ws_path(data)
                if ss_path is not None:
                    ss_be = _ss_ws_routes().get(ss_path)
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
        if ss_be is not None:
            _serve_ss_ws(client, backend, addr, ss_be, ss_path,
                         head_done=plan is not None)
            backend.close()
            return
        if ws_info is not None:
            t = threading.Thread(target=_pipe_c2b_snoop,
                                 args=(client, backend, addr,
                                       plan is not None),
                                 daemon=True)
        else:
            t = threading.Thread(target=pipe,
                                 args=(client, backend), daemon=True)
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
