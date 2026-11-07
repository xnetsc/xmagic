#!/usr/bin/env python3
"""Passkey-only admin console for the single-port Xray gateway.

Configuration lives behind one HTTP service instead of a host-side CLI:
the console is part of the deployment unit (its own container), shares the
SQLite identity database with the gateway, renders config.json /
authorized_keys after every change and, when the Docker socket is
available, restarts the xray / sshd containers to apply them.

Access model: exactly ONE admin account. The first passkey registered
becomes the admin; registration then closes permanently. There is no
password, no second user, no recovery flow in the UI - if the passkey is
lost, clear the credential on the host with `users.py admin-reset` and
register a new one. WebAuthn only (ES256 / P-256 credentials), user
verification required.

Stdlib only, like the rest of this package: WebAuthn verification needs a
CBOR decoder, authenticator-data parsing, DER signature decoding and
P-256 ECDSA verification, all implemented below in plain Python. ECDSA
*verification* inputs are public (signature + public key), so a non
constant-time implementation leaks nothing here.

Environment:
  PROXY_DB               database path (default ./data/users.db)
  XMAGIC_ADMIN_BIND      listen address (default 127.0.0.1 standalone;
                         the image sets 0.0.0.0 inside the container
                         network, and compose publishes it only on the
                         host's loopback backend port - the dispatcher
                         routes the console's share of the public port
                         to it)
  XMAGIC_ADMIN_PORT      listen port (default 8090)
  XMAGIC_ADMIN_RPID      WebAuthn relying-party id (default localhost).
                         Set to the domain when the console is served on
                         one, e.g. admin.example.com
  XMAGIC_ADMIN_ORIGINS   comma-separated allowed origins
                         (default http://localhost:PORT,http://127.0.0.1:PORT)
  XMAGIC_DOCKER_SOCK     Docker socket for apply-by-restart
                         (default /var/run/docker.sock; unset the mount
                         and restarts are skipped, renders still happen)
  XMAGIC_XRAY_CONTAINER  container restarted after a render (proxy-xray)
  XMAGIC_SSHD_CONTAINER  container restarted after a render (proxy-sshd)
  XMAGIC_PID_DIR         pidfile directory (single-container form);
                         when set, apply restarts the gateway by
                         signalling the recorded processes, which
                         restarts the container as a whole
"""
import base64
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
import uuid as uuidlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import users as users_mod  # the CLI engine: db(), render_config(), ...

BIND = os.environ.get("XMAGIC_ADMIN_BIND", "127.0.0.1")
PORT = int(os.environ.get("XMAGIC_ADMIN_PORT", "8090"))
RP_ID = os.environ.get("XMAGIC_ADMIN_RPID", "localhost")
RP_NAME = "xmagic gateway admin"
ORIGINS = [o.strip() for o in os.environ.get(
    "XMAGIC_ADMIN_ORIGINS",
    f"http://localhost:{PORT},http://127.0.0.1:{PORT}").split(",") if o.strip()]
DOCKER_SOCK = os.environ.get("XMAGIC_DOCKER_SOCK", "/var/run/docker.sock")
CHALLENGE_TTL = 300


def session_ttl_seconds() -> int:
    """Effective session lifetime: the admin_settings value (default one
    week), read fresh so a change applies to the next issued session.
    Sessions already issued keep the expiry they were minted with."""
    with admin_db() as conn:
        return users_mod.session_ttl_hours(conn) * 3600

ADMIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_credentials (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  credential_id TEXT UNIQUE NOT NULL,
  public_key_x TEXT NOT NULL,
  public_key_y TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  label TEXT,
  created_at TEXT NOT NULL
);
"""


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    if isinstance(text, str):
        text = text.encode()
    return base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))


# ---------------------------------------------------------------- CBOR
# Minimal definite-length CBOR decoder - enough for attestation objects
# and COSE keys. Returns (value, next_offset) so callers can decode a
# value embedded mid-buffer (the COSE key inside authenticator data).

def cbor_decode(data: bytes, offset: int = 0):
    if offset >= len(data):
        raise ValueError("cbor: unexpected end")
    first = data[offset]
    offset += 1
    major, info = first >> 5, first & 0x1F
    if info < 24:
        arg = info
    elif info == 24:
        arg = data[offset]; offset += 1
    elif info == 25:
        arg = int.from_bytes(data[offset:offset + 2], "big"); offset += 2
    elif info == 26:
        arg = int.from_bytes(data[offset:offset + 4], "big"); offset += 4
    elif info == 27:
        arg = int.from_bytes(data[offset:offset + 8], "big"); offset += 8
    else:
        raise ValueError(f"cbor: unsupported info {info} (indefinite/float not needed)")
    if major == 0:
        return arg, offset
    if major == 1:
        return -1 - arg, offset
    if major == 2:
        return data[offset:offset + arg], offset + arg
    if major == 3:
        return data[offset:offset + arg].decode("utf-8"), offset + arg
    if major == 4:
        items = []
        for _ in range(arg):
            value, offset = cbor_decode(data, offset)
            items.append(value)
        return items, offset
    if major == 5:
        mapping = {}
        for _ in range(arg):
            key, offset = cbor_decode(data, offset)
            value, offset = cbor_decode(data, offset)
            mapping[key] = value
        return mapping, offset
    if major == 6:  # tag: unwrap
        return cbor_decode(data, offset)
    # major 7: simple values
    if arg == 20:
        return False, offset
    if arg == 21:
        return True, offset
    if arg in (22, 23):
        return None, offset
    raise ValueError(f"cbor: unsupported simple value {arg}")


# ---------------------------------------------------------------- P-256
# ECDSA verification on NIST P-256 (COSE ES256, the passkey default).

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (slope * slope - x1 - x2) % _P
    return x3, (slope * (x1 - x3) - y1) % _P


def _ec_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _der_int(data, offset):
    if data[offset] != 0x02:
        raise ValueError("der: expected INTEGER")
    length = data[offset + 1]
    start = offset + 2
    if data[start] == 0x00:
        start += 1
        length -= 1
    return int.from_bytes(data[start:start + length], "big"), offset + 2 + data[offset + 1]


def ecdsa_verify(pub_xy, signature_der: bytes, message: bytes) -> bool:
    """Verify an ASN.1 DER ECDSA/P-256 signature (WebAuthn's format)."""
    try:
        if signature_der[0] != 0x30:
            return False
        r, off = _der_int(signature_der, 2)
        s, _ = _der_int(signature_der, off)
    except (IndexError, ValueError):
        return False
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _N)
    point = _ec_add(_ec_mul(e * w % _N, _G), _ec_mul(r * w % _N, pub_xy))
    return point is not None and point[0] % _N == r


# ------------------------------------------------------- session crypto
# Sessions are key-bound, not token-bound. During the passkey
# ceremony the client contributes an ephemeral P-256 public key with
# its options request; the server answers with its own ephemeral
# public key and a challenge that binds both shares:
#     challenge = SHA-256(nonce || client_pub || server_pub)
# so the passkey signature covers both ECDH shares (the client
# recomputes the challenge from the nonce and refuses a mismatch).
# The session key is HKDF-SHA256 over the ECDH shared secret, and
# every authenticated API call then travels in an AEAD envelope
# keyed by it: HMAC-SHA256 in counter mode as the keystream plus
# encrypt-then-MAC - a construction every client here (browser
# WebCrypto, the pure-Python CLI) can implement from hash/HMAC
# primitives alone. The session id is a public lookup key, not a
# credential: without the key, requests can neither be produced
# nor read.

_CURVE_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _ec_pub_bytes(point):
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _ec_point_from_pub(pub: bytes):
    if len(pub) != 65 or pub[0] != 0x04:
        raise ApiError(400, "ecdh public key must be an uncompressed P-256 point")
    x = int.from_bytes(pub[1:33], "big")
    y = int.from_bytes(pub[33:65], "big")
    if (y * y - (x * x * x + _A * x + _CURVE_B)) % _P != 0:
        raise ApiError(400, "ecdh public key is not on the P-256 curve")
    return x, y


def _ec_keypair():
    priv = secrets.randbelow(_N - 1) + 1
    return priv, _ec_pub_bytes(_ec_mul(priv, _G))


def _hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_session_key(client_pub: bytes, server_priv: int,
                       server_pub: bytes) -> bytes:
    shared = _ec_mul(server_priv, _ec_point_from_pub(client_pub))
    return _hkdf_sha256(shared[0].to_bytes(32, "big"),
                        client_pub + server_pub,
                        b"xmagic session key v1")


def _env_keys(master):
    return (hmac.new(master, b"xmagic enc", hashlib.sha256).digest(),
            hmac.new(master, b"xmagic mac", hashlib.sha256).digest())


def _keystream(enc_key, nonce, length):
    out, counter = b"", 0
    while len(out) < length:
        out += hmac.new(enc_key, nonce + counter.to_bytes(4, "big"),
                        hashlib.sha256).digest()
        counter += 1
    return out[:length]


def seal_envelope(master, aad: bytes, plaintext: bytes) -> str:
    enc_key, mac_key = _env_keys(master)
    nonce = secrets.token_bytes(16)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(mac_key, aad + nonce + ct, hashlib.sha256).digest()[:16]
    return b64u_encode(nonce + tag + ct)


def open_envelope(master, aad: bytes, blob: str) -> bytes:
    try:
        raw = b64u_decode(blob)
        nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
        if len(nonce) != 16 or len(tag) != 16:
            raise ValueError("short envelope")
    except Exception:
        raise ApiError(401, "malformed encrypted envelope")
    enc_key, mac_key = _env_keys(master)
    want = hmac.new(mac_key, aad + nonce + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, want):
        raise ApiError(401, "encrypted envelope failed authentication")
    ks = _keystream(enc_key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


# ---------------------------------------------------------------- WebAuthn

def parse_auth_data(auth_data: bytes):
    """Split authenticator data; returns dict incl. parsed attestation."""
    if len(auth_data) < 37:
        raise ValueError("authData too short")
    out = {
        "rp_id_hash": auth_data[:32],
        "flags": auth_data[32],
        "sign_count": int.from_bytes(auth_data[33:37], "big"),
    }
    out["user_present"] = bool(out["flags"] & 0x01)
    out["user_verified"] = bool(out["flags"] & 0x04)
    offset = 37
    if out["flags"] & 0x40:  # AT: attested credential data follows
        out["aaguid"] = auth_data[offset:offset + 16]; offset += 16
        cred_len = int.from_bytes(auth_data[offset:offset + 2], "big"); offset += 2
        out["credential_id"] = auth_data[offset:offset + cred_len]; offset += cred_len
        cose, offset = cbor_decode(auth_data, offset)
        out["cose_key"] = cose
    return out


def check_client_data(raw: bytes, expected_type: str, challenge: bytes):
    try:
        data = json.loads(raw)
    except ValueError:
        raise ApiError(400, "clientDataJSON is not JSON")
    if data.get("type") != expected_type:
        raise ApiError(400, f"clientData type is {data.get('type')!r}, want {expected_type}")
    try:
        got = b64u_decode(data.get("challenge", ""))
    except Exception:
        raise ApiError(400, "clientData challenge is not base64url")
    if not secrets.compare_digest(got, challenge):
        raise ApiError(400, "challenge mismatch")
    if data.get("origin") not in ORIGINS:
        raise ApiError(400, f"origin {data.get('origin')!r} not allowed (want one of {ORIGINS})")
    return data


def check_auth_data_basics(auth, require_uv=True):
    if auth["rp_id_hash"] != hashlib.sha256(RP_ID.encode()).digest():
        raise ApiError(400, "rpId hash mismatch")
    if not auth["user_present"]:
        raise ApiError(400, "user-presence flag not set")
    if require_uv and not auth["user_verified"]:
        raise ApiError(400, "user verification required but UV flag not set")


# ------------------------------------------------------------ state stores

_lock = threading.Lock()
_challenges = {}  # challenge -> {purpose, expires, ecdh}
_seen_envelopes = {}  # sid -> {envelope hash: seen_at} (anti-replay)
_cli_replace_tickets = {}  # passkey-replace ticket -> {expires, initiator_sid, done}


def new_challenge(purpose: str, client_pub_b64=None):
    """Issue a WebAuthn challenge -> (challenge_bytes, ecdh_public).
    With a client ECDH public key the challenge binds both shares:
    SHA-256(nonce || client_pub || server_pub); the ceremony state
    (both pubs, the nonce, the server's ephemeral private) stays
    server-side until verify pops it. ecdh_public is the part the
    options response may show: {server_pub, nonce}."""
    ecdh = None
    if client_pub_b64:
        client_pub = b64u_decode(client_pub_b64)
        _ec_point_from_pub(client_pub)  # validate before binding to it
        server_priv, server_pub = _ec_keypair()
        nonce = secrets.token_bytes(32)
        raw = hashlib.sha256(nonce + client_pub + server_pub).digest()
        ecdh = {"client_pub": client_pub_b64,
                "server_pub": b64u_encode(server_pub),
                "nonce": b64u_encode(nonce), "_priv": server_priv}
    else:
        raw = secrets.token_bytes(32)
    with _lock:
        _challenges[b64u_encode(raw)] = {
            "purpose": purpose, "expires": time.time() + CHALLENGE_TTL,
            "ecdh": ecdh}
    public = None
    if ecdh:
        public = {"server_pub": ecdh["server_pub"], "nonce": ecdh["nonce"]}
    return raw, public


def take_challenge(raw: bytes, purpose: str):
    """Pop a ceremony; returns its ECDH state (dict or None)."""
    key = b64u_encode(raw)
    with _lock:
        entry = _challenges.pop(key, None)
    if entry is None or entry["purpose"] != purpose \
            or entry["expires"] < time.time():
        raise ApiError(400, "challenge expired or unknown - retry the ceremony")
    return entry["ecdh"]


def establish_session(kind: str, label, ecdh) -> dict:
    """Turn a passkey ceremony's ECDH state into a stored key-bound
    session. Sessions live in the DB (users.py), so they survive
    console restarts and every interface can list and revoke them."""
    if ecdh is None:
        raise ApiError(400, "the ceremony did not negotiate a session key")
    master = derive_session_key(b64u_decode(ecdh["client_pub"]),
                                ecdh["_priv"],
                                b64u_decode(ecdh["server_pub"]))
    sid = secrets.token_urlsafe(24)
    with admin_db() as conn:
        expires = users_mod.mint_session_keyed(
            conn, sid, b64u_encode(master), ecdh["client_pub"],
            ecdh["server_pub"], kind, label, session_ttl_seconds())
    return {"id": sid, "server_pub": ecdh["server_pub"],
            "expires_at": expires}


def establish_cli_session(client_pub_b64, label) -> dict:
    """Key exchange for a CLI session, run inside an already
    encrypted channel (that channel's session is the authentication):
    the CLI contributed its ephemeral public key, the server answers
    with its own, and both sides derive the same session key. No
    passkey ceremony and no challenge are involved here."""
    client_pub = b64u_decode(client_pub_b64 or "")
    _ec_point_from_pub(client_pub)
    server_priv, server_pub = _ec_keypair()
    master = derive_session_key(client_pub, server_priv, server_pub)
    sid = secrets.token_urlsafe(24)
    with admin_db() as conn:
        expires = users_mod.mint_session_keyed(
            conn, sid, b64u_encode(master), b64u_encode(client_pub),
            b64u_encode(server_pub), "cli", label, session_ttl_seconds())
    return {"id": sid, "server_pub": b64u_encode(server_pub),
            "expires_at": expires}


def api_create_cli_session(body):
    label = (body.get("label") or "")[:80] or None
    return establish_cli_session(body.get("client_pub"), label)


# ------------------------------------------------------------ CLI handoff
# The xmagic CLI logs in by opening the browser at /cli-auth on this
# console, carrying the CLI's ephemeral ECDH public key. Once the
# page holds an encrypted web session (an existing one, or one it
# just established with the passkey ceremony), it asks this server
# - inside that encrypted channel - to mint a CLI session bound to
# the CLI's public key (api_create_cli_session), and redirects the
# browser to the CLI's loopback callback with only public values:
# the new session id and the server's public key. The CLI derives
# the session key with its private half; the key itself never
# travels anywhere.

CLI_REPLACE_TTL = 300


def cli_replace_ticket(initiator_sid):
    """Issue a one-time ticket authorizing a browser ceremony that
    replaces the admin passkey on behalf of the calling (CLI) session.
    The ticket remembers the initiator's session id so the ceremony
    can keep exactly that session alive while revoking all others -
    the same semantics as a console-side replacement, with the CLI
    session treated as the operator's current one."""
    ticket = secrets.token_urlsafe(24)
    with _lock:
        for stale in [t for t, v in _cli_replace_tickets.items()
                      if v["initiator_sid"] == initiator_sid]:
            del _cli_replace_tickets[stale]
        _cli_replace_tickets[ticket] = {
            "expires": time.time() + CLI_REPLACE_TTL,
            "initiator_sid": initiator_sid, "done": False}
    return {"ticket": ticket, "expires_in": CLI_REPLACE_TTL}


def _live_replace_ticket(ticket):
    with _lock:
        entry = _cli_replace_tickets.get(ticket or "")
    if entry is None or entry["expires"] < time.time():
        raise ApiError(400, "replace ticket unknown or expired - "
                            "start again from the CLI")
    return entry


def cli_replace_status(ticket):
    return {"done": _live_replace_ticket(ticket)["done"]}


def cli_replace_verify(ticket, body):
    """Complete a CLI-issued passkey replacement: verify the
    attestation (registration_verify), swap the credential, establish
    the browser's fresh key-bound session and revoke every other
    session except that one and the initiating CLI session."""
    entry = _live_replace_ticket(ticket)
    if entry["done"]:
        raise ApiError(400, "this replace ticket was already used")
    result, ecdh = registration_verify(body, allow_replace=True)
    session = establish_session("web", body.get("label"), ecdh)
    with admin_db() as conn:
        conn.execute(
            "DELETE FROM admin_sessions WHERE sid NOT IN (?, ?)",
            (session["id"], entry["initiator_sid"]))
    with _lock:
        entry["done"] = True
    result["session"] = session
    return result


def api_list_sessions(current_sid):
    with admin_db() as conn:
        rows = users_mod.list_session_rows(conn)
    out = []
    for r in rows:
        entry = users_mod.session_row_dict(r)
        entry["current"] = r["sid"] == current_sid
        out.append(entry)
    return {"sessions": out}


def api_revoke_session(id_prefix):
    with admin_db() as conn:
        row = users_mod.revoke_session_by_id(conn, id_prefix)
    if row is None:
        raise ApiError(404, f"no unique live session with id {id_prefix!r}")
    return {"revoked": row["sid"][:12]}


def api_revoke_others(current_sid):
    with admin_db() as conn:
        n = users_mod.revoke_other_sessions(conn, current_sid)
    return {"revoked_others": n}


def drop_session(sid):
    if sid:
        with admin_db() as conn:
            users_mod.revoke_sid(conn, sid)


# ------------------------------------------------------------ admin DB

def admin_db():
    conn = users_mod.db()
    conn.executescript(ADMIN_SCHEMA)
    return conn


def load_credential(conn):
    return conn.execute("SELECT * FROM admin_credentials WHERE id = 1").fetchone()


def store_credential(conn, credential_id: bytes, x: int, y: int, sign_count: int, label):
    from datetime import datetime, timezone
    conn.execute(
        "INSERT OR REPLACE INTO admin_credentials (id, credential_id, public_key_x,"
        " public_key_y, sign_count, label, created_at) VALUES (1, ?, ?, ?, ?, ?, ?)",
        (b64u_encode(credential_id), str(x), str(y), sign_count, label,
         datetime.now(timezone.utc).isoformat()))


# ------------------------------------------------------------ ceremonies

def registration_options(body=None, allow_replace=False):
    with admin_db() as conn:
        if load_credential(conn) is not None and not allow_replace:
            raise ApiError(403, "an admin passkey is already registered; "
                                "registration is closed (users.py admin-reset reopens it)")
    challenge, ecdh_public = new_challenge(
        "register", (body or {}).get("ecdh_pub"))
    out = {
        "challenge": b64u_encode(challenge),
        "rp": {"id": RP_ID, "name": RP_NAME},
        "user": {"id": b64u_encode(secrets.token_bytes(32)),
                 "name": "admin", "displayName": "admin"},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"userVerification": "required",
                                   "residentKey": "required"},
        "attestation": "none",
        "timeout": 60000,
    }
    if ecdh_public:
        out["ecdh"] = ecdh_public
    return out


def registration_verify(body, allow_replace=False):
    with admin_db() as conn:
        if load_credential(conn) is not None and not allow_replace:
            raise ApiError(403, "an admin passkey is already registered")
    response = body.get("response") or {}
    try:
        client_data = b64u_decode(response["clientDataJSON"])
        attestation, _ = cbor_decode(b64u_decode(response["attestationObject"]))
        client_json = json.loads(client_data)
        raw_challenge = b64u_decode(client_json.get("challenge", ""))
    except Exception as exc:
        raise ApiError(400, f"malformed registration response: {exc}")
    ecdh = take_challenge(raw_challenge, "register")
    check_client_data(client_data, "webauthn.create", raw_challenge)
    auth = parse_auth_data(attestation["authData"])
    check_auth_data_basics(auth)
    if "credential_id" not in auth:
        raise ApiError(400, "no attested credential data in authData")
    cose = auth["cose_key"]
    if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
        raise ApiError(400, "credential is not an ES256 P-256 key")
    if not (isinstance(cose.get(-2), bytes) and isinstance(cose.get(-3), bytes)):
        raise ApiError(400, "COSE key is missing its x/y coordinates")
    x = int.from_bytes(cose[-2], "big")
    y = int.from_bytes(cose[-3], "big")
    if (y * y - (x * x * x + _A * x + 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)) % _P != 0:
        raise ApiError(400, "COSE public key is not on the P-256 curve")
    fmt = attestation.get("fmt")
    if fmt == "packed":
        att_stmt = attestation.get("attStmt") or {}
        if "x5c" in att_stmt:
            raise ApiError(400, "packed attestation with x5c is not accepted "
                                "(self-attestation or none only)")
        signed = attestation["authData"] + hashlib.sha256(client_data).digest()
        if not ecdsa_verify((x, y), att_stmt.get("sig", b""), signed):
            raise ApiError(400, "packed attestation signature invalid")
    elif fmt != "none":
        raise ApiError(400, f"attestation format {fmt!r} not accepted (none or packed)")
    with admin_db() as conn:
        store_credential(conn, auth["credential_id"], x, y,
                         auth["sign_count"], body.get("label"))
    return {"status": "registered"}, ecdh


def login_options(body=None):
    with admin_db() as conn:
        cred = load_credential(conn)
    if cred is None:
        raise ApiError(404, "no admin passkey registered yet")
    challenge, ecdh_public = new_challenge(
        "login", (body or {}).get("ecdh_pub"))
    out = {
        "challenge": b64u_encode(challenge),
        "rpId": RP_ID,
        "allowCredentials": [{"type": "public-key", "id": cred["credential_id"]}],
        "userVerification": "required",
        "timeout": 60000,
    }
    if ecdh_public:
        out["ecdh"] = ecdh_public
    return out


def login_verify(body):
    with admin_db() as conn:
        cred = load_credential(conn)
    if cred is None:
        raise ApiError(404, "no admin passkey registered yet")
    if body.get("id") != cred["credential_id"]:
        raise ApiError(400, "credential not recognized")
    response = body.get("response") or {}
    try:
        client_data = b64u_decode(response["clientDataJSON"])
        auth_data = b64u_decode(response["authenticatorData"])
        signature = b64u_decode(response["signature"])
        client_json = json.loads(client_data)
        raw_challenge = b64u_decode(client_json.get("challenge", ""))
    except Exception as exc:
        raise ApiError(400, f"malformed assertion: {exc}")
    ecdh = take_challenge(raw_challenge, "login")
    check_client_data(client_data, "webauthn.get", raw_challenge)
    auth = parse_auth_data(auth_data)
    check_auth_data_basics(auth)
    pub = (int(cred["public_key_x"]), int(cred["public_key_y"]))
    signed = auth_data + hashlib.sha256(client_data).digest()
    if not ecdsa_verify(pub, signature, signed):
        raise ApiError(401, "signature verification failed")
    stored = cred["sign_count"]
    if stored and auth["sign_count"] and auth["sign_count"] <= stored:
        raise ApiError(401, "sign counter did not increase (cloned authenticator?)")
    with admin_db() as conn:
        conn.execute("UPDATE admin_credentials SET sign_count = ? WHERE id = 1",
                     (auth["sign_count"],))
    return {"status": "ok"}, ecdh


# ------------------------------------------------------------ render/apply
# The render/restart engine lives in users.py (apply_changes) so the web
# console and the CLI perform the identical operation.

def apply_changes():
    return users_mod.apply_changes()


# ------------------------------------------------------------ data API
# Mutations mirror users.py's CLI validation; each successful mutation
# re-renders and (socket permitting) restarts the gateway containers.

def _user_dict(r, with_secrets=False):
    out = {"username": r["username"], "enabled": bool(r["enabled"]),
           "group": r["upstream_group"], "ssh_key": bool(r["ssh_pubkey"]),
           "ssh_fingerprint": users_mod._fingerprint_or_none(r["ssh_pubkey"]),
           "note": r["note"], "created_at": r["created_at"]}
    if with_secrets:
        out.update({"vless_uuid": r["vless_uuid"],
                    "password": r["trojan_password"],
                    "ss_method": r["ss_method"], "ss_password": r["ss_password"],
                    "ssh_pubkey": r["ssh_pubkey"]})
    return out


def api_list_users():
    with users_mod.db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        members = users_mod.interconnect_members(conn)
        v_on = users_mod.vless_enabled(conn)
    users = []
    for r in rows:
        d = _user_dict(r, with_secrets=True)
        if r["username"] in members:
            d["interconnect"] = list(members[r["username"]])
        users.append(d)
    return {"users": users, "vless_enabled": v_on}


def api_add_user(body):
    username = (body.get("username") or "").strip()
    if not username or any(c.isspace() for c in username):
        raise ApiError(400, "username must be non-empty without whitespace")
    from datetime import datetime, timezone
    user_uuid = str(uuidlib.uuid4())
    trojan_pw, ss_pw = users_mod.gen_password(), users_mod.gen_password()
    with users_mod.db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, vless_uuid, trojan_password, ss_password,"
                " ss_method, ssh_pubkey, upstream_group, note, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (username, user_uuid, trojan_pw, ss_pw,
                 users_mod.default_ss_method(conn),
                 (body.get("ssh_pubkey") or None), body.get("group") or "default",
                 body.get("note"), datetime.now(timezone.utc).isoformat()))
        except users_mod.IntegrityError:
            raise ApiError(409, f"user already exists: {username}")
        row = users_mod.get_user(conn, username)
        v_on = users_mod.vless_enabled(conn)
    applied = apply_changes()
    return {"user": _user_dict(row, with_secrets=True), "applied": applied,
            "vless_enabled": v_on}


def api_user_action(username, action, body):
    with users_mod.db() as conn:
        users_mod.get_user(conn, username)
        if action == "remove":
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
        elif action in ("enable", "disable"):
            conn.execute("UPDATE users SET enabled = ? WHERE username = ?",
                         (1 if action == "enable" else 0, username))
        elif action == "passwd":
            conn.execute("UPDATE users SET trojan_password = ?, ss_password = ?"
                         " WHERE username = ?",
                         (users_mod.gen_password(), users_mod.gen_password(), username))
        elif action == "setkey":
            conn.execute("UPDATE users SET ssh_pubkey = ? WHERE username = ?",
                         (body.get("ssh_pubkey") or None, username))
        elif action == "setgroup":
            conn.execute("UPDATE users SET upstream_group = ? WHERE username = ?",
                         (body.get("group") or "default", username))
        elif action == "rotate-uuid":
            conn.execute("UPDATE users SET vless_uuid = ? WHERE username = ?",
                         (str(uuidlib.uuid4()), username))
        elif action == "setmethod":
            if body.get("method") not in users_mod.SS_METHODS:
                raise ApiError(400, f"method must be one of {users_mod.SS_METHODS}")
            conn.execute("UPDATE users SET ss_method = ? WHERE username = ?",
                         (body["method"], username))
        elif action == "setnote":
            conn.execute("UPDATE users SET note = ? WHERE username = ?",
                         (body.get("note") or None, username))
        else:
            raise ApiError(404, f"unknown user action {action}")
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                           (username,)).fetchone() if action != "remove" else None
        v_on = users_mod.vless_enabled(conn)
    applied = apply_changes()
    return {"applied": applied, "vless_enabled": v_on,
            "user": _user_dict(row, with_secrets=True) if row else None}


def _upstream_dict(r):
    return {"name": r["name"], "group": r["grp"], "enabled": bool(r["enabled"]),
            "protocol": r["protocol"], "address": r["address"], "port": r["port"],
            "path": r["path"], "uuid": r["uuid"], "username": r["username"],
            "password": r["password"], "key_file": r["key_file"],
            "tls": bool(r["tls"]), "method": r["method"], "note": r["note"]}


def api_list_upstreams():
    with users_mod.db() as conn:
        rows = conn.execute("SELECT * FROM upstreams ORDER BY grp, name").fetchall()
    return {"upstreams": [_upstream_dict(r) for r in rows]}


def api_generate_keypair(body):
    """Mint a fresh ed25519 keypair FOR NODE-OWNED KEYS ONLY (the SSH
    upstream button): those private keys live on the node by design.
    USER keypairs are never minted here - the console generates them
    in the page (genUserKeypair) and the remote CLI generates them
    locally, so a user's private key never exists on the server."""
    comment = str((body or {}).get("comment") or "xmagic")[:64]
    pem, pub, fp = users_mod.generate_ed25519_keypair(comment)
    return {"private_key": pem, "public_key": pub, "fingerprint": fp}


def api_add_upstream(body):
    proto = body.get("protocol")
    if body.get("method") and body["method"] not in users_mod.SS_METHODS:
        raise ApiError(400, f"method must be one of {users_mod.SS_METHODS}")
    if proto in ("vless-ws", "vless") and not body.get("uuid"):
        raise ApiError(400, f"{proto} upstream needs a uuid")
    if proto in ("trojan-ws", "ss") and not body.get("password"):
        raise ApiError(400, f"{proto} upstream needs a password")
    if proto in ("http", "socks") and body.get("username") and not body.get("password"):
        raise ApiError(400, f"{proto} upstream with a username also needs a password")
    key_content = body.get("key_content")
    if body.get("key_generate") and not key_content:
        key_content = users_mod.generate_ed25519_keypair(
            f"xmagic upstream {body.get('name') or 'upstream'}")[0]
    if proto == "ssh" and not (body.get("username")
                               and (body.get("key_file") or key_content)):
        raise ApiError(400, "ssh upstream needs a username and a key"
                            " (key_file path or key_content)")
    if key_content:
        try:
            users_mod.validate_key_content(key_content)
        except ValueError as exc:
            raise ApiError(400, str(exc))
    key_file = (users_mod.managed_key_path(body.get("name") or "")
                if key_content else body.get("key_file"))
    from datetime import datetime, timezone
    with users_mod.db() as conn:
        if proto in ("vless-ws", "vless") and not users_mod.vless_enabled(conn):
            raise ApiError(400, "vless upstreams are disabled together with"
                                " the vless protocol (enable vless first)")
        try:
            conn.execute(
                "INSERT INTO upstreams (name, grp, address, port, protocol, path, uuid,"
                " username, password, key_file, tls, method, note, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (body["name"], body.get("group") or "default", body["address"],
                 int(body["port"]), proto, body.get("path"), body.get("uuid"),
                 body.get("username"), body.get("password"), key_file,
                 1 if body.get("tls") else 0, body.get("method") or "aes-256-gcm",
                 body.get("note"), datetime.now(timezone.utc).isoformat()))
        except users_mod.IntegrityError:
            raise ApiError(409, f"upstream already exists: {body.get('name')}")
        except KeyError as exc:
            raise ApiError(400, f"missing field: {exc}")
        row = users_mod.get_upstream(conn, body["name"])
    if key_content:
        users_mod.write_upstream_key(body["name"], key_content)
    applied = apply_changes()
    return {"upstream": _upstream_dict(row), "applied": applied}


def api_upstream_action(name, action):
    with users_mod.db() as conn:
        row = users_mod.get_upstream(conn, name)
        if action == "remove":
            conn.execute("DELETE FROM upstreams WHERE name = ?", (name,))
            users_mod.delete_managed_key(row["key_file"])
        elif action in ("enable", "disable"):
            conn.execute("UPDATE upstreams SET enabled = ? WHERE name = ?",
                         (1 if action == "enable" else 0, name))
        else:
            raise ApiError(404, f"unknown upstream action {action}")
    applied = apply_changes()
    return {"applied": applied}


def api_update_upstream(name, body):
    changes = {k: body.get(k) for k in
               ("grp", "address", "port", "protocol", "path", "uuid", "username",
                "password", "key_file", "key_content", "tls", "method", "note")}
    if body.get("key_generate"):
        changes["key_content"] = users_mod.generate_ed25519_keypair(
            f"xmagic upstream {name}")[0]
    if "group" in body:  # friendlier alias for grp
        changes["grp"] = body["group"]
    with users_mod.db() as conn:
        try:
            row = users_mod.update_upstream(conn, name, changes)
        except ValueError as exc:
            raise ApiError(400, str(exc))
    applied = apply_changes()
    return {"upstream": _upstream_dict(row), "applied": applied}


def _route_dict(r):
    return {"id": r["id"], "kind": r["kind"], "pattern": r["pattern"],
            "target": r["target"], "username": r["username"],
            "enabled": bool(r["enabled"]), "note": r["note"]}


def api_list_routes():
    with users_mod.db() as conn:
        rows = conn.execute("SELECT * FROM routes ORDER BY id").fetchall()
    return {"routes": [_route_dict(r) for r in rows]}


def api_add_route(body):
    kind, pattern = body.get("kind"), body.get("pattern") or ""
    try:
        users_mod.validate_route_fields(kind, pattern)
    except ValueError as exc:
        raise ApiError(400, str(exc))
    from datetime import datetime, timezone
    with users_mod.db() as conn:
        if body.get("username"):
            users_mod.get_user(conn, body["username"])
        rid = conn.insert_id(
            "INSERT INTO routes (kind, pattern, target, username, note, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (kind, pattern, body["to"], body.get("username"), body.get("note"),
             datetime.now(timezone.utc).isoformat()))
        row = users_mod.get_route(conn, rid)
    applied = apply_changes()
    return {"route": _route_dict(row), "applied": applied}


def api_route_action(rid, action):
    with users_mod.db() as conn:
        users_mod.get_route(conn, rid)
        if action == "remove":
            conn.execute("DELETE FROM routes WHERE id = ?", (rid,))
        elif action in ("enable", "disable"):
            conn.execute("UPDATE routes SET enabled = ? WHERE id = ?",
                         (1 if action == "enable" else 0, rid))
        else:
            raise ApiError(404, f"unknown route action {action}")
    applied = apply_changes()
    return {"applied": applied}


def api_update_route(rid, body):
    changes = {k: body.get(k) for k in
               ("kind", "pattern", "target", "username", "note")}
    if "to" in body:
        changes["target"] = body["to"]
    with users_mod.db() as conn:
        try:
            row = users_mod.update_route(conn, rid, changes)
        except ValueError as exc:
            raise ApiError(400, str(exc))
    applied = apply_changes()
    return {"route": _route_dict(row), "applied": applied}


def api_get_settings():
    with users_mod.db() as conn:
        info = users_mod.settings_info(conn)
        info["db_values"] = {
            k: users_mod.get_setting(conn, k) for k in
            ("vless_ws_paths", "trojan_ws_paths", "upstream_strategy", "ss_method",
             "interconnect_off_groups")}
    info.update({
        "session_ttl_default": users_mod.SESSION_TTL_HOURS_DEFAULT,
        "session_ttl_min": users_mod.SESSION_TTL_HOURS_MIN,
        "session_ttl_max": users_mod.SESSION_TTL_HOURS_MAX,
        "strategies": list(users_mod.STRATEGIES),
        "ss_methods": list(users_mod.SS_METHODS)})
    return info


def api_set_settings(body):
    render_relevant = False
    with users_mod.db() as conn:
        if "session_ttl_hours" in body:
            hours = body["session_ttl_hours"]
            if (not isinstance(hours, int) or isinstance(hours, bool)
                    or not (users_mod.SESSION_TTL_HOURS_MIN <= hours
                            <= users_mod.SESSION_TTL_HOURS_MAX)):
                raise ApiError(400, f"session_ttl_hours must be an integer "
                                    f"{users_mod.SESSION_TTL_HOURS_MIN}.."
                                    f"{users_mod.SESSION_TTL_HOURS_MAX}")
            users_mod.set_setting(conn, "session_ttl_hours", hours)
        for key in ("vless_ws_paths", "trojan_ws_paths"):
            if key in body:
                render_relevant = True
                value = body[key]
                if value is None or value == "" or value == []:
                    users_mod.delete_setting(conn, key)
                else:
                    if isinstance(value, list):
                        value = ",".join(value)
                    users_mod.set_setting(
                        conn, key,
                        ",".join(users_mod._parse_paths(value, "/unused")))
        for key, choices in (("upstream_strategy", users_mod.STRATEGIES),
                             ("ss_method", users_mod.SS_METHODS)):
            if key in body:
                render_relevant = True
                value = body[key]
                if value is None or value == "":
                    users_mod.delete_setting(conn, key)
                elif value not in choices:
                    raise ApiError(400, f"{key} must be one of {choices}")
                else:
                    users_mod.set_setting(conn, key, value)
        if "vless_enabled" in body:
            render_relevant = True
            value = body["vless_enabled"]
            if value is None:
                users_mod.delete_setting(conn, "vless_enabled")
            elif isinstance(value, bool):
                users_mod.set_setting(conn, "vless_enabled",
                                      "1" if value else "0")
            else:
                raise ApiError(400, "vless_enabled must be a boolean")
        if "direct_allow_private" in body:
            render_relevant = True
            value = body["direct_allow_private"]
            if value is None or value == "":
                users_mod.delete_setting(conn, "direct_allow_private")
            elif isinstance(value, bool):
                users_mod.set_setting(conn, "direct_allow_private",
                                      "1" if value else "0")
            else:
                raise ApiError(400, "direct_allow_private must be a boolean")
        if "interconnect_off_groups" in body:
            render_relevant = True
            value = body["interconnect_off_groups"]
            if value is None or value == "" or value == []:
                users_mod.delete_setting(conn, "interconnect_off_groups")
            else:
                if isinstance(value, list):
                    value = ",".join(str(v) for v in value)
                try:
                    users_mod.set_setting(
                        conn, "interconnect_off_groups",
                        users_mod.normalize_group_list(value))
                except ValueError as exc:
                    raise ApiError(400, str(exc))
    result = api_get_settings()
    if render_relevant:
        result["applied"] = apply_changes()
    return result


# ------------------------------------------------------------ databases
# The database configs themselves live in the node's local registry
# (users_mod, backed by a local SQLite file); these endpoints expose
# the same operations as the db-* CLI commands.

def _db_call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except users_mod.DBError as exc:
        raise ApiError(400, str(exc))


def api_list_databases():
    return {"databases": users_mod.list_db_configs()}


def api_add_database(body):
    cfg = _db_call(users_mod.add_db_config, body.get("name") or "",
                   body.get("type") or "", body.get("target") or "",
                   body.get("note"))
    return {"database": cfg}


def api_database_action(name, action, body):
    if action == "edit":
        cfg = _db_call(users_mod.edit_db_config, name,
                       target=body.get("target"), note=body.get("note"))
        return {"database": cfg}
    if action == "remove":
        _db_call(users_mod.remove_db_config, name)
        return {"removed": name}
    if action == "test":
        return {"test": _db_call(users_mod.test_db_config, name)}
    if action == "switch":
        cfg = _db_call(users_mod.switch_db_config, name)
        return {"database": cfg, "applied": apply_changes()}
    raise ApiError(404, f"unknown database action {action}")


def api_migrate_database(body):
    result = _db_call(users_mod.migrate_db_config, body.get("from") or "",
                      body.get("to") or "",
                      replace=bool(body.get("replace")))
    return {"migration": result}


def api_state():
    with users_mod.db() as conn:
        n_users = conn.execute("SELECT COUNT(*) FROM users WHERE enabled = 1").fetchone()[0]
        n_up = conn.execute("SELECT COUNT(*) FROM upstreams WHERE enabled = 1").fetchone()[0]
        n_routes = conn.execute("SELECT COUNT(*) FROM routes WHERE enabled = 1").fetchone()[0]
        cred = load_credential(conn)
    return {"admin_registered": cred is not None,
            "admin_created_at": cred["created_at"] if cred else None,
            "admin_label": cred["label"] if cred else None,
            "admin_sign_count": cred["sign_count"] if cred else None,
            "enabled_users": n_users, "enabled_upstreams": n_up,
            "enabled_routes": n_routes,
            "docker_socket": os.path.exists(DOCKER_SOCK),
            "restart_via": users_mod.restart_channel(),
            "public_port": users_mod.PUBLIC_PORT}


# ------------------------------------------------------------ HTTP layer

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep stdout for real errors only
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- plumbing
    def _send_json(self, status, payload):
        row = getattr(self, "_session_row", None)
        if row is not None:
            wrapped = json.dumps(
                {"t": int(time.time()), "body": payload}).encode()
            raw = json.dumps({"e": seal_envelope(
                b64u_decode(row["key"]), self._aad(), wrapped)}).encode()
        else:
            raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _aad(self):
        row = getattr(self, "_session_row", None)
        sid = row["sid"] if row else ""
        path = self.path.split("?", 1)[0]
        return f"{sid}\n{self.command}\n{path}".encode()

    def _unwrap(self, blob):
        """Decrypt one envelope from the request's session and return
        its body. Enforces the timestamp window and one-use envelopes
        (a captured request cannot be replayed)."""
        row = self._session_row
        plain = open_envelope(b64u_decode(row["key"]), self._aad(), blob)
        try:
            wrapped = json.loads(plain)
            ts, body = int(wrapped["t"]), wrapped["body"]
        except Exception:
            raise ApiError(400, "envelope payload is not a wrapped JSON body")
        if abs(int(time.time()) - ts) > 300:
            raise ApiError(401, "envelope timestamp outside the accepted window")
        marker = hashlib.sha256(blob.encode()).hexdigest()
        now = time.time()
        with _lock:
            seen = _seen_envelopes.setdefault(row["sid"], {})
            for k in [k for k, v in seen.items() if v < now - 600]:
                del seen[k]
            if marker in seen:
                raise ApiError(401, "envelope replay detected")
            seen[marker] = now
        return body

    def _load_session_row(self):
        sid = self.headers.get("X-Session-Id")
        if not sid:
            return None
        with admin_db() as conn:
            return users_mod.find_session_by_sid(conn, sid)

    def _send_html(self, html):
        raw = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline';"
                         " script-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(raw)

    def _send_cli_script(self):
        """Serve the remote CLI bundled with THIS deployment, so installs
        and self-updates always match the running service byte for byte.
        Public on purpose: installing the CLI is step one (no login can
        exist yet) and the file is open source carrying no secret."""
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "xmagic.py")
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            raise ApiError(404, "xmagic.py is not bundled with this deployment")
        self.send_response(200)
        self.send_header("Content-Type", "text/x-python; charset=utf-8")
        self.send_header("Content-Disposition",
                         'attachment; filename="xmagic.py"')
        self.send_header("X-Xmagic-Cli-Sha256",
                         hashlib.sha256(data).hexdigest())
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _require_auth(self):
        if getattr(self, "_session_row", None) is None:
            raise ApiError(401, "not logged in")

    def _check_origin(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ORIGINS:
            raise ApiError(403, f"origin {origin!r} not allowed")

    # -- routing
    def do_GET(self):
        try:
            self._route_get()
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.message})
        except SystemExit as exc:
            self._send_json(404, {"error": str(exc.code)})
        except Exception as exc:  # noqa: BLE001 - surface as 500 JSON
            self._send_json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self):
        try:
            self._route_post()
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.message})
        except SystemExit as exc:
            self._send_json(404, {"error": str(exc.code)})
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def _route_get(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send_html(UI_HTML)
            return
        if path == "/cli-auth":
            self._send_html(CLI_AUTH_HTML)
            return
        if path == "/cli-replace":
            self._send_html(CLI_REPLACE_HTML)
            return
        if path == "/api/status":
            with admin_db() as conn:
                registered = load_credential(conn) is not None
            self._send_json(200, {"registered": registered,
                                  "rp_id": RP_ID})
            return
        if path == "/cli/xmagic.py":
            self._send_cli_script()
            return
        # Authenticated GETs: the session id names the session, an
        # encrypted proof envelope (of an empty body, bound to this
        # method+path) proves the caller holds its key.
        self._session_row = self._load_session_row()
        if self._session_row is None:
            raise ApiError(401, "not logged in")
        proof = self.headers.get("X-Enc")
        if not proof:
            raise ApiError(401, "missing encrypted session proof")
        self._unwrap(proof)
        if path == "/api/state":
            self._send_json(200, api_state())
        elif path == "/api/settings":
            self._send_json(200, api_get_settings())
        elif path == "/api/sessions":
            self._send_json(200, api_list_sessions(self._session_row["sid"]))
        elif path == "/api/users":
            self._send_json(200, api_list_users())
        elif path == "/api/upstreams":
            self._send_json(200, api_list_upstreams())
        elif path == "/api/routes":
            self._send_json(200, api_list_routes())
        elif path == "/api/databases":
            self._send_json(200, api_list_databases())
        else:
            raise ApiError(404, "not found")

    def _route_post(self):
        path = self.path.split("?", 1)[0]
        self._check_origin()
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1 << 20:
            raise ApiError(413, "request body too large")
        raw = self.rfile.read(length) if length else b""
        # A request carrying a session id speaks ONLY in envelopes:
        # decrypt before dispatch; anything else is a bootstrap call
        # (options/verify ceremonies) whose body is plain JSON.
        self._session_row = self._load_session_row()
        body = {}
        bootstrap = path in ("/api/register/options", "/api/register/verify",
                             "/api/login/options", "/api/login/verify")
        if self.headers.get("X-Session-Id") and self._session_row is None \
                and not bootstrap:
            # a dead session id on an authenticated call: hard fail.
            # On a bootstrap call it is simply ignored, so a client
            # holding a stale id can always sign in again.
            raise ApiError(401, "session expired or revoked - sign in again")
        if self._session_row is not None:
            try:
                envelope = json.loads(raw) if raw else {}
            except ValueError:
                raise ApiError(400, "request body is not JSON")
            if not isinstance(envelope, dict) or "e" not in envelope:
                raise ApiError(400, "session requests must be encrypted envelopes")
            body = self._unwrap(envelope["e"])
        elif raw:
            try:
                body = json.loads(raw)
            except ValueError:
                raise ApiError(400, "request body is not JSON")
        ua_label = (self.headers.get("User-Agent") or "")[:80] or None
        if path == "/api/register/options":
            allow = self._session_row is not None
            self._send_json(200, registration_options(body, allow_replace=allow))
            return
        if path == "/api/register/verify":
            authed = self._session_row is not None
            with admin_db() as conn:
                had_credential = load_credential(conn) is not None
            result, ecdh = registration_verify(body, allow_replace=authed)
            session = establish_session("web", ua_label, ecdh)
            if had_credential:
                # The passkey was replaced: every other session dies here.
                with admin_db() as conn:
                    users_mod.revoke_other_sessions(conn, session["id"])
            result["session"] = session
            self._send_json(200, result)
            return
        if path == "/api/login/options":
            self._send_json(200, login_options(body))
            return
        if path == "/api/login/verify":
            result, ecdh = login_verify(body)
            result["session"] = establish_session("web", ua_label, ecdh)
            self._send_json(200, result)
            return
        self._require_auth()
        if path == "/api/keys/generate":
            self._send_json(200, api_generate_keypair(body))
            return
        if path == "/api/cli/sessions":
            self._send_json(201, api_create_cli_session(body))
            return
        if path == "/api/cli-replace-ticket":
            self._send_json(200, cli_replace_ticket(self._session_row["sid"]))
            return
        if path == "/api/cli-replace-status":
            self._send_json(200, cli_replace_status(body.get("ticket")))
            return
        if path == "/api/cli-replace-options":
            _live_replace_ticket(body.get("ticket"))
            self._send_json(200, registration_options(body, allow_replace=True))
            return
        if path == "/api/cli-replace-verify":
            self._send_json(200, cli_replace_verify(body.get("ticket"), body))
            return
        if path == "/api/logout":
            drop_session(self._session_row["sid"])
            self._send_json(200, {"status": "logged out"})
        elif path == "/api/apply":
            self._send_json(200, {"applied": apply_changes()})
        elif path == "/api/settings":
            self._send_json(200, api_set_settings(body))
        elif path == "/api/sessions/revoke-others":
            self._send_json(200, api_revoke_others(self._session_row["sid"]))
        elif path.startswith("/api/sessions/"):
            sid, _, action = path[len("/api/sessions/"):].partition("/")
            if action != "revoke":
                raise ApiError(404, f"unknown session action {action}")
            self._send_json(200, api_revoke_session(sid))
        elif path == "/api/users":
            self._send_json(201, api_add_user(body))
        elif path.startswith("/api/users/"):
            username, _, action = path[len("/api/users/"):].partition("/")
            self._send_json(200, api_user_action(username, action, body))
        elif path == "/api/upstreams":
            self._send_json(201, api_add_upstream(body))
        elif path.startswith("/api/upstreams/"):
            name, _, action = path[len("/api/upstreams/"):].partition("/")
            if action == "update":
                self._send_json(200, api_update_upstream(name, body))
            else:
                self._send_json(200, api_upstream_action(name, action))
        elif path == "/api/routes":
            self._send_json(201, api_add_route(body))
        elif path == "/api/databases":
            self._send_json(201, api_add_database(body))
        elif path == "/api/databases/migrate":
            self._send_json(200, api_migrate_database(body))
        elif path.startswith("/api/databases/"):
            name, _, action = path[len("/api/databases/"):].partition("/")
            self._send_json(200, api_database_action(name, action, body))
        elif path.startswith("/api/routes/"):
            rid, _, action = path[len("/api/routes/"):].partition("/")
            if action == "update":
                self._send_json(200, api_update_route(int(rid), body))
            else:
                self._send_json(200, api_route_action(int(rid), action))
        else:
            raise ApiError(404, "not found")


UI_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xmagic 管理后台</title>
<style>
:root{
  --bg:#f4f6fb; --card:#ffffff; --border:#e4e8f1; --border-strong:#d3d9e6;
  --text:#101828; --muted:#667085; --faint:#98a2b3;
  --accent:#2563eb; --accent-hover:#1d4ed8; --accent-soft:#eff4ff;
  --ok:#12805c; --ok-soft:#ecfdf3; --err:#b42318; --err-soft:#fef3f2;
  --side:#0b1220; --side-text:#c3cad9; --side-active:#ffffff;
  --radius:12px; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
  background:var(--bg);color:var(--text);font-size:14px;line-height:1.55}
.hidden{display:none!important}
button{font:inherit;cursor:pointer;border:1px solid var(--border-strong);background:#fff;color:var(--text);
  border-radius:8px;padding:.42rem .85rem;font-size:.85rem;transition:background .12s,border-color .12s}
button:hover{background:#f2f5fa}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
button.primary:hover{background:var(--accent-hover)}
button.ghost{border-color:transparent;background:transparent;color:var(--muted)}
button.ghost:hover{background:#eef1f7;color:var(--text)}
button.sm{padding:.22rem .6rem;font-size:.8rem;border-radius:7px}
button.danger{color:var(--err)}
button.danger:hover{background:var(--err-soft);border-color:#f3c2bd}
input,select{font:inherit;font-size:.88rem;padding:.45rem .6rem;border:1px solid var(--border-strong);
  border-radius:8px;background:#fff;color:var(--text);width:100%}
input:focus,select:focus{outline:2px solid var(--accent-soft);border-color:var(--accent)}
input[readonly]{background:#f8fafc;font-family:var(--mono);font-size:.78rem}
code{font-family:var(--mono);font-size:.76rem;word-break:break-all;color:#344054}
label{font-size:.82rem;color:var(--muted);display:block;margin-bottom:.3rem;font-weight:500}
.hint{color:var(--muted);font-size:.82rem}
.small{color:var(--muted);font-size:.82rem}

/* ---------- auth screens (setup / login) ---------- */
.auth-wrap{min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:9vh 1rem 2rem}
.auth-card{background:var(--card);border:1px solid var(--border);border-radius:16px;
  box-shadow:0 12px 32px rgba(16,24,40,.08);max-width:520px;width:100%;padding:2.2rem 2.4rem}
.auth-card .logo{font-size:1.5rem;font-weight:700;letter-spacing:-.02em}
.auth-card .logo span{color:var(--accent)}
.auth-card h2{font-size:1.05rem;margin:1.1rem 0 .4rem}
.auth-card p{color:var(--muted);margin:.4rem 0 1.2rem}
.auth-card button{width:100%;padding:.6rem;font-size:.95rem}

/* ---------- app shell ---------- */
.shell{display:flex;min-height:100vh}
.sidebar{width:230px;flex:0 0 230px;background:var(--side);color:var(--side-text);
  position:sticky;top:0;height:100vh;display:flex;flex-direction:column;padding:1.1rem .8rem}
.brand{font-size:1.25rem;font-weight:700;color:#fff;letter-spacing:-.02em;padding:.2rem .6rem}
.brand span{color:#6ea8ff}
.brand-sub{font-size:.72rem;color:#7d879c;padding:0 .6rem;margin-bottom:1.4rem}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{display:flex;align-items:center;gap:.55rem;text-align:left;background:transparent;border:0;
  color:var(--side-text);padding:.5rem .6rem;border-radius:8px;font-size:.9rem;width:100%}
.nav button:hover{background:#141d31;color:#fff}
.nav button.active{background:#1b2740;color:var(--side-active);font-weight:600}
.nav button .dot{width:6px;height:6px;border-radius:50%;background:#3d4a63;flex:0 0 6px}
.nav button.active .dot{background:#6ea8ff}
.side-foot{margin-top:auto;font-size:.72rem;padding:0 .6rem;color:#5b6678}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{position:sticky;top:0;z-index:5;background:rgba(255,255,255,.88);backdrop-filter:blur(8px);
  border-bottom:1px solid var(--border);padding:.8rem 1.6rem;display:flex;align-items:center;gap:1rem}
.topbar h1{font-size:1.08rem;margin:0;font-weight:650}
.topbar .spacer{flex:1}
.topbar .actions{display:flex;gap:.5rem;align-items:center}
.content{padding:1.4rem 1.6rem 3rem;max-width:1180px;width:100%;margin:0 auto}
#msg{position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:60;min-width:280px;max-width:min(720px,92vw);border-radius:10px;padding:.6rem .95rem;font-size:.88rem;display:none;white-space:pre-wrap;box-shadow:0 10px 28px rgba(16,24,40,.16);background:#fff}
#msg.ok{display:block;background:var(--ok-soft);color:var(--ok);border:1px solid #a6e9c5}
#msg.err{display:block;background:var(--err-soft);color:var(--err);border:1px solid #f3c2bd}
.view{display:none}
.view.active{display:block}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:1.15rem 1.25rem;margin-bottom:1.1rem;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.card h2{font-size:.98rem;margin:0 0 .2rem;font-weight:650}
.card .sub{color:var(--muted);font-size:.83rem;margin:0 0 .9rem}
.card .divider{border-top:1px solid var(--border);margin:1rem -1.25rem 0;padding:.9rem 1.25rem 0}

/* ---------- overview stats ---------- */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.1rem}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1rem 1.15rem}
.stat .k{color:var(--muted);font-size:.8rem;font-weight:500}
.stat .v{font-size:1.55rem;font-weight:700;letter-spacing:-.02em;margin-top:.15rem}
.stat .v small{font-size:.8rem;color:var(--muted);font-weight:500}
.cmd-row{display:flex;gap:.5rem;margin:.55rem 0}
.cmd-row input{flex:1}
.cmd-row button{flex:0 0 auto}

/* ---------- tables ---------- */
.tbl-wrap{overflow-x:auto;margin:0 -1.25rem;padding:0 1.25rem}
table{border-collapse:collapse;width:100%;min-width:700px;font-size:.86rem}
th{ text-align:left;color:var(--muted);font-size:.74rem;font-weight:600;letter-spacing:.04em;
  text-transform:uppercase;padding:.45rem .6rem;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:.55rem .6rem;border-bottom:1px solid #eef1f6;vertical-align:top}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:#f8fafd}
td .row-actions{display:flex;flex-wrap:wrap;gap:.3rem}
.badge{display:inline-block;padding:.08rem .55rem;border-radius:999px;font-size:.76rem;font-weight:600;white-space:nowrap}
.badge.on{background:var(--ok-soft);color:var(--ok)}
.badge.off{background:#f2f4f7;color:var(--muted)}
.badge.cur{background:var(--accent-soft);color:var(--accent)}

/* ---------- forms ---------- */
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.8rem .9rem;margin-top:1rem}
.form-grid .wide{grid-column:span 2}
.form-grid .full{grid-column:1/-1}
.add-bar{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-top:1rem}
.add-bar .lbl{color:var(--muted);font-size:.85rem}
.tabs{display:flex;gap:.3rem;border-bottom:1px solid var(--border);margin-bottom:1rem}
.tabs .tab{border:0;background:none;border-bottom:2px solid transparent;border-radius:0;
  padding:.5rem .95rem;font-size:.9rem;font-weight:600;color:var(--muted);margin-bottom:-1px}
.tabs .tab:hover{background:none;color:var(--text)}
.tabs .tab.active{color:var(--accent);border-bottom-color:var(--accent)}
#form-upstream .form-grid, #form-user .form-grid{grid-template-columns:1fr;max-width:560px;margin-top:.2rem}
#form-upstream .form-grid .wide, #form-user .form-grid .wide{grid-column:auto}
.keyrow{display:flex;gap:.5rem;align-items:flex-start}
.keyrow>input,.keyrow>textarea{flex:1}
.form-actions{display:flex;gap:.5rem;align-items:center;margin-top:1rem;flex-wrap:wrap}
.check{display:flex;align-items:center;gap:.45rem;font-size:.88rem;color:var(--text)}
.check input{width:auto}
.check label{margin:0;font-size:.88rem;color:var(--text);font-weight:400}

@media (max-width:860px){
  .shell{flex-direction:column}
  .sidebar{width:100%;flex:none;height:auto;position:static;padding:.8rem}
  .brand-sub{display:none}
  .nav{flex-direction:row;flex-wrap:wrap}
  .nav button{width:auto}
  .side-foot{display:none}
  .content{padding:1rem}
  .topbar{padding:.7rem 1rem}
}
</style></head><body>
<div id="msg"></div>

<div class="auth-wrap" id="auth-wrap">
  <div class="auth-card hidden" id="setup">
    <div class="logo">x<span>magic</span></div>
    <h2>初始化管理后台</h2>
    <p>尚未注册管理员。这个后台只支持一个管理员账号、且只能用 Passkey：
    第一个注册的 Passkey 即为管理员，之后注册永久关闭。</p>
    <button id="btn-register" class="primary">注册管理员 Passkey</button>
  </div>
  <div class="auth-card hidden" id="login">
    <div class="logo">x<span>magic</span></div>
    <h2>管理员登录</h2>
    <p>管理员已注册。请用 Passkey 登录（不支持其它方式）。</p>
    <button id="btn-login" class="primary">用 Passkey 登录</button>
  </div>
</div>

<div id="console" class="hidden">
<div class="shell">
  <aside class="sidebar">
    <div class="brand">x<span>magic</span></div>
    <div class="brand-sub">代理管理后台</div>
    <nav class="nav">
      <button data-nav="overview" class="active"><span class="dot"></span>概览</button>
      <button data-nav="users"><span class="dot"></span>代理用户</button>
      <button data-nav="upstreams"><span class="dot"></span>上级节点</button>
      <button data-nav="routes"><span class="dot"></span>目标路由</button>
      <button data-nav="settings"><span class="dot"></span>设置</button>
      <button data-nav="databases"><span class="dot"></span>数据库</button>
      <button data-nav="sessions"><span class="dot"></span>管理员会话</button>
    </nav>
    <div class="side-foot">Passkey 管理员会话</div>
  </aside>
  <div class="main">
    <div class="topbar">
      <h1 id="view-title">概览</h1>
      <div class="spacer"></div>
      <div class="actions">
        <button id="btn-apply" class="primary">重新渲染并应用</button>
        <button id="btn-logout" class="ghost">退出</button>
      </div>
    </div>
    <div class="content">

      <section class="view active" data-view="overview">
        <div class="stats">
          <div class="stat"><div class="k">启用用户</div><div class="v" id="stat-users">–</div></div>
          <div class="stat"><div class="k">启用上级</div><div class="v" id="stat-upstreams">–</div></div>
          <div class="stat"><div class="k">启用路由</div><div class="v" id="stat-routes">–</div></div>
          <div class="stat"><div class="k">公共端口</div><div class="v" id="stat-port">–</div></div>
          <div class="stat"><div class="k">重启通道</div><div class="v" id="stat-restart" style="font-size:1.05rem;padding-top:.45rem">–</div></div>
        </div>
        <p class="hint" id="state-line" style="margin:0 0 1.1rem"></p>
        <div class="card">
          <h2>远程 CLI</h2>
          <p class="sub">在自己的机器上安装单文件 CLI（纯 Python 标准库，不用 pip），装完把本节点加进去登录即可管理。</p>
          <div class="cmd-row"><input id="cli-install" readonly value="">
            <button type="button" id="btn-copy-install">复制</button></div>
          <div class="cmd-row"><input id="cli-onboard" readonly value="">
            <button type="button" id="btn-copy-onboard">复制</button></div>
          <p class="hint">若提示找不到 xmagic 命令，把 ~/.local/bin 加入 PATH 后重试。</p>
        </div>
      </section>

      <section class="view" data-view="users">
        <div class="card">
          <h2>代理用户</h2>
          <p class="sub">每个用户有一套 Trojan / HTTP 凭证与独立的 Shadowsocks 密码，可选登记 SSH 公钥。VLESS 默认关闭（在「设置」里开启后凭 UUID 接入），公网 SOCKS5 默认关闭。</p>
          <div class="add-bar"><span class="lbl">添加用户：</span><button class="btn ghost sm" data-add-user>+ 代理用户</button></div>
          <div class="tabs" id="user-tabs">
            <button type="button" class="tab active" data-user-tab="list">用户列表</button>
            <button type="button" class="tab hidden" data-user-tab="form" id="user-form-tab"></button>
          </div>
          <div id="user-panel-list">
            <div class="tbl-wrap"><table id="users-table"></table></div>
          </div>
          <div id="user-panel-form" class="hidden">
          <form id="form-user">
            <div class="form-grid">
              <div><label>用户名</label><input name="username" placeholder="用户名" required></div>
              <div><label>上级分组</label><input name="group" placeholder="默认 default"></div>
              <div><label>备注</label><input name="note" placeholder="可选"></div>
              <div class="wide"><label>SSH 公钥（可选，可粘贴或选文件）</label>
                <div class="keyrow"><input name="ssh_pubkey" placeholder="ssh-ed25519 AAAA…">
                <button type="button" class="btn ghost sm" id="btn-pick-pubkey">选文件</button>
                <button type="button" class="btn ghost sm" id="btn-gen-userkey">生成密钥对</button>
                <input type="file" id="pick-pubkey" class="hidden"></div></div>
            </div>
            <div class="form-actions"><button class="primary">保存</button>
              <button type="button" id="user-cancel">取消</button></div>
          </form>
          </div>
        </div>
      </section>

      <section class="view" data-view="upstreams">
        <div class="card">
          <h2>上级节点</h2>
          <p class="sub">级联上级按用户分组选择，池策略在「设置」里调整。带 * 的凭据字段在编辑时留空表示不改动。</p>
          <div class="add-bar"><span class="lbl">添加上级：</span><span id="up-add-btns"></span></div>
          <div class="tabs" id="up-tabs">
            <button type="button" class="tab active" data-up-tab="list">上级列表</button>
            <button type="button" class="tab hidden" data-up-tab="form" id="up-form-tab"></button>
          </div>
          <div id="up-panel-list">
            <div class="tbl-wrap"><table id="upstreams-table"></table></div>
          </div>
          <div id="up-panel-form" class="hidden">
          <form id="form-upstream">
            <div class="form-grid">
              <div><label>名称</label><input name="name" placeholder="名称" required></div>
              <div><label>协议</label><select name="protocol">
                <option>vless-ws</option><option>vless</option><option>trojan-ws</option>
                <option>ss</option><option>http</option><option>socks</option><option>ssh</option>
              </select></div>
              <div class="wide"><label>地址</label><input name="address" placeholder="主机名或 IP" required></div>
              <div><label>端口</label><input name="port" placeholder="端口" type="number" required></div>
              <div><label>分组</label><input name="group" placeholder="分组"></div>
              <div data-proto="vless-ws trojan-ws"><label>WS 路径</label><input name="path" placeholder="/path"></div>
              <div class="wide" data-proto="vless-ws vless"><label>UUID</label><input name="uuid" placeholder="VLESS UUID"></div>
              <div data-proto="http socks ssh"><label>用户名</label><input name="username" placeholder="用户名"></div>
              <div data-proto="trojan-ws ss http socks"><label>密码</label><input name="password" placeholder="密码"></div>
              <div class="wide" data-proto="ssh"><label>SSH 私钥（粘贴内容或选文件上传，存于节点、不回显）</label>
                <div class="keyrow"><textarea name="key_content" rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                <button type="button" class="btn ghost sm" id="btn-pick-privkey">选文件</button>
                <button type="button" class="btn ghost sm" id="btn-gen-upkey">生成密钥对</button>
                <input type="file" id="pick-privkey" class="hidden"></div></div>
              <div data-proto="ssh"><label>或：节点上的密钥路径</label><input name="key_file" placeholder="/keys/id_ed25519"></div>
              <div data-proto="ss"><label>SS 方法</label><select name="method">
                <option>aes-256-gcm</option><option>aes-128-gcm</option>
                <option>chacha20-ietf-poly1305</option><option>2022-blake3-aes-128-gcm</option>
                <option>2022-blake3-aes-256-gcm</option><option>2022-blake3-chacha20-poly1305</option>
              </select></div>
              <div><label>备注</label><input name="note" placeholder="可选"></div>
            </div>
            <div class="form-actions">
              <span class="check" data-proto="vless-ws vless trojan-ws"><input type="checkbox" name="tls" id="up-tls"><label for="up-tls">TLS</label></span>
              <button id="up-submit" class="primary">保存</button>
              <button type="button" id="up-cancel">取消</button>
            </div>
          </form>
          </div>
        </div>
      </section>

      <section class="view" data-view="routes">
        <div class="card">
          <h2>目标路由</h2>
          <p class="sub">按域名 / 关键词 / 正则 / IP 把流量导向某个上级分组、直连或拦截；可限定只对某个用户生效。</p>
          <div class="tbl-wrap"><table id="routes-table"></table></div>
          <form id="form-route">
            <div class="form-grid">
              <div><label>类型</label><select name="kind"><option>domain</option><option>full</option>
                <option>keyword</option><option>regexp</option><option>ip</option></select></div>
              <div class="wide"><label>匹配目标</label><input name="pattern" placeholder="如 example.com 或 10.0.0.0/8" required></div>
              <div><label>去向</label><input name="to" placeholder="分组名 / direct / block" required></div>
              <div><label>限定用户（可选）</label><input name="username" placeholder="留空 = 全部用户"></div>
              <div><label>备注</label><input name="note" placeholder="可选"></div>
            </div>
            <div class="form-actions">
              <button id="route-submit" class="primary">添加路由</button>
              <button type="button" id="route-cancel" class="hidden">取消编辑</button>
            </div>
          </form>
          <p class="hint">每次修改都会自动重新渲染配置，并按需只重启受影响的进程生效。渲染结果见「概览」页状态。</p>
        </div>
      </section>

      <section class="view" data-view="settings">
        <div class="card">
          <h2>设置</h2>
          <p class="sub">渲染级配置保存在数据库里，优先于部署时的环境变量；保存后自动重新渲染生效。</p>
          <form id="form-settings">
            <div class="form-grid">
              <div><label>管理员会话有效期（小时）</label>
                <input name="session_ttl_hours" type="number" min="1" max="2160"></div>
              <div><label>上级池策略</label><select name="upstream_strategy"></select></div>
              <div><label>新用户默认 SS 方法</label><select name="ss_method"></select></div>
              <div class="wide" id="row-vless-paths"><label>VLESS WS 路径（逗号分隔）</label><input name="vless_ws_paths"></div>
              <div class="wide"><label>Trojan WS 路径（逗号分隔）</label><input name="trojan_ws_paths"></div>
              <div class="wide"><label>关闭组内互访的分组（逗号分隔，空 = 全部组互访）</label><input name="interconnect_off_groups" placeholder="例如 team"></div>
            </div>
            <div class="form-actions">
              <span class="check"><input type="checkbox" name="direct_allow_private" id="set-dap"><label for="set-dap">允许直连内网地址</label></span>
              <span class="check"><input type="checkbox" name="vless_enabled" id="set-vless"><label for="set-vless">启用 VLESS 入站（默认关：协议自身不加密）</label></span>
              <button class="primary">保存</button>
            </div>
          </form>
          <p class="hint">会话有效期默认 168 小时（1 周），范围 1–2160，只影响新签发会话。
          WS 路径 / 策略 / 默认方法：留空保存 = 回退到部署时 .env 的值；输入框灰字是当前生效值。
          直连内网地址默认关闭：经 VLESS / Trojan / Shadowsocks 进来的流量直连时不能访问本机与内网地址
          （Xray 的防 SSRF 默认规则）；节点需要访问自家局域网服务时再打开。<br>
          组内互访默认开启：同一分组的成员可用 <code>ssh -R</code> 把自己机器上的服务暴露到网关回环的
          专属端口段（每人 16 个端口，见用户列表），同组成员经代理拨 <code>127.0.0.1:端口</code> 即可
          互访，如同在同一局域网；不想互访的分组填到上面即关闭该组互访。非同组成员拨回环一律拦截。<br>
          默认不加密的协议不开：VLESS 入站默认关闭（协议自身不加密，需要时勾选上面的开关开启）；
          公网 SOCKS5 默认关闭（明文且不能借道 HTTPS，靠部署环境变量 XMAGIC_ENABLE_SOCKS5=1 开启）。
          Trojan（设计上强制 TLS）、Shadowsocks（自带加密）、HTTP 代理（借道外层 HTTPS）不受影响。</p>
          <div class="divider">
            <p class="small" style="margin:0 0 .5rem"><span id="admin-line"></span></p>
            <button type="button" id="btn-replace">更换管理员 Passkey</button>
            <span class="small">更换后，其它所有管理员会话立即失效，本页面会切到新签发的会话。</span>
          </div>
        </div>
      </section>

      <section class="view" data-view="databases">
        <div class="card">
          <h2>数据库</h2>
          <p class="sub">数据库配置本身保存在节点本地，业务数据在当前启用的库里；切到还没有表的库时自动建表。列表中 DSN 的密码已打码。</p>
          <div class="tbl-wrap"><table id="databases-table"></table></div>
          <form id="form-database">
            <div class="form-grid">
              <div><label>名称</label><input name="name" required></div>
              <div><label>类型</label><select name="type">
                <option value="sqlite">SQLite</option>
                <option value="postgres">PostgreSQL</option>
                <option value="mysql">MySQL</option></select></div>
              <div class="wide"><label>目标</label><input name="target" required
                placeholder="sqlite 文件路径，或 postgresql:// / mysql:// DSN"></div>
              <div><label>备注</label><input name="note"></div>
            </div>
            <div class="form-actions"><button class="primary">添加配置</button></div>
          </form>
          <div class="divider">
            <h2 style="margin-bottom:.6rem">数据迁移</h2>
            <form id="form-migrate">
              <div class="form-grid">
                <div><label>从</label><select name="from"></select></div>
                <div><label>迁移到</label><select name="to"></select></div>
              </div>
              <div class="form-actions">
                <span class="check"><input type="checkbox" name="replace" id="mig-replace"><label for="mig-replace">覆盖目标已有数据</label></span>
                <button class="primary">迁移数据</button>
              </div>
            </form>
            <p class="hint">迁移会把全部业务表（用户 / 上级 / 路由 / 设置 / 管理员凭证 / 会话）复制到目标库；切换后立即重新渲染生效。</p>
          </div>
        </div>
      </section>

      <section class="view" data-view="sessions">
        <div class="card">
          <h2>管理员会话</h2>
          <p class="sub">同一管理员可以有多个会话（不同浏览器、不同机器的 CLI）。「当前」是本页面正在用的会话；撤销它会立即退出本页面。</p>
          <div class="tbl-wrap"><table id="sessions-table"></table></div>
          <div class="form-actions">
            <button id="btn-revoke-others" class="danger">撤销其它全部会话</button>
          </div>
        </div>
      </section>

    </div>
  </div>
</div>
</div>

<script>
const $ = id => document.getElementById(id);
const msg = (text, ok) => { const m = $("msg"); m.textContent = text || "";
  m.className = text ? (ok ? "ok" : "err") : ""; };
const b64uToBuf = s => { s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - s.length % 4) % 4);
  const bin = atob(s), buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i); return buf.buffer; };
const bufToB64u = buf => { let bin = ""; const b = new Uint8Array(buf);
  for (const c of b) bin += String.fromCharCode(c);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
// ---- session crypto: ECDH (P-256) + HKDF-SHA256 + HMAC envelope.
// Mirrors the server's session crypto (admin.py). The passkey
// challenge binds both ECDH public keys
// (SHA-256(nonce || client_pub || server_pub)); the client checks
// that binding before letting the authenticator sign. After the
// ceremony, every API call is an encrypted envelope keyed by the
// derived session key; the session id alone proves nothing.
const enc8 = new TextEncoder(), dec8 = new TextDecoder();
const concatBytes = (...parts) => { let n = 0; for (const p of parts) n += p.length;
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const b64uToBytes = s => new Uint8Array(b64uToBuf(s));
const bytesToB64u = b => bufToB64u(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
let __sess = null;  // {id, master: Uint8Array, expires_at}
function sessSave() {
  if (__sess) sessionStorage.setItem("xmagic_session", JSON.stringify(
    {id: __sess.id, key: bytesToB64u(__sess.master), expires_at: __sess.expires_at}));
  else sessionStorage.removeItem("xmagic_session");
}
function sessLoad() {
  __sess = null;
  try { const s = JSON.parse(sessionStorage.getItem("xmagic_session") || "null");
    if (s && s.expires_at > Math.floor(Date.now() / 1000))
      __sess = {id: s.id, master: b64uToBytes(s.key), expires_at: s.expires_at};
  } catch (e) { __sess = null; }
  return __sess;
}
async function hmacSha(key, data) {
  const k = await crypto.subtle.importKey("raw", key,
    {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
async function hkdfSha(ikm, salt, info, len) {
  const prk = await hmacSha(salt, ikm);
  let out = new Uint8Array(0), prev = new Uint8Array(0);
  for (let c = 1; out.length < len; c++) {
    prev = await hmacSha(prk, concatBytes(prev, info, new Uint8Array([c])));
    out = concatBytes(out, prev);
  }
  return out.slice(0, len);
}
async function keystreamSha(encKey, nonce, len) {
  let out = new Uint8Array(0);
  for (let c = 0; out.length < len; c++) {
    const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, c);
    out = concatBytes(out, await hmacSha(encKey, concatBytes(nonce, ctr)));
  }
  return out.slice(0, len);
}
function aadFor(method, path) {
  return enc8.encode((__sess ? __sess.id : "") + "\n" + method + "\n" + path);
}
async function sealEnvelope(method, path, payloadObj) {
  const ek = await hmacSha(__sess.master, enc8.encode("xmagic enc"));
  const mk = await hmacSha(__sess.master, enc8.encode("xmagic mac"));
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const plain = enc8.encode(JSON.stringify(
    {t: Math.floor(Date.now() / 1000), body: payloadObj}));
  const ks = await keystreamSha(ek, nonce, plain.length);
  const ct = plain.map((b, i) => b ^ ks[i]);
  const tag = (await hmacSha(mk, concatBytes(aadFor(method, path), nonce, ct))).slice(0, 16);
  return bytesToB64u(concatBytes(nonce, tag, ct));
}
async function openEnvelope(method, path, blob) {
  const raw = b64uToBytes(blob);
  const nonce = raw.slice(0, 16), tag = raw.slice(16, 32), ct = raw.slice(32);
  const ek = await hmacSha(__sess.master, enc8.encode("xmagic enc"));
  const mk = await hmacSha(__sess.master, enc8.encode("xmagic mac"));
  const want = (await hmacSha(mk, concatBytes(aadFor(method, path), nonce, ct))).slice(0, 16);
  if (want.length !== tag.length || !want.every((b, i) => b === tag[i]))
    throw new Error("服务器响应解密校验失败");
  const ks = await keystreamSha(ek, nonce, ct.length);
  return JSON.parse(dec8.decode(ct.map((b, i) => b ^ ks[i]))).body;
}
async function api(path, body) {
  const method = body === undefined ? "GET" : "POST";
  const headers = {"Content-Type": "application/json"};
  let payload;
  if (__sess) {
    headers["X-Session-Id"] = __sess.id;
    if (method === "GET") headers["X-Enc"] = await sealEnvelope("GET", path, {});
    else payload = JSON.stringify({e: await sealEnvelope("POST", path, body ?? {})});
  } else if (body !== undefined) payload = JSON.stringify(body);
  const r = await fetch(path, {method, headers, body: payload});
  const data = await r.json().catch(() => ({}));
  if (__sess && data.e) {
    const plain = await openEnvelope(method, path, data.e);
    if (!r.ok) throw new Error(plain.error || ("HTTP " + r.status));
    return plain;
  }
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}
async function ecdhGenerate() {
  return crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
}
async function ecdhPubBytes(kp) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
}
async function checkChallengeBinding(opts, clientPubBytes) {
  if (!opts.ecdh) throw new Error("服务器未协商会话密钥");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256",
    concatBytes(b64uToBytes(opts.ecdh.nonce), clientPubBytes,
                b64uToBytes(opts.ecdh.server_pub))));
  const given = b64uToBytes(opts.challenge);
  if (digest.length !== given.length || !digest.every((b, i) => b === given[i]))
    throw new Error("挑战值与 ECDH 公钥的绑定校验失败 - 已拒绝继续");
}
async function adoptSession(verifyRes, kp, clientPubBytes) {
  const s = verifyRes.session;
  const serverKey = await crypto.subtle.importKey("raw", b64uToBuf(s.server_pub),
    {name: "ECDH", namedCurve: "P-256"}, false, []);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    {name: "ECDH", public: serverKey}, kp.privateKey, 256));
  const master = await hkdfSha(bits,
    concatBytes(clientPubBytes, b64uToBytes(s.server_pub)),
    enc8.encode("xmagic session key v1"), 32);
  __sess = {id: s.id, master, expires_at: s.expires_at};
  sessSave();
}
function appliedText(a) {
  if (!a) return "";
  let t = `已渲染：${a.users} 用户 / ${a.upstreams} 上级 / ${a.ssh_keys} SSH 公钥`;
  if (a.restart_skipped) t += "；有变更待生效：无重启通道（需在节点上手动重启相关进程）";
  else if (a.container_restart) t += "；单进程重启失败，已回退为整容器重启";
  else if (!a.restarted || !Object.keys(a.restarted).length) t += "；配置无变化，未重启任何进程";
  else t += "；已按需重启：" + Object.entries(a.restarted).map(([k, v]) => k + (v ? "✓" : "✗")).join(" ");
  return t; }
async function refresh() {
  const authed = !!sessLoad();
  const st = await api("/api/status");
  $("setup").classList.toggle("hidden", st.registered);
  $("login").classList.toggle("hidden", !st.registered || authed);
  $("auth-wrap").classList.toggle("hidden", authed);
  $("console").classList.toggle("hidden", !authed);
  if (!authed) return;
  let s;
  try { s = await api("/api/state"); }
  catch (e) { __sess = null; sessSave(); return refresh(); }
  const restartName = s.restart_via === "container" ? "整容器重启" : s.restart_via === "docker" ? "Docker socket" : "无（仅渲染）";
  $("state-line").textContent =
    `状态：${s.enabled_users} 启用用户 / ${s.enabled_upstreams} 上级 / ${s.enabled_routes} 路由` +
    `，公共端口 ${s.public_port}，重启通道 ${restartName}。`;
  $("stat-users").textContent = s.enabled_users;
  $("stat-upstreams").textContent = s.enabled_upstreams;
  $("stat-routes").textContent = s.enabled_routes;
  $("stat-port").textContent = s.public_port;
  $("stat-restart").textContent = restartName;
  const usersResp = await api("/api/users");
  const users = usersResp.users;
  window.__vlessOn = !!usersResp.vless_enabled;
  $("users-table").innerHTML = "<tr><th>用户</th><th>分组</th><th>启用</th><th>凭证</th><th>操作</th></tr>" +
    users.map(u => `<tr><td><strong>${u.username}</strong>${u.note ? `<br><span class="small">${u.note}</span>` : ""}</td><td>${u.group}</td>
      <td><span class="badge ${u.enabled ? "on" : "off"}">${u.enabled ? "启用" : "停用"}</span></td>
      <td><code>vless uuid ${u.vless_uuid}${window.__vlessOn ? "" : "（未启用）"}<br>密码 ${u.password}<br>ss ${u.ss_method} / ${u.ss_password}` +
      `${u.ssh_key ? "<br>SSH 公钥已登记" + (u.ssh_fingerprint ? " " + u.ssh_fingerprint : "") + "<br>ssh -D 1080 -N -i xmagic-" + u.username + ".key -p " + s.public_port + " proxy@" + location.hostname : ""}${u.interconnect ? "<br>组内互访端口 " + u.interconnect[0] + "-" + u.interconnect[1] : ""}</code></td>
      <td><div class="row-actions"><button class="sm" data-act="passwd" data-u="${u.username}">换密码</button>
      <button class="sm" data-act="rotate-uuid" data-u="${u.username}">换UUID</button>
      <button class="sm" data-act="setkey" data-u="${u.username}">公钥</button>
      <button class="sm" data-act="setgroup" data-u="${u.username}" data-g="${u.group}">分组</button>
      <button class="sm" data-act="setmethod" data-u="${u.username}" data-m="${u.ss_method}">SS方法</button>
      <button class="sm" data-act="setnote" data-u="${u.username}" data-n="${u.note || ""}">备注</button>
      <button class="sm" data-act="${u.enabled ? "disable" : "enable"}" data-u="${u.username}">${u.enabled ? "停用" : "启用"}</button>
      <button class="sm danger" data-act="remove" data-u="${u.username}">删除</button></div></td></tr>`).join("");
  const ups = (await api("/api/upstreams")).upstreams;
  window._ups = ups;
  $("upstreams-table").innerHTML = "<tr><th>名称</th><th>分组</th><th>协议</th><th>地址</th><th>启用</th><th>操作</th></tr>" +
    ups.map(u => `<tr><td><strong>${u.name}</strong>${u.note ? `<br><span class="small">${u.note}</span>` : ""}</td><td>${u.group}</td><td>${u.protocol}${u.tls ? " +tls" : ""}</td>
      <td><code>${u.address}:${u.port}${u.path || ""}</code></td>
      <td><span class="badge ${u.enabled ? "on" : "off"}">${u.enabled ? "启用" : "停用"}</span></td>
      <td><div class="row-actions"><button class="sm" data-edit-up="${u.name}">编辑</button>
      <button class="sm" data-act="${u.enabled ? "disable" : "enable"}" data-up="${u.name}">${u.enabled ? "停用" : "启用"}</button>
      <button class="sm danger" data-act="remove" data-up="${u.name}">删除</button></div></td></tr>`).join("");
  const settings = await api("/api/settings");
  document.querySelector("[name=session_ttl_hours]").value = settings.session_ttl_hours;
  const sf = $("form-settings");
  sf.querySelector("[name=vless_ws_paths]").value = settings.db_values.vless_ws_paths || "";
  sf.querySelector("[name=vless_ws_paths]").placeholder = settings.vless_ws_paths.join(",");
  sf.querySelector("[name=trojan_ws_paths]").value = settings.db_values.trojan_ws_paths || "";
  sf.querySelector("[name=trojan_ws_paths]").placeholder = settings.trojan_ws_paths.join(",");
  const strat = sf.querySelector("[name=upstream_strategy]");
  strat.innerHTML = settings.strategies.map(x =>
    `<option ${x === settings.upstream_strategy ? "selected" : ""}>${x}</option>`).join("");
  const meth = sf.querySelector("[name=ss_method]");
  meth.innerHTML = settings.ss_methods.map(x =>
    `<option ${x === settings.ss_method ? "selected" : ""}>${x}</option>`).join("");
  sf.querySelector("[name=direct_allow_private]").checked =
    !!settings.direct_allow_private;
  sf.querySelector("[name=vless_enabled]").checked =
    !!settings.vless_enabled;
  window.__vlessOn = !!settings.vless_enabled;
  buildUpProtoOptions(); buildUpAddBtns(); syncUpProto(); syncVlessPaths();
  sf.querySelector("[name=interconnect_off_groups]").value =
    settings.db_values.interconnect_off_groups || "";
  $("admin-line").textContent = s.admin_registered
    ? `管理员 Passkey：${s.admin_label || "(无标签)"}，注册于 ${s.admin_created_at || "?"}，累计验签 ${s.admin_sign_count} 次。` : "";
  const sessions = (await api("/api/sessions")).sessions;

  const fmtTs = ts => new Date(ts * 1000).toLocaleString();
  $("sessions-table").innerHTML = "<tr><th>标识</th><th>类型</th><th>来源</th><th>创建时间</th><th>到期</th><th></th><th>操作</th></tr>" +
    sessions.map(s => `<tr><td><code>${s.id}</code></td><td>${s.kind}</td><td>${s.label || ""}</td>
      <td>${fmtTs(s.created_at)}</td><td>${fmtTs(s.expires_at)}</td>
      <td>${s.current ? '<span class="badge cur">当前</span>' : ""}</td>
      <td><button class="sm danger" data-session="${s.id}">撤销</button></td></tr>`).join("");
  const dbs = (await api("/api/databases")).databases;
  window._dbs = dbs;
  $("databases-table").innerHTML = "<tr><th></th><th>名称</th><th>类型</th><th>目标</th><th>备注</th><th>操作</th></tr>" +
    dbs.map(d => `<tr><td>${d.active ? '<span class="badge cur">当前</span>' : ""}</td><td><strong>${d.name}</strong></td><td>${d.type}</td>
      <td><code>${d.target}</code></td><td>${d.note || ""}</td>
      <td><div class="row-actions"><button class="sm" data-dbtest="${d.name}">测试</button>
      <button class="sm" data-dbedit="${d.name}">编辑</button>
      ${d.active ? "" : `<button class="sm" data-dbswitch="${d.name}">切换</button>
      <button class="sm danger" data-dbremove="${d.name}">删除</button>`}</div></td></tr>`).join("");
  const dbOpts = dbs.map(d => `<option>${d.name}</option>`).join("");
  $("form-migrate").querySelector("[name=from]").innerHTML = dbOpts;
  $("form-migrate").querySelector("[name=to]").innerHTML = dbOpts;
  const routes = (await api("/api/routes")).routes;
  window._routes = routes;
  $("routes-table").innerHTML = "<tr><th>#</th><th>类型</th><th>目标模式</th><th>去向</th><th>限定用户</th><th>启用</th><th>操作</th></tr>" +
    routes.map(r => `<tr><td>${r.id}</td><td>${r.kind}</td><td><code>${r.pattern}</code></td><td>${r.target}</td>
      <td>${r.username || "*"}</td>
      <td><span class="badge ${r.enabled ? "on" : "off"}">${r.enabled ? "启用" : "停用"}</span></td>
      <td><div class="row-actions"><button class="sm" data-edit-route="${r.id}">编辑</button>
      <button class="sm" data-act="${r.enabled ? "disable" : "enable"}" data-route="${r.id}">${r.enabled ? "停用" : "启用"}</button>
      <button class="sm danger" data-act="remove" data-route="${r.id}">删除</button></div></td></tr>`).join("");
}
$("btn-register").onclick = async () => { try {
  const kp = await ecdhGenerate();
  const clientPub = await ecdhPubBytes(kp);
  const opts = await api("/api/register/options", {ecdh_pub: bytesToB64u(clientPub)});
  await checkChallengeBinding(opts, clientPub);
  opts.challenge = b64uToBuf(opts.challenge); opts.user.id = b64uToBuf(opts.user.id);
  const cred = await navigator.credentials.create({publicKey: opts});
  const res = await api("/api/register/verify", {id: cred.id,
    response: {attestationObject: bufToB64u(cred.response.attestationObject),
               clientDataJSON: bufToB64u(cred.response.clientDataJSON)},
    label: navigator.userAgent.slice(0, 80)});
  await adoptSession(res, kp, clientPub);
  msg("管理员 Passkey 注册成功：" + res.status, true); refresh();
} catch (e) { msg(String(e)); } };
$("btn-login").onclick = async () => { try {
  const kp = await ecdhGenerate();
  const clientPub = await ecdhPubBytes(kp);
  const opts = await api("/api/login/options", {ecdh_pub: bytesToB64u(clientPub)});
  await checkChallengeBinding(opts, clientPub);
  opts.challenge = b64uToBuf(opts.challenge);
  opts.allowCredentials = opts.allowCredentials.map(c => ({...c, id: b64uToBuf(c.id)}));
  const cred = await navigator.credentials.get({publicKey: opts});
  const res = await api("/api/login/verify", {id: cred.id,
    response: {authenticatorData: bufToB64u(cred.response.authenticatorData),
               clientDataJSON: bufToB64u(cred.response.clientDataJSON),
               signature: bufToB64u(cred.response.signature),
               userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null}});
  await adoptSession(res, kp, clientPub);
  msg("登录成功（会话已加密）", true); refresh();
} catch (e) { msg(String(e)); } };
$("btn-logout").onclick = async () => { try { await api("/api/logout", {}); } catch (e) {}
  __sess = null; sessSave(); refresh(); };
$("btn-revoke-others").onclick = async () => { try {
  const r = await api("/api/sessions/revoke-others", {});
  msg(`已撤销其它 ${r.revoked_others} 个会话`, true); refresh();
} catch (e) { msg(String(e)); } };
document.addEventListener("click", async e => {
  const b = e.target.closest("button[data-session]"); if (!b) return;
  try { await api(`/api/sessions/${b.dataset.session}/revoke`, {});
    msg(`会话 ${b.dataset.session} 已撤销`, true); refresh(); }
  catch (err) { msg(String(err)); refresh(); } });
$("btn-apply").onclick = async () => { try {
  const r = await api("/api/apply", {}); msg(appliedText(r.applied), true); refresh();
} catch (e) { msg(String(e)); } };
$("cli-install").value = "mkdir -p ~/.local/bin && curl -fsSL " + location.origin + "/cli/xmagic.py -o ~/.local/bin/xmagic && chmod +x ~/.local/bin/xmagic";
$("cli-onboard").value = "xmagic node add main --url " + location.origin + " && xmagic login";
function copyCmd(id, btn) { const el = $(id); el.select();
  const done = () => { btn.textContent = "已复制"; setTimeout(() => btn.textContent = "复制", 1500); };
  if (navigator.clipboard && window.isSecureContext)
    navigator.clipboard.writeText(el.value).then(done, () => { document.execCommand("copy"); done(); });
  else { document.execCommand("copy"); done(); } }
$("btn-copy-install").onclick = e => copyCmd("cli-install", e.target);
$("btn-copy-onboard").onclick = e => copyCmd("cli-onboard", e.target);
// Key fields: picking a local file fills the field with its text, so a
// key can be uploaded instead of pasted; the form submits the text.
function wireKeyPicker(btnId, pickId, target) {
  const btn = $(btnId), pick = $(pickId);
  if (!btn || !pick || !target) return;
  btn.onclick = () => pick.click();
  pick.onchange = () => { const f = pick.files[0]; pick.value = "";
    if (f) f.text().then(t => { target.value = t.trim(); msg("已读取密钥文件 " + f.name, true); }); };
}
wireKeyPicker("btn-pick-pubkey", "pick-pubkey", document.querySelector('#form-user [name="ssh_pubkey"]'));
wireKeyPicker("btn-pick-privkey", "pick-privkey", document.querySelector('#form-upstream [name="key_content"]'));
// Keypair generation: the node mints the pair; for a USER the private
// half is downloaded once and never stored on the node; for an
// UPSTREAM it is filled into the form (stored on the node on submit)
// with a downloaded copy for the operator's own records.
function downloadText(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], {type: "text/plain"}));
  a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
// In-browser ed25519 keypair generation for USER keys: the private half
// is minted here, in the page, and never reaches the server (only the
// public half is submitted). Mirrors the pure-Python generator in
// users.py (same curve math, same OpenSSH wire formats).
const ED_Q = 2n ** 255n - 19n;
const _edMod = a => { const r = a % ED_Q; return r >= 0n ? r : r + ED_Q; };
const _edPow = (a, e) => { let r = 1n; a = _edMod(a);
  while (e > 0n) { if (e & 1n) r = r * a % ED_Q; a = a * a % ED_Q; e >>= 1n; }
  return r; };
const ED_D = _edMod(-121665n * _edPow(121666n, ED_Q - 2n));
const ED_I = _edPow(2n, (ED_Q - 1n) / 4n);
function _edXRecover(y) {
  const xx = _edMod((y * y - 1n) * _edPow(_edMod(ED_D * y * y + 1n), ED_Q - 2n));
  let x = _edPow(xx, (ED_Q + 3n) / 8n);
  if (_edMod(x * x - xx) !== 0n) x = x * ED_I % ED_Q;
  if (x % 2n !== 0n) x = ED_Q - x;
  return x;
}
const ED_BY = 4n * _edPow(5n, ED_Q - 2n) % ED_Q;
const ED_BX = _edXRecover(ED_BY);
const ED_B = [ED_BX, ED_BY, 1n, ED_BX * ED_BY % ED_Q];
function _edAdd(P, Q) {
  const A = _edMod((P[1] - P[0]) * (Q[1] - Q[0]));
  const B = _edMod((P[1] + P[0]) * (Q[1] + Q[0]));
  const C = 2n * ED_D * P[3] % ED_Q * Q[3] % ED_Q;
  const D = 2n * P[2] % ED_Q * Q[2] % ED_Q;
  const E = B - A, F = D - C, G = D + C, H = B + A;
  return [_edMod(E * F), _edMod(G * H), _edMod(F * G), _edMod(E * H)];
}
function _edDouble(P) {
  const A = P[0] * P[0] % ED_Q, B = P[1] * P[1] % ED_Q;
  const C = 2n * P[2] * P[2] % ED_Q, D = _edMod(-A);
  const E = _edMod((P[0] + P[1]) * (P[0] + P[1]) - A - B);
  const G = D + B, F = G - C, H = D - B;
  return [_edMod(E * F), _edMod(G * H), _edMod(F * G), _edMod(E * H)];
}
function _edScalarMult(P, e) {
  let R = [0n, 1n, 1n, 0n];
  while (e > 0n) { if (e & 1n) R = _edAdd(R, P); P = _edDouble(P); e >>= 1n; }
  return R;
}
function _u8cat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function _sshStr(bytes) {
  const len = new Uint8Array([(bytes.length >>> 24) & 255,
    (bytes.length >>> 16) & 255, (bytes.length >>> 8) & 255,
    bytes.length & 255]);
  return _u8cat(len, bytes);
}
function _b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
async function genUserKeypair(comment) {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const h = new Uint8Array(
    await crypto.subtle.digest("SHA-512", seed)).slice(0, 32);
  h[0] &= 248; h[31] &= 63; h[31] |= 64;
  let a = 0n;
  for (let i = 31; i >= 0; i--) a = (a << 8n) | BigInt(h[i]);
  const P = _edScalarMult(ED_B, a);
  const zi = _edPow(P[2], ED_Q - 2n);
  const x = P[0] * zi % ED_Q, y = P[1] * zi % ED_Q;
  let pubInt = y | ((x & 1n) << 255n);
  const pub = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { pub[i] = Number(pubInt & 255n); pubInt >>= 8n; }
  const enc = new TextEncoder();
  const blob = _u8cat(_sshStr(enc.encode("ssh-ed25519")), _sshStr(pub));
  const chk = crypto.getRandomValues(new Uint8Array(4));
  let section = _u8cat(chk, chk, _sshStr(enc.encode("ssh-ed25519")),
    _sshStr(pub), _sshStr(_u8cat(seed, pub)),
    _sshStr(enc.encode(comment || "")));
  const pad = 8 - (section.length % 8);
  const padding = new Uint8Array(pad);
  for (let i = 0; i < pad; i++) padding[i] = i + 1;
  section = _u8cat(section, padding);
  const raw = _u8cat(enc.encode("openssh-key-v1\0"),
    _sshStr(enc.encode("none")), _sshStr(enc.encode("none")),
    _sshStr(new Uint8Array(0)), new Uint8Array([0, 0, 0, 1]),
    _sshStr(blob), _sshStr(section));
  const b64 = _b64(raw);
  const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    + (b64.match(/.{1,70}/g) || []).join("\n")
    + "\n-----END OPENSSH PRIVATE KEY-----\n";
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
  return {private_key: pem,
          public_key: "ssh-ed25519 " + _b64(blob)
            + (comment ? " " + comment : ""),
          fingerprint: "SHA256:" + _b64(digest).replace(/=+$/, "")};
}
$("btn-gen-userkey").onclick = async () => {
  try { const form = $("form-user");
    const uname = form.querySelector("[name=username]").value.trim() || "user";
    const r = await genUserKeypair("xmagic " + uname);
    form.querySelector('[name="ssh_pubkey"]').value = r.public_key;
    downloadText("xmagic-" + uname + ".key", r.private_key);
    msg("已生成密钥对：在本页内生成，私钥从未经过服务器、已下载；公钥已填入", true);
  } catch (err) { msg(String(err)); } };
$("btn-gen-upkey").onclick = async () => {
  try { const form = $("form-upstream");
    const uname = form.querySelector("[name=name]").value.trim() || "upstream";
    const r = await api("/api/keys/generate", {comment: "xmagic upstream " + uname});
    form.querySelector('[name="key_content"]').value = r.private_key;
    downloadText("xmagic-upstream-" + uname + ".key", r.private_key);
    msg("已生成密钥对：私钥已填入（提交后存于节点），并下载了一份副本", true);
  } catch (err) { msg(String(err)); } };
$("form-database").onsubmit = async e => { e.preventDefault();
  try { const r = await api("/api/databases", formJson(e.target));
    msg(`数据库配置 ${r.database.name} 已添加`, true); e.target.reset(); refresh(); }
  catch (err) { msg(String(err)); } };
$("form-migrate").onsubmit = async e => { e.preventDefault();
  const o = formJson(e.target);
  o.replace = e.target.querySelector("[name=replace]").checked;
  if (o.from === o.to) { msg("源和目标不能是同一个库"); return; }
  if (!confirm(`把 ${o.from} 的全部业务数据迁移到 ${o.to}？`)) return;
  try { const r = await api("/api/databases/migrate", o);
    msg("迁移完成：" + Object.entries(r.migration.tables).map(([k, v]) => `${k}=${v}`).join("，"), true);
    refresh(); }
  catch (err) { msg(String(err)); } };
document.addEventListener("click", async e => {
  const t = e.target.closest("button[data-dbtest],button[data-dbedit],button[data-dbswitch],button[data-dbremove]");
  if (!t) return;
  try {
    if (t.dataset.dbtest) { const r = await api(`/api/databases/${t.dataset.dbtest}/test`, {});
      msg(`${t.dataset.dbtest} 可达：` + Object.entries(r.test.tables).map(([k, v]) => `${k}=${v}`).join("，"), true); }
    else if (t.dataset.dbedit) { const v = prompt("新目标（sqlite 路径或完整 DSN，含密码；取消 = 不改目标）");
      const n = prompt("备注（留空 = 清除；取消 = 不改备注）");
      if (v === null && n === null) return;
      const body = {};
      if (v !== null && v !== "") body.target = v;
      if (n !== null) body.note = n;
      const r = await api(`/api/databases/${t.dataset.dbedit}/edit`, body);
      msg(`配置 ${r.database.name} 已更新`, true); refresh(); }
    else if (t.dataset.dbswitch) { if (!confirm(`切换到数据库 ${t.dataset.dbswitch}？将改用该库的数据并立即重新渲染。`)) return;
      const r = await api(`/api/databases/${t.dataset.dbswitch}/switch`, {});
      msg(`已切换到 ${r.database.name}。` + appliedText(r.applied), true); refresh(); }
    else if (t.dataset.dbremove) { if (!confirm("删除这个数据库配置？只删配置，不会删库里的数据。")) return;
      await api(`/api/databases/${t.dataset.dbremove}/remove`, {});
      msg("配置已删除", true); refresh(); }
  } catch (err) { msg(String(err)); } });
document.addEventListener("click", async e => {
  const b = e.target.closest("button[data-act]"); if (!b) return;
  const act = b.dataset.act;
  try {
    let r, body = {};
    if (act === "setkey") { const v = prompt("SSH 公钥（留空 = 清除）"); if (v === null) return; body = {ssh_pubkey: v}; }
    if (act === "setgroup") { const v = prompt("上级分组", b.dataset.g || "default"); if (v === null) return; body = {group: v}; }
    if (act === "setmethod") { const v = prompt("SS 方法", b.dataset.m || ""); if (v === null) return; body = {method: v}; }
    if (act === "setnote") { const v = prompt("备注（留空 = 清除）", b.dataset.n || ""); if (v === null) return; body = {note: v}; }
    if (act === "rotate-uuid" && !confirm("换掉该用户的 VLESS UUID？旧 UUID 随即失效。")) return;
    if (act === "remove" && !confirm("确认删除？")) return;
    if (b.dataset.u) r = await api(`/api/users/${b.dataset.u}/${act}`, body);
    else if (b.dataset.up) r = await api(`/api/upstreams/${b.dataset.up}/${act}`, body);
    else if (b.dataset.route) r = await api(`/api/routes/${b.dataset.route}/${act}`, body);
    if (r && r.user && act === "passwd")
      msg(`新密码：${r.user.password}（trojan/http/socks），ss：${r.user.ss_password}`, true);
    else if (r && r.user && act === "rotate-uuid")
      msg(`新 UUID：${r.user.vless_uuid}。` + appliedText(r.applied), true);
    else if (r) msg(appliedText(r.applied), true);
    refresh();
  } catch (err) { msg(String(err)); } });
const formJson = form => { const o = {};
  for (const [k, v] of new FormData(form).entries()) if (v !== "") o[k] = v;
  if (form.querySelector("[name=tls]")) o.tls = form.querySelector("[name=tls]").checked;
  if (o.port) o.port = Number(o.port); return o; };
$("form-user").onsubmit = async e => { e.preventDefault();
  try { const r = await api("/api/users", formJson(e.target));
    msg(`用户 ${r.user.username} 已建：uuid ${r.user.vless_uuid}，密码 ${r.user.password}，ss ${r.user.ss_password}。` +
        appliedText(r.applied), true); closeUserFormTab(); refresh(); }
  catch (err) { msg(String(err)); } };
let editingUp = null, editingRoute = null;
const setField = (form, name, value) => { const el = form.querySelector(`[name=${name}]`);
  if (el) el.value = value ?? ""; };
document.addEventListener("click", e => {
  const bu = e.target.closest("button[data-edit-up]");
  if (bu) { const u = (window._ups || []).find(x => x.name === bu.dataset.editUp); if (!u) return;
    switchView("upstreams");
    const f = $("form-upstream"); editingUp = u.name;
    for (const k of ["name", "address", "port", "group", "path", "uuid", "username",
                     "password", "key_file", "method", "note"])
      setField(f, k, k === "group" ? u.group : u[k]);
    buildUpProtoOptions(u.protocol);
    f.querySelector("[name=protocol]").value = u.protocol;
    syncUpProto();
    f.querySelector("[name=tls]").checked = !!u.tls;
    f.querySelector("[name=name]").disabled = true;
    $("up-submit").textContent = "保存修改：" + u.name;
    openUpFormTab("编辑上级：" + u.name);
    msg("正在编辑上级 " + u.name + "：密码等字段留空 = 不改动", true); return; }
  const bu2 = e.target.closest("button[data-add-user]");
  if (bu2) { $("form-user").reset(); openUserFormTab(); return; }
  const ba = e.target.closest("button[data-add-up]");
  if (ba) { const p = ba.dataset.addUp; const f = $("form-upstream");
    editingUp = null; f.reset(); buildUpProtoOptions(p);
    f.querySelector("[name=protocol]").value = p; syncUpProto();
    f.querySelector("[name=name]").disabled = false;
    $("up-submit").textContent = "保存";
    openUpFormTab("添加上级 · " + p); return; }
  const br = e.target.closest("button[data-edit-route]");
  if (br) { const r = (window._routes || []).find(x => x.id === Number(br.dataset.editRoute)); if (!r) return;
    switchView("routes");
    const f = $("form-route"); editingRoute = r.id;
    setField(f, "kind", r.kind); setField(f, "pattern", r.pattern);
    setField(f, "to", r.target); setField(f, "username", r.username || "");
    setField(f, "note", r.note || "");
    $("route-submit").textContent = "保存修改：路由 #" + r.id;
    $("route-cancel").classList.remove("hidden");
    msg("正在编辑路由 #" + r.id, true); }
});
$("up-cancel").onclick = () => { editingUp = null; const f = $("form-upstream");
  f.reset(); buildUpProtoOptions(); syncUpProto();
  f.querySelector("[name=name]").disabled = false;
  closeUpFormTab(); };
$("route-cancel").onclick = () => { editingRoute = null; $("form-route").reset();
  $("route-submit").textContent = "添加路由"; $("route-cancel").classList.add("hidden"); };
const UP_PROTOS = ["vless-ws", "vless", "trojan-ws", "ss", "http", "socks", "ssh"];
const UP_LABELS = {"vless-ws": "VLESS-WS", "vless": "VLESS", "trojan-ws": "Trojan-WS",
  "ss": "Shadowsocks", "http": "HTTP", "socks": "SOCKS5", "ssh": "SSH"};
function switchUpTab(which) {
  document.querySelectorAll("#up-tabs .tab").forEach(t =>
    t.classList.toggle("active", t.dataset.upTab === which));
  $("up-panel-list").classList.toggle("hidden", which !== "list");
  $("up-panel-form").classList.toggle("hidden", which !== "form");
}
function openUpFormTab(title) {
  const tab = $("up-form-tab");
  tab.textContent = title; tab.classList.remove("hidden");
  switchUpTab("form");
}
function closeUpFormTab() {
  $("up-form-tab").classList.add("hidden");
  switchUpTab("list");
}
document.querySelectorAll("#up-tabs .tab").forEach(t =>
  t.addEventListener("click", () => switchUpTab(t.dataset.upTab)));
function switchUserTab(which) {
  document.querySelectorAll("#user-tabs .tab").forEach(t =>
    t.classList.toggle("active", t.dataset.userTab === which));
  $("user-panel-list").classList.toggle("hidden", which !== "list");
  $("user-panel-form").classList.toggle("hidden", which !== "form");
}
function openUserFormTab() {
  const tab = $("user-form-tab");
  tab.textContent = "添加用户"; tab.classList.remove("hidden");
  switchUserTab("form");
}
function closeUserFormTab() {
  $("form-user").reset();
  $("user-form-tab").classList.add("hidden");
  switchUserTab("list");
}
document.querySelectorAll("#user-tabs .tab").forEach(t =>
  t.addEventListener("click", () => switchUserTab(t.dataset.userTab)));
$("user-cancel").onclick = () => closeUserFormTab();
function buildUpAddBtns() {
  const list = UP_PROTOS.filter(p =>
    window.__vlessOn || (p !== "vless-ws" && p !== "vless"));
  $("up-add-btns").innerHTML = list.map(p =>
    `<button class="btn ghost sm" data-add-up="${p}">+ ${UP_LABELS[p]}</button>`).join(" ");
}
function buildUpProtoOptions(keep) {
  const sel = $("form-upstream").querySelector("[name=protocol]");
  const cur = keep || sel.value;
  const list = UP_PROTOS.filter(p =>
    window.__vlessOn || (p !== "vless-ws" && p !== "vless") || p === keep);
  sel.innerHTML = list.map(p => `<option>${p}</option>`).join("");
  sel.value = list.includes(cur) ? cur : list[0];
}
function syncUpProto() {
  const f = $("form-upstream");
  const p = f.querySelector("[name=protocol]").value;
  f.querySelectorAll("[data-proto]").forEach(d => {
    d.style.display = d.dataset.proto.split(" ").includes(p) ? "" : "none";
  });
}
$("form-upstream").querySelector("[name=protocol]")
  .addEventListener("change", syncUpProto);
function syncVlessPaths() {
  const on = $("form-settings").querySelector("[name=vless_enabled]").checked;
  $("row-vless-paths").style.display = on ? "" : "none";
}
$("form-settings").querySelector("[name=vless_enabled]")
  .addEventListener("change", syncVlessPaths);
$("form-upstream").onsubmit = async e => { e.preventDefault();
  try { if (editingUp) {
      const o = formJson(e.target); delete o.name;
      for (const k of ["password", "uuid", "username", "key_file", "key_content", "path"])
        if (!o[k]) delete o[k];  // blank in edit mode = leave unchanged
      if (!("note" in o)) o.note = "";  // the form was prefilled: blank = cleared
      const r = await api(`/api/upstreams/${editingUp}/update`, o);
      msg("上级已修改。" + appliedText(r.applied), true); $("up-cancel").onclick();
    } else {
      const r = await api("/api/upstreams", formJson(e.target));
      msg("上级已添加。" + appliedText(r.applied), true); $("up-cancel").onclick(); }
    refresh(); }
  catch (err) { msg(String(err)); } };
$("form-route").onsubmit = async e => { e.preventDefault();
  try { if (editingRoute !== null) {
      const o = formJson(e.target); if (!("username" in o)) o.username = "";
      const r = await api(`/api/routes/${editingRoute}/update`, o);
      msg("路由已修改。" + appliedText(r.applied), true); $("route-cancel").onclick();
    } else {
      const r = await api("/api/routes", formJson(e.target));
      msg("路由已添加。" + appliedText(r.applied), true); e.target.reset(); }
    refresh(); }
  catch (err) { msg(String(err)); } };
$("form-settings").onsubmit = async e => { e.preventDefault();
  try { const f = e.target;
    const r = await api("/api/settings", {
      session_ttl_hours: Number(f.querySelector("[name=session_ttl_hours]").value),
      vless_ws_paths: f.querySelector("[name=vless_ws_paths]").value,
      trojan_ws_paths: f.querySelector("[name=trojan_ws_paths]").value,
      upstream_strategy: f.querySelector("[name=upstream_strategy]").value,
      direct_allow_private: f.querySelector("[name=direct_allow_private]").checked,
      vless_enabled: f.querySelector("[name=vless_enabled]").checked,
      interconnect_off_groups: f.querySelector("[name=interconnect_off_groups]").value,
      ss_method: f.querySelector("[name=ss_method]").value});
    msg("设置已保存。" + (r.applied ? appliedText(r.applied) : ""), true); refresh(); }
  catch (err) { msg(String(err)); } };
$("btn-replace").onclick = () => $("btn-register").onclick();
const VIEW_TITLES = {overview: "概览", users: "代理用户", upstreams: "上级节点",
  routes: "目标路由", settings: "设置", databases: "数据库", sessions: "管理员会话"};
function switchView(name) {
  document.querySelectorAll(".view").forEach(v =>
    v.classList.toggle("active", v.dataset.view === name));
  document.querySelectorAll("[data-nav]").forEach(b =>
    b.classList.toggle("active", b.dataset.nav === name));
  $("view-title").textContent = VIEW_TITLES[name] || name;
}
document.querySelectorAll("[data-nav]").forEach(b =>
  b.addEventListener("click", () => switchView(b.dataset.nav)));
refresh().catch(e => msg(String(e)));
</script></body></html>
"""


CLI_AUTH_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xmagic CLI 登录</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:560px;padding:0 1rem}
button{padding:.5rem 1rem;cursor:pointer}.err{color:#b00020;white-space:pre-wrap}</style>
</head><body>
<h1>xmagic 命令行登录</h1>
<div id="msg">正在检查登录状态…</div>
<p><button id="btn" class="hidden" style="display:none"></button></p>
<script>
const params = new URLSearchParams(location.search);
const callback = params.get("callback"), state = params.get("state");
const cliPub = params.get("cli_pub");
const msgEl = document.getElementById("msg"), btn = document.getElementById("btn");
const b64uToBuf = s => { s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - s.length % 4) % 4);
  const bin = atob(s), buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i); return buf.buffer; };
const bufToB64u = buf => { let bin = ""; const b = new Uint8Array(buf);
  for (const c of b) bin += String.fromCharCode(c);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
// ---- session crypto: ECDH (P-256) + HKDF-SHA256 + HMAC envelope.
// Mirrors the server's session crypto (admin.py). The passkey
// challenge binds both ECDH public keys
// (SHA-256(nonce || client_pub || server_pub)); the client checks
// that binding before letting the authenticator sign. After the
// ceremony, every API call is an encrypted envelope keyed by the
// derived session key; the session id alone proves nothing.
const enc8 = new TextEncoder(), dec8 = new TextDecoder();
const concatBytes = (...parts) => { let n = 0; for (const p of parts) n += p.length;
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const b64uToBytes = s => new Uint8Array(b64uToBuf(s));
const bytesToB64u = b => bufToB64u(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
let __sess = null;  // {id, master: Uint8Array, expires_at}
function sessSave() {
  if (__sess) sessionStorage.setItem("xmagic_session", JSON.stringify(
    {id: __sess.id, key: bytesToB64u(__sess.master), expires_at: __sess.expires_at}));
  else sessionStorage.removeItem("xmagic_session");
}
function sessLoad() {
  __sess = null;
  try { const s = JSON.parse(sessionStorage.getItem("xmagic_session") || "null");
    if (s && s.expires_at > Math.floor(Date.now() / 1000))
      __sess = {id: s.id, master: b64uToBytes(s.key), expires_at: s.expires_at};
  } catch (e) { __sess = null; }
  return __sess;
}
async function hmacSha(key, data) {
  const k = await crypto.subtle.importKey("raw", key,
    {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
async function hkdfSha(ikm, salt, info, len) {
  const prk = await hmacSha(salt, ikm);
  let out = new Uint8Array(0), prev = new Uint8Array(0);
  for (let c = 1; out.length < len; c++) {
    prev = await hmacSha(prk, concatBytes(prev, info, new Uint8Array([c])));
    out = concatBytes(out, prev);
  }
  return out.slice(0, len);
}
async function keystreamSha(encKey, nonce, len) {
  let out = new Uint8Array(0);
  for (let c = 0; out.length < len; c++) {
    const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, c);
    out = concatBytes(out, await hmacSha(encKey, concatBytes(nonce, ctr)));
  }
  return out.slice(0, len);
}
function aadFor(method, path) {
  return enc8.encode((__sess ? __sess.id : "") + "\n" + method + "\n" + path);
}
async function sealEnvelope(method, path, payloadObj) {
  const ek = await hmacSha(__sess.master, enc8.encode("xmagic enc"));
  const mk = await hmacSha(__sess.master, enc8.encode("xmagic mac"));
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const plain = enc8.encode(JSON.stringify(
    {t: Math.floor(Date.now() / 1000), body: payloadObj}));
  const ks = await keystreamSha(ek, nonce, plain.length);
  const ct = plain.map((b, i) => b ^ ks[i]);
  const tag = (await hmacSha(mk, concatBytes(aadFor(method, path), nonce, ct))).slice(0, 16);
  return bytesToB64u(concatBytes(nonce, tag, ct));
}
async function openEnvelope(method, path, blob) {
  const raw = b64uToBytes(blob);
  const nonce = raw.slice(0, 16), tag = raw.slice(16, 32), ct = raw.slice(32);
  const ek = await hmacSha(__sess.master, enc8.encode("xmagic enc"));
  const mk = await hmacSha(__sess.master, enc8.encode("xmagic mac"));
  const want = (await hmacSha(mk, concatBytes(aadFor(method, path), nonce, ct))).slice(0, 16);
  if (want.length !== tag.length || !want.every((b, i) => b === tag[i]))
    throw new Error("服务器响应解密校验失败");
  const ks = await keystreamSha(ek, nonce, ct.length);
  return JSON.parse(dec8.decode(ct.map((b, i) => b ^ ks[i]))).body;
}
async function api(path, body) {
  const method = body === undefined ? "GET" : "POST";
  const headers = {"Content-Type": "application/json"};
  let payload;
  if (__sess) {
    headers["X-Session-Id"] = __sess.id;
    if (method === "GET") headers["X-Enc"] = await sealEnvelope("GET", path, {});
    else payload = JSON.stringify({e: await sealEnvelope("POST", path, body ?? {})});
  } else if (body !== undefined) payload = JSON.stringify(body);
  const r = await fetch(path, {method, headers, body: payload});
  const data = await r.json().catch(() => ({}));
  if (__sess && data.e) {
    const plain = await openEnvelope(method, path, data.e);
    if (!r.ok) throw new Error(plain.error || ("HTTP " + r.status));
    return plain;
  }
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}
async function ecdhGenerate() {
  return crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
}
async function ecdhPubBytes(kp) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
}
async function checkChallengeBinding(opts, clientPubBytes) {
  if (!opts.ecdh) throw new Error("服务器未协商会话密钥");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256",
    concatBytes(b64uToBytes(opts.ecdh.nonce), clientPubBytes,
                b64uToBytes(opts.ecdh.server_pub))));
  const given = b64uToBytes(opts.challenge);
  if (digest.length !== given.length || !digest.every((b, i) => b === given[i]))
    throw new Error("挑战值与 ECDH 公钥的绑定校验失败 - 已拒绝继续");
}
async function adoptSession(verifyRes, kp, clientPubBytes) {
  const s = verifyRes.session;
  const serverKey = await crypto.subtle.importKey("raw", b64uToBuf(s.server_pub),
    {name: "ECDH", namedCurve: "P-256"}, false, []);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    {name: "ECDH", public: serverKey}, kp.privateKey, 256));
  const master = await hkdfSha(bits,
    concatBytes(clientPubBytes, b64uToBytes(s.server_pub)),
    enc8.encode("xmagic session key v1"), 32);
  __sess = {id: s.id, master, expires_at: s.expires_at};
  sessSave();
}
function fail(e) { msgEl.className = "err"; msgEl.textContent = String(e); }
async function handoff() {
  // Inside this page's encrypted web session, mint a CLI session
  // bound to the CLI's own ECDH public key; only public values
  // (session id + server public key) travel back over the loopback
  // callback - the CLI derives the session key locally.
  msgEl.textContent = "已在加密通道内为命令行协商独立的会话密钥…";
  const res = await api("/api/cli/sessions", {client_pub: cliPub,
    label: "cli " + navigator.userAgent.slice(0, 60)});
  const q = new URLSearchParams({sid: res.id, spub: res.server_pub, state,
    exp: res.expires_at});
  location.replace(callback + (callback.includes("?") ? "&" : "?") + q.toString());
}
async function start() {
  if (!callback || !state || !cliPub) {
    fail("这个页面需要从 xmagic 命令行发起（缺少 callback/state/cli_pub 参数）。");
    return;
  }
  try {
    const st = await api("/api/status");
    if (sessLoad()) {
      try { await api("/api/state"); await handoff(); return; }
      catch (e) { __sess = null; sessSave(); }
    }
    btn.style.display = "";
    if (!st.registered) {
      msgEl.textContent = "这个节点还没有管理员 Passkey。先注册（第一个注册的即为管理员），随后自动交回命令行。";
      btn.textContent = "注册管理员 Passkey 并继续";
      btn.onclick = async () => { try {
        const kp = await ecdhGenerate();
        const clientPub = await ecdhPubBytes(kp);
        const opts = await api("/api/register/options", {ecdh_pub: bytesToB64u(clientPub)});
        await checkChallengeBinding(opts, clientPub);
        opts.challenge = b64uToBuf(opts.challenge); opts.user.id = b64uToBuf(opts.user.id);
        const cred = await navigator.credentials.create({publicKey: opts});
        const res = await api("/api/register/verify", {id: cred.id,
          response: {attestationObject: bufToB64u(cred.response.attestationObject),
                     clientDataJSON: bufToB64u(cred.response.clientDataJSON)},
          label: "cli-login " + navigator.userAgent.slice(0, 60)});
        await adoptSession(res, kp, clientPub);
        await handoff();
      } catch (e) { fail(e); } };
    } else {
      msgEl.textContent = "请用管理员 Passkey 登录，登录后自动交回命令行。";
      btn.textContent = "用 Passkey 登录并继续";
      btn.onclick = async () => { try {
        const kp = await ecdhGenerate();
        const clientPub = await ecdhPubBytes(kp);
        const opts = await api("/api/login/options", {ecdh_pub: bytesToB64u(clientPub)});
        await checkChallengeBinding(opts, clientPub);
        opts.challenge = b64uToBuf(opts.challenge);
        opts.allowCredentials = opts.allowCredentials.map(c => ({...c, id: b64uToBuf(c.id)}));
        const cred = await navigator.credentials.get({publicKey: opts});
        const res = await api("/api/login/verify", {id: cred.id,
          response: {authenticatorData: bufToB64u(cred.response.authenticatorData),
                     clientDataJSON: bufToB64u(cred.response.clientDataJSON),
                     signature: bufToB64u(cred.response.signature),
                     userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null}});
        await adoptSession(res, kp, clientPub);
        await handoff();
      } catch (e) { fail(e); } };
    }
  } catch (e) { fail(e); }
}
start();
</script></body></html>
"""

CLI_REPLACE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xmagic 更换 Passkey</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:560px;padding:0 1rem}
button{padding:.5rem 1rem;cursor:pointer}.err{color:#b00020;white-space:pre-wrap}</style>
</head><body>
<h1>更换管理员 Passkey</h1>
<div id="msg">正在检查…</div>
<p><button id="btn" style="display:none"></button></p>
<script>
const params = new URLSearchParams(location.search);
const ticket = params.get("ticket");
const msgEl = document.getElementById("msg"), btn = document.getElementById("btn");
const b64uToBuf = s => { s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - s.length % 4) % 4);
  const bin = atob(s), buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i); return buf.buffer; };
const bufToB64u = buf => { let bin = ""; const b = new Uint8Array(buf);
  for (const c of b) bin += String.fromCharCode(c);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
// ---- session crypto: ECDH (P-256) + HKDF-SHA256 + HMAC envelope.
// Mirrors the server's session crypto (admin.py). The passkey
// challenge binds both ECDH public keys
// (SHA-256(nonce || client_pub || server_pub)); the client checks
// that binding before letting the authenticator sign. After the
// ceremony, every API call is an encrypted envelope keyed by the
// derived session key; the session id alone proves nothing.
const enc8 = new TextEncoder(), dec8 = new TextDecoder();
const concatBytes = (...parts) => { let n = 0; for (const p of parts) n += p.length;
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const b64uToBytes = s => new Uint8Array(b64uToBuf(s));
const bytesToB64u = b => bufToB64u(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
let __sess = null;  // {id, master: Uint8Array, expires_at}
function sessSave() {
  if (__sess) sessionStorage.setItem("xmagic_session", JSON.stringify(
    {id: __sess.id, key: bytesToB64u(__sess.master), expires_at: __sess.expires_at}));
  else sessionStorage.removeItem("xmagic_session");
}
function sessLoad() {
  __sess = null;
  try { const s = JSON.parse(sessionStorage.getItem("xmagic_session") || "null");
    if (s && s.expires_at > Math.floor(Date.now() / 1000))
      __sess = {id: s.id, master: b64uToBytes(s.key), expires_at: s.expires_at};
  } catch (e) { __sess = null; }
  return __sess;
}
async function hmacSha(key, data) {
  const k = await crypto.subtle.importKey("raw", key,
    {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
async function hkdfSha(ikm, salt, info, len) {
  const prk = await hmacSha(salt, ikm);
  let out = new Uint8Array(0), prev = new Uint8Array(0);
  for (let c = 1; out.length < len; c++) {
    prev = await hmacSha(prk, concatBytes(prev, info, new Uint8Array([c])));
    out = concatBytes(out, prev);
  }
  return out.slice(0, len);
}
async function keystreamSha(encKey, nonce, len) {
  let out = new Uint8Array(0);
  for (let c = 0; out.length < len; c++) {
    const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, c);
    out = concatBytes(out, await hmacSha(encKey, concatBytes(nonce, ctr)));
  }
  return out.slice(0, len);
}
function aadFor(method, path) {
  return enc8.encode((__sess ? __sess.id : "") + "\n" + method + "\n" + path);
}
async function sealEnvelope(method, path, payloadObj) {
  const ek = await hmacSha(__sess.master, enc8.encode("xmagic enc"));
  const mk = await hmacSha(__sess.master, enc8.encode("xmagic mac"));
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const plain = enc8.encode(JSON.stringify(
    {t: Math.floor(Date.now() / 1000), body: payloadObj}));
  const ks = await keystreamSha(ek, nonce, plain.length);
  const ct = plain.map((b, i) => b ^ ks[i]);
  const tag = (await hmacSha(mk, concatBytes(aadFor(method, path), nonce, ct))).slice(0, 16);
  return bytesToB64u(concatBytes(nonce, tag, ct));
}
async function openEnvelope(method, path, blob) {
  const raw = b64uToBytes(blob);
  const nonce = raw.slice(0, 16), tag = raw.slice(16, 32), ct = raw.slice(32);
  const ek = await hmacSha(__sess.master, enc8.encode("xmagic enc"));
  const mk = await hmacSha(__sess.master, enc8.encode("xmagic mac"));
  const want = (await hmacSha(mk, concatBytes(aadFor(method, path), nonce, ct))).slice(0, 16);
  if (want.length !== tag.length || !want.every((b, i) => b === tag[i]))
    throw new Error("服务器响应解密校验失败");
  const ks = await keystreamSha(ek, nonce, ct.length);
  return JSON.parse(dec8.decode(ct.map((b, i) => b ^ ks[i]))).body;
}
async function api(path, body) {
  const method = body === undefined ? "GET" : "POST";
  const headers = {"Content-Type": "application/json"};
  let payload;
  if (__sess) {
    headers["X-Session-Id"] = __sess.id;
    if (method === "GET") headers["X-Enc"] = await sealEnvelope("GET", path, {});
    else payload = JSON.stringify({e: await sealEnvelope("POST", path, body ?? {})});
  } else if (body !== undefined) payload = JSON.stringify(body);
  const r = await fetch(path, {method, headers, body: payload});
  const data = await r.json().catch(() => ({}));
  if (__sess && data.e) {
    const plain = await openEnvelope(method, path, data.e);
    if (!r.ok) throw new Error(plain.error || ("HTTP " + r.status));
    return plain;
  }
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}
async function ecdhGenerate() {
  return crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
}
async function ecdhPubBytes(kp) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
}
async function checkChallengeBinding(opts, clientPubBytes) {
  if (!opts.ecdh) throw new Error("服务器未协商会话密钥");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256",
    concatBytes(b64uToBytes(opts.ecdh.nonce), clientPubBytes,
                b64uToBytes(opts.ecdh.server_pub))));
  const given = b64uToBytes(opts.challenge);
  if (digest.length !== given.length || !digest.every((b, i) => b === given[i]))
    throw new Error("挑战值与 ECDH 公钥的绑定校验失败 - 已拒绝继续");
}
async function adoptSession(verifyRes, kp, clientPubBytes) {
  const s = verifyRes.session;
  const serverKey = await crypto.subtle.importKey("raw", b64uToBuf(s.server_pub),
    {name: "ECDH", namedCurve: "P-256"}, false, []);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    {name: "ECDH", public: serverKey}, kp.privateKey, 256));
  const master = await hkdfSha(bits,
    concatBytes(clientPubBytes, b64uToBytes(s.server_pub)),
    enc8.encode("xmagic session key v1"), 32);
  __sess = {id: s.id, master, expires_at: s.expires_at};
  sessSave();
}
function fail(e) { msgEl.className = "err"; msgEl.textContent = String(e); }
async function start() {
  if (!ticket) {
    fail("这个页面需要从 xmagic 命令行发起（缺少 ticket 参数）。");
    return;
  }
  try {
    const st = await api("/api/status");
    if (!st.registered) {
      fail("这个节点还没有管理员 Passkey，无法更换。");
      return;
    }
    msgEl.textContent = "更换需要两步：先用当前 Passkey 验证身份，再注册新 Passkey。完成后，除发起更换的命令行会话和本页会话外，其余管理员会话都会被撤销。";
    btn.style.display = "";
    btn.textContent = "开始更换 Passkey";
    btn.onclick = async () => { try {
      const lkp = await ecdhGenerate();
      const lpub = await ecdhPubBytes(lkp);
      const lopts = await api("/api/login/options", {ecdh_pub: bytesToB64u(lpub)});
      await checkChallengeBinding(lopts, lpub);
      lopts.challenge = b64uToBuf(lopts.challenge);
      lopts.allowCredentials = lopts.allowCredentials.map(c => ({...c, id: b64uToBuf(c.id)}));
      const assertion = await navigator.credentials.get({publicKey: lopts});
      const lres = await api("/api/login/verify", {id: assertion.id,
        response: {authenticatorData: bufToB64u(assertion.response.authenticatorData),
                   clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
                   signature: bufToB64u(assertion.response.signature),
                   userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null}});
      await adoptSession(lres, lkp, lpub);
      msgEl.textContent = "身份已验证，请注册新 Passkey…";
      const rkp = await ecdhGenerate();
      const rpub = await ecdhPubBytes(rkp);
      const opts = await api("/api/cli-replace-options", {ticket, ecdh_pub: bytesToB64u(rpub)});
      await checkChallengeBinding(opts, rpub);
      opts.challenge = b64uToBuf(opts.challenge); opts.user.id = b64uToBuf(opts.user.id);
      const cred = await navigator.credentials.create({publicKey: opts});
      const vres = await api("/api/cli-replace-verify", {ticket, id: cred.id,
        response: {attestationObject: bufToB64u(cred.response.attestationObject),
                   clientDataJSON: bufToB64u(cred.response.clientDataJSON)},
        label: "cli-replace " + navigator.userAgent.slice(0, 60)});
      await adoptSession(vres, rkp, rpub);
      btn.style.display = "none";
      msgEl.textContent = "Passkey 已更换。今后请用新 Passkey 登录；可以关闭此页，回到命令行。";
    } catch (e) { fail(e); } };
  } catch (e) { fail(e); }
}
start();
</script></body></html>
"""


def main():
    with admin_db() as conn:
        registered = load_credential(conn) is not None
    data_dir = os.path.dirname(os.path.abspath(users_mod.DB_PATH))
    if not os.path.exists(os.path.join(data_dir, "config.json")):
        # First boot: render an empty-but-valid config so the xray/sshd
        # containers (which mount these files) can start before the
        # admin has added anyone.
        try:
            result = users_mod.render_all(data_dir)
            print(f"first boot: rendered initial config ({result['users']} users)")
        except Exception as exc:  # noqa: BLE001
            print(f"first-boot render failed: {exc}", file=sys.stderr)
    server = http.server.ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"xmagic admin console on http://{BIND}:{PORT} "
          f"(rp_id={RP_ID}, origins={ORIGINS}, "
          f"admin {'registered' if registered else 'NOT registered - setup open'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
