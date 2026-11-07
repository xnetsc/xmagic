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
_challenges = {}  # token -> (purpose, expires_at)
_cli_codes = {}   # one-time handoff code -> expires_at


def new_challenge(purpose: str) -> bytes:
    raw = secrets.token_bytes(32)
    with _lock:
        _challenges[b64u_encode(raw)] = (purpose, time.time() + CHALLENGE_TTL)
    return raw


def take_challenge(raw: bytes, purpose: str):
    key = b64u_encode(raw)
    with _lock:
        entry = _challenges.pop(key, None)
    if entry is None or entry[0] != purpose or entry[1] < time.time():
        raise ApiError(400, "challenge expired or unknown - retry the ceremony")


def new_session(kind: str = "web", label=None) -> str:
    """Mint a session. Sessions are stored in the DB keyed by the
    token's SHA-256 (see users.py), so they survive console restarts
    and every interface can list and revoke them."""
    token = secrets.token_urlsafe(32)
    with admin_db() as conn:
        users_mod.mint_session(conn, token, kind, label, session_ttl_seconds())
    return token


def session_valid(token) -> bool:
    if not token:
        return False
    with admin_db() as conn:
        return users_mod.find_session(conn, token) is not None


# ------------------------------------------------------------ CLI handoff
# The xmagic CLI logs in by opening the browser at /cli-auth on this
# console. After the passkey ceremony, the page asks for a one-time code
# (bound to a loopback callback the CLI is listening on) and redirects
# the browser to it; the CLI exchanges the code for a session token over
# a direct API call, so the long-lived token never appears in a URL.

CLI_CODE_TTL = 120


def cli_token_request(body, ):
    callback = body.get("callback") or ""
    state = body.get("state") or ""
    from urllib.parse import urlparse
    parsed = urlparse(callback)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ApiError(400, "callback must be an http loopback URL")
    if not state:
        raise ApiError(400, "state is required")
    code = secrets.token_urlsafe(24)
    with _lock:
        _cli_codes[code] = time.time() + CLI_CODE_TTL
    sep = "&" if "?" in callback else "?"
    return {"redirect": f"{callback}{sep}code={code}&state={state}"}


def cli_exchange(body):
    code = body.get("code") or ""
    with _lock:
        expires = _cli_codes.pop(code, None)
    if expires is None or expires < time.time():
        raise ApiError(401, "handoff code unknown or expired")
    token = new_session("cli", (body.get("label") or "")[:80] or None)
    return {"token": token,
            "expires_at": int(time.time()) + session_ttl_seconds()}


def api_list_sessions(current_token):
    with admin_db() as conn:
        rows = users_mod.list_session_rows(conn)
    current_id = users_mod.session_id_of(current_token) if current_token else None
    out = []
    for r in rows:
        entry = users_mod.session_row_dict(r)
        entry["current"] = entry["id"] == current_id
        out.append(entry)
    return {"sessions": out}


def api_revoke_session(id_prefix):
    with admin_db() as conn:
        row = users_mod.revoke_session_by_id(conn, id_prefix)
    if row is None:
        raise ApiError(404, f"no unique live session with id {id_prefix!r}")
    return {"revoked": row["token_hash"][:12]}


def api_revoke_others(current_token):
    with admin_db() as conn:
        n = users_mod.revoke_other_sessions(conn, current_token)
    return {"revoked_others": n}


def drop_session(token):
    if token:
        with admin_db() as conn:
            users_mod.revoke_token(conn, token)


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

def registration_options(allow_replace=False):
    with admin_db() as conn:
        if load_credential(conn) is not None and not allow_replace:
            raise ApiError(403, "an admin passkey is already registered; "
                                "registration is closed (users.py admin-reset reopens it)")
    challenge = new_challenge("register")
    return {
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
    take_challenge(raw_challenge, "register")
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
    return {"status": "registered"}


def login_options():
    with admin_db() as conn:
        cred = load_credential(conn)
    if cred is None:
        raise ApiError(404, "no admin passkey registered yet")
    challenge = new_challenge("login")
    return {
        "challenge": b64u_encode(challenge),
        "rpId": RP_ID,
        "allowCredentials": [{"type": "public-key", "id": cred["credential_id"]}],
        "userVerification": "required",
        "timeout": 60000,
    }


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
    take_challenge(raw_challenge, "login")
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
    return {"status": "ok"}


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
    return {"users": [_user_dict(r, with_secrets=True) for r in rows]}


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
    applied = apply_changes()
    return {"user": _user_dict(row, with_secrets=True), "applied": applied}


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
    applied = apply_changes()
    return {"applied": applied,
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


def api_add_upstream(body):
    proto = body.get("protocol")
    if proto in ("vless-ws", "vless") and not body.get("uuid"):
        raise ApiError(400, f"{proto} upstream needs a uuid")
    if proto in ("trojan-ws", "ss") and not body.get("password"):
        raise ApiError(400, f"{proto} upstream needs a password")
    if proto in ("http", "socks") and body.get("username") and not body.get("password"):
        raise ApiError(400, f"{proto} upstream with a username also needs a password")
    if proto == "ssh" and not (body.get("username") and body.get("key_file")):
        raise ApiError(400, "ssh upstream needs username and key_file")
    from datetime import datetime, timezone
    with users_mod.db() as conn:
        try:
            conn.execute(
                "INSERT INTO upstreams (name, grp, address, port, protocol, path, uuid,"
                " username, password, key_file, tls, method, note, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (body["name"], body.get("group") or "default", body["address"],
                 int(body["port"]), proto, body.get("path"), body.get("uuid"),
                 body.get("username"), body.get("password"), body.get("key_file"),
                 1 if body.get("tls") else 0, body.get("method") or "aes-256-gcm",
                 body.get("note"), datetime.now(timezone.utc).isoformat()))
        except users_mod.IntegrityError:
            raise ApiError(409, f"upstream already exists: {body.get('name')}")
        except KeyError as exc:
            raise ApiError(400, f"missing field: {exc}")
        row = users_mod.get_upstream(conn, body["name"])
    applied = apply_changes()
    return {"upstream": _upstream_dict(row), "applied": applied}


def api_upstream_action(name, action):
    with users_mod.db() as conn:
        users_mod.get_upstream(conn, name)
        if action == "remove":
            conn.execute("DELETE FROM upstreams WHERE name = ?", (name,))
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
                "password", "key_file", "tls", "method", "note")}
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
            ("vless_ws_paths", "trojan_ws_paths", "upstream_strategy", "ss_method")}
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
    def _send_json(self, status, payload, cookie=None):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

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

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1 << 20:
            raise ApiError(413, "request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw)
        except ValueError:
            raise ApiError(400, "request body is not JSON")

    def _session_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("xmagic_session="):
                return part.split("=", 1)[1]
        return None

    def _require_auth(self):
        if not session_valid(self._session_token()):
            raise ApiError(401, "not logged in")

    def _check_origin(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ORIGINS:
            raise ApiError(403, f"origin {origin!r} not allowed")

    @staticmethod
    def _session_cookie(token):
        return (f"xmagic_session={token}; HttpOnly; SameSite=Strict; Path=/;"
                f" Max-Age={session_ttl_seconds()}")

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
        if path == "/api/status":
            with admin_db() as conn:
                registered = load_credential(conn) is not None
            self._send_json(200, {"registered": registered,
                                  "authenticated": session_valid(self._session_token()),
                                  "rp_id": RP_ID})
            return
        self._require_auth()
        if path == "/api/state":
            self._send_json(200, api_state())
        elif path == "/api/settings":
            self._send_json(200, api_get_settings())
        elif path == "/api/sessions":
            self._send_json(200, api_list_sessions(self._session_token()))
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
        body = self._body() if self.headers.get("Content-Length") else {}
        if path == "/api/register/options":
            allow = session_valid(self._session_token())
            self._send_json(200, registration_options(allow_replace=allow))
            return
        if path == "/api/register/verify":
            authed = session_valid(self._session_token())
            with admin_db() as conn:
                had_credential = load_credential(conn) is not None
            result = registration_verify(body, allow_replace=authed)
            token = new_session("web", (self.headers.get("User-Agent") or "")[:80] or None)
            if had_credential:
                # The passkey was replaced: every other session dies here.
                with admin_db() as conn:
                    users_mod.revoke_other_sessions(conn, token)
            self._send_json(200, result, cookie=self._session_cookie(token))
            return
        if path == "/api/login/options":
            self._send_json(200, login_options())
            return
        if path == "/api/login/verify":
            result = login_verify(body)
            token = new_session("web", (self.headers.get("User-Agent") or "")[:80] or None)
            self._send_json(200, result, cookie=self._session_cookie(token))
            return
        if path == "/api/cli-exchange":
            self._send_json(200, cli_exchange(body))
            return
        self._require_auth()
        if path == "/api/cli-token":
            self._send_json(200, cli_token_request(body))
            return
        if path == "/api/logout":
            drop_session(self._session_token())
            self._send_json(200, {"status": "logged out"},
                            cookie="xmagic_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        elif path == "/api/apply":
            self._send_json(200, {"applied": apply_changes()})
        elif path == "/api/settings":
            self._send_json(200, api_set_settings(body))
        elif path == "/api/sessions/revoke-others":
            self._send_json(200, api_revoke_others(self._session_token()))
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
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:980px;padding:0 1rem;color:#1c1c1e}
h1{font-size:1.3rem} h2{font-size:1.05rem;margin-top:1.6rem}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{border:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}
code{font-size:.78rem;word-break:break-all}
button{padding:.4rem .8rem;margin:.15rem;cursor:pointer}
input,select{padding:.35rem;margin:.15rem}
.err{color:#b00020;white-space:pre-wrap}.ok{color:#146c2e}
.tab{font-weight:600}.hidden{display:none}
.small{color:#666;font-size:.8rem}
</style></head><body>
<h1>xmagic 管理后台</h1>
<div id="msg"></div>

<div id="setup" class="hidden">
  <p>尚未注册管理员。这个后台只支持一个管理员账号、且只能用 Passkey：
  第一个注册的 Passkey 即为管理员，之后注册永久关闭。</p>
  <button id="btn-register">注册管理员 Passkey</button>
</div>

<div id="login" class="hidden">
  <p>管理员已注册。请用 Passkey 登录（不支持其它方式）。</p>
  <button id="btn-login">用 Passkey 登录</button>
</div>

<div id="console" class="hidden">
  <p><span id="state-line"></span>
     <button id="btn-apply">重新渲染并应用</button>
     <button id="btn-logout">退出</button></p>

  <h2>远程 CLI</h2>
  <p class="small">在自己的机器上安装单文件 CLI（纯 Python 标准库，不用 pip），
     装完把本节点加进去登录即可管理：</p>
  <p><input id="cli-install" readonly size="92" value="mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/xnetsc/xmagic/main/xmagic.py -o ~/.local/bin/xmagic && chmod +x ~/.local/bin/xmagic">
     <button type="button" id="btn-copy-install">复制</button></p>
  <p><input id="cli-onboard" readonly size="92" value="">
     <button type="button" id="btn-copy-onboard">复制</button></p>
  <p class="small">若提示找不到 xmagic 命令，把 ~/.local/bin 加入 PATH 后重试。</p>

  <h2>网关用户</h2>
  <table id="users-table"></table>
  <form id="form-user">
    <input name="username" placeholder="用户名" required>
    <input name="group" placeholder="上级分组（默认 default）">
    <input name="ssh_pubkey" placeholder="SSH 公钥（可选）" size="42">
    <input name="note" placeholder="备注（可选）" size="16">
    <button>添加用户</button>
  </form>

  <h2>上级节点</h2>
  <table id="upstreams-table"></table>
  <form id="form-upstream">
    <input name="name" placeholder="名称" required>
    <select name="protocol">
      <option>vless-ws</option><option>vless</option><option>trojan-ws</option>
      <option>ss</option><option>http</option><option>socks</option><option>ssh</option>
    </select>
    <input name="address" placeholder="地址" required>
    <input name="port" placeholder="端口" type="number" required size="7">
    <input name="group" placeholder="分组" size="9">
    <input name="path" placeholder="WS 路径" size="10">
    <input name="uuid" placeholder="UUID" size="20">
    <input name="username" placeholder="用户名" size="10">
    <input name="password" placeholder="密码" size="14">
    <input name="key_file" placeholder="SSH 密钥路径" size="14">
    <input name="method" placeholder="SS 方法" size="14">
    <input name="note" placeholder="备注" size="12">
    <label><input type="checkbox" name="tls"> TLS</label>
    <button id="up-submit">添加上级</button>
    <button type="button" id="up-cancel" class="hidden">取消编辑</button>
  </form>

  <h2>目标路由</h2>
  <table id="routes-table"></table>
  <form id="form-route">
    <select name="kind"><option>domain</option><option>full</option>
      <option>keyword</option><option>regexp</option><option>ip</option></select>
    <input name="pattern" placeholder="匹配目标" required>
    <input name="to" placeholder="目标：分组名 / direct / block" required size="24">
    <input name="username" placeholder="限定用户（可选）" size="14">
    <input name="note" placeholder="备注" size="12">
    <button id="route-submit">添加路由</button>
    <button type="button" id="route-cancel" class="hidden">取消编辑</button>
  </form>
  <p class="small">每次修改都会自动重新渲染配置；若 Docker socket 可用，还会重启
  xray / sshd 容器生效。渲染结果见上方状态行。</p>

  <h2>设置</h2>
  <form id="form-settings">
    <label>登录会话有效期（小时）
      <input name="session_ttl_hours" type="number" min="1" max="2160" size="6"></label>
    <label>VLESS WS 路径（逗号分隔）
      <input name="vless_ws_paths" size="26"></label>
    <label>Trojan WS 路径
      <input name="trojan_ws_paths" size="26"></label>
    <label>上级池策略 <select name="upstream_strategy"></select></label>
    <label>新用户默认 SS 方法 <select name="ss_method"></select></label>
    <label><input type="checkbox" name="direct_allow_private"> 允许直连内网地址</label>
    <button>保存</button>
    <span class="small">会话有效期默认 168 小时（1 周），范围 1–2160，只影响新签发会话。
    WS 路径 / 策略 / 默认方法：留空保存 = 回退到部署时 .env 的值；输入框灰字是当前生效值。
    直连内网地址默认关闭：经 VLESS / Trojan / Shadowsocks 进来的流量直连时不能访问本机与内网地址
    （Xray 的防 SSRF 默认规则）；节点需要访问自家局域网服务时再打开。
    保存后自动重新渲染生效。</span>
  </form>
  <p class="small"><span id="admin-line"></span>
     <button type="button" id="btn-replace">更换管理员 Passkey</button>
     <span>更换后，其它所有登录会话立即失效，本页面会切到新签发的会话。</span></p>

  <h2>数据库</h2>
  <table id="databases-table"></table>
  <form id="form-database">
    <label>名称 <input name="name" size="12" required></label>
    <label>类型 <select name="type">
      <option value="sqlite">SQLite</option>
      <option value="postgres">PostgreSQL</option>
      <option value="mysql">MySQL</option></select></label>
    <label>目标 <input name="target" size="46" required
      placeholder="sqlite 文件路径，或 postgresql:// / mysql:// DSN"></label>
    <label>备注 <input name="note" size="12"></label>
    <button>添加配置</button>
  </form>
  <form id="form-migrate">
    <label>从 <select name="from"></select></label>
    <label>迁移到 <select name="to"></select></label>
    <label><input type="checkbox" name="replace"> 覆盖目标已有数据</label>
    <button>迁移数据</button>
    <span class="small">数据库配置本身保存在节点本地，业务数据在当前启用的库里。
    切到一个还没有表的库时会自动建表；切换后立即重新渲染生效。
    迁移会把全部业务表（用户 / 上级 / 路由 / 设置 / 管理员凭证 / 会话）复制到目标库。
    列表中 DSN 的密码已打码显示。</span>
  </form>

  <h2>登录会话</h2>
  <table id="sessions-table"></table>
  <p><button id="btn-revoke-others">撤销其它全部会话</button>
     <span class="small">同一管理员可以有多个会话（不同浏览器、不同机器的 CLI）。
     「当前」是本页面正在用的会话；撤销它会立即退出本页面。</span></p>
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
async function api(path, body) {
  const r = await fetch(path, {method: body === undefined ? "GET" : "POST",
    headers: {"Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data; }
function appliedText(a) {
  if (!a) return "";
  let t = `已渲染：${a.users} 用户 / ${a.upstreams} 上级 / ${a.ssh_keys} SSH 公钥`;
  if (a.restart_skipped) t += "；未挂 Docker socket，未自动重启（需手动重启 xray/sshd）";
  else t += "；重启：" + Object.entries(a.restarted).map(([k, v]) => k + (v ? "✓" : "✗")).join(" ");
  return t; }
async function refresh() {
  const st = await api("/api/status");
  $("setup").classList.toggle("hidden", st.registered);
  $("login").classList.toggle("hidden", !st.registered || st.authenticated);
  $("console").classList.toggle("hidden", !st.authenticated);
  if (!st.authenticated) return;
  const s = await api("/api/state");
  $("state-line").textContent =
    `状态：${s.enabled_users} 启用用户 / ${s.enabled_upstreams} 上级 / ${s.enabled_routes} 路由` +
    `，公共端口 ${s.public_port}，重启通道 ${s.restart_via === "container" ? "整容器重启" : s.restart_via === "docker" ? "Docker socket" : "无（仅渲染）"}。`;
  const users = (await api("/api/users")).users;
  $("users-table").innerHTML = "<tr><th>用户</th><th>分组</th><th>启用</th><th>凭证</th><th>操作</th></tr>" +
    users.map(u => `<tr><td>${u.username}</td><td>${u.group}</td><td>${u.enabled}</td>
      <td><code>uuid ${u.vless_uuid}<br>密码 ${u.password}<br>ss ${u.ss_method} / ${u.ss_password}` +
      `${u.ssh_key ? "<br>SSH 公钥已登记" : ""}</code></td>
      <td><button data-act="passwd" data-u="${u.username}">换密码</button>
      <button data-act="rotate-uuid" data-u="${u.username}">换UUID</button>
      <button data-act="setkey" data-u="${u.username}">公钥</button>
      <button data-act="setgroup" data-u="${u.username}" data-g="${u.group}">分组</button>
      <button data-act="setmethod" data-u="${u.username}" data-m="${u.ss_method}">SS方法</button>
      <button data-act="setnote" data-u="${u.username}" data-n="${u.note || ""}">备注</button>
      <button data-act="${u.enabled ? "disable" : "enable"}" data-u="${u.username}">${u.enabled ? "停用" : "启用"}</button>
      <button data-act="remove" data-u="${u.username}">删除</button></td></tr>`).join("");
  const ups = (await api("/api/upstreams")).upstreams;
  window._ups = ups;
  $("upstreams-table").innerHTML = "<tr><th>名称</th><th>分组</th><th>协议</th><th>地址</th><th>启用</th><th>操作</th></tr>" +
    ups.map(u => `<tr><td>${u.name}</td><td>${u.group}</td><td>${u.protocol}${u.tls ? " +tls" : ""}</td>
      <td>${u.address}:${u.port}${u.path || ""}</td><td>${u.enabled}</td>
      <td><button data-edit-up="${u.name}">编辑</button>
      <button data-act="${u.enabled ? "disable" : "enable"}" data-up="${u.name}">${u.enabled ? "停用" : "启用"}</button>
      <button data-act="remove" data-up="${u.name}">删除</button></td></tr>`).join("");
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
  $("admin-line").textContent = s.admin_registered
    ? `管理员 Passkey：${s.admin_label || "(无标签)"}，注册于 ${s.admin_created_at || "?"}，累计验签 ${s.admin_sign_count} 次。` : "";
  const sessions = (await api("/api/sessions")).sessions;
  const fmtTs = ts => new Date(ts * 1000).toLocaleString();
  $("sessions-table").innerHTML = "<tr><th>标识</th><th>类型</th><th>来源</th><th>创建时间</th><th>到期</th><th></th><th>操作</th></tr>" +
    sessions.map(s => `<tr><td><code>${s.id}</code></td><td>${s.kind}</td><td>${s.label || ""}</td>
      <td>${fmtTs(s.created_at)}</td><td>${fmtTs(s.expires_at)}</td><td>${s.current ? "当前" : ""}</td>
      <td><button data-session="${s.id}">撤销</button></td></tr>`).join("");
  const dbs = (await api("/api/databases")).databases;
  window._dbs = dbs;
  $("databases-table").innerHTML = "<tr><th></th><th>名称</th><th>类型</th><th>目标</th><th>备注</th><th>操作</th></tr>" +
    dbs.map(d => `<tr><td>${d.active ? "当前" : ""}</td><td>${d.name}</td><td>${d.type}</td>
      <td><code>${d.target}</code></td><td>${d.note || ""}</td>
      <td><button data-dbtest="${d.name}">测试</button>
      <button data-dbedit="${d.name}">编辑</button>
      ${d.active ? "" : `<button data-dbswitch="${d.name}">切换</button>
      <button data-dbremove="${d.name}">删除</button>`}</td></tr>`).join("");
  const dbOpts = dbs.map(d => `<option>${d.name}</option>`).join("");
  $("form-migrate").querySelector("[name=from]").innerHTML = dbOpts;
  $("form-migrate").querySelector("[name=to]").innerHTML = dbOpts;
  const routes = (await api("/api/routes")).routes;
  window._routes = routes;
  $("routes-table").innerHTML = "<tr><th>#</th><th>类型</th><th>目标模式</th><th>去向</th><th>限定用户</th><th>启用</th><th>操作</th></tr>" +
    routes.map(r => `<tr><td>${r.id}</td><td>${r.kind}</td><td>${r.pattern}</td><td>${r.target}</td>
      <td>${r.username || "*"}</td><td>${r.enabled}</td>
      <td><button data-edit-route="${r.id}">编辑</button>
      <button data-act="${r.enabled ? "disable" : "enable"}" data-route="${r.id}">${r.enabled ? "停用" : "启用"}</button>
      <button data-act="remove" data-route="${r.id}">删除</button></td></tr>`).join("");
}
$("btn-register").onclick = async () => { try {
  const opts = await api("/api/register/options", {});
  opts.challenge = b64uToBuf(opts.challenge); opts.user.id = b64uToBuf(opts.user.id);
  const cred = await navigator.credentials.create({publicKey: opts});
  const res = await api("/api/register/verify", {id: cred.id,
    response: {attestationObject: bufToB64u(cred.response.attestationObject),
               clientDataJSON: bufToB64u(cred.response.clientDataJSON)},
    label: navigator.userAgent.slice(0, 80)});
  msg("管理员 Passkey 注册成功：" + res.status, true); refresh();
} catch (e) { msg(String(e)); } };
$("btn-login").onclick = async () => { try {
  const opts = await api("/api/login/options", {});
  opts.challenge = b64uToBuf(opts.challenge);
  opts.allowCredentials = opts.allowCredentials.map(c => ({...c, id: b64uToBuf(c.id)}));
  const cred = await navigator.credentials.get({publicKey: opts});
  await api("/api/login/verify", {id: cred.id,
    response: {authenticatorData: bufToB64u(cred.response.authenticatorData),
               clientDataJSON: bufToB64u(cred.response.clientDataJSON),
               signature: bufToB64u(cred.response.signature),
               userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null}});
  msg("登录成功", true); refresh();
} catch (e) { msg(String(e)); } };
$("btn-logout").onclick = async () => { await api("/api/logout", {}); refresh(); };
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
$("cli-onboard").value = "xmagic node add main --url " + location.origin + " && xmagic login";
function copyCmd(id, btn) { const el = $(id); el.select();
  const done = () => { btn.textContent = "已复制"; setTimeout(() => btn.textContent = "复制", 1500); };
  if (navigator.clipboard && window.isSecureContext)
    navigator.clipboard.writeText(el.value).then(done, () => { document.execCommand("copy"); done(); });
  else { document.execCommand("copy"); done(); } }
$("btn-copy-install").onclick = e => copyCmd("cli-install", e.target);
$("btn-copy-onboard").onclick = e => copyCmd("cli-onboard", e.target);
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
    else if (t.dataset.dbswitch) { if (!confirm(`切换到数据库 ${t.dataset.dbswitch}？网关将改用该库的数据并立即重新渲染。`)) return;
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
        appliedText(r.applied), true); e.target.reset(); refresh(); }
  catch (err) { msg(String(err)); } };
let editingUp = null, editingRoute = null;
const setField = (form, name, value) => { const el = form.querySelector(`[name=${name}]`);
  if (el) el.value = value ?? ""; };
document.addEventListener("click", e => {
  const bu = e.target.closest("button[data-edit-up]");
  if (bu) { const u = (window._ups || []).find(x => x.name === bu.dataset.editUp); if (!u) return;
    const f = $("form-upstream"); editingUp = u.name;
    for (const k of ["name", "address", "port", "group", "path", "uuid", "username",
                     "password", "key_file", "method", "note"])
      setField(f, k, k === "group" ? u.group : u[k]);
    f.querySelector("[name=protocol]").value = u.protocol;
    f.querySelector("[name=tls]").checked = !!u.tls;
    f.querySelector("[name=name]").disabled = true;
    $("up-submit").textContent = "保存修改：" + u.name;
    $("up-cancel").classList.remove("hidden");
    msg("正在编辑上级 " + u.name + "：密码等字段留空 = 不改动", true); return; }
  const br = e.target.closest("button[data-edit-route]");
  if (br) { const r = (window._routes || []).find(x => x.id === Number(br.dataset.editRoute)); if (!r) return;
    const f = $("form-route"); editingRoute = r.id;
    setField(f, "kind", r.kind); setField(f, "pattern", r.pattern);
    setField(f, "to", r.target); setField(f, "username", r.username || "");
    setField(f, "note", r.note || "");
    $("route-submit").textContent = "保存修改：路由 #" + r.id;
    $("route-cancel").classList.remove("hidden");
    msg("正在编辑路由 #" + r.id, true); }
});
$("up-cancel").onclick = () => { editingUp = null; const f = $("form-upstream");
  f.reset(); f.querySelector("[name=name]").disabled = false;
  $("up-submit").textContent = "添加上级"; $("up-cancel").classList.add("hidden"); };
$("route-cancel").onclick = () => { editingRoute = null; $("form-route").reset();
  $("route-submit").textContent = "添加路由"; $("route-cancel").classList.add("hidden"); };
$("form-upstream").onsubmit = async e => { e.preventDefault();
  try { if (editingUp) {
      const o = formJson(e.target); delete o.name;
      for (const k of ["password", "uuid", "username", "key_file", "path"])
        if (!o[k]) delete o[k];  // blank in edit mode = leave unchanged
      if (!("note" in o)) o.note = "";  // the form was prefilled: blank = cleared
      const r = await api(`/api/upstreams/${editingUp}/update`, o);
      msg("上级已修改。" + appliedText(r.applied), true); $("up-cancel").onclick();
    } else {
      const r = await api("/api/upstreams", formJson(e.target));
      msg("上级已添加。" + appliedText(r.applied), true); e.target.reset(); }
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
      ss_method: f.querySelector("[name=ss_method]").value});
    msg("设置已保存。" + (r.applied ? appliedText(r.applied) : ""), true); refresh(); }
  catch (err) { msg(String(err)); } };
$("btn-replace").onclick = () => $("btn-register").onclick();
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
const msgEl = document.getElementById("msg"), btn = document.getElementById("btn");
const b64uToBuf = s => { s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - s.length % 4) % 4);
  const bin = atob(s), buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i); return buf.buffer; };
const bufToB64u = buf => { let bin = ""; const b = new Uint8Array(buf);
  for (const c of b) bin += String.fromCharCode(c);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
async function api(path, body) {
  const r = await fetch(path, {method: body === undefined ? "GET" : "POST",
    headers: {"Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data; }
function fail(e) { msgEl.className = "err"; msgEl.textContent = String(e); }
async function handoff() {
  msgEl.textContent = "已通过 Passkey 验证，正在把登录状态交回命令行…";
  const res = await api("/api/cli-token", {callback, state});
  location.replace(res.redirect);
}
async function start() {
  if (!callback || !state) {
    fail("这个页面需要从 xmagic 命令行发起（缺少 callback/state 参数）。");
    return;
  }
  try {
    const st = await api("/api/status");
    if (st.authenticated) { await handoff(); return; }
    btn.style.display = "";
    if (!st.registered) {
      msgEl.textContent = "这个节点还没有管理员 Passkey。先注册（第一个注册的即为管理员），随后自动交回命令行。";
      btn.textContent = "注册管理员 Passkey 并继续";
      btn.onclick = async () => { try {
        const opts = await api("/api/register/options", {});
        opts.challenge = b64uToBuf(opts.challenge); opts.user.id = b64uToBuf(opts.user.id);
        const cred = await navigator.credentials.create({publicKey: opts});
        await api("/api/register/verify", {id: cred.id,
          response: {attestationObject: bufToB64u(cred.response.attestationObject),
                     clientDataJSON: bufToB64u(cred.response.clientDataJSON)},
          label: "cli-login " + navigator.userAgent.slice(0, 60)});
        await handoff();
      } catch (e) { fail(e); } };
    } else {
      msgEl.textContent = "请用管理员 Passkey 登录，登录后自动交回命令行。";
      btn.textContent = "用 Passkey 登录并继续";
      btn.onclick = async () => { try {
        const opts = await api("/api/login/options", {});
        opts.challenge = b64uToBuf(opts.challenge);
        opts.allowCredentials = opts.allowCredentials.map(c => ({...c, id: b64uToBuf(c.id)}));
        const cred = await navigator.credentials.get({publicKey: opts});
        await api("/api/login/verify", {id: cred.id,
          response: {authenticatorData: bufToB64u(cred.response.authenticatorData),
                     clientDataJSON: bufToB64u(cred.response.clientDataJSON),
                     signature: bufToB64u(cred.response.signature),
                     userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null}});
        await handoff();
      } catch (e) { fail(e); } };
    }
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
