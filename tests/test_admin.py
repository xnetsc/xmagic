#!/usr/bin/env python3
"""End-to-end test of the admin console with a software authenticator.

Implements the authenticator side of WebAuthn (P-256 keygen, ECDSA sign,
CBOR encode, attestation/assertion construction) with the same stdlib
math the server verifies with, then drives the real HTTP server through:
setup -> register -> registration closed -> login -> replay rejected ->
wrong key rejected -> gateway-user management -> admin-reset.

Run: python3 tests/test_admin.py
"""
import hashlib
import http.client
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import admin as admin_mod  # noqa: E402  (for EC helpers + b64u)

PORT = 18099
ORIGIN = f"http://localhost:{PORT}"
PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""))


# ------------------------------------------------ authenticator side

def cbor_encode(value):
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head(0, value)
        return _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _cbor_head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        out = _cbor_head(5, len(value))
        for k, v in value.items():
            out += cbor_encode(k) + cbor_encode(v)
        return out
    raise TypeError(type(value))


def _cbor_head(major, arg):
    mt = major << 5
    if arg < 24:
        return bytes([mt | arg])
    if arg < 256:
        return bytes([mt | 24, arg])
    if arg < 65536:
        return bytes([mt | 25]) + arg.to_bytes(2, "big")
    return bytes([mt | 26]) + arg.to_bytes(4, "big")


def der_encode_sig(r, s):
    def der_int(v):
        raw = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body


class Authenticator:
    def __init__(self):
        self.d = secrets.randbelow(admin_mod._N - 1) + 1
        self.q = admin_mod._ec_mul(self.d, admin_mod._G)
        self.cred_id = secrets.token_bytes(32)
        self.counter = 0

    def sign(self, message: bytes) -> bytes:
        e = int.from_bytes(hashlib.sha256(message).digest(), "big")
        while True:
            k = secrets.randbelow(admin_mod._N - 1) + 1
            r = admin_mod._ec_mul(k, admin_mod._G)[0] % admin_mod._N
            if r == 0:
                continue
            s = pow(k, -1, admin_mod._N) * (e + self.d * r) % admin_mod._N
            if s:
                return der_encode_sig(r, s)

    def attestation(self, challenge_b64u: str, rp_id: str, origin: str = None) -> dict:
        self.counter += 1
        x = self.q[0].to_bytes(32, "big")
        y = self.q[1].to_bytes(32, "big")
        cose = {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        auth_data = (hashlib.sha256(rp_id.encode()).digest()
                     + bytes([0x01 | 0x04 | 0x40])  # UP | UV | AT
                     + self.counter.to_bytes(4, "big")
                     + bytes(16)
                     + len(self.cred_id).to_bytes(2, "big") + self.cred_id
                     + cbor_encode(cose))
        client_data = json.dumps({
            "type": "webauthn.create", "challenge": challenge_b64u,
            "origin": origin or ORIGIN, "crossOrigin": False}).encode()
        att_obj = cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": admin_mod.b64u_encode(self.cred_id),
                "response": {
                    "attestationObject": admin_mod.b64u_encode(att_obj),
                    "clientDataJSON": admin_mod.b64u_encode(client_data)}}

    def assertion(self, challenge_b64u: str, rp_id: str, origin: str = None) -> dict:
        self.counter += 1
        auth_data = (hashlib.sha256(rp_id.encode()).digest()
                     + bytes([0x01 | 0x04])
                     + self.counter.to_bytes(4, "big"))
        client_data = json.dumps({
            "type": "webauthn.get", "challenge": challenge_b64u,
            "origin": origin or ORIGIN, "crossOrigin": False}).encode()
        sig = self.sign(auth_data + hashlib.sha256(client_data).digest())
        return {"id": admin_mod.b64u_encode(self.cred_id),
                "response": {
                    "authenticatorData": admin_mod.b64u_encode(auth_data),
                    "clientDataJSON": admin_mod.b64u_encode(client_data),
                    "signature": admin_mod.b64u_encode(sig),
                    "userHandle": None}}


# ------------------------------------------------ HTTP client

class Client:
    def __init__(self):
        self.cookie = None

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        headers = {"Content-Type": "application/json", "Origin": ORIGIN}
        if self.cookie:
            headers["Cookie"] = self.cookie
        conn.request(method, path,
                     json.dumps(body) if body is not None else None, headers)
        resp = conn.getresponse()
        raw = resp.read()
        set_cookie = resp.getheader("Set-Cookie")
        if set_cookie and "xmagic_session=" in set_cookie:
            token = set_cookie.split("xmagic_session=", 1)[1].split(";", 1)[0]
            self.cookie = f"xmagic_session={token}" if token else None
        conn.close()
        try:
            return resp.status, json.loads(raw)
        except ValueError:
            return resp.status, {"raw": raw[:200]}


def main():
    workdir = tempfile.mkdtemp(prefix="xmagic-admin-test-")
    db_path = os.path.join(workdir, "data", "users.db")
    env = dict(os.environ, PROXY_DB=db_path,
               XMAGIC_ADMIN_BIND="127.0.0.1", XMAGIC_ADMIN_PORT=str(PORT),
               XMAGIC_ADMIN_RPID="localhost", XMAGIC_DOCKER_SOCK="/nonexistent.sock")
    server = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "admin.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        client = Client()
        for _ in range(50):
            try:
                status, _ = client.call("GET", "/api/status")
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("server did not come up")

        status, body = client.call("GET", "/api/status")
        check("status: not registered at first", body["registered"] is False)

        status, _ = client.call("POST", "/api/users", {"username": "mallory"})
        check("API rejects anonymous writes", status == 401, f"got {status}")

        auth = Authenticator()
        status, opts = client.call("POST", "/api/register/options", {})
        check("register options issued", status == 200 and "challenge" in opts)
        status, body = client.call("POST", "/api/register/verify",
                                   auth.attestation(opts["challenge"], "localhost"))
        check("registration succeeds", status == 200, f"{status} {body}")
        check("session cookie set on register", client.cookie is not None)

        status, body = client.call("GET", "/api/status")
        check("status: registered + authenticated",
              body["registered"] is True and body["authenticated"] is True)

        status, _ = client.call("POST", "/api/register/options", {})
        check("second registration refused", status == 403, f"got {status}")

        status, body = client.call("POST", "/api/users", {"username": "alice"})
        check("admin adds a gateway user", status == 201, f"{status} {body}")
        config_path = os.path.join(workdir, "data", "config.json")
        rendered = json.load(open(config_path)) if os.path.exists(config_path) else {}
        flat = json.dumps(rendered)
        check("rendered config contains the user",
              body.get("user", {}).get("vless_uuid", "") in flat)
        check("apply reports restart skipped (no socket)",
              body.get("applied", {}).get("restart_skipped") is True)

        status, body = client.call("POST", "/api/routes",
                                   {"kind": "domain", "pattern": "example.com",
                                    "to": "block"})
        check("admin adds a route", status == 201, f"{status} {body}")

        status, body = client.call("GET", "/api/settings")
        check("settings default session ttl is one week (168h)",
              status == 200 and body["session_ttl_hours"] == 168, f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"session_ttl_hours": 24})
        check("settings update accepted",
              status == 200 and body["session_ttl_hours"] == 24, f"{status} {body}")
        status, _ = client.call("POST", "/api/settings", {"session_ttl_hours": 0})
        check("settings rejects 0 hours", status == 400, f"got {status}")
        status, _ = client.call("POST", "/api/settings",
                                {"session_ttl_hours": 99999})
        check("settings rejects > 90 days", status == 400, f"got {status}")

        status, body = client.call("GET", "/api/sessions")
        sess = body.get("sessions", [])
        check("session list shows the current web session",
              status == 200 and len(sess) == 1 and sess[0]["current"] is True
              and sess[0]["kind"] == "web", f"{status} {body}")

        client.call("POST", "/api/logout", {})
        status, _ = client.call("GET", "/api/users")
        check("API closed after logout", status == 401, f"got {status}")

        status, opts = client.call("POST", "/api/login/options", {})
        assertion = auth.assertion(opts["challenge"], "localhost")
        status, body = client.call("POST", "/api/login/verify", assertion)
        check("login succeeds", status == 200, f"{status} {body}")

        status, body = client.call("POST", "/api/cli-token",
                                   {"callback": "http://127.0.0.1:9999/callback",
                                    "state": "s1"})
        code = body["redirect"].split("code=")[1].split("&")[0]
        anon = Client()
        status, body = anon.call("POST", "/api/cli-exchange",
                                 {"code": code, "label": "test-cli"})
        cli_token = body.get("token")
        check("cli exchange mints a token", status == 200 and bool(cli_token),
              f"{status} {body}")
        check("cli session expiry follows the 24h setting",
              abs(body.get("expires_at", 0)
                  - (time.time() + 24 * 3600)) < 120, f"{body}")
        status, _ = anon.call("POST", "/api/cli-exchange", {"code": code})
        check("handoff code is single-use", status == 401, f"got {status}")
        status, body = client.call("GET", "/api/sessions")
        kinds = sorted(s["kind"] for s in body["sessions"])
        check("session list shows web + cli sessions", kinds == ["cli", "web"],
              f"{kinds}")
        cli_id = next(s["id"] for s in body["sessions"] if s["kind"] == "cli")
        status, body = client.call("POST", f"/api/sessions/{cli_id}/revoke", {})
        check("revoke cli session by id", status == 200, f"{status} {body}")
        dead = Client()
        dead.cookie = f"xmagic_session={cli_token}"
        status, _ = dead.call("GET", "/api/users")
        check("revoked token is rejected", status == 401, f"got {status}")
        status, body = client.call("POST", "/api/sessions/revoke-others", {})
        check("revoke-others keeps the current session",
              status == 200 and body["revoked_others"] == 0, f"{status} {body}")

        status, body = client.call("POST", "/api/login/verify", assertion)
        check("assertion replay rejected", status in (400, 401), f"got {status}")

        impostor = Authenticator()
        impostor.cred_id = auth.cred_id  # right id, wrong key
        status, opts = client.call("POST", "/api/login/options", {})
        status, body = client.call("POST", "/api/login/verify",
                                   impostor.assertion(opts["challenge"], "localhost"))
        check("wrong-key assertion rejected", status == 401, f"got {status}")

        proc = subprocess.run([sys.executable, os.path.join(ROOT, "users.py"),
                               "admin-reset"],
                              env=dict(os.environ, PROXY_DB=db_path),
                              capture_output=True, text=True)
        check("users.py admin-reset works", proc.returncode == 0, proc.stderr[-200:])
        fresh = Client()
        status, body = fresh.call("GET", "/api/status")
        check("setup reopens after admin-reset", body["registered"] is False)
    finally:
        server.terminate()
        out = server.stdout.read() if server.stdout else ""
        if FAIL:
            print("\n--- server log tail ---\n" + "\n".join(out.splitlines()[-15:]))
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
