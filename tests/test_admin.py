#!/usr/bin/env python3
"""End-to-end test of the admin console with a software authenticator.

Implements the authenticator side of WebAuthn (P-256 keygen, ECDSA sign,
CBOR encode, attestation/assertion construction) with the same stdlib
math the server verifies with, then drives the real HTTP server through:
setup -> register -> registration closed -> login -> replay rejected ->
wrong key rejected -> gateway-user management -> admin-reset.

Run: python3 tests/test_admin.py
"""
import base64
import hashlib
import http.client
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import admin as admin_mod  # noqa: E402  (for EC helpers + b64u)
import xmagic as cli_mod  # noqa: E402  (the real client's envelope code)

PORT = 18099
ORIGIN = f"http://localhost:{PORT}"
PASS = []
FAIL = []

SSH_PUBKEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminKey"
              " test@admin")


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
    """Speaks the key-bound session protocol, like the browser pages
    and the real CLI: ceremonies contribute an ECDH public key and
    verify the challenge binding (SHA-256 of nonce || client pub ||
    server pub), the verify response's session material is adopted,
    and every later call is an encrypted envelope."""

    def __init__(self, port=None):
        self.port = port or PORT
        self.origin = f"http://localhost:{self.port}"
        self.sid = None
        self.master = None
        self._kp = None  # (priv, pub) of the in-flight ceremony

    def drop(self):
        self.sid = None
        self.master = None

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json", "Origin": self.origin}
        data = None
        if self.master is not None:
            headers["X-Session-Id"] = self.sid
            if method == "GET":
                headers["X-Enc"] = cli_mod.seal_envelope(
                    self.master, cli_mod._aad(self.sid, method, path),
                    cli_mod._wrap_body({}))
            else:
                data = json.dumps({"e": cli_mod.seal_envelope(
                    self.master, cli_mod._aad(self.sid, method, path),
                    cli_mod._wrap_body(body or {}))})
        elif body is not None:
            data = json.dumps(body)
        conn.request(method, path, data, headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            payload = json.loads(raw)
        except ValueError:
            return resp.status, {"raw": raw[:200]}
        if self.master is not None and isinstance(payload, dict) \
                and "e" in payload:
            plain = cli_mod.open_envelope(
                self.master, cli_mod._aad(self.sid, method, path),
                payload["e"])
            payload = json.loads(plain)["body"]
        return resp.status, payload

    def options(self, kind, extra=None):
        return self.options_at(f"/api/{kind}/options", extra)

    def options_at(self, path, extra=None):
        priv, pub = cli_mod._ec_keypair()
        self._kp = (priv, pub)
        body = {"ecdh_pub": admin_mod.b64u_encode(pub)}
        body.update(extra or {})
        status, resp = self.call("POST", path, body)
        if status == 200 and "ecdh" in resp:
            digest = hashlib.sha256(
                admin_mod.b64u_decode(resp["ecdh"]["nonce"]) + pub
                + admin_mod.b64u_decode(resp["ecdh"]["server_pub"])).digest()
            if digest != admin_mod.b64u_decode(resp["challenge"]):
                raise AssertionError("challenge does not bind the ECDH pubs")
        return status, resp

    def verify(self, kind, payload):
        return self.verify_at(f"/api/{kind}/verify", payload)

    def verify_at(self, path, payload):
        status, resp = self.call("POST", path, payload)
        if status in (200, 201) and "session" in resp:
            priv, pub = self._kp
            self.sid = resp["session"]["id"]
            self.master = cli_mod.derive_session_key(
                pub, priv,
                admin_mod.b64u_decode(resp["session"]["server_pub"]))
        return status, resp

    def mint_cli_session(self, label="test-cli"):
        """In-channel ECDH delegation -> (status, body, cli_client)."""
        priv, pub = cli_mod._ec_keypair()
        status, resp = self.call(
            "POST", "/api/cli/sessions",
            {"client_pub": admin_mod.b64u_encode(pub), "label": label})
        other = Client()
        if status == 201:
            other.sid = resp["id"]
            other.master = cli_mod.derive_session_key(
                pub, priv, admin_mod.b64u_decode(resp["server_pub"]))
        return status, resp, other


def main():
    workdir = tempfile.mkdtemp(prefix="xmagic-admin-test-")
    db_path = os.path.join(workdir, "data", "users.db")
    env = dict(os.environ, PROXY_DB=db_path,
               XMAGIC_ADMIN_BIND="127.0.0.1", XMAGIC_ADMIN_PORT=str(PORT),
               XMAGIC_ENABLE_SSH="1", XMAGIC_DOCKER_SOCK="/nonexistent.sock")
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

        status, _ = client.call("POST", "/api/keys/generate", {})
        check("keys/generate rejects anonymous calls", status == 401,
              f"got {status}")

        auth = Authenticator()
        status, opts = client.options("register")
        check("register options issued", status == 200 and "challenge" in opts)
        check("challenge binds both ECDH public keys",
              "ecdh" in opts and bool(opts["ecdh"].get("server_pub"))
              and bool(opts["ecdh"].get("nonce")), f"{opts}")
        status, body = client.verify(
            "register", auth.attestation(opts["challenge"], "localhost"))
        check("registration succeeds", status == 200, f"{status} {body}")
        check("register establishes a key-bound session",
              client.master is not None and bool(client.sid))

        status, body = client.call("GET", "/api/status")
        check("status: registered", body["registered"] is True)
        check("status rp_id comes from the request headers",
              body.get("rp_id") == "localhost", f"{body}")
        status, body = client.call("GET", "/api/users")
        check("users payload reports ssh_enabled true",
              body.get("ssh_enabled") is True, f"{body}")
        status, _ = client.call("GET", "/api/state")
        check("the negotiated session key opens the API", status == 200)

        # envelope discipline: a replayed request and a tampered one die
        headers = {"Content-Type": "application/json", "Origin": ORIGIN,
                   "X-Session-Id": client.sid}
        sealed = json.dumps({"e": cli_mod.seal_envelope(
            client.master, cli_mod._aad(client.sid, "POST", "/api/apply"),
            cli_mod._wrap_body({}))})
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        conn.request("POST", "/api/apply", sealed, headers)
        first = conn.getresponse(); first.read(); conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        conn.request("POST", "/api/apply", sealed, headers)
        second = conn.getresponse(); second.read(); conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        blob = json.loads(sealed)["e"]
        conn.request("POST", "/api/apply",
                     json.dumps({"e": blob[:-6] + "AAAAAA"}), headers)
        third = conn.getresponse(); third.read(); conn.close()
        check("envelope replay + tamper are rejected",
              first.status == 200 and second.status == 401
              and third.status == 401,
              f"{first.status} {second.status} {third.status}")

        stranger = Client()
        status, _ = stranger.options("register")
        check("second registration refused for strangers", status == 403,
              f"got {status}")

        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "upv", "protocol": "vless-ws",
                                    "address": "10.0.0.9", "port": 443,
                                    "uuid": "11111111-2222-3333-4444-"
                                            "555555555555"})
        check("vless upstream refused while the protocol is off",
              status == 400, f"{status} {body}")
        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "upb", "protocol": "ss",
                                    "address": "10.0.0.9", "port": 8388,
                                    "password": "pw",
                                    "method": "aes-999-bogus"})
        check("bogus ss method refused by the API",
              status == 400, f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"vless_enabled": True})
        check("settings: vless opt-in (render checks below need it)",
              status == 200 and body["vless_enabled"] is True,
              f"{status} {body}")
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

        # --- full-surface parity: user fields, edits, render-level settings
        status, body = client.call("POST", "/api/users/alice/rotate-uuid", {})
        check("rotate-uuid issues a fresh uuid",
              status == 200 and bool(body.get("user", {}).get("vless_uuid")),
              f"{status} {body}")
        status, body = client.call("POST", "/api/users/alice/setmethod",
                                   {"method": "chacha20-ietf-poly1305"})
        check("setmethod applies", status == 200
              and body.get("user", {}).get("ss_method") == "chacha20-ietf-poly1305",
              f"{status} {body}")
        status, body = client.call("POST", "/api/users/alice/setnote",
                                   {"note": "primary"})
        check("setnote applies", status == 200
              and body.get("user", {}).get("note") == "primary", f"{status} {body}")

        # --- share URLs + QR: only enabled protocols, explicit
        # endpoint override wins over the request-derived one
        status, body = client.call("GET", "/api/users")
        alice = next(u for u in body["users"]
                     if u["username"] == "alice")
        status, body = client.call("POST", "/api/users/alice/share",
                                   {"server": "node.example.com",
                                    "port": 443, "tls": True})
        protos = sorted(e["protocol"] for e in body.get("urls", []))
        check("share: only enabled protocols are generated",
              status == 200 and protos == ["ss-ws", "trojan-ws",
                                           "vless-ws", "vmess-ws"],
              f"{status} {protos}")
        by_proto = {e["protocol"]: e for e in body.get("urls", [])}
        ss_url = by_proto.get("ss-ws", {}).get("url", "")
        ui = ss_url.split("ss://", 1)[1].split("@", 1)[0]
        cred = base64.urlsafe_b64decode(
            ui + "=" * (-len(ui) % 4)).decode()
        check("share: ss userinfo carries alice's method + password",
              cred == f"{alice['ss_method']}:{alice['ss_password']}",
              cred)
        check("share: ss pins udp off; trojan aims at the node host",
              "&udp=0" in ss_url.split("#", 1)[0] and all(
                  e["url"].startswith("trojan://")
                  and "@node.example.com:443" in e["url"]
                  for e in body["urls"]
                  if e["protocol"] == "trojan-ws"))
        check("share: every entry carries an svg qr code",
              all((e.get("qr") or "").startswith("<svg")
                  and "viewBox=" in e["qr"] for e in body["urls"]))
        status, body = client.call("POST", "/api/users/alice/share",
                                   {"protocol": "ss"})
        check("share: a disabled protocol is refused",
              status == 400 and "not enabled" in body.get("error", ""),
              f"{status} {body}")
        status, body = client.call("POST", "/api/users/alice/share",
                                   {"protocol": "trojan-ws"})
        check("share: a single-protocol request narrows the list",
              status == 200
              and [e["protocol"] for e in body["urls"]] == ["trojan-ws"],
              f"{status} {body}")
        status, _ = client.call("POST", "/api/users/nobody/share", {})
        check("share: unknown user is a 404", status == 404, f"{status}")

        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "up-a", "protocol": "ss",
                                    "address": "10.3.3.3", "port": 8388,
                                    "password": "pw-old"})
        check("admin adds an upstream", status == 201, f"{status} {body}")
        status, body = client.call("POST", "/api/upstreams/up-a/update",
                                   {"port": 9999, "password": "pw-new"})
        check("upstream edit applies",
              status == 200 and body.get("upstream", {}).get("port") == 9999
              and body["upstream"]["password"] == "pw-new", f"{status} {body}")
        status, _ = client.call("POST", "/api/upstreams/up-a/update",
                                {"password": ""})
        check("upstream edit rejects an empty ss password", status == 400,
              f"got {status}")
        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "up-ssws", "protocol": "ss",
                                    "address": "cdn.example.com", "port": 443,
                                    "password": "pw", "path": "/ss-ws",
                                    "tls": True})
        check("admin adds an ss upstream with path+tls (SS over WS)",
              status == 201 and body.get("upstream", {}).get("path")
              == "/ss-ws" and body["upstream"]["tls"] is True,
              f"{status} {body}")
        rendered = json.load(open(config_path))
        wss_out = next((o for o in rendered["outbounds"]
                        if o["tag"] == "up-default-up-ssws"), {})
        check("rendered ss upstream dials WSS to the CDN shape",
              wss_out.get("streamSettings", {}).get("network") == "ws"
              and wss_out["streamSettings"]["wsSettings"]
                  == {"path": "/ss-ws"}
              and wss_out["streamSettings"].get("security") == "tls"
              and wss_out["streamSettings"]["tlsSettings"]
                  == {"serverName": "cdn.example.com"},
              json.dumps(wss_out))
        status, _ = client.call("POST", "/api/upstreams/up-ssws/remove", {})
        check("ss-ws test upstream removed again", status == 200,
              f"got {status}")

        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "up-vmbad", "protocol": "vmess-ws",
                                    "address": "10.0.0.9", "port": 443})
        check("vmess-ws upstream without a uuid refused by the API",
              status == 400, f"{status} {body}")
        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "up-vmbare", "protocol": "vmess",
                                    "address": "10.0.0.9", "port": 10086,
                                    "uuid": "11111111-2222-3333-4444-"
                                            "555555555555"})
        check("bare vmess upstream refused while vmess TCP is off",
              status == 400, f"{status} {body}")
        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "up-vmws", "protocol": "vmess-ws",
                                    "address": "cdn.example.com", "port": 443,
                                    "uuid": "22222222-3333-4444-5555-"
                                            "666666666666", "tls": True})
        check("admin adds a vmess-ws upstream with tls",
              status == 201 and body.get("upstream", {}).get("protocol")
              == "vmess-ws" and body["upstream"]["tls"] is True,
              f"{status} {body}")
        rendered = json.load(open(config_path))
        vmws_out = next((o for o in rendered["outbounds"]
                         if o["tag"] == "up-default-up-vmws"), {})
        vmws_ss = vmws_out.get("streamSettings", {})
        check("rendered vmess-ws upstream dials WSS with the vmess path",
              vmws_out.get("protocol") == "vmess"
              and vmws_ss.get("network") == "ws"
              and vmws_ss.get("wsSettings", {}).get("path") == "/vmess-ws"
              and vmws_ss.get("security") == "tls"
              and vmws_ss.get("tlsSettings", {}).get("serverName")
                  == "cdn.example.com",
              json.dumps(vmws_out))
        status, _ = client.call("POST", "/api/upstreams/up-vmws/remove", {})
        check("vmess-ws test upstream removed again", status == 200,
              f"got {status}")

        # ssh upstream private keys: pasted/uploaded content is stored
        # on the node (0600), the row records /keys/<name>.key, and the
        # content itself is never returned by the API.
        key_v1 = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                  "ZmFrZS12MQ==\n-----END OPENSSH PRIVATE KEY-----")
        key_v2 = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                  "ZmFrZS12Mg==\n-----END OPENSSH PRIVATE KEY-----")
        stored = os.path.join(workdir, "data", "ssh_client_keys", "up-ssh.key")
        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "up-ssh", "protocol": "ssh",
                                    "address": "10.4.4.4", "port": 22,
                                    "username": "tunnel", "key_content": key_v1})
        check("ssh upstream with uploaded key content",
              status == 201 and body["upstream"]["key_file"] == "/keys/up-ssh.key"
              and os.path.exists(stored)
              and open(stored).read().strip() == key_v1
              and (os.stat(stored).st_mode & 0o777) == 0o600,
              f"{status} {body}")
        status, body = client.call("GET", "/api/upstreams")
        check("key content is never listed",
              status == 200 and "ZmFrZS" not in json.dumps(body), f"{status}")
        tunnels_script = os.path.join(workdir, "data", "start-tunnels.sh")
        check("rendered tunnels use the stored key path",
              os.path.exists(tunnels_script)
              and "-i /keys/up-ssh.key" in open(tunnels_script).read())
        status, _ = client.call("POST", "/api/upstreams",
                                {"name": "up-bad", "protocol": "ssh",
                                 "address": "10.4.4.5", "port": 22,
                                 "username": "tunnel", "key_content": "not a key"})
        check("invalid key content rejected", status == 400, f"got {status}")
        status, body = client.call("POST", "/api/upstreams/up-ssh/update",
                                   {"key_content": key_v2})
        check("key content replaced on edit",
              status == 200 and open(stored).read().strip() == key_v2,
              f"{status} {body}")
        status, body = client.call("POST", "/api/upstreams/up-ssh/remove", {})
        check("removing the upstream deletes the stored key",
              status == 200 and not os.path.exists(stored), f"{status} {body}")

        # ---- keypair generation endpoint + upstream key_generate
        status, gen1 = client.call("POST", "/api/keys/generate",
                                   {"comment": "t"})
        status2, gen2 = client.call("POST", "/api/keys/generate",
                                    {"comment": "t"})
        check("keys/generate mints a fresh ed25519 pair per call",
              status == 200 and status2 == 200
              and "BEGIN OPENSSH PRIVATE KEY" in gen1["private_key"]
              and gen1["public_key"].startswith("ssh-ed25519 ")
              and gen1["fingerprint"].startswith("SHA256:")
              and gen1["private_key"] != gen2["private_key"], f"{status}")
        gen_stored = os.path.join(workdir, "data", "ssh_client_keys",
                                  "up-gen.key")
        status, body = client.call("POST", "/api/upstreams",
                                   {"name": "up-gen", "protocol": "ssh",
                                    "address": "10.4.4.6", "port": 22,
                                    "username": "tunnel", "key_generate": True})
        check("ssh upstream with key_generate stores a node-generated key",
              status == 201
              and body["upstream"]["key_file"] == "/keys/up-gen.key"
              and os.path.exists(gen_stored)
              and "BEGIN OPENSSH PRIVATE KEY" in open(gen_stored).read(),
              f"{status} {body}")
        status, body = client.call("POST", "/api/upstreams/up-gen/remove", {})
        check("generated upstream key removed with the upstream",
              status == 200 and not os.path.exists(gen_stored),
              f"{status} {body}")

        # ---- interconnect via settings + user rows
        status, body = client.call(
            "POST", "/api/users",
            {"username": "gina", "group": "team",
             "ssh_pubkey": SSH_PUBKEY})
        check("console adds a team user with a key", status == 201,
              f"{status} {body}")
        status, body = client.call("GET", "/api/users")
        gina = [u for u in body["users"] if u["username"] == "gina"][0]
        check("keyed add claims the first slice at once",
              gina.get("interconnect") == [20000, 20015], f"{gina}")
        status, body = client.call("POST", "/api/users",
                                   {"username": "hank", "group": "team"})
        check("console adds a keyless team user", status == 201,
              f"{status} {body}")
        status, body = client.call("GET", "/api/users")
        hank = [u for u in body["users"] if u["username"] == "hank"][0]
        check("keyless member holds no slice (dialers need none)",
              "interconnect" not in hank, f"{hank}")
        status, body = client.call("POST", "/api/users/hank/remove", {})
        check("keyless user removed again", status == 200,
              f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"vless_enabled": True})
        check("settings: vless_enabled can be switched on",
              status == 200 and body["vless_enabled"] is True,
              f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"vless_enabled": False})
        check("settings: vless_enabled back off (the default)",
              status == 200 and body["vless_enabled"] is False,
              f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"vless_enabled": True})
        check("settings: vless restored on for the render checks below",
              status == 200 and body["vless_enabled"] is True,
              f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"interconnect_off_groups": "team"})
        check("settings: interconnect opt-out stored",
              status == 200 and body["interconnect_off_groups"] == ["team"]
              and body["db_values"]["interconnect_off_groups"] == "team",
              f"{status} {body}")
        check("settings payload reports ssh_enabled true",
              body.get("ssh_enabled") is True, f"{body}")
        status, body = client.call("GET", "/api/users")
        gina = [u for u in body["users"] if u["username"] == "gina"][0]
        check("opting the group out releases the member's slice",
              "interconnect" not in gina, f"{gina}")
        status, body = client.call("POST", "/api/settings",
                                   {"interconnect_off_groups": ""})
        check("settings: opt-out cleared, default-on restored",
              status == 200 and body["interconnect_off_groups"] == [],
              f"{status} {body}")
        status, body = client.call("GET", "/api/users")
        gina = [u for u in body["users"] if u["username"] == "gina"][0]
        check("re-enabled member regains the remembered block",
              gina.get("interconnect") == [20000, 20015], f"{gina}")
        status, body = client.call("POST", "/api/settings",
                                   {"interconnect_paused_groups": "team"})
        check("settings: interconnect paused list stored",
              status == 200
              and body["interconnect_paused_groups"] == ["team"]
              and body["interconnect_paused_groups_from_db"] is True
              and body["db_values"]["interconnect_paused_groups"]
              == "team", f"{status} {body}")
        status, body = client.call("GET", "/api/users")
        gina = [u for u in body["users"] if u["username"] == "gina"][0]
        check("paused member keeps her slice in the user list"
              " (held, not usable)",
              gina.get("interconnect") == [20000, 20015], f"{gina}")
        status, body = client.call("POST", "/api/settings",
                                   {"interconnect_off_groups": "team"})
        check("conflict: closing a stored-paused group is refused"
              " and names the group",
              status == 400 and "team" in body.get("error", "")
              and "both" in body.get("error", ""), f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"interconnect_off_groups": "team",
                                    "interconnect_paused_groups": "team"})
        check("conflict: naming one group in both lists in a"
              " single write is refused too",
              status == 400 and "team" in body.get("error", ""),
              f"{status} {body}")
        status, body = client.call("GET", "/api/settings")
        check("conflicts leave both stored lists untouched",
              body["interconnect_off_groups"] == []
              and body["interconnect_paused_groups"] == ["team"],
              f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"interconnect_paused_groups": ""})
        check("settings: paused list cleared, group back on",
              status == 200
              and body["interconnect_paused_groups"] == [],
              f"{status} {body}")
        status, body = client.call("POST", "/api/users/gina/remove", {})
        check("interconnect test user removed again", status == 200,
              f"{status} {body}")
        status, body = client.call("POST", "/api/routes/1/update",
                                   {"to": "direct"})
        check("route edit applies",
              status == 200 and body.get("route", {}).get("target") == "direct",
              f"{status} {body}")

        status, body = client.call("POST", "/api/settings",
                                   {"vless_ws_paths": "/cv,/cv2"})
        check("settings: ws paths stored in db",
              status == 200 and body["vless_ws_paths"] == ["/cv", "/cv2"]
              and body["vless_ws_paths_from_db"] is True, f"{status} {body}")
        flat = json.dumps(json.load(open(config_path)))
        check("rendered config uses the db ws paths", "/cv" in flat)
        status, body = client.call("POST", "/api/settings",
                                   {"vless_ws_paths": ""})
        check("settings: clearing paths falls back to env",
              status == 200 and body["vless_ws_paths"] == ["/vless-ws"]
              and body["vless_ws_paths_from_db"] is False, f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"ss_ws_paths": "/sw,/sw2"})
        check("settings: ss-ws paths stored in db",
              status == 200 and body["ss_ws_paths"] == ["/sw", "/sw2"]
              and body["ss_ws_paths_from_db"] is True
              and body["db_values"]["ss_ws_paths"] == "/sw,/sw2",
              f"{status} {body}")
        flat = json.dumps(json.load(open(config_path)))
        check("rendered config uses the db ss-ws paths",
              '"/sw"' in flat and '"ss-ws-1"' in flat)
        status, body = client.call("POST", "/api/settings",
                                   {"ss_ws_paths": ""})
        check("settings: clearing ss-ws paths falls back to env",
              status == 200 and body["ss_ws_paths"] == ["/ss-ws"]
              and body["ss_ws_paths_from_db"] is False, f"{status} {body}")

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
        client.drop()
        status, _ = client.call("GET", "/api/users")
        check("API closed after logout", status == 401, f"got {status}")

        status, opts = client.options("login")
        assertion = auth.assertion(opts["challenge"], "localhost")
        status, body = client.verify("login", assertion)
        check("login succeeds and re-negotiates the session key",
              status == 200 and client.master is not None, f"{status} {body}")

        anon = Client()
        status, _ = anon.call("POST", "/api/cli/sessions",
                              {"client_pub": "AAAA"})
        check("minting a CLI session requires an encrypted channel",
              status == 401, f"got {status}")
        status, body, cli_client = client.mint_cli_session()
        check("in-channel ECDH mints a CLI session",
              status == 201 and bool(body.get("id"))
              and bool(body.get("server_pub")), f"{status} {body}")
        check("cli session expiry follows the 24h setting",
              abs(body.get("expires_at", 0)
                  - (time.time() + 24 * 3600)) < 120, f"{body}")
        status, _ = cli_client.call("GET", "/api/users")
        check("the CLI session key opens the API", status == 200,
              f"got {status}")
        status, body = client.call("GET", "/api/sessions")
        kinds = sorted(s["kind"] for s in body["sessions"])
        check("session list shows web + cli sessions", kinds == ["cli", "web"],
              f"{kinds}")
        cli_id = next(s["id"] for s in body["sessions"] if s["kind"] == "cli")
        status, body = client.call("POST", f"/api/sessions/{cli_id}/revoke", {})
        check("revoke cli session by id", status == 200, f"{status} {body}")
        status, _ = cli_client.call("GET", "/api/users")
        check("revoked session key is rejected", status == 401, f"got {status}")
        status, body = client.call("POST", "/api/sessions/revoke-others", {})
        check("revoke-others keeps the current session",
              status == 200 and body["revoked_others"] == 0, f"{status} {body}")

        status, body = client.verify("login", assertion)
        check("assertion replay rejected", status in (400, 401), f"got {status}")

        impostor = Authenticator()
        impostor.cred_id = auth.cred_id  # right id, wrong key
        status, opts = client.options("login")
        status, body = client.verify(
            "login", impostor.assertion(opts["challenge"], "localhost"))
        check("wrong-key assertion rejected", status == 401, f"got {status}")

        # --- full surface: state, lists, remaining user/upstream/route
        # actions, remaining settings keys, standalone apply, console page
        status, body = client.call("GET", "/api/state")
        check("state endpoint reports counts + restart channel",
              status == 200 and body.get("enabled_users") == 1
              and body.get("enabled_upstreams") == 1
              and body.get("enabled_routes") == 1
              and body.get("restart_via") is None, f"{status} {body}")

        status, body = client.call("GET", "/api/users")
        check("users list shows alice's fields",
              status == 200
              and [u["username"] for u in body["users"]] == ["alice"]
              and body["users"][0]["note"] == "primary", f"{status} {body}")

        dave_key = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDaveTestKey"
                    "0123456789abcdef0123456789abcdef01234567 dave@test")
        status, body = client.call("POST", "/api/users",
                                   {"username": "dave", "group": "intl",
                                    "note": "second", "ssh_pubkey": dave_key})
        check("add user with group/note/ssh key",
              status == 201 and body["user"]["group"] == "intl"
              and body["user"]["note"] == "second"
              and body["user"]["ssh_key"] is True, f"{status} {body}")
        check("user dict carries the ssh key fingerprint",
              body["user"].get("ssh_fingerprint")
              == admin_mod.users_mod.pubkey_fingerprint(dave_key),
              f"{body}")
        dave_pw = body["user"]["password"]
        status, body = client.call("POST", "/api/users/dave/passwd", {})
        check("passwd rotates the shared password",
              status == 200 and body["user"]["password"] != dave_pw,
              f"{status} {body}")
        status, body = client.call("POST", "/api/users/dave/setgroup",
                                   {"group": "backup"})
        check("setgroup applies", status == 200
              and body["user"]["group"] == "backup", f"{status} {body}")
        status, body = client.call("POST", "/api/users/dave/setkey",
                                   {"ssh_pubkey": dave_key})
        check("setkey stores the key", status == 200
              and body["user"]["ssh_pubkey"] == dave_key, f"{status} {body}")
        status, body = client.call("POST", "/api/users/dave/setkey",
                                   {"ssh_pubkey": ""})
        check("setkey with empty clears the key",
              status == 200 and body["user"]["ssh_key"] is False,
              f"{status} {body}")
        status, body = client.call("POST", "/api/users/dave/setnote",
                                   {"note": ""})
        check("setnote with empty clears the note",
              status == 200 and body["user"]["note"] is None, f"{status} {body}")
        status, body = client.call("POST", "/api/users/dave/disable", {})
        check("disable user", status == 200
              and body["user"]["enabled"] is False, f"{status} {body}")
        status, body = client.call("POST", "/api/users/dave/enable", {})
        check("enable user", status == 200
              and body["user"]["enabled"] is True, f"{status} {body}")
        status, body = client.call("POST", "/api/users/dave/remove", {})
        check("remove user", status == 200, f"{status} {body}")
        status, body = client.call("GET", "/api/users")
        check("removed user leaves the list",
              [u["username"] for u in body["users"]] == ["alice"], f"{body}")

        status, body = client.call("GET", "/api/upstreams")
        check("upstreams list shows up-a",
              status == 200
              and [u["name"] for u in body["upstreams"]] == ["up-a"],
              f"{status} {body}")
        status, _ = client.call("POST", "/api/upstreams/up-a/disable", {})
        status2, body = client.call("GET", "/api/upstreams")
        check("disable upstream", status == 200
              and body["upstreams"][0]["enabled"] is False,
              f"{status} {status2} {body}")
        status, _ = client.call("POST", "/api/upstreams/up-a/enable", {})
        status2, body = client.call("GET", "/api/upstreams")
        check("enable upstream", status == 200
              and body["upstreams"][0]["enabled"] is True,
              f"{status} {status2} {body}")
        status, body = client.call("POST", "/api/upstreams/up-a/remove", {})
        check("remove upstream", status == 200, f"{status} {body}")
        status, body = client.call("GET", "/api/upstreams")
        check("upstreams list empty after remove", body["upstreams"] == [],
              f"{body}")

        status, body = client.call("GET", "/api/routes")
        check("routes list shows the route",
              status == 200 and len(body["routes"]) == 1
              and body["routes"][0]["target"] == "direct", f"{status} {body}")
        rid = body["routes"][0]["id"]
        status, _ = client.call("POST", f"/api/routes/{rid}/disable", {})
        status2, body = client.call("GET", "/api/routes")
        check("disable route", status == 200
              and body["routes"][0]["enabled"] is False,
              f"{status} {status2} {body}")
        status, _ = client.call("POST", f"/api/routes/{rid}/enable", {})
        status2, body = client.call("GET", "/api/routes")
        check("enable route", status == 200
              and body["routes"][0]["enabled"] is True,
              f"{status} {status2} {body}")
        status, body = client.call("POST", "/api/routes",
                                   {"kind": "ip", "pattern": "203.0.113.7",
                                    "to": "pool", "username": "alice"})
        check("add user-scoped route", status == 201
              and body["route"]["username"] == "alice", f"{status} {body}")
        status, body = client.call(
            "POST", f"/api/routes/{body['route']['id']}/remove", {})
        check("remove route", status == 200, f"{status} {body}")
        status, body = client.call("GET", "/api/routes")
        check("routes list back to one after remove",
              len(body["routes"]) == 1, f"{body}")

        status, body = client.call("POST", "/api/settings",
                                   {"trojan_ws_paths": "/tj,/tj2",
                                    "upstream_strategy": "leastPing",
                                    "ss_method": "aes-128-gcm",
                                    "direct_allow_private": True})
        check("settings: remaining keys stored",
              status == 200 and body["trojan_ws_paths"] == ["/tj", "/tj2"]
              and body["upstream_strategy"] == "leastPing"
              and body["ss_method"] == "aes-128-gcm"
              and body["direct_allow_private"] is True, f"{status} {body}")
        status, body = client.call("GET", "/api/settings")
        check("settings: remaining keys read back",
              status == 200 and body["trojan_ws_paths"] == ["/tj", "/tj2"]
              and body["upstream_strategy"] == "leastPing", f"{status} {body}")
        status, _ = client.call("POST", "/api/settings",
                                {"upstream_strategy": "bogus"})
        check("settings rejects a bogus strategy", status == 400,
              f"got {status}")
        status, body = client.call("POST", "/api/settings",
                                   {"direct_allow_private": False})
        check("settings: direct_allow_private back off",
              status == 200 and body["direct_allow_private"] is False,
              f"{status} {body}")

        status, body = client.call("GET", "/api/settings")
        check("settings: reality off by default, client parameters ready",
              status == 200 and body["reality_enabled"] is False
              and body["reality_dest"] == "www.microsoft.com:443"
              and body["reality_server_names"] == ["www.microsoft.com"]
              and len(body["reality_short_ids"]) == 1
              and len(body["reality_short_ids"][0]) == 8
              and len(body["reality_public_key"]) == 43,
              f"{status} {body}")
        with sqlite3.connect(db_path) as raw:
            priv = raw.execute("SELECT value FROM admin_settings"
                               " WHERE key = 'reality_private_key'"
                               ).fetchone()[0]
        check("settings: reality private key never leaves the node",
              len(priv) == 43 and priv not in json.dumps(body)
              and "reality_private_key" not in json.dumps(body),
              "private key leaked into the settings response")
        status, body = client.call("POST", "/api/settings",
                                   {"reality_dest": "www.apple.com:443",
                                    "reality_server_names": "www.apple.com",
                                    "reality_short_ids": "0123abcd,eeff"})
        check("settings: reality dest/names/short ids stored",
              status == 200 and body["reality_dest"] == "www.apple.com:443"
              and body["reality_server_names"] == ["www.apple.com"]
              and body["reality_short_ids"] == ["0123abcd", "eeff"],
              f"{status} {body}")
        status, _ = client.call("POST", "/api/settings",
                                {"reality_dest": "no-port-here"})
        check("settings rejects a reality dest without a port",
              status == 400, f"got {status}")
        status, _ = client.call("POST", "/api/settings",
                                {"reality_short_ids": "xyz"})
        check("settings rejects a non-hex reality short id",
              status == 400, f"got {status}")
        status, _ = client.call("POST", "/api/settings",
                                {"reality_enabled": "yes"})
        check("settings rejects a non-boolean reality_enabled",
              status == 400, f"got {status}")
        status, before = client.call("GET", "/api/settings")
        old_pub = before["reality_public_key"]
        status, body = client.call("POST", "/api/settings",
                                   {"reality_rotate_key": True})
        check("settings: reality key rotation returns a fresh public key",
              status == 200 and len(body["reality_public_key"]) == 43
              and body["reality_public_key"] != old_pub,
              f"{status} {body}")
        with sqlite3.connect(db_path) as raw:
            priv2 = raw.execute("SELECT value FROM admin_settings"
                                " WHERE key = 'reality_private_key'"
                                ).fetchone()[0]
        check("settings: rotated private key stays off the wire too",
              priv2 != priv and priv2 not in json.dumps(body),
              "rotated private key leaked into the settings response")
        status, body = client.call("POST", "/api/settings",
                                   {"reality_enabled": False})
        check("settings: reality can be switched off",
              status == 200 and body["reality_enabled"] is False,
              f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"reality_enabled": True,
                                    "reality_dest": "",
                                    "reality_server_names": "",
                                    "reality_short_ids": ""})
        check("settings: reality restored, overrides cleared to defaults",
              status == 200 and body["reality_enabled"] is True
              and body["reality_dest"] == "www.microsoft.com:443"
              and body["reality_server_names"] == ["www.microsoft.com"]
              and len(body["reality_short_ids"]) == 1,
              f"{status} {body}")

        status, body = client.call("POST", "/api/apply", {})
        check("standalone apply endpoint (nothing pending)",
              status == 200 and body["applied"]["changed"] == []
              and body["applied"]["restart_skipped"] is False,
              f"{status} {body}")

        # VMess settings + the bare-form toggles through the API: the
        # paths store like the other families, the switches default
        # off, and an apply renders each bare inbound only while on.
        status, body = client.call("GET", "/api/settings")
        check("settings: vmess paths + bare toggles default off",
              status == 200 and body["vmess_ws_paths"] == ["/vmess-ws"]
              and body["vmess_tcp_enabled"] is False
              and body["ss_tcp_enabled"] is False
              and body["http_enabled"] is False, f"{status} {body}")
        status, body = client.call("POST", "/api/settings",
                                   {"vmess_ws_paths": "/vm1,/vm2",
                                    "vmess_tcp_enabled": True,
                                    "ss_tcp_enabled": True,
                                    "http_enabled": True})
        check("settings: vmess paths + bare toggles stored",
              status == 200 and body["vmess_ws_paths"] == ["/vm1", "/vm2"]
              and body["vmess_tcp_enabled"] is True
              and body["ss_tcp_enabled"] is True
              and body["http_enabled"] is True, f"{status} {body}")
        status, body = client.call("POST", "/api/apply", {})
        rendered = json.load(open(config_path))
        atags = [i["tag"] for i in rendered["inbounds"]]
        apaths = sorted(i["streamSettings"]["wsSettings"]["path"]
                        for i in rendered["inbounds"]
                        if i["tag"].startswith("vmess-ws-"))
        check("apply renders the enabled bare forms + db vmess paths",
              status == 200 and "vmess" in atags and "ss" in atags
              and "http-in" in atags and apaths == ["/vm1", "/vm2"],
              f"{status} {atags} {apaths}")
        status, body = client.call("POST", "/api/settings",
                                   {"vmess_ws_paths": "",
                                    "vmess_tcp_enabled": False,
                                    "ss_tcp_enabled": False,
                                    "http_enabled": False})
        check("settings: bare toggles back off, paths cleared",
              status == 200 and body["vmess_tcp_enabled"] is False
              and body["vmess_ws_paths"] == ["/vmess-ws"],
              f"{status} {body}")
        status, body = client.call("POST", "/api/apply", {})
        rendered = json.load(open(config_path))
        atags = [i["tag"] for i in rendered["inbounds"]]
        check("apply drops the bare forms again once switched off",
              status == 200 and "vmess" not in atags
              and "ss" not in atags and "http-in" not in atags
              and "vmess-ws-0" in atags, f"{status} {atags}")

        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        conn.request("GET", "/")
        resp = conn.getresponse()
        page = resp.read().decode("utf-8", "replace")
        conn.close()
        check("console page carries the copyable CLI install command",
              resp.status == 200
              and "raw.githubusercontent" not in page
              and "/cli/xmagic.py" in page
              and 'id="cli-install"' in page
              and 'id="btn-copy-install"' in page
              and 'id="cli-onboard"' in page, f"status {resp.status}")

        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        conn.request("GET", "/cli/xmagic.py")
        resp = conn.getresponse()
        served = resp.read()
        served_sha = resp.getheader("X-Xmagic-Cli-Sha256")
        conn.close()
        bundled = open(os.path.join(ROOT, "xmagic.py"), "rb").read()
        check("node serves its bundled CLI publicly, byte for byte",
              resp.status == 200 and served == bundled
              and served_sha == hashlib.sha256(bundled).hexdigest(),
              f"status {resp.status} bytes {len(served)}/{len(bundled)}")

        check("console page carries the keypair-generate buttons and the "
              "interconnect setting",
              'id="btn-gen-userkey"' in page
              and 'id="btn-gen-upkey"' in page
              and 'name="interconnect_off_groups"' in page
              and 'id="interconnect-ssh-note"' in page
              and "本节点未启用 SSH，组内互访不可用" in page
              and "icInput.disabled = !on" in page
              and 'name="vless_enabled"' in page
              and 'name="reality_enabled"' in page
              and 'name="reality_dest"' in page
              and 'name="reality_server_names"' in page
              and 'name="reality_short_ids"' in page
              and 'name="reality_public_key"' in page
              and 'id="btn-reality-rotate"' in page
              and 'name="ss_ws_paths"' in page
              and 'name="vmess_ws_paths"' in page
              and 'name="vmess_tcp_enabled"' in page
              and 'name="ss_tcp_enabled"' in page
              and 'name="http_enabled"' in page
              and 'data-proto="vless-ws trojan-ws ss vmess-ws"' in page
              and 'data-proto="vless-ws vless trojan-ws ss vmess-ws vmess"'
                  in page
              and "组内互访端口" in page
              and "公网 SOCKS5 默认关闭" in page
              and '<select name="method"' in page
              and "buildUpProtoOptions" in page
              and "genUserKeypair" in page
              and "crypto.subtle" in page
              and "checkChallengeBinding" in page
              and "sealEnvelope" in page
              and "localStorage" in page
              and 'id="up-add-btns"' in page
              and 'data-up-tab="list"' in page
              and 'id="up-form-tab"' in page
              and 'data-user-tab="list"' in page
              and 'id="user-form-tab"' in page
              and "data-add-user" in page
              and "（未启用）" in page,
              f"status {resp.status}")

        # --- CLI-issued passkey replacement (ticket flow): the ticket
        # is issued by one session, the ceremony runs in a browser, and
        # exactly those two sessions survive the credential swap
        anon2 = Client()
        status, _ = anon2.call("POST", "/api/cli-replace-ticket", {})
        check("replace ticket requires auth", status == 401, f"got {status}")
        other = Client()
        status, opts = other.options("login")
        status, _ = other.verify(
            "login", auth.assertion(opts["challenge"], "localhost"))
        check("second web session established", status == 200, f"{status}")
        _, _, initiator = client.mint_cli_session(label="initiator-cli")
        status, body = initiator.call("POST", "/api/cli-replace-ticket", {})
        ticket = body.get("ticket")
        check("CLI session can issue a replace ticket",
              status == 200 and bool(ticket), f"{status} {body}")
        status, body = initiator.call("POST", "/api/cli-replace-status",
                                      {"ticket": ticket})
        check("ticket starts not-done",
              status == 200 and body["done"] is False, f"{status} {body}")
        status, _ = client.options_at("/api/cli-replace-options",
                                      {"ticket": "bogus"})
        check("replace options reject a bogus ticket", status == 400,
              f"got {status}")
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        conn.request("GET", "/cli-replace?ticket=x")
        resp = conn.getresponse()
        page = resp.read().decode("utf-8", "replace")
        conn.close()
        check("replace ceremony page is served",
              resp.status == 200 and "更换管理员 Passkey" in page,
              f"status {resp.status}")
        auth_new = Authenticator()
        status, opts = client.options_at("/api/cli-replace-options",
                                         {"ticket": ticket})
        check("replace options issued", status == 200 and "challenge" in opts,
              f"{status}")
        status, body = client.verify_at(
            "/api/cli-replace-verify",
            dict(auth_new.attestation(opts["challenge"], "localhost"),
                 ticket=ticket))
        check("CLI-ticket passkey replacement succeeds",
              status == 200, f"{status} {body}")
        status, body = initiator.call("POST", "/api/cli-replace-status",
                                      {"ticket": ticket})
        check("ticket reports done after the ceremony",
              status == 200 and body["done"] is True, f"{status} {body}")
        status, _ = initiator.call("GET", "/api/users")
        check("initiating CLI session survives replacement",
              status == 200, f"got {status}")
        status, _ = other.call("GET", "/api/users")
        check("unrelated web session is revoked by replacement",
              status == 401, f"got {status}")
        status, _ = client.call("GET", "/api/users")
        check("performing browser session survives (fresh session key)",
              status == 200, f"got {status}")
        status, opts = client.options("login")
        status, _ = client.verify(
            "login", auth.assertion(opts["challenge"], "localhost"))
        check("old passkey dead after CLI-ticket replacement",
              status in (400, 401), f"got {status}")
        status, opts = client.options("login")
        status, _ = client.verify(
            "login", auth_new.assertion(opts["challenge"], "localhost"))
        check("new passkey logs in after CLI-ticket replacement",
              status == 200, f"got {status}")

        # --- admin passkey replacement while authenticated ---
        victim = Client()
        status, opts = victim.options("login")
        status, _ = victim.verify(
            "login", auth_new.assertion(opts["challenge"], "localhost"))
        check("bystander session established before replacement",
              status == 200, f"{status}")
        auth2 = Authenticator()
        status, opts = client.options("register")
        check("authed admin may start a passkey replacement",
              status == 200 and "challenge" in opts, f"{status}")
        status, body = client.verify(
            "register", auth2.attestation(opts["challenge"], "localhost"))
        check("passkey replacement succeeds", status == 200, f"{status} {body}")
        status, body = client.call("GET", "/api/sessions")
        check("replacement revokes every other session",
              status == 200 and len(body["sessions"]) == 1
              and body["sessions"][0]["current"] is True, f"{status} {body}")
        status, _ = victim.call("GET", "/api/users")
        check("pre-replacement session is dead", status == 401, f"got {status}")
        status, opts = client.options("login")
        status, body = client.verify(
            "login", auth.assertion(opts["challenge"], "localhost"))
        check("old passkey no longer logs in", status in (400, 401),
              f"got {status}")
        status, opts = client.options("login")
        status, body = client.verify(
            "login", auth2.assertion(opts["challenge"], "localhost"))
        check("new passkey logs in", status == 200, f"{status} {body}")

        proc = subprocess.run([sys.executable, os.path.join(ROOT, "users.py"),
                               "admin-reset"],
                              env=dict(os.environ, PROXY_DB=db_path),
                              capture_output=True, text=True)
        check("users.py admin-reset works", proc.returncode == 0, proc.stderr[-200:])
        fresh = Client()
        status, body = fresh.call("GET", "/api/status")
        check("setup reopens after admin-reset", body["registered"] is False)

        # -------------------------------------- ssh off by default
        # A node started without XMAGIC_ENABLE_SSH refuses every
        # SSH-shaped operation; the rest of the API is unaffected.
        workdir2 = tempfile.mkdtemp(prefix="xmagic-admin-sshoff-")
        env2 = dict(os.environ,
                    PROXY_DB=os.path.join(workdir2, "data", "users.db"),
                    XMAGIC_ADMIN_BIND="127.0.0.1",
                    XMAGIC_ADMIN_PORT=str(PORT + 7),
                    XMAGIC_DOCKER_SOCK="/nonexistent.sock")
        server2 = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "admin.py")],
            env=env2, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            c2 = Client(port=PORT + 7)
            for _ in range(50):
                try:
                    c2.call("GET", "/api/status")
                    break
                except OSError:
                    time.sleep(0.2)
            auth_off = Authenticator()
            origin2 = f"http://localhost:{PORT + 7}"
            status, opts = c2.options("register")
            status, body = c2.verify(
                "register",
                auth_off.attestation(opts["challenge"], "localhost",
                                     origin2))
            check("ssh-off node: registration still works",
                  status == 200, f"{status} {body}")
            status, body = c2.call("GET", "/api/users")
            check("ssh-off node: users payload reports ssh_enabled false",
                  body.get("ssh_enabled") is False, f"{body}")
            status, body = c2.call("GET", "/api/settings")
            check("ssh-off node: settings payload reports ssh_enabled false",
                  status == 200 and body.get("ssh_enabled") is False,
                  f"{status} {body}")
            status, body = c2.call("POST", "/api/settings",
                                   {"interconnect_off_groups": "team"})
            check("ssh-off node: interconnect opt-out still stored",
                  status == 200
                  and body.get("interconnect_off_groups") == ["team"],
                  f"{status} {body}")
            status, body = c2.call("POST", "/api/settings",
                                   {"interconnect_off_groups": ""})
            check("ssh-off node: interconnect opt-out cleared again",
                  status == 200
                  and body.get("interconnect_off_groups") == [],
                  f"{status} {body}")
            conn = http.client.HTTPConnection("127.0.0.1", PORT + 7,
                                              timeout=10)
            conn.request("GET", "/")
            resp = conn.getresponse()
            page2 = resp.read().decode("utf-8", "replace")
            conn.close()
            check("ssh-off node: console page carries the interconnect"
                  " ssh note and the disabling logic",
                  resp.status == 200
                  and 'id="interconnect-ssh-note"' in page2
                  and "本节点未启用 SSH，组内互访不可用" in page2
                  and "icInput.disabled = !on" in page2,
                  f"status {resp.status}")
            status, _ = c2.call("POST", "/api/keys/generate", {})
            check("ssh-off node: keys/generate refused",
                  status == 400, f"got {status}")
            status, _ = c2.call("POST", "/api/users",
                                {"username": "ned",
                                 "ssh_pubkey": "ssh-ed25519 AAAA"})
            check("ssh-off node: add user with an ssh key refused",
                  status == 400, f"got {status}")
            status, _ = c2.call("POST", "/api/users",
                                {"username": "ned"})
            check("ssh-off node: add user without a key works",
                  status == 201, f"got {status}")
            status, _ = c2.call("POST", "/api/users/ned/setkey",
                                {"ssh_pubkey": "ssh-ed25519 AAAA"})
            check("ssh-off node: setkey refused",
                  status == 400, f"got {status}")
            status, _ = c2.call("POST", "/api/upstreams",
                                {"name": "upoff", "address": "10.9.9.9",
                                 "port": 22, "protocol": "ssh",
                                 "username": "proxy",
                                 "key_file": "/keys/x.key"})
            check("ssh-off node: ssh upstream refused",
                  status == 400, f"got {status}")

            # ---- interconnect capacity: the limit is on slices
            # HELD. 100 keyed holders of group "capped" are seeded
            # directly (user rows + allocation rows); ned is keyless
            # and holds nothing.
            raw = sqlite3.connect(os.path.join(workdir2, "data",
                                               "users.db"))
            for i in range(1, 101):
                name = f"cap{i:03d}"
                raw.execute(
                    "INSERT INTO users (username, vless_uuid,"
                    " trojan_password, ss_password, ss_method,"
                    " ssh_pubkey, upstream_group, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (name, f"uuid-{i}", "pw", "pw", "aes-256-gcm",
                     f"ssh-ed25519 AAAA {name}", "capped",
                     f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}"
                     ".000000+00:00"))
                lo = 20000 + (i - 1) * 16
                raw.execute(
                    "INSERT INTO interconnect_allocations (username,"
                    " port_lo, port_hi) VALUES (?,?,?)",
                    (name, lo, lo + 15))
            raw.commit()
            raw.close()
            # (This node has SSH off, so keyed members are seeded as
            # data rows; the API paths exercised below - settings
            # transitions, disable, list - are the ones that run.)
            status, body = c2.call("POST", "/api/users",
                                   {"username": "user102",
                                    "group": "capped"})
            check("capacity: keyless add allowed past 100 users",
                  status == 201, f"{status} {body}")
            # quantified, atomic turn-on refusal: group "late" has two
            # keyed members; exactly one block is free.
            raw = sqlite3.connect(os.path.join(workdir2, "data",
                                               "users.db"))
            for late_user, day in (("late2", "01"), ("late3", "02")):
                raw.execute(
                    "INSERT INTO users (username, vless_uuid,"
                    " trojan_password, ss_password, ss_method,"
                    " ssh_pubkey, upstream_group, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (late_user, f"uuid-{late_user}", "pw", "pw",
                     "aes-256-gcm", f"ssh-ed25519 AAAA {late_user}",
                     "late", f"2026-02-{day}T00:00:00.000000+00:00"))
            raw.commit()
            raw.close()
            status, body = c2.call("POST", "/api/settings",
                                   {"interconnect_off_groups": "late"})
            check("capacity: opt a fresh group out", status == 200,
                  f"{status} {body}")
            status, _ = c2.call("POST", "/api/users/cap002/disable", {})
            check("capacity: free exactly one block", status == 200,
                  f"got {status}")
            status, body = c2.call("POST", "/api/settings",
                                   {"interconnect_off_groups": ""})
            check("capacity: turn-on refusal is quantified (N, free M,"
                  " shortfall, unserved names)",
                  status == 400
                  and "cannot enable interconnect for group 'late'"
                  in body.get("error", "")
                  and "2 member(s) need a port slice (16 ports each,"
                      " 32 ports in total)" in body.get("error", "")
                  and "only 1 free block(s) (16 ports)"
                  in body.get("error", "")
                  and "short 1 block(s) (16 ports)"
                  in body.get("error", "")
                  and "cannot be served: late3" in body.get("error", "")
                  and body.get("code")
                  == "interconnect_insufficient_ports"
                  and body.get("needed_count") == 2
                  and body.get("free_blocks") == 1
                  and body.get("users_without_ports") == ["late3"],
                  f"{status} {body}")
            status, body = c2.call("GET", "/api/settings")
            check("capacity: refused turn-on leaves the stored opt-out"
                  " untouched",
                  status == 200
                  and body["interconnect_off_groups"] == ["late"],
                  f"{status} {body}")
            status, body = c2.call("GET", "/api/users")
            rows2 = {u["username"]: u for u in body["users"]}
            check("capacity: refusal is atomic - neither waiting"
                  " member claimed a slice",
                  "interconnect" not in rows2["late2"]
                  and "interconnect" not in rows2["late3"],
                  f"{rows2.get('late2')} {rows2.get('late3')}")
            status, _ = c2.call("POST", "/api/users/cap003/disable", {})
            check("capacity: free one more block", status == 200,
                  f"got {status}")
            status, body = c2.call("POST", "/api/settings",
                                   {"interconnect_off_groups": ""})
            check("capacity: turn-on succeeds once both fit",
                  status == 200 and body["interconnect_off_groups"] == [],
                  f"{status} {body}")
            status, body = c2.call("GET", "/api/users")
            rows2 = {u["username"]: u for u in body["users"]}
            check("capacity: both members claimed lowest-free in order",
                  rows2["late2"].get("interconnect") == [20016, 20031]
                  and rows2["late3"].get("interconnect")
                  == [20032, 20047],
                  f"{rows2.get('late2')} {rows2.get('late3')}")
            status, body = c2.call("GET", "/api/settings")
            check("capacity: settings payload summary matches the"
                  " table (98 seeded holders left + 2 new claims)",
                  status == 200
                  and body.get("interconnect_capacity") == {
                      "total_blocks": 100, "claimed_blocks": 100,
                      "free_blocks": 0}, f"{status} {body}")
        finally:
            server2.terminate()
    finally:
        server.terminate()
        out = server.stdout.read() if server.stdout else ""
        if FAIL:
            print("\n--- server log tail ---\n" + "\n".join(out.splitlines()[-15:]))
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
