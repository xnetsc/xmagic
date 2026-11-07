#!/usr/bin/env python3
"""CLI parity test: every admin-console function must work from users.py.

Also proves the two frontends share one engine: users created through
the CLI show up in the web console and vice versa, and `apply` from the
CLI renders the same files the console renders.

Run: python3 tests/test_cli.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_admin as t  # noqa: E402  (Authenticator + Client + check helpers)

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""))


def main():
    workdir = tempfile.mkdtemp(prefix="xmagic-cli-test-")
    db_path = os.path.join(workdir, "data", "users.db")
    env = dict(os.environ, PROXY_DB=db_path, XMAGIC_DOCKER_SOCK="/nonexistent.sock")
    users_py = os.path.join(ROOT, "users.py")

    def cli(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, out, _ = cli("init")
    check("init", rc == 0)
    rc, out, _ = cli("add", "alice")
    check("add prints credentials once", rc == 0 and "vless uuid:" in out, out)
    rc, out, err = cli("--json", "add", "bob")
    try:
        bob = json.loads(out)
    except ValueError:
        bob = {}
    check("--json add emits parseable credentials",
          rc == 0 and bool(bob.get("vless_uuid")) and bool(bob.get("password")), err)
    rc, out, _ = cli("--json", "list")
    names = [u["username"] for u in json.loads(out)]
    check("--json list shows both users", names == ["alice", "bob"], out)
    rc, _, _ = cli("upstream-add", "up1", "--proto", "ss", "--addr", "10.0.0.9",
                   "--port", "8388", "--password", "pw")
    check("upstream-add", rc == 0)
    rc, out, _ = cli("--json", "route-add", "--kind", "domain",
                     "--pattern", "example.com", "--to", "block")
    check("--json route-add", rc == 0 and json.loads(out)["pattern"] == "example.com")
    rc, out, _ = cli("status")
    check("status (human)", rc == 0 and "users: 2/2 enabled" in out, out)
    rc, out, _ = cli("--json", "status")
    st = json.loads(out)
    check("--json status", st["users_enabled"] == 2 and st["admin_registered"] is False)
    rc, out, err = cli("apply")
    config_path = os.path.join(workdir, "data", "config.json")
    flat = open(config_path).read() if os.path.exists(config_path) else ""
    check("apply renders config with CLI users",
          rc == 0 and "applied:" in out and bob.get("vless_uuid", "?") in flat, err)
    rc, out, _ = cli("--json", "apply")
    check("--json apply reports restart skipped",
          json.loads(out)["restart_skipped"] is True)
    rc, out, _ = cli("--json", "settings")
    check("settings default 168h", json.loads(out)["session_ttl_hours"] == 168, out)
    rc, out, _ = cli("settings", "--session-ttl-hours", "48")
    check("settings set via CLI", rc == 0 and "48" in out, out)
    rc, out, _ = cli("--json", "settings")
    check("settings persisted", json.loads(out)["session_ttl_hours"] == 48, out)
    rc, _, _ = cli("settings", "--session-ttl-hours", "0")
    check("settings rejects 0h", rc != 0)

    # ---- edits + the rest of the user surface + render-level settings
    rc, out, _ = cli("--json", "upstream-edit", "up1", "--port", "9999")
    check("--json upstream-edit", rc == 0 and json.loads(out)["port"] == 9999, out)
    rc, out, _ = cli("--json", "route-edit", "1", "--to", "direct")
    check("--json route-edit", rc == 0 and json.loads(out)["target"] == "direct", out)
    rc, _, err = cli("rotate-uuid", "alice")
    check("rotate-uuid via node CLI", rc == 0, err)
    rc, _, err = cli("setmethod", "alice", "chacha20-ietf-poly1305")
    check("setmethod via node CLI", rc == 0, err)
    rc, _, err = cli("setnote", "alice", "via cli")
    check("setnote via node CLI", rc == 0, err)
    rc, _, err = cli("setkey", "alice", "--clear")
    check("setkey --clear via node CLI", rc == 0, err)
    rc, out, _ = cli("settings", "--vless-ws-paths", "/x1,/x2")
    check("settings paths set via CLI", rc == 0 and "/x1" in out, out)
    rc, out, _ = cli("--json", "settings")
    check("settings --json shows db paths",
          json.loads(out)["vless_ws_paths"] == ["/x1", "/x2"], out)
    rc, out, err = cli("apply")
    check("apply renders db ws paths + new ss method",
          rc == 0 and "/x1" in open(config_path).read()
          and "chacha20-ietf-poly1305" in open(config_path).read(), err)

    # ---- parity: same DB through the web console
    server_env = dict(env, XMAGIC_ADMIN_BIND="127.0.0.1",
                      XMAGIC_ADMIN_PORT=str(t.PORT), XMAGIC_ADMIN_RPID="localhost")
    server = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "admin.py")],
        env=server_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        client = t.Client()
        for _ in range(50):
            try:
                client.call("GET", "/api/status")
                break
            except OSError:
                time.sleep(0.2)
        auth = t.Authenticator()
        _, opts = client.call("POST", "/api/register/options", {})
        status, body = client.call("POST", "/api/register/verify",
                                   auth.attestation(opts["challenge"], "localhost"))
        check("console registration on CLI-built DB", status == 200, f"{status} {body}")
        _, body = client.call("GET", "/api/users")
        web_names = sorted(u["username"] for u in body["users"])
        check("CLI users visible in console", web_names == ["alice", "bob"], str(web_names))
        status, body = client.call("POST", "/api/users", {"username": "carol"})
        check("console adds a user", status == 201, f"{status} {body}")
    finally:
        server.terminate()
    rc, out, _ = cli("--json", "list")
    names = [u["username"] for u in json.loads(out)]
    check("console user visible in CLI", names == ["alice", "bob", "carol"], out)
    # ---- direct-to-private (LAN) egress opt-in: default off, and the
    # render only gains freedom finalRules when the operator turns it on
    cfg_path = os.path.join(workdir, "data", "config.json")
    rc, out, _ = cli("--json", "settings")
    check("direct_allow_private defaults off",
          json.loads(out)["direct_allow_private"] is False, out)
    rc, out, _ = cli("render", "--out", cfg_path)
    cfg = json.load(open(cfg_path))
    direct = [o for o in cfg["outbounds"] if o.get("tag") == "direct"][0]
    check("default render has no finalRules (xray blocks private targets)",
          "settings" not in direct, json.dumps(direct))
    rc, out, _ = cli("settings", "--direct-allow-private", "on")
    check("settings enable direct_allow_private via CLI",
          rc == 0 and "True" in out, out)
    rc, out, _ = cli("render", "--out", cfg_path)
    cfg = json.load(open(cfg_path))
    direct = [o for o in cfg["outbounds"] if o.get("tag") == "direct"][0]
    rules = direct.get("settings", {}).get("finalRules", [])
    check("render emits the allow finalRule when enabled",
          len(rules) == 1 and rules[0]["action"] == "allow"
          and "127.0.0.0/8" in rules[0]["ip"], json.dumps(direct))
    rc, out, _ = cli("settings", "--direct-allow-private", "off")
    check("settings disable direct_allow_private via CLI",
          rc == 0 and "False" in out, out)

    rc, out, _ = cli("--json", "status")
    check("status shows registered admin", json.loads(out)["admin_registered"] is True)
    rc, out, _ = cli("--json", "sessions")
    rows = json.loads(out)
    check("CLI lists the console's sessions",
          rc == 0 and len(rows) >= 1 and rows[0]["kind"] == "web", out)
    if rows:
        rc, out, _ = cli("sessions-revoke", rows[0]["id"])
        check("CLI revokes a session by id", rc == 0 and "revoked" in out, out)
    rc, out, _ = cli("sessions-revoke-all")
    check("CLI revoke-all", rc == 0 and "revoked" in out, out)
    rc, out, _ = cli("admin-reset")
    check("admin-reset", rc == 0 and "cleared" in out, out)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
