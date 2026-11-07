#!/usr/bin/env python3
"""End-to-end test of the xmagic remote CLI (xmagic.py).

Two admin servers stand in for two nodes. A simulated browser performs
the Passkey ceremonies (software authenticator from test_admin) against
each node's /cli-auth handoff, so the real login path - loopback
callback, one-time code, code exchange, session file - is exercised
exactly as an operator's browser would drive it. Then: node registry,
per-node sessions, --session-file selection, argument-over-config
precedence, settings round-trip, and the effective session TTL.

Run: python3 tests/test_client.py
"""
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_admin import Authenticator  # noqa: E402

PASS, FAIL = [], []
PORT_A, PORT_B = 18101, 18102


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""))


class Browser:
    """Cookie-aware HTTP client standing in for the operator's browser."""

    def __init__(self, port):
        self.port = port
        self.cookie = None

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json",
                   "Origin": f"http://localhost:{self.port}"}
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


def start_server(port, workdir):
    env = dict(os.environ,
               PROXY_DB=os.path.join(workdir, "data", "users.db"),
               XMAGIC_ADMIN_BIND="127.0.0.1", XMAGIC_ADMIN_PORT=str(port),
               XMAGIC_ADMIN_RPID="localhost", XMAGIC_DOCKER_SOCK="/nonexistent.sock")
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "admin.py")],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    browser = Browser(port)
    for _ in range(50):
        try:
            browser.call("GET", "/api/status")
            return proc, browser
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"server on {port} did not come up")


def drive_login(cli_home, port, auth, extra_args=()):
    """Run `xmagic login --no-browser`, play the browser, return the proc result."""
    env = dict(os.environ, XMAGIC_HOME=cli_home)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "xmagic.py"), "login", "--no-browser",
         *extra_args],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    url = None
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        if line.startswith("http"):
            url = line.strip()
            break
    if url is None:
        out, err = proc.communicate()
        raise RuntimeError(f"login printed no URL: {out} {err}")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    callback, state = query["callback"][0], query["state"][0]
    browser = Browser(port)
    status, _ = browser.call("GET", f"/cli-auth?callback="
                             f"{urllib.parse.quote(callback)}&state={state}")
    assert status == 200, status
    _, st = browser.call("GET", "/api/status")
    origin = f"http://localhost:{port}"
    if not st["registered"]:
        _, opts = browser.call("POST", "/api/register/options", {})
        status, body = browser.call(
            "POST", "/api/register/verify",
            auth.attestation(opts["challenge"], "localhost", origin))
        assert status == 200, body
    else:
        _, opts = browser.call("POST", "/api/login/options", {})
        status, body = browser.call(
            "POST", "/api/login/verify",
            auth.assertion(opts["challenge"], "localhost", origin))
        assert status == 200, body
    status, body = browser.call("POST", "/api/cli-token",
                                {"callback": callback, "state": state})
    assert status == 200, body
    redirect = urllib.parse.urlparse(body["redirect"])
    conn = http.client.HTTPConnection(redirect.hostname, redirect.port, timeout=10)
    conn.request("GET", redirect.path + "?" + redirect.query)
    resp = conn.getresponse()
    resp.read()
    conn.close()
    out, err = proc.communicate(timeout=30)
    return proc.returncode, out, err


def main():
    workdir = tempfile.mkdtemp(prefix="xmagic-client-test-")
    cli_home = os.path.join(workdir, "home")
    server_a, _ = start_server(PORT_A, os.path.join(workdir, "a"))
    server_b, browser_b = start_server(PORT_B, os.path.join(workdir, "b"))
    env = dict(os.environ, XMAGIC_HOME=cli_home)
    xmagic = os.path.join(ROOT, "xmagic.py")

    def cli(*args):
        proc = subprocess.run([sys.executable, xmagic, *args], env=env,
                              capture_output=True, text=True, timeout=30)
        return proc.returncode, proc.stdout, proc.stderr

    try:
        rc, out, err = cli("node", "add", "a", "--url", f"http://127.0.0.1:{PORT_A}")
        check("node add a", rc == 0, err)
        rc, out, err = cli("node", "add", "b", "--url", f"http://127.0.0.1:{PORT_B}")
        check("node add b", rc == 0, err)
        rc, out, _ = cli("users", "list")
        check("management before login exits 3", rc == 3, f"rc={rc} {out}")

        auth_a = Authenticator()
        rc, out, err = drive_login(cli_home, PORT_A, auth_a)
        session_a = os.path.join(cli_home, "sessions", "a.json")
        check("browser login to A succeeds", rc == 0, err)
        check("session file stored per node", os.path.exists(session_a))
        if os.path.exists(session_a):
            mode = os.stat(session_a).st_mode & 0o777
            check("session file is 0600", mode == 0o600, oct(mode))
            saved = json.load(open(session_a))
            ttl = saved["expires_at"] - time.time()
            check("default session ttl is one week",
                  167 * 3600 < ttl <= 168 * 3600, f"ttl={ttl:.0f}s")

        rc, out, err = cli("users", "add", "alice")
        check("CLI adds a user on A", rc == 0 and "vless uuid:" in out, err + out)
        rc, out, _ = cli("--json", "users", "list")
        names = [u["username"] for u in json.loads(out)["users"]]
        check("--json users list on A", names == ["alice"], out)

        rc, out, err = cli("--json", "users", "rotate-uuid", "alice")
        rotated = json.loads(out).get("user", {}).get("vless_uuid") if rc == 0 else None
        rc, out, _ = cli("--json", "users", "list")
        check("users rotate-uuid via remote CLI",
              bool(rotated)
              and json.loads(out)["users"][0]["vless_uuid"] == rotated, out)
        rc, out, err = cli("upstreams", "add", "up1", "--proto", "ss",
                           "--addr", "10.9.9.9", "--port", "8388",
                           "--password", "pw")
        check("upstreams add via remote CLI", rc == 0, err + out)
        rc, out, err = cli("--json", "upstreams", "edit", "up1", "--port", "9999")
        check("upstreams edit via remote CLI",
              rc == 0 and json.loads(out)["upstream"]["port"] == 9999, err + out)
        rc, out, err = cli("routes", "add", "--kind", "domain",
                           "--pattern", "example.com", "--to", "block")
        check("routes add via remote CLI", rc == 0, err + out)
        rc, out, err = cli("--json", "routes", "edit", "1", "--to", "direct")
        check("routes edit via remote CLI",
              rc == 0 and json.loads(out)["route"]["target"] == "direct",
              err + out)
        rc, out, err = cli("settings", "set", "--upstream-strategy", "random")
        check("settings strategy via remote CLI",
              rc == 0 and "random" in out, err + out)

        rc, out, err = cli("settings", "set", "--session-ttl-hours", "24")
        check("settings set via CLI", rc == 0 and "24" in out, err + out)
        rc, out, _ = cli("--json", "settings", "show")
        check("settings show via CLI", json.loads(out)["session_ttl_hours"] == 24)

        rc, out, err = drive_login(cli_home, PORT_A, auth_a)
        saved = json.load(open(session_a))
        ttl = saved["expires_at"] - time.time()
        check("re-login mints a session with the new 24h ttl",
              rc == 0 and 23 * 3600 < ttl <= 24 * 3600, f"rc={rc} ttl={ttl:.0f}s {err}")

        rc, out, err = cli("--json", "sessions", "list")
        sess = json.loads(out)["sessions"]
        currents = [s for s in sess if s["current"]]
        check("CLI lists sessions with the current one marked",
              rc == 0 and len(currents) == 1 and currents[0]["kind"] == "cli",
              out + err)
        web_ids = [s["id"] for s in sess if s["kind"] == "web"]
        check("browser-login web sessions are listed too", len(web_ids) >= 1)
        if web_ids:
            rc, out, err = cli("sessions", "revoke", web_ids[0])
            check("CLI revokes a web session", rc == 0 and "revoked" in out,
                  err + out)
        rc, out, err = cli("sessions", "revoke-others")
        check("CLI revoke-others", rc == 0 and "revoked" in out, err + out)
        rc, out, _ = cli("--json", "sessions", "list")
        sess = json.loads(out)["sessions"]
        check("only the current session survives revoke-others",
              len(sess) == 1 and sess[0]["current"] is True, out)

        # a one-time code is single-use; a bogus code is refused
        status, _ = browser_b.call("POST", "/api/cli-exchange", {"code": "bogus"})
        check("bogus handoff code rejected", status == 401, f"got {status}")
        _, st = browser_b.call("GET", "/api/status")
        auth_b = Authenticator()
        _, opts = browser_b.call("POST", "/api/register/options", {})
        browser_b.call("POST", "/api/register/verify",
                       auth_b.attestation(opts["challenge"], "localhost",
                                          f"http://localhost:{PORT_B}"))
        status, _ = browser_b.call("POST", "/api/cli-token",
                                   {"callback": "https://evil.example.com/cb",
                                    "state": "x"})
        check("non-loopback callback rejected", status == 400, f"got {status}")

        # multi-node: log in to B with an explicit session file
        custom = os.path.join(workdir, "b-session.json")
        rc, out, err = drive_login(cli_home, PORT_B, auth_b,
                                   extra_args=("--node", "b",
                                               "--session-file", custom))
        check("login to B with --session-file", rc == 0 and os.path.exists(custom),
              err)
        rc, out, err = cli("--node", "b", "--session-file", custom,
                           "users", "add", "bob")
        check("add user on B via selected session", rc == 0, err + out)
        rc, out, _ = cli("--node", "b", "--session-file", custom,
                         "--json", "users", "list")
        check("B has only bob", [u["username"] for u in json.loads(out)["users"]] == ["bob"])
        rc, out, _ = cli("--json", "users", "list")
        check("current node still A with only alice",
              [u["username"] for u in json.loads(out)["users"]] == ["alice"])
        rc, out, _ = cli("--node", "b", "users", "list")
        check("B without its session file exits 3 (no default stored)",
              rc == 3, f"rc={rc}")
        rc, out, _ = cli("--url", f"http://127.0.0.1:{PORT_A}",
                         "--json", "users", "list")
        check("--url resolves to node A's stored session",
              [u["username"] for u in json.loads(out)["users"]] == ["alice"])

        # ---- remaining remote-CLI surface: node registry management,
        # status/apply, the full user/upstream/route action sets and the
        # remaining settings keys
        rc, out, err = cli("node", "list")
        check("node list shows both nodes",
              rc == 0 and "a" in out and "b" in out, err + out)
        rc, out, err = cli("node", "use", "b")
        check("node use b", rc == 0, err + out)
        rc, out, err = cli("node", "use", "a")
        check("node use a (restore)", rc == 0, err + out)

        rc, out, err = cli("--json", "status")
        check("status via remote CLI",
              rc == 0 and json.loads(out)["enabled_users"] == 1, err + out)
        rc, out, err = cli("apply")
        check("apply via remote CLI", rc == 0, err + out)

        temp_key = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITempTestKey"
                    "0123456789abcdef0123456789abcdef01234567 temp@test")
        rc, out, err = cli("users", "add", "temp", "--group", "intl",
                           "--note", "tmpnote", "--ssh-pubkey", temp_key)
        temp_pw = None
        for line in out.splitlines():
            if "password (trojan/http/socks):" in line:
                temp_pw = line.split(":", 1)[1].strip()
        check("users add with group/note/key via remote CLI",
              rc == 0 and bool(temp_pw), err + out)
        rc, out, _ = cli("--json", "users", "list")
        temp = next(u for u in json.loads(out)["users"]
                    if u["username"] == "temp")
        check("temp user's fields landed",
              temp["group"] == "intl" and temp["note"] == "tmpnote"
              and temp["ssh_key"] is True, out)
        rc, out, err = cli("users", "passwd", "temp")
        new_pw = None
        for line in out.splitlines():
            if "password (trojan/http/socks):" in line:
                new_pw = line.split(":", 1)[1].strip()
        check("users passwd via remote CLI",
              rc == 0 and bool(new_pw) and new_pw != temp_pw, err + out)
        rc, out, err = cli("users", "setkey", "temp")
        rc2, out, _ = cli("--json", "users", "list")
        temp = next(u for u in json.loads(out)["users"]
                    if u["username"] == "temp")
        check("users setkey with no key clears it",
              rc == 0 and temp["ssh_key"] is False, err + out)
        rc, out, err = cli("users", "setgroup", "temp", "backup")
        rc2, out, _ = cli("--json", "users", "list")
        temp = next(u for u in json.loads(out)["users"]
                    if u["username"] == "temp")
        check("users setgroup via remote CLI",
              rc == 0 and temp["group"] == "backup", err + out)
        rc, out, err = cli("users", "setmethod", "temp", "aes-128-gcm")
        rc2, out, _ = cli("--json", "users", "list")
        temp = next(u for u in json.loads(out)["users"]
                    if u["username"] == "temp")
        check("users setmethod via remote CLI",
              rc == 0 and temp["ss_method"] == "aes-128-gcm", err + out)
        rc, out, err = cli("users", "setnote", "temp", "hello note")
        rc2, out, _ = cli("--json", "users", "list")
        temp = next(u for u in json.loads(out)["users"]
                    if u["username"] == "temp")
        check("users setnote via remote CLI",
              rc == 0 and temp["note"] == "hello note", err + out)
        rc, out, err = cli("users", "disable", "temp")
        rc2, out, _ = cli("--json", "users", "list")
        temp = next(u for u in json.loads(out)["users"]
                    if u["username"] == "temp")
        check("users disable via remote CLI",
              rc == 0 and temp["enabled"] is False, err + out)
        rc, out, err = cli("users", "enable", "temp")
        rc2, out, _ = cli("--json", "users", "list")
        temp = next(u for u in json.loads(out)["users"]
                    if u["username"] == "temp")
        check("users enable via remote CLI",
              rc == 0 and temp["enabled"] is True, err + out)
        rc, out, err = cli("users", "remove", "temp")
        rc2, out, _ = cli("--json", "users", "list")
        check("users remove via remote CLI",
              rc == 0 and [u["username"] for u in json.loads(out)["users"]]
              == ["alice"], err + out)

        rc, out, _ = cli("--json", "upstreams", "list")
        check("upstreams list via remote CLI",
              [u["name"] for u in json.loads(out)["upstreams"]] == ["up1"], out)
        rc, out, err = cli("upstreams", "disable", "up1")
        rc2, out, _ = cli("--json", "upstreams", "list")
        check("upstreams disable via remote CLI",
              rc == 0 and json.loads(out)["upstreams"][0]["enabled"] is False,
              err + out)
        rc, out, err = cli("upstreams", "enable", "up1")
        rc2, out, _ = cli("--json", "upstreams", "list")
        check("upstreams enable via remote CLI",
              rc == 0 and json.loads(out)["upstreams"][0]["enabled"] is True,
              err + out)
        rc, out, err = cli("upstreams", "add", "tmpup", "--proto", "socks",
                           "--addr", "10.0.0.1", "--port", "1080")
        check("upstreams add tmpup", rc == 0, err + out)
        rc, out, err = cli("upstreams", "remove", "tmpup")
        rc2, out, _ = cli("--json", "upstreams", "list")
        check("upstreams remove via remote CLI",
              rc == 0 and [u["name"] for u in json.loads(out)["upstreams"]]
              == ["up1"], err + out)

        rc, out, _ = cli("--json", "routes", "list")
        check("routes list via remote CLI",
              len(json.loads(out)["routes"]) == 1, out)
        rc, out, err = cli("routes", "disable", "1")
        rc2, out, _ = cli("--json", "routes", "list")
        check("routes disable via remote CLI",
              rc == 0 and json.loads(out)["routes"][0]["enabled"] is False,
              err + out)
        rc, out, err = cli("routes", "enable", "1")
        rc2, out, _ = cli("--json", "routes", "list")
        check("routes enable via remote CLI",
              rc == 0 and json.loads(out)["routes"][0]["enabled"] is True,
              err + out)
        rc, out, err = cli("routes", "add", "--kind", "keyword",
                           "--pattern", "ads", "--to", "block")
        check("routes add temp route", rc == 0, err + out)
        rc, out, _ = cli("--json", "routes", "list")
        ads = next(r for r in json.loads(out)["routes"]
                   if r["pattern"] == "ads")
        rc, out, err = cli("routes", "remove", str(ads["id"]))
        rc2, out, _ = cli("--json", "routes", "list")
        check("routes remove via remote CLI",
              rc == 0 and len(json.loads(out)["routes"]) == 1, err + out)

        rc, out, err = cli("settings", "set", "--vless-ws-paths", "/r1,/r2",
                           "--trojan-ws-paths", "/tj",
                           "--ss-method", "aes-128-gcm",
                           "--direct-allow-private")
        check("settings set remaining keys via remote CLI", rc == 0, err + out)
        rc, out, _ = cli("--json", "settings", "show")
        st = json.loads(out)
        check("settings remaining keys read back",
              st["vless_ws_paths"] == ["/r1", "/r2"]
              and st["trojan_ws_paths"] == ["/tj"]
              and st["ss_method"] == "aes-128-gcm"
              and st["direct_allow_private"] is True, out)
        rc, out, err = cli("settings", "set", "--no-direct-allow-private")
        rc2, out, _ = cli("--json", "settings", "show")
        check("settings --no-direct-allow-private",
              rc == 0 and json.loads(out)["direct_allow_private"] is False,
              err + out)

        rc, out, err = cli("node", "remove", "b")
        check("node remove b", rc == 0, err + out)
        rc, _, _ = cli("--node", "b", "users", "list")
        check("removed node no longer resolves", rc != 0, f"rc={rc}")

        rc, out, err = cli("logout")
        check("logout removes A's session",
              rc == 0 and not os.path.exists(session_a), err + out)
        rc, _, _ = cli("users", "list")
        check("A requires login after logout", rc == 3, f"rc={rc}")

        # ---- remote db management: the whole `db` group against A.
        # Runs last: the final bare switch leaves the CLI logged out
        # on purpose (that is the behaviour under test).
        rc, out, err = drive_login(cli_home, PORT_A, auth_a)
        check("re-login to A for the db block", rc == 0, err)
        rc, out, err = cli("--json", "db", "list")
        dbs = json.loads(out)["databases"]
        check("remote db list shows the implicit default, active",
              rc == 0 and len(dbs) == 1 and dbs[0]["name"] == "default"
              and dbs[0]["active"] is True, err + out)
        data_dir = os.path.join(workdir, "a", "data")
        rc, out, err = cli("db", "add", "second", "--type", "sqlite",
                           "--path", os.path.join(data_dir, "second.db"))
        check("remote db add second", rc == 0, err + out)
        rc, out, err = cli("db", "add", "third", "--type", "sqlite",
                           "--path", os.path.join(data_dir, "third.db"))
        check("remote db add third (stays empty)", rc == 0, err + out)
        rc, out, err = cli("db", "add", "tempdb", "--type", "sqlite",
                           "--path", os.path.join(data_dir, "temp.db"))
        rc2, out2, err2 = cli("db", "remove", "tempdb")
        check("remote db remove (non-active)",
              rc == 0 and rc2 == 0, err + out + err2 + out2)
        rc, out, err = cli("--json", "db", "test", "second")
        check("remote db test second", rc == 0, err + out)
        rc, out, err = cli("db", "edit", "second", "--note", "standby")
        rc2, out, _ = cli("--json", "db", "list")
        notes = {d["name"]: d.get("note")
                 for d in json.loads(out)["databases"]}
        check("remote db edit note",
              rc == 0 and notes.get("second") == "standby", err + out)
        rc, out, err = cli("db", "migrate", "default", "second")
        check("remote db migrate default -> second", rc == 0, err + out)
        rc, out, err = cli("db", "switch", "second")
        check("remote db switch to the migrated db", rc == 0, err + out)
        rc, out, _ = cli("--json", "users", "list")
        check("session survives a switch to the migrated db",
              [u["username"] for u in json.loads(out)["users"]] == ["alice"],
              out)
        rc, out, err = cli("db", "switch", "third")
        check("remote db switch to the empty db", rc == 0, err + out)
        rc, _, _ = cli("users", "list")
        check("bare switch to a db without the session logs the CLI out",
              rc == 3, f"rc={rc}")
    finally:
        server_a.terminate()
        server_b.terminate()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
