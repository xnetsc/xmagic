#!/usr/bin/env python3
"""End-to-end test of the xmagic remote CLI (xmagic.py).

Two admin servers stand in for two nodes. A simulated browser performs
the Passkey ceremonies (software authenticator from test_admin) against
each node's /cli-auth handoff, so the real login path - ECDH-bound
ceremony, in-channel CLI session delegation, loopback callback with
public values only, encrypted session file - is exercised exactly as
an operator's browser would drive it. Then: node registry, per-node
sessions, --session-file selection, argument-over-config precedence,
settings round-trip, and the effective session TTL.

Run: python3 tests/test_client.py
"""
import http.client
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_admin import Authenticator, Client as Browser  # noqa: E402

PASS, FAIL = [], []
PORT_A, PORT_B = 18101, 18102
PORT_C = 18104  # 18103 is the self-update test's http.server


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""))


def start_server(port, workdir, ssh=True):
    env = dict(os.environ,
               PROXY_DB=os.path.join(workdir, "data", "users.db"),
               XMAGIC_ADMIN_BIND="127.0.0.1", XMAGIC_ADMIN_PORT=str(port),
               XMAGIC_ENABLE_SSH="1" if ssh else "",
               XMAGIC_DOCKER_SOCK="/nonexistent.sock")
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


def hit_callback(callback, **params):
    p = urllib.parse.urlparse(callback)
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=10)
    conn.request("GET", "/callback?" + urllib.parse.urlencode(params))
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status


def play_browser_login(port, auth, callback, state, cli_pub):
    """Play the /cli-auth page: passkey ceremony if needed (adopting
    the web session it negotiates), then mint the CLI session inside
    that encrypted channel and hand public values to the callback."""
    browser = Browser(port)
    status, _ = browser.call(
        "GET", f"/cli-auth?callback={urllib.parse.quote(callback)}"
               f"&state={state}&cli_pub={cli_pub}")
    assert status == 200, status
    _, st = browser.call("GET", "/api/status")
    origin = f"http://localhost:{port}"
    if not st["registered"]:
        _, opts = browser.options("register")
        status, body = browser.verify(
            "register", auth.attestation(opts["challenge"], "localhost",
                                         origin))
        assert status == 200, body
    else:
        _, opts = browser.options("login")
        status, body = browser.verify(
            "login", auth.assertion(opts["challenge"], "localhost", origin))
        assert status == 200, body
    status, body = browser.call("POST", "/api/cli/sessions",
                                {"client_pub": cli_pub,
                                 "label": "test drive"})
    assert status == 201, body
    hit_callback(callback, sid=body["id"], spub=body["server_pub"],
                 state=state, exp=body["expires_at"])
    return browser


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
    play_browser_login(port, auth, query["callback"][0], query["state"][0],
                       query["cli_pub"][0])
    out, err = proc.communicate(timeout=30)
    return proc.returncode, out, err


def drive_replace(cli_home, port, current_auth, new_auth):
    """Run `xmagic passkey replace --no-browser`, play the browser
    (fresh login with the current passkey, then register the new one
    under the CLI-issued ticket), return the proc result."""
    env = dict(os.environ, XMAGIC_HOME=cli_home)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "xmagic.py"), "passkey",
         "replace", "--no-browser"],
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
        raise RuntimeError(f"replace printed no URL: {out} {err}")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    ticket = query["ticket"][0]
    browser = Browser(port)
    status, _ = browser.call("GET", f"/cli-replace?ticket={ticket}")
    assert status == 200, status
    origin = f"http://localhost:{port}"
    _, opts = browser.options("login")
    status, body = browser.verify(
        "login", current_auth.assertion(opts["challenge"], "localhost",
                                        origin))
    assert status == 200, body
    _, opts = browser.options_at("/api/cli-replace-options",
                                 {"ticket": ticket})
    status, body = browser.verify_at(
        "/api/cli-replace-verify",
        dict(new_auth.attestation(opts["challenge"], "localhost", origin),
             ticket=ticket))
    assert status == 200, body
    out, err = proc.communicate(timeout=30)
    return proc.returncode, out, err


def spawn_login(cli_home):
    """Start `xmagic login --no-browser`; return (proc, callback, state)
    parsed from the printed auth URL."""
    env = dict(os.environ, XMAGIC_HOME=cli_home)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "xmagic.py"), "login",
         "--no-browser"],
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
    return (proc, query["callback"][0], query["state"][0],
            query["cli_pub"][0])


def hit_listener(callback, path):
    p = urllib.parse.urlparse(callback)
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status


def drive_login_stray(cli_home, port, auth):
    """Login while stray requests (favicon, bare /) hit the loopback
    listener before the real callback - they must be ignored, not
    mistaken for a failed handoff."""
    proc, callback, state, cli_pub = spawn_login(cli_home)
    hit_listener(callback, "/favicon.ico")
    hit_listener(callback, "/")
    play_browser_login(port, auth, callback, state, cli_pub)
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

        # Stray requests to the loopback listener (favicon, probes)
        # must not poison the login; a callback carrying a genuinely
        # wrong state must still abort it.
        rc, out, err = drive_login_stray(cli_home, PORT_A, auth_a)
        check("login tolerates stray listener hits before the callback",
              rc == 0 and "logged in" in out, err + out)
        proc, callback, _state, _pub = spawn_login(cli_home)
        hit_listener(callback, "/callback?sid=fake&spub=fake"
                               "&state=wrong-state")
        out, err = proc.communicate(timeout=30)
        check("callback with a wrong state still aborts the login",
              proc.returncode == 3 and "state mismatch" in err, err + out)
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
        rc, out, err = cli("upstreams", "add", "upvmws", "--proto",
                           "vmess-ws", "--addr", "10.9.9.11",
                           "--port", "443", "--uuid",
                           "11111111-2222-3333-4444-555555555555",
                           "--tls")
        check("upstreams add vmess-ws via remote CLI", rc == 0, err + out)
        rc, out, err = cli("upstreams", "remove", "upvmws")
        check("upstreams remove vmess-ws via remote CLI", rc == 0,
              err + out)
        rc, out, err = cli("upstreams", "add", "upvmbare", "--proto",
                           "vmess", "--addr", "10.9.9.12",
                           "--port", "10086", "--uuid",
                           "11111111-2222-3333-4444-555555555555")
        check("upstreams add bare vmess refused while vmess TCP is off",
              rc != 0, err + out)
        rc, out, err = cli("--json", "upstreams", "edit", "up1", "--port", "9999")
        check("upstreams edit via remote CLI",
              rc == 0 and json.loads(out)["upstream"]["port"] == 9999, err + out)
        up_key = os.path.join(workdir, "upssh.pem")
        with open(up_key, "w") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    "ZmFrZS11cHNzaA==\n-----END OPENSSH PRIVATE KEY-----\n")
        stored = os.path.join(workdir, "a", "data", "ssh_client_keys",
                              "upssh.key")
        rc, out, err = cli("--json", "upstreams", "add", "upssh",
                           "--proto", "ssh", "--addr", "10.9.9.10",
                           "--port", "22", "--username", "tunnel",
                           "--key-upload", up_key)
        check("upstreams add ssh with --key-upload stores the key",
              rc == 0
              and json.loads(out)["upstream"]["key_file"] == "/keys/upssh.key"
              and os.path.exists(stored)
              and "ZmFrZS11cHNzaA==" in open(stored).read(), err + out)
        rc, out, err = cli("upstreams", "remove", "upssh")
        check("upstreams remove deletes the uploaded key",
              rc == 0 and not os.path.exists(stored), err + out)
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
        rc, out, err = cli("--json", "settings", "show")
        check("settings show reports ssh_enabled true via remote CLI",
              rc == 0 and json.loads(out).get("ssh_enabled") is True,
              err + out)
        rc, out, err = cli("settings", "show")
        check("settings show marks interconnect available via remote CLI",
              rc == 0 and "ssh_enabled: True" in out
              and "interconnect: available" in out, err + out)

        # ---- ssh keys: generate, scan, select (remote CLI)
        rc, out, err = cli("--json", "keys", "generate", "ck1")
        kg = json.loads(out) if rc == 0 else {}
        ck_priv = os.path.join(cli_home, "keys", "ck1")
        check("keys generate writes a managed 0600 keypair",
              rc == 0 and os.path.exists(ck_priv)
              and (os.stat(ck_priv).st_mode & 0o777) == 0o600
              and kg.get("public_key", "").startswith("ssh-ed25519 "),
              err + out)
        rc, out, err = cli("--json", "keys", "generate", "ck2")
        kg2 = json.loads(out) if rc == 0 else {}
        fake_home = os.path.join(workdir, "fakehome")
        os.makedirs(os.path.join(fake_home, ".ssh"))
        for src_name, dst in (("ck2", "id_test"),):
            with open(os.path.join(cli_home, "keys", src_name), "rb") as f:
                data = f.read()
            with open(os.path.join(fake_home, ".ssh", dst), "wb") as f:
                f.write(data)
            with open(os.path.join(fake_home, ".ssh", dst + ".pub"), "w") as f:
                f.write(kg2["public_key"] + "\n")
        real_home = env.get("HOME")
        env["HOME"] = fake_home
        rc, out, err = cli("--json", "keys", "list")
        env["HOME"] = real_home
        listed = json.loads(out)["keys"] if rc == 0 else []
        check("keys list scans ~/.ssh pairs, ~/.xmagic keys and dedupes",
              rc == 0
              and any(k["name"] == "id_test" and k["source"] == "file"
                      for k in listed)
              and sum(1 for k in listed
                      if k["fingerprint"] == kg["fingerprint"]) == 1,
              err + out)
        rc, out, err = cli("keys", "show", "ck1")
        check("keys show resolves a name to the public key line",
              rc == 0 and out.strip() == kg["public_key"], err + out)
        rc, out, err = cli("--json", "users", "add", "henry",
                           "--ssh-key", "ck1")
        henry = json.loads(out)["user"] if rc == 0 else {}
        check("users add --ssh-key registers the scanned pubkey",
              rc == 0 and henry.get("ssh_pubkey") == kg["public_key"],
              err + out)
        rc, out, err = cli("--json", "users", "add", "irene",
                           "--ssh-key-generate")
        check("users add --ssh-key-generate mints + registers a keypair",
              rc == 0
              and os.path.exists(os.path.join(cli_home, "keys", "irene"))
              and json.loads(out)["user"].get("ssh_key") is True, err + out)
        rc, out, err = cli("--json", "upstreams", "add", "upgen",
                           "--proto", "ssh", "--addr", "10.9.9.11",
                           "--port", "22", "--username", "tunnel",
                           "--key-generate")
        check("upstreams add ssh with --key-generate stores a node key",
              rc == 0
              and json.loads(out)["upstream"]["key_file"] == "/keys/upgen.key"
              and os.path.exists(os.path.join(
                  workdir, "a", "data", "ssh_client_keys", "upgen.key")),
              err + out)
        rc, out, err = cli("--json", "settings", "set", "--vless-enabled")
        check("settings set --vless-enabled via remote CLI",
              rc == 0 and json.loads(out)["vless_enabled"] is True,
              err + out)
        rc, out, err = cli("--json", "settings", "set", "--no-vless-enabled")
        check("settings set --no-vless-enabled via remote CLI",
              rc == 0 and json.loads(out)["vless_enabled"] is False,
              err + out)
        rc, out, err = cli("--json", "settings", "set",
                           "--vmess-ws-paths", "/rm1,/rm2")
        check("settings set --vmess-ws-paths via remote CLI",
              rc == 0 and json.loads(out)["vmess_ws_paths"]
              == ["/rm1", "/rm2"], err + out)
        rc, out, err = cli("--json", "settings", "set",
                           "--vmess-ws-paths", "")
        check("settings set --vmess-ws-paths '' clears to the default",
              rc == 0 and json.loads(out)["vmess_ws_paths"]
              == ["/vmess-ws"], err + out)
        for flag, key in (("--vmess-tcp-enabled", "vmess_tcp_enabled"),
                          ("--ss-tcp-enabled", "ss_tcp_enabled"),
                          ("--http-enabled", "http_enabled")):
            rc, out, err = cli("--json", "settings", "set", flag)
            check(f"settings set {flag} via remote CLI",
                  rc == 0 and json.loads(out)[key] is True, err + out)
            rc, out, err = cli("--json", "settings", "set",
                               "--no-" + flag[2:])
            check(f"settings set --no-{flag[2:]} via remote CLI",
                  rc == 0 and json.loads(out)[key] is False, err + out)
        rc, out, err = cli("--json", "settings", "show")
        st = json.loads(out)
        check("settings show carries the reality client parameters",
              rc == 0 and st["reality_enabled"] is False
              and st["reality_dest"] == "www.microsoft.com:443"
              and st["reality_server_names"] == ["www.microsoft.com"]
              and len(st["reality_short_ids"]) == 1
              and len(st["reality_public_key"]) == 43,
              err + out)
        with sqlite3.connect(os.path.join(
                workdir, "a", "data", "users.db")) as raw:
            priv = raw.execute("SELECT value FROM admin_settings"
                               " WHERE key = 'reality_private_key'"
                               ).fetchone()[0]
        check("reality private key never reaches the remote CLI",
              priv not in out and "reality_private_key" not in out, out)
        rc, out, err = cli("--json", "settings", "set",
                           "--reality-dest", "www.apple.com:443",
                           "--reality-server-names", "www.apple.com",
                           "--reality-short-ids", "0123abcd,eeff")
        st = json.loads(out) if rc == 0 else {}
        check("settings set reality dest/names/short ids via remote CLI",
              rc == 0 and st["reality_dest"] == "www.apple.com:443"
              and st["reality_server_names"] == ["www.apple.com"]
              and st["reality_short_ids"] == ["0123abcd", "eeff"],
              err + out)
        pub_before_rotate = st.get("reality_public_key")
        rc, out, err = cli("--json", "settings", "set",
                           "--reality-rotate-key")
        st = json.loads(out) if rc == 0 else {}
        check("settings set --reality-rotate-key via remote CLI",
              rc == 0 and len(st.get("reality_public_key", "")) == 43
              and st["reality_public_key"] != pub_before_rotate,
              err + out)
        pub_rotated = st.get("reality_public_key")
        rc, out, err = cli("--json", "settings", "show")
        check("rotated reality public key persists on the node",
              rc == 0
              and json.loads(out)["reality_public_key"] == pub_rotated,
              err + out)
        rc, out, err = cli("settings", "set", "--no-reality-enabled")
        check("settings set --no-reality-enabled (human output)",
              rc == 0 and "reality_enabled=False" in out, err + out)
        rc, out, err = cli("--json", "settings", "set",
                           "--reality-enabled",
                           "--reality-dest", "",
                           "--reality-server-names", "",
                           "--reality-short-ids", "")
        st = json.loads(out) if rc == 0 else {}
        check("settings reality restored and cleared to defaults",
              rc == 0 and st["reality_enabled"] is True
              and st["reality_dest"] == "www.microsoft.com:443"
              and st["reality_server_names"] == ["www.microsoft.com"]
              and len(st["reality_short_ids"]) == 1,
              err + out)
        rc, out, err = cli("settings", "set", "--interconnect-off-groups",
                           "team")
        check("settings opt a group out of interconnect via remote CLI",
              rc == 0 and "interconnect_off_groups=team" in out, err + out)
        rc, out, err = cli("settings", "set", "--interconnect-off-groups", "")
        check("settings clear the interconnect opt-out via remote CLI",
              rc == 0 and "interconnect_off_groups=(none)" in out, err + out)
        cli("users", "remove", "henry")
        cli("users", "remove", "irene")
        rc, out, err = cli("upstreams", "remove", "upgen")
        check("cleanup: key-test users + upstream removed again",
              rc == 0, err + out)

        rc, out, err = cli("upstreams", "add", "upbad", "--proto", "ss",
                           "--addr", "10.0.0.9", "--port", "8388",
                           "--password", "pw", "--method", "aes-999-bogus")
        check("remote CLI: bogus ss method refused by the node",
              rc == 1, err + out)

        # ---- self-update: a copied CLI updates itself from a local
        # server (never the repo file itself)
        upd_dir = os.path.join(workdir, "upd")
        os.makedirs(upd_dir)
        cli_src = open(xmagic).read()
        copy_path = os.path.join(upd_dir, "cli.py")
        with open(copy_path, "w") as f:
            f.write(cli_src)
        with open(os.path.join(upd_dir, "xmagic.py"), "w") as f:
            f.write(cli_src.replace('VERSION = "1.2.0"',
                                    'VERSION = "9.9.9"'))
        with open(os.path.join(upd_dir, "bad.py"), "w") as f:
            f.write("not a cli\n")
        httpd = subprocess.Popen(
            [sys.executable, "-m", "http.server", "18103",
             "--directory", upd_dir, "--bind", "127.0.0.1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def cli_copy(*args):
            proc = subprocess.run([sys.executable, copy_path, *args],
                                  env=env, capture_output=True, text=True,
                                  timeout=30)
            return proc.returncode, proc.stdout, proc.stderr

        try:
            base = "http://127.0.0.1:18103"
            rc, out, err = cli_copy("update", "--check", "--from",
                                    base + "/xmagic.py")
            check("update --check reports the newer version, file untouched",
                  rc == 0 and "9.9.9" in out
                  and 'VERSION = "1.2.0"' in open(copy_path).read(), err + out)
            rc, out, err = cli_copy("update", "--from", base + "/bad.py")
            check("update refuses a download that is not xmagic.py",
                  rc == 1 and 'VERSION = "1.2.0"' in open(copy_path).read(),
                  err + out)
            rc, out, err = cli_copy("update", "--from", base + "/xmagic.py")
            check("update replaces the file and keeps a .bak",
                  rc == 0 and 'VERSION = "9.9.9"' in open(copy_path).read()
                  and 'VERSION = "1.2.0"' in open(copy_path + ".bak").read(),
                  err + out)
            rc, out, err = cli_copy("--version")
            check("updated CLI runs and reports the new version",
                  rc == 0 and "9.9.9" in out, err + out)
        finally:
            httpd.terminate()

        # ---- self-update from the node itself: the installed CLI must
        # end up byte-identical to the copy the deployment bundles
        with open(copy_path, "w") as f:
            f.write(cli_src)  # pristine again (the .bak still holds 1.2.0)
        rc, out, err = cli_copy("update")
        check("update from the node: already identical, nothing replaced",
              rc == 0 and "identical" in out
              and open(copy_path).read() == cli_src, err + out)
        with open(copy_path, "a") as f:
            f.write("\n# local drift\n")
        rc, out, err = cli_copy("update", "--check")
        check("update --check from the node reports content drift",
              rc == 0 and "differs" in out, err + out)
        rc, out, err = cli_copy("update")
        check("update from the node re-aligns drifted bytes exactly",
              rc == 0 and open(copy_path).read() == cli_src, err + out)

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

        # no channel, no CLI session: delegation needs the web
        # session's encrypted channel; a forged callback state aborts
        # the CLI's login instead of storing anything
        status, _ = browser_b.call("POST", "/api/cli/sessions",
                                   {"client_pub": "AAAA"})
        check("CLI session minting without a channel rejected",
              status == 401, f"got {status}")
        proc, callback, state, cli_pub = spawn_login(cli_home)
        hit_callback(callback, sid="forged", spub="AAAA", state="WRONG",
                     exp=0)
        _, err = proc.communicate(timeout=30)
        check("forged callback state aborts the login",
              proc.returncode == 3 and "state mismatch" in err,
              f"rc={proc.returncode} {err}")
        _, st = browser_b.call("GET", "/api/status")
        auth_b = Authenticator()
        _, opts = browser_b.options("register")
        browser_b.verify("register",
                         auth_b.attestation(opts["challenge"], "localhost",
                                            f"http://localhost:{PORT_B}"))

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
        check("--json list carries the full pubkey and its fingerprint",
              temp["ssh_pubkey"] == temp_key
              and temp["ssh_fingerprint"].startswith("SHA256:"), out)
        rc, out, _ = cli("users", "list")
        check("human list shows the key fingerprint, not just yes",
              rc == 0 and "ssh-key=SHA256:" in out, out)
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
        rc, out, err = cli("upstreams", "add", "tmpssws", "--proto", "ss",
                           "--addr", "cdn.example.com", "--port", "443",
                           "--password", "pw", "--path", "/ss-ws", "--tls")
        check("upstreams add ss with path+tls via remote CLI",
              rc == 0, err + out)
        rc, out, _ = cli("--json", "upstreams", "list")
        tmpssws = next((u for u in json.loads(out)["upstreams"]
                        if u["name"] == "tmpssws"), {})
        check("ss-ws upstream row carries path+tls",
              tmpssws.get("path") == "/ss-ws"
              and tmpssws.get("tls") is True, out)
        rc, out, err = cli("upstreams", "remove", "tmpssws")
        check("upstreams remove tmpssws", rc == 0, err + out)
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
        rc, out, err = cli("settings", "set", "--ss-ws-paths", "/p1,/p2")
        check("settings set ss-ws paths (human output)",
              rc == 0 and "ss_ws_paths" not in err, err + out)
        rc, out, _ = cli("--json", "settings", "show")
        st = json.loads(out)
        check("settings ss-ws paths read back via remote CLI",
              st["ss_ws_paths"] == ["/p1", "/p2"]
              and st["ss_ws_paths_from_db"] is True, out)
        rc, out, err = cli("settings", "set", "--ss-ws-paths", "")
        rc2, out, _ = cli("--json", "settings", "show")
        check("settings ss-ws paths cleared back to env via remote CLI",
              rc == 0 and json.loads(out)["ss_ws_paths"] == ["/ss-ws"]
              and json.loads(out)["ss_ws_paths_from_db"] is False,
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

        # ---- a node with SSH off: settings show ssh_enabled false
        # and interconnect unavailable, while the stored opt-out
        # stays editable through the remote CLI.
        server_c, _ = start_server(PORT_C, os.path.join(workdir, "c"),
                                   ssh=False)
        try:
            auth_c = Authenticator()
            rc, out, err = cli("node", "add", "c", "--url",
                               f"http://127.0.0.1:{PORT_C}")
            check("node add c (ssh off)", rc == 0, err + out)
            rc, out, err = drive_login(cli_home, PORT_C, auth_c,
                                       extra_args=("--node", "c"))
            check("browser login to C (ssh off) succeeds", rc == 0, err)
            rc, out, err = cli("--node", "c", "--json", "settings", "show")
            check("ssh off: settings show reports ssh_enabled false"
                  " via remote CLI",
                  rc == 0 and json.loads(out).get("ssh_enabled") is False,
                  err + out)
            rc, out, err = cli("--node", "c", "settings", "show")
            check("ssh off: settings show marks interconnect unavailable"
                  " via remote CLI",
                  rc == 0 and "ssh_enabled: False" in out
                  and "interconnect: unavailable (SSH not enabled)" in out,
                  err + out)
            rc, out, err = cli("--node", "c", "settings", "set",
                               "--interconnect-off-groups", "team")
            check("ssh off: interconnect opt-out still stored via"
                  " remote CLI, with the unavailable mark",
                  rc == 0 and "interconnect_off_groups=team" in out
                  and "interconnect unavailable: SSH not enabled" in out,
                  err + out)
            rc, out, err = cli("--node", "c", "--json", "settings", "show")
            check("ssh off: stored opt-out reads back via remote CLI",
                  rc == 0
                  and json.loads(out)["interconnect_off_groups"] == ["team"],
                  err + out)
            rc, out, err = cli("--node", "c", "settings", "set",
                               "--interconnect-off-groups", "")
            check("ssh off: clearing the opt-out via remote CLI",
                  rc == 0 and "interconnect_off_groups=(none)" in out,
                  err + out)
            rc, out, err = cli("--node", "c", "settings", "set",
                               "--interconnect-paused-groups", "team")
            check("ssh off: paused list stored via remote CLI, with"
                  " the unavailable mark",
                  rc == 0
                  and "interconnect_paused_groups=team" in out
                  and "interconnect unavailable: SSH not enabled"
                  in out, err + out)
            rc, out, err = cli("--node", "c", "settings", "show")
            check("ssh off: settings show lists the paused groups"
                  " via remote CLI",
                  rc == 0
                  and "interconnect_paused_groups: team" in out,
                  err + out)
            rc, out, err = cli("--node", "c", "--json", "settings",
                               "show")
            check("ssh off: --json settings show carries the paused"
                  " list and its source flag",
                  rc == 0
                  and json.loads(out)["interconnect_paused_groups"]
                  == ["team"]
                  and json.loads(out)[
                      "interconnect_paused_groups_from_db"] is True,
                  err + out)
            rc, out, err = cli("--node", "c", "settings", "set",
                               "--interconnect-off-groups", "team")
            check("conflict: closing a paused group via remote CLI"
                  " is refused and names the group",
                  rc != 0 and "team" in err + out
                  and "both" in err + out, err + out)
            rc, out, err = cli("--node", "c", "settings", "set",
                               "--interconnect-paused-groups", "")
            check("ssh off: clearing the paused list via remote CLI",
                  rc == 0
                  and "interconnect_paused_groups=(none)" in out,
                  err + out)

            # Capacity: seed 100 keyed holders of group "capped"
            # directly (user rows + allocation rows), then exercise
            # the claim gates through the remote surface.
            raw = sqlite3.connect(os.path.join(workdir, "c", "data",
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
            # user101 exists as a keyed, sliceless member (seeded:
            # this node has SSH off, so keys cannot be registered
            # through the API here).
            raw = sqlite3.connect(os.path.join(workdir, "c", "data",
                                               "users.db"))
            raw.execute(
                "INSERT INTO users (username, vless_uuid,"
                " trojan_password, ss_password, ss_method, ssh_pubkey,"
                " upstream_group, created_at) VALUES (?,?,?,?,?,?,?,?)",
                ("user101", "uuid-101", "pw", "pw", "aes-256-gcm",
                 "ssh-ed25519 AAAA user101", "capped",
                 "2026-11-01T00:00:00.000000+00:00"))
            raw.commit()
            raw.close()
            rc, out, err = cli("--node", "c", "settings", "set",
                               "--interconnect-off-groups", "capped")
            check("capacity: opting the group out via remote CLI",
                  rc == 0 and "interconnect_off_groups=capped" in out,
                  err + out)
            rc, out, err = cli("--node", "c", "settings", "set",
                               "--interconnect-off-groups", "")
            check("capacity: turning the group on refused via remote"
                  " CLI; the quantified error names the shortfall",
                  rc != 0
                  and "cannot enable interconnect for group 'capped'"
                  in err + out
                  and "101 member(s) need a port slice" in err + out
                  and "only 100 free block(s) (1600 ports)" in err + out
                  and "short 1 block(s) (16 ports)" in err + out
                  and "cannot be served: user101" in err + out,
                  err + out)
            rc, out, err = cli("--node", "c", "--json", "settings",
                               "set", "--interconnect-off-groups", "")
            try:
                eobj = json.loads(err)
            except ValueError:
                eobj = {}
            check("capacity: --json refusal is the structured error"
                  " object with the same figures",
                  rc != 0 and eobj.get("code")
                  == "interconnect_insufficient_ports"
                  and eobj.get("group") == "capped"
                  and eobj.get("needed_count") == 101
                  and len(eobj.get("needed_users", [])) == 101
                  and eobj.get("needed_users", [None])[-1] == "user101"
                  and eobj.get("free_blocks") == 100
                  and eobj.get("free_ports") == 1600
                  and eobj.get("shortfall_blocks") == 1
                  and eobj.get("shortfall_ports") == 16
                  and eobj.get("users_without_ports") == ["user101"],
                  err + out)
            rc, out, err = cli("--node", "c", "--json", "settings",
                               "show")
            c_show = json.loads(out) if rc == 0 else {}
            check("capacity: refusal was atomic (opt-out kept, all"
                  " slices still released, capacity summary agrees)",
                  c_show.get("interconnect_off_groups") == ["capped"]
                  and c_show.get("interconnect_capacity") == {
                      "total_blocks": 100, "claimed_blocks": 0,
                      "free_blocks": 100}, err + out)
        finally:
            server_c.terminate()

        # ---- remote db management: the whole `db` group against A.
        # Runs last: the final bare switch leaves the CLI logged out
        # on purpose (that is the behaviour under test).
        rc, out, err = drive_login(cli_home, PORT_A, auth_a)
        check("re-login to A for the db block", rc == 0, err)

        # ---- passkey replacement initiated from the CLI: the ticket
        # ceremony swaps the credential, keeps this CLI session, and
        # the old key dies while the new one works.
        auth_a2 = Authenticator()
        rc, out, err = drive_replace(cli_home, PORT_A, auth_a, auth_a2)
        check("passkey replace via CLI + browser ceremony",
              rc == 0 and "replaced" in out, err + out)
        rc, out, _ = cli("--json", "users", "list")
        check("initiating CLI session survives the replacement",
              rc == 0 and [u["username"] for u in json.loads(out)["users"]]
              == ["alice"], out)
        probe = Browser(PORT_A)
        _, opts = probe.options("login")
        status, _ = probe.verify(
            "login", auth_a.assertion(opts["challenge"], "localhost",
                                      f"http://localhost:{PORT_A}"))
        check("old passkey rejected after CLI replacement",
              status in (400, 401), f"got {status}")
        _, opts = probe.options("login")
        status, _ = probe.verify(
            "login", auth_a2.assertion(opts["challenge"], "localhost",
                                       f"http://localhost:{PORT_A}"))
        check("new passkey logs in after CLI replacement",
              status == 200, f"got {status}")
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
