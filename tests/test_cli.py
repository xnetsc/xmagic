#!/usr/bin/env python3
"""CLI parity test: every admin-console function must work from users.py.

Also proves the two frontends share one engine: users created through
the CLI show up in the web console and vice versa, and `apply` from the
CLI renders the same files the console renders.

Run: python3 tests/test_cli.py
"""
import json
import os
import shutil
import sqlite3
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
    check("--json apply with nothing pending restarts nothing",
          json.loads(out)["restarted"] == {}
          and json.loads(out)["restart_skipped"] is False)
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
    rules0 = direct.get("settings", {}).get("finalRules", [])
    check("default render: only the interconnect loopback finalRule, "
          "private targets stay blocked",
          len(rules0) == 1 and rules0[0]["ip"] == ["127.0.0.0/8"],
          json.dumps(direct))
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

    # ---- ssh key generation (engine) + upstream --key-generate
    keys_dir = os.path.join(workdir, "keys")
    rc, out, err = cli("--json", "keygen", "kg1", "--out-dir", keys_dir)
    kg = json.loads(out) if rc == 0 else {}
    priv = os.path.join(keys_dir, "kg1")
    check("keygen writes a 0600 private key + matching .pub",
          rc == 0 and os.path.exists(priv)
          and (os.stat(priv).st_mode & 0o777) == 0o600
          and open(priv + ".pub").read().strip() == kg.get("public_key"),
          err + out)
    if shutil.which("ssh-keygen"):
        derived = subprocess.run(["ssh-keygen", "-y", "-f", priv],
                                 capture_output=True, text=True).stdout.split()[:2]
        check("generated keypair matches ssh-keygen -y",
              derived == (kg.get("public_key") or "").split()[:2])
    rc, out, _ = cli("keygen", "kg1", "--out-dir", keys_dir)
    check("keygen refuses to overwrite an existing key", rc != 0)
    dave_key = os.path.join(workdir, "kdave.key")
    rc, out, err = cli("--json", "add", "kdave", "--group", "team",
                       "--ssh-key-generate", dave_key)
    dave = json.loads(out) if rc == 0 else {}
    check("add --ssh-key-generate registers pubkey, private stays local",
          rc == 0 and dave.get("ssh_key") is True
          and bool(dave.get("ssh_fingerprint"))
          and os.path.exists(dave_key), err + out)
    rc, out, err = cli("--json", "upstream-add", "upssh2", "--proto", "ssh",
                       "--addr", "10.1.1.1", "--port", "22",
                       "--username", "tun", "--key-generate")
    up = json.loads(out) if rc == 0 else {}
    up_stored = os.path.join(workdir, "data", "ssh_client_keys", "upssh2.key")
    check("upstream-add --key-generate stores a node-generated key",
          rc == 0 and up.get("key_file") == "/keys/upssh2.key"
          and os.path.exists(up_stored)
          and "BEGIN OPENSSH PRIVATE KEY" in open(up_stored).read(),
          err + out)
    rc, _, _ = cli("upstream-remove", "upssh2")
    check("upstream-remove after --key-generate cleans up",
          rc == 0 and not os.path.exists(up_stored))

    # ---- same-group interconnect: settings + render assertions
    rc, out, err = cli("--json", "add", "kerin", "--group", "team",
                       "--ssh-key-file", os.path.join(keys_dir, "kg1.pub"))
    check("add kerin (team, with key)", rc == 0, err)
    rc, out, _ = cli("--json", "settings")
    info = json.loads(out)
    everyone = {"alice", "bob", "carol", "kdave", "kerin"}
    check("interconnect on by default: no opt-outs, every user a member",
          info.get("interconnect_off_groups") == []
          and set(info.get("interconnect_slices", {})) == everyone, out)
    rc, out, _ = cli("render", "--out", cfg_path)
    cfg = json.load(open(cfg_path))
    rules = cfg["routing"]["rules"]
    band = [r for r in rules if r.get("outboundTag") == "direct"
            and r.get("ip") == ["127.0.0.0/8"]]
    blocks = [r for r in rules if r.get("outboundTag") == "block"
              and r.get("ip") == ["127.0.0.0/8"]]
    direct = [o for o in cfg["outbounds"] if o.get("tag") == "direct"][0]
    by_port = {r.get("port"): r.get("user") for r in band}
    check("interconnect render: one slice rule per member, dialers are"
          " groupmates only, loopback block, loopback-only finalRule",
          len(band) == 5
          and by_port.get("20000-20015") == ["alice", "bob", "carol"]
          and by_port.get("20048-20063") == ["kdave", "kerin"]
          and by_port.get("20064-20079") == ["kdave", "kerin"]
          and set(by_port) == {"20000-20015", "20016-20031", "20032-20047",
                               "20048-20063", "20064-20079"}
          and len(blocks) == 1
          and direct.get("settings", {}).get("finalRules", [{}])[0].get("ip")
          == ["127.0.0.0/8"], json.dumps(rules))
    keys_out = os.path.join(workdir, "data", "authorized_keys")
    rc, out, _ = cli("render-keys", "--out", keys_out)
    ktext = open(keys_out).read()
    check("interconnect keys: every keyed user carries their own slice only",
          'permitlisten="127.0.0.1:20048"' in ktext
          and 'permitlisten="127.0.0.1:20064"' in ktext
          and ktext.count("permitlisten=") == 32, ktext[:160])
    if shutil.which("ssh-keygen"):
        derived = subprocess.run(["ssh-keygen", "-y", "-f", dave_key],
                                 capture_output=True, text=True).stdout
        check("kdave's generated pubkey is the one in authorized_keys",
              derived.split()[1] in ktext)
    rc, out, _ = cli("settings", "--interconnect-off-groups", "team")
    check("settings opt team out of interconnect",
          rc == 0 and "team" in out, out)
    rc, out, _ = cli("render", "--out", cfg_path)
    cfg = json.load(open(cfg_path))
    band = [r for r in cfg["routing"]["rules"]
            if r.get("outboundTag") == "direct"
            and r.get("ip") == ["127.0.0.0/8"]]
    check("opted-out members lose their slice rules (unreachable + cannot dial)",
          {r.get("port") for r in band}
          == {"20000-20015", "20016-20031", "20032-20047"}
          and all(r.get("user") == ["alice", "bob", "carol"] for r in band),
          json.dumps(band))
    rc, out, _ = cli("settings", "--interconnect-off-groups", "")
    check("clearing the opt-out restores the default", rc == 0, out)

    # Pidfile restart channel (single-container form): apply restarts
    # only the processes whose rendered inputs changed - it writes a
    # restart marker naming the pid, then SIGTERMs exactly those
    # processes. (The entrypoint relaunches a marked process in place;
    # a relaunch that dies again takes the whole container down.)
    pid_dir = os.path.join(workdir, "pids")
    os.makedirs(pid_dir)
    env_pid = dict(env, XMAGIC_PID_DIR=pid_dir)
    standins = {}

    def spawn(name):
        proc = subprocess.Popen(["sleep", "60"])
        standins[name] = proc
        with open(os.path.join(pid_dir, name + ".pid"), "w") as f:
            f.write(str(proc.pid))

    def pid_apply():
        proc = subprocess.run([sys.executable, users_py, "--json", "apply"],
                              env=env_pid, capture_output=True, text=True)
        try:
            return proc, json.loads(proc.stdout)
        except ValueError:
            return proc, {}

    def exited(name):
        try:
            return standins[name].wait(timeout=10) == -15
        except subprocess.TimeoutExpired:
            return False

    cli("apply")  # sync the rendered files before the scenarios
    for n in ("xray", "sshd", "tunnels"):
        spawn(n)
    proc, applied = pid_apply()
    check("pidfile apply with no changes restarts nothing",
          proc.returncode == 0 and applied.get("changed") == []
          and applied.get("restarted") == {}
          and applied.get("restart_skipped") is False
          and all(standins[n].poll() is None for n in standins),
          proc.stdout + proc.stderr)
    rc, _, err = cli("upstream-add", "edge-1", "--proto", "vless-ws",
                     "--addr", "203.0.113.9", "--port", "443",
                     "--uuid", "22222222-2222-4222-8222-222222222222")
    check("upstream-add for the pidfile scenarios", rc == 0, err)
    proc, applied = pid_apply()
    req = os.path.join(pid_dir, "restart-xray.req")
    check("config change restarts only xray (marker + SIGTERM)",
          applied.get("restarted") == {"xray": True}
          and applied.get("changed") == ["config"]
          and os.path.exists(req)
          and open(req).read() == str(standins["xray"].pid)
          and exited("xray")
          and standins["sshd"].poll() is None
          and standins["tunnels"].poll() is None,
          proc.stdout + proc.stderr)
    spawn("xray")
    pub_path = os.path.join(workdir, "alice.pub")
    with open(pub_path, "w") as f:
        f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPidfileTestKey alice\n")
    rc, _, err = cli("setkey", "alice", "--ssh-key-file", pub_path)
    check("setkey for the pidfile scenarios", rc == 0, err)
    proc, applied = pid_apply()
    check("key change restarts only sshd",
          applied.get("restarted") == {"sshd": True}
          and applied.get("changed") == ["keys"]
          and exited("sshd")
          and standins["xray"].poll() is None
          and standins["tunnels"].poll() is None,
          proc.stdout + proc.stderr)
    spawn("sshd")
    rc, _, err = cli("upstream-add", "tun-1", "--proto", "ssh",
                     "--addr", "203.0.113.10", "--port", "22",
                     "--username", "tunnel", "--key-file", "/keys/tun-1.key")
    check("ssh upstream-add for the pidfile scenarios", rc == 0, err)
    proc, applied = pid_apply()
    check("tunnels change restarts xray + tunnels, not sshd",
          applied.get("restarted") == {"xray": True, "tunnels": True}
          and "tunnels" in applied.get("changed", [])
          and exited("xray") and exited("tunnels")
          and standins["sshd"].poll() is None,
          proc.stdout + proc.stderr)
    for p in standins.values():
        p.kill()
    cli("upstream-remove", "edge-1")  # scenario rows must not leak into
    cli("upstream-remove", "tun-1")   # the exact-list checks below
    proc = subprocess.run([sys.executable, users_py, "--json", "status"],
                          env=env_pid, capture_output=True, text=True)
    check("status restart_via is 'container' in pidfile mode",
          json.loads(proc.stdout)["restart_via"] == "container",
          proc.stdout)
    rc, out, _ = cli("--json", "status")
    check("status restart_via is null without a channel",
          json.loads(out)["restart_via"] is None, out)

    # ssh upstream keys supplied as content are stored on the node.
    key_path = os.path.join(workdir, "tun-2.pem")
    with open(key_path, "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "ZmFrZS10dW4tMg==\n-----END OPENSSH PRIVATE KEY-----\n")
    stored = os.path.join(workdir, "data", "ssh_client_keys", "tun-2.key")
    rc, out, err = cli("--json", "upstream-add", "tun-2", "--proto", "ssh",
                       "--addr", "203.0.113.11", "--port", "22",
                       "--username", "tunnel", "--key-content-file", key_path)
    check("upstream-add with --key-content-file stores the key",
          rc == 0 and json.loads(out)["key_file"] == "/keys/tun-2.key"
          and os.path.exists(stored)
          and "ZmFrZS10dW4tMg==" in open(stored).read()
          and (os.stat(stored).st_mode & 0o777) == 0o600, err + out)
    rc, _, err = cli("upstream-add", "tun-bad", "--proto", "ssh",
                     "--addr", "203.0.113.12", "--port", "22",
                     "--username", "tunnel", "--key-content-file", pub_path)
    check("upstream-add rejects non-key content", rc != 0, err)
    rc, out, err = cli("--json", "upstream-edit", "tun-2",
                       "--key-content-file", key_path)
    check("upstream-edit replaces the stored key",
          rc == 0 and json.loads(out)["key_file"] == "/keys/tun-2.key",
          err + out)
    rc, _, err = cli("upstream-remove", "tun-2")
    check("upstream-remove deletes the stored key",
          rc == 0 and not os.path.exists(stored), err)

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

    # ---- remaining engine-CLI surface: full user lifecycle, upstream /
    # route toggles + removal, gen-paths, render-keys, remaining settings.
    # Field-level assertions read the DB directly where the CLI's own
    # list output omits the field (note, passwords, keys).
    def dbval(sql, params=()):
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(sql, params).fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    key_path = os.path.join(workdir, "dave.pub")
    dave_key = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDaveTestKey"
                "0123456789abcdef0123456789abcdef01234567 dave@test")
    with open(key_path, "w") as f:
        f.write(dave_key + "\n")
    rc, out, err = cli("--json", "add", "dave", "--group", "intl",
                       "--note", "via cli", "--ssh-key-file", key_path)
    try:
        dave = json.loads(out)
    except ValueError:
        dave = {}
    check("add with group/note/ssh-key-file",
          rc == 0 and bool(dave.get("password")), err + out)
    check("add stored the ssh key + group + note",
          dbval("SELECT ssh_pubkey FROM users WHERE username='dave'") == dave_key
          and dbval("SELECT upstream_group FROM users WHERE username='dave'") == "intl"
          and dbval("SELECT note FROM users WHERE username='dave'") == "via cli")
    rc, out, err = cli("passwd", "dave")
    new_pw = dbval("SELECT trojan_password FROM users WHERE username='dave'")
    check("passwd rotates the password",
          rc == 0 and bool(new_pw) and new_pw != dave.get("password"),
          err + out)
    keys_out = os.path.join(workdir, "keys_out")
    rc, out, err = cli("render-keys", "--out", keys_out)
    keys_flat = open(keys_out).read() if rc == 0 and os.path.exists(keys_out) else ""
    check("render-keys emits dave's key", rc == 0 and dave_key in keys_flat, err)
    rc, _, err = cli("setkey", "dave", "--clear")
    check("setkey --clear (dave)", rc == 0
          and dbval("SELECT ssh_pubkey FROM users WHERE username='dave'") is None,
          err)
    rc, _, err = cli("setgroup", "dave", "backup")
    check("setgroup via node CLI", rc == 0
          and dbval("SELECT upstream_group FROM users WHERE username='dave'") == "backup",
          err)
    rc, _, err = cli("setnote", "dave", "")
    check("setnote empty clears", rc == 0
          and dbval("SELECT note FROM users WHERE username='dave'") is None, err)
    rc, _, err = cli("disable", "dave")
    check("disable user via node CLI", rc == 0
          and dbval("SELECT enabled FROM users WHERE username='dave'") == 0, err)
    rc, _, err = cli("enable", "dave")
    check("enable user via node CLI", rc == 0
          and dbval("SELECT enabled FROM users WHERE username='dave'") == 1, err)
    rc, out, _ = cli("--json", "list")
    check("list flags dave's group + no key",
          any(u["username"] == "dave" and u["group"] == "backup"
              and u["ssh_key"] is False for u in json.loads(out)), out)
    rc, _, err = cli("remove", "dave")
    check("remove user via node CLI", rc == 0
          and dbval("SELECT COUNT(*) FROM users WHERE username='dave'") == 0, err)

    rc, out, _ = cli("--json", "upstream-list")
    check("--json upstream-list shows up1",
          [u["name"] for u in json.loads(out)] == ["up1"], out)
    rc, _, err = cli("upstream-disable", "up1")
    check("upstream-disable via node CLI", rc == 0
          and dbval("SELECT enabled FROM upstreams WHERE name='up1'") == 0, err)
    rc, _, err = cli("upstream-enable", "up1")
    check("upstream-enable via node CLI", rc == 0
          and dbval("SELECT enabled FROM upstreams WHERE name='up1'") == 1, err)
    rc, _, err = cli("upstream-remove", "up1")
    check("upstream-remove via node CLI", rc == 0
          and dbval("SELECT COUNT(*) FROM upstreams WHERE name='up1'") == 0, err)

    rc, out, _ = cli("--json", "route-list")
    routes = json.loads(out)
    check("--json route-list shows the route",
          len(routes) == 1 and routes[0]["pattern"] == "example.com", out)
    rc, _, err = cli("route-disable", "1")
    check("route-disable via node CLI", rc == 0
          and dbval("SELECT enabled FROM routes WHERE id=1") == 0, err)
    rc, _, err = cli("route-enable", "1")
    check("route-enable via node CLI", rc == 0
          and dbval("SELECT enabled FROM routes WHERE id=1") == 1, err)
    rc, _, err = cli("route-remove", "1")
    check("route-remove via node CLI", rc == 0
          and dbval("SELECT COUNT(*) FROM routes WHERE id=1") == 0, err)

    rc, out, err = cli("gen-paths", "3")
    paths = [ln for ln in out.splitlines() if "/" in ln]
    check("gen-paths prints N paths", rc == 0 and len(paths) == 3, err + out)

    rc, _, err = cli("settings", "--trojan-ws-paths", "/t1,/t2",
                     "--upstream-strategy", "roundRobin",
                     "--ss-method", "aes-128-gcm")
    check("settings remaining keys via CLI", rc == 0, err)
    rc, out, _ = cli("--json", "settings")
    st = json.loads(out)
    check("settings remaining keys persisted",
          st["trojan_ws_paths"] == ["/t1", "/t2"]
          and st["upstream_strategy"] == "roundRobin"
          and st["ss_method"] == "aes-128-gcm", out)
    rc, _, _ = cli("settings", "--upstream-strategy", "bogus")
    check("settings rejects a bogus strategy", rc != 0)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
