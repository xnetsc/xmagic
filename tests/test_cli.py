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
    env = dict(os.environ, PROXY_DB=db_path, XMAGIC_DOCKER_SOCK="/nonexistent.sock",
               XMAGIC_ENABLE_SSH="1")
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
    listed = {u["username"]: u for u in json.loads(out)}
    check("--json list records carry credentials (API parity)",
          bool(listed["alice"]["vless_uuid"])
          and bool(listed["alice"]["password"])
          and bool(listed["alice"]["ss_password"]), out)

    # ---- --json parity: every user mutation answers with the canonical
    # record (or a removal receipt), never human text
    rc, out, err = cli("--json", "add", "jsonuser")
    rec = json.loads(out) if rc == 0 else {}
    check("--json add emits the canonical user record",
          rec.get("username") == "jsonuser" and rec.get("ssh_key") is False
          and "ssh_fingerprint" in rec and "created_at" in rec, err + out)
    rc, out, err = cli("--json", "setmethod", "jsonuser", "aes-128-gcm")
    rec = json.loads(out) if rc == 0 else {}
    check("--json setmethod returns the record with the new method",
          rec.get("ss_method") == "aes-128-gcm"
          and bool(rec.get("vless_uuid")), err + out)
    rc, out, err = cli("--json", "setnote", "jsonuser", "via json")
    rec = json.loads(out) if rc == 0 else {}
    check("--json setnote returns the record",
          rec.get("note") == "via json", err + out)
    rc, out, err = cli("--json", "setgroup", "jsonuser", "team")
    rec = json.loads(out) if rc == 0 else {}
    check("--json setgroup returns the record",
          rec.get("group") == "team", err + out)
    rc, out, err = cli("--json", "disable", "jsonuser")
    rec = json.loads(out) if rc == 0 else {}
    check("--json disable returns the record",
          rec.get("enabled") is False, err + out)
    rc, out, err = cli("--json", "enable", "jsonuser")
    rec = json.loads(out) if rc == 0 else {}
    check("--json enable returns the record",
          rec.get("enabled") is True, err + out)
    key_base = os.path.join(workdir, "jsonuser_key")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C",
                    "json@test", "-f", key_base],
                   capture_output=True, check=True)
    rc, out, err = cli("--json", "setkey", "jsonuser",
                       "--ssh-key-file", key_base + ".pub")
    rec = json.loads(out) if rc == 0 else {}
    check("--json setkey returns the record with key + fingerprint",
          bool(rec.get("ssh_pubkey"))
          and (rec.get("ssh_fingerprint") or "").startswith("SHA256:"),
          err + out)
    rc, out, err = cli("--json", "passwd", "jsonuser")
    rec = json.loads(out) if rc == 0 else {}
    check("--json passwd returns the full record, not just passwords",
          bool(rec.get("password")) and rec.get("group") == "team",
          err + out)
    rc, out, err = cli("--json", "rotate-uuid", "jsonuser")
    rec = json.loads(out) if rc == 0 else {}
    check("--json rotate-uuid returns the full record",
          bool(rec.get("vless_uuid")) and bool(rec.get("ss_password")),
          err + out)
    rc, out, err = cli("--json", "remove", "jsonuser")
    check("--json remove returns a removal receipt",
          rc == 0 and json.loads(out) == {"removed": "jsonuser"},
          err + out)
    rc, out, err = cli("--json", "init")
    check("--json init returns the database identity",
          rc == 0 and json.loads(out).get("type") == "sqlite", err + out)
    rc, out, err = cli("--json", "db-add", "tmpdb", "--type", "sqlite",
                       "--path", os.path.join(workdir, "tmp.db"))
    check("--json db-add", rc == 0
          and json.loads(out)["name"] == "tmpdb", err + out)
    rc, out, err = cli("--json", "db-remove", "tmpdb")
    check("--json db-remove returns a receipt",
          rc == 0 and json.loads(out) == {"removed": "tmpdb"}, err + out)
    rc, _, _ = cli("upstream-add", "up1", "--proto", "ss", "--addr", "10.0.0.9",
                   "--port", "8388", "--password", "pw")
    check("upstream-add", rc == 0)
    rc, out, _ = cli("--json", "route-add", "--kind", "domain",
                     "--pattern", "example.com", "--to", "block")
    check("--json route-add", rc == 0 and json.loads(out)["pattern"] == "example.com")
    rc, out, _ = cli("--json", "route-list")
    rid = json.loads(out)[0]["id"]
    rc, out, err = cli("--json", "route-disable", str(rid))
    rt = json.loads(out) if rc == 0 else {}
    check("--json route-disable returns the row",
          rt.get("enabled") in (0, False) and rt.get("id") == rid, err + out)
    rc, out, err = cli("--json", "route-enable", str(rid))
    rt = json.loads(out) if rc == 0 else {}
    check("--json route-enable returns the row",
          rt.get("enabled") in (1, True), err + out)
    rc, out, err = cli("--json", "upstream-disable", "up1")
    up = json.loads(out) if rc == 0 else {}
    check("--json upstream-disable returns the row",
          up.get("enabled") in (0, False) and up.get("name") == "up1",
          err + out)
    rc, out, err = cli("--json", "upstream-enable", "up1")
    up = json.loads(out) if rc == 0 else {}
    check("--json upstream-enable returns the row",
          up.get("enabled") in (1, True), err + out)
    rc, out, err = cli("--json", "route-remove", str(rid))
    check("--json route-remove returns a receipt",
          rc == 0 and json.loads(out) == {"removed": rid}, err + out)
    rc, out, err = cli("--json", "route-add", "--kind", "domain",
                       "--pattern", "example.com", "--to", "block")
    check("route re-added for the checks below", rc == 0, err + out)
    rc, out, _ = cli("status")
    check("status (human)", rc == 0 and "users: 2/2 enabled" in out, out)
    rc, out, _ = cli("--json", "status")
    st = json.loads(out)
    check("--json status", st["users_enabled"] == 2 and st["admin_registered"] is False)
    voff_path = os.path.join(workdir, "voff.json")
    rc, out, _ = cli("render", "--out", voff_path)
    vcfg = json.load(open(voff_path))
    rc, out, err = cli("--json", "render", "--out",
                       os.path.join(workdir, "vjson.json"))
    rj = json.loads(out) if rc == 0 else {}
    check("--json render returns a summary",
          rj.get("users") == 2 and "strategy" in rj, err + out)
    rc, out, err = cli("--json", "render-keys", "--out",
                       os.path.join(workdir, "ak.txt"))
    kj = json.loads(out) if rc == 0 else {}
    check("--json render-keys returns a summary",
          kj.get("keys") == 0, err + out)
    rc, out, err = cli("--json", "gen-paths", "2")
    pj = json.loads(out) if rc == 0 else []
    check("--json gen-paths returns an array",
          rc == 0 and len(pj) == 2
          and all(x.startswith("/") for x in pj), err + out)
    check("VLESS off by default: no vless-ws inbound, mux clients empty",
          all(i["tag"] != "vless-ws-0" for i in vcfg["inbounds"])
          and vcfg["inbounds"][0]["settings"]["clients"] == [],
          json.dumps([i["tag"] for i in vcfg["inbounds"]]))
    # Policy pin: REALITY is an independent inbound with its own
    # switch - it must never drag the plaintext protocols back on.
    # With reality on (the default) and vless off (the default), the
    # render holds a reality inbound and NO vless-ws inbound, and the
    # mux still authenticates nobody.
    reality_in = next((i for i in vcfg["inbounds"] if i["tag"] == "reality"),
                      None)
    rc, out, _ = cli("--json", "settings")
    st0 = json.loads(out) if rc == 0 else {}
    check("reality on + vless off: reality inbound present, no vless-ws,"
          " mux clients empty (independent switches)",
          reality_in is not None
          and all(not i["tag"].startswith("vless-ws")
                  for i in vcfg["inbounds"])
          and vcfg["inbounds"][0]["settings"]["clients"] == []
          and st0.get("reality_enabled") is True
          and st0.get("vless_enabled") is False,
          json.dumps([i["tag"] for i in vcfg["inbounds"]]) + out)
    check("reality inbound clients are the users, with vision flow",
          reality_in is not None
          and {c["id"] for c in reality_in["settings"]["clients"]}
              == {u["vless_uuid"] for u in json.loads(
                      cli("--json", "list")[1])}
          and all(c["flow"] == "xtls-rprx-vision"
                  for c in reality_in["settings"]["clients"]),
          json.dumps(reality_in))
    # SS over WS rides the same mux as the other WS families: one
    # backend inbound per path, the bare SS client list, and a mux
    # fallback entry pointing at it.
    ssws_in = next((i for i in vcfg["inbounds"] if i["tag"] == "ss-ws-0"),
                   None)
    users_now = json.loads(cli("--json", "list")[1])
    check("ss-ws inbound on by default: /ss-ws path, ss clients, fallback",
          ssws_in is not None
          and ssws_in["streamSettings"] == {
              "network": "ws", "wsSettings": {"path": "/ss-ws"}}
          and {c["password"] for c in ssws_in["settings"]["clients"]}
              == {u["ss_password"] for u in users_now}
          and {c["email"] for c in ssws_in["settings"]["clients"]}
              == {u["username"] for u in users_now}
          and {"path": "/ss-ws", "dest": ssws_in["port"]}
              in vcfg["inbounds"][0]["settings"]["fallbacks"]
          and st0.get("ss_ws_paths") == ["/ss-ws"]
          and st0.get("ss_ws_paths_from_db") is False,
          json.dumps(ssws_in) + out)
    rc, out, err = cli("upstream-add", "upv", "--proto", "vless-ws",
                       "--addr", "10.0.0.9", "--port", "443",
                       "--uuid", "11111111-2222-3333-4444-555555555555")
    check("vless upstream refused while the protocol is off",
          rc != 0, out + err)
    rc, out, err = cli("upstream-add", "upb", "--proto", "ss",
                       "--addr", "10.0.0.9", "--port", "8388",
                       "--password", "pw", "--method", "aes-999-bogus")
    check("bogus ss method refused at add time", rc != 0, out + err)
    rc, out, _ = cli("settings", "--vless", "on")
    check("settings --vless on (VLESS is opt-in)",
          rc == 0 and "vless_enabled: True" in out, out)
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
    rc, out, _ = cli("settings", "--ss-ws-paths", "/s1,/s2")
    check("settings ss-ws paths set via CLI", rc == 0 and "/s1" in out, out)
    rc, out, _ = cli("--json", "settings")
    check("settings --json shows db ss-ws paths",
          json.loads(out)["ss_ws_paths"] == ["/s1", "/s2"]
          and json.loads(out)["ss_ws_paths_from_db"] is True, out)
    rc, out, err = cli("apply")
    applied_cfg = json.load(open(config_path)) if rc == 0 else {}
    ssws_tags = [i["tag"] for i in applied_cfg.get("inbounds", [])]
    ssws_paths = sorted(
        i["streamSettings"]["wsSettings"]["path"]
        for i in applied_cfg.get("inbounds", [])
        if i["tag"].startswith("ss-ws-"))
    check("apply re-renders ss-ws inbounds for the db paths",
          rc == 0 and ssws_tags.count("ss-ws-0") == 1
          and "ss-ws-1" in ssws_tags and ssws_paths == ["/s1", "/s2"],
          err + json.dumps(ssws_tags))
    rc, _, _ = cli("settings", "--ss-ws-paths", "")
    check("settings ss-ws paths cleared back to env", rc == 0)

    # ---- parity: same DB through the web console
    server_env = dict(env, XMAGIC_ADMIN_BIND="127.0.0.1",
                      XMAGIC_ADMIN_PORT=str(t.PORT))
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
        _, opts = client.options("register")
        status, body = client.verify(
            "register", auth.attestation(opts["challenge"], "localhost"))
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

    # ---- user keys are minted on the client side ONLY: the node CLI
    # refuses to generate them (a private key born on the server is a
    # private key leaked to the server)
    keys_dir = os.path.join(workdir, "keys")
    os.makedirs(keys_dir)
    rc, _, _ = cli("keygen", "kg1", "--out-dir", keys_dir)
    check("keygen is gone from the node CLI", rc != 0)
    rc, _, _ = cli("add", "kdave", "--ssh-key-generate", "kdave.key")
    check("add --ssh-key-generate is gone from the node CLI", rc != 0)
    # client-minted fixture pairs stand in for keys a user generated in
    # the browser page or the remote CLI; only .pub files reach the node
    FIXTURE_A_PRIV = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB+WOt/zaK6VjjfYQ1yEU/R7W+jm+UqFvJsoVszj6tndgAAAJil3EqxpdxK
sQAAAAtzc2gtZWQyNTUxOQAAACB+WOt/zaK6VjjfYQ1yEU/R7W+jm+UqFvJsoVszj6tndg
AAAEDjLMZS4jbzx+TTyEyzQAL9b+YD7P8bN8fq62vLV1/EGX5Y63/NorpWON9hDXIRT9Ht
b6Ob5SoW8myhWzOPq2d2AAAAEHhtYWdpYyBmaXh0dXJlLWEBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"""
    FIXTURE_A_PUB = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH5Y63/NorpWON9"
                     "hDXIRT9Htb6Ob5SoW8myhWzOPq2d2 xmagic fixture-a")
    FIXTURE_B_PRIV = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCuEwuCWalst9A82xP3NxULSiR3XuLQLHZV2RhujBe04gAAAJjvASaE7wEm
hAAAAAtzc2gtZWQyNTUxOQAAACCuEwuCWalst9A82xP3NxULSiR3XuLQLHZV2RhujBe04g
AAAEAIznhF1QSUbR3o2wsbMMIOgB/+XRAVJTQRVGFa9j1MN64TC4JZqWy30DzbE/c3FQtK
JHde4tAsdlXZGG6MF7TiAAAAEHhtYWdpYyBmaXh0dXJlLWIBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"""
    FIXTURE_B_PUB = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK4TC4JZqWy30DzbE"
                     "/c3FQtKJHde4tAsdlXZGG6MF7Ti xmagic fixture-b")
    kg1_priv = os.path.join(keys_dir, "kg1")
    with open(kg1_priv, "w") as f:
        f.write(FIXTURE_A_PRIV)
    os.chmod(kg1_priv, 0o600)
    with open(kg1_priv + ".pub", "w") as f:
        f.write(FIXTURE_A_PUB + "\n")
    dave_key = os.path.join(workdir, "kdave.key")
    with open(dave_key, "w") as f:
        f.write(FIXTURE_B_PRIV)
    os.chmod(dave_key, 0o600)
    dave_pub = os.path.join(workdir, "kdave.pub")
    with open(dave_pub, "w") as f:
        f.write(FIXTURE_B_PUB + "\n")
    if shutil.which("ssh-keygen"):
        derived = subprocess.run(["ssh-keygen", "-y", "-f", dave_key],
                                 capture_output=True, text=True).stdout.split()[:2]
        check("client-minted fixture pair is real (ssh-keygen -y agrees)",
              derived == FIXTURE_B_PUB.split()[:2])
    rc, out, err = cli("--json", "add", "kdave", "--group", "team",
                       "--ssh-key-file", dave_pub)
    dave = json.loads(out) if rc == 0 else {}
    check("add --ssh-key-file registers the client-minted pubkey",
          rc == 0 and dave.get("ssh_key") is True, err + out)
    rc, out, _ = cli("--json", "list")
    kdave = next(u for u in json.loads(out) if u["username"] == "kdave")
    check("--json list carries the full ssh pubkey for automation",
          kdave["ssh_pubkey"] == FIXTURE_B_PUB
          and kdave["ssh_fingerprint"]
          == "SHA256:bNmrOHDN63AWm7TXHGthrY+y2dwnI5Ub4k2a30yM9Ek", out)
    rc, out, _ = cli("list")
    check("human list shows the key fingerprint, not just yes",
          "SHA256:bNmrOHDN63AWm7TXHGthrY+y2dwnI5Ub4k2a30yM9Ek" in out, out)
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
        check("kdave's registered pubkey is the one in authorized_keys",
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
    rc, out, _ = cli("--json", "sessions-revoke-all")
    check("--json revoke-all returns a receipt",
          rc == 0 and isinstance(json.loads(out).get("revoked"), int), out)
    rc, out, _ = cli("sessions-revoke-all")
    check("CLI revoke-all", rc == 0 and "revoked" in out, out)
    rc, out, _ = cli("--json", "admin-reset")
    check("--json admin-reset returns a receipt",
          rc == 0 and json.loads(out) == {"reset": True}, out)
    rc, out, _ = cli("admin-reset")
    check("admin-reset", rc == 0 and "no admin passkey" in out, out)

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

    # SS upstreams: a path switches the dial to SS over WS (the CDN
    # shape), --tls wraps it in TLS with SNI = the upstream address;
    # without a path the outbound stays bare, with no streamSettings.
    rc, _, err = cli("upstream-add", "upssw", "--proto", "ss",
                     "--addr", "cdn.example.com", "--port", "443",
                     "--password", "pw", "--path", "/ss-ws", "--tls")
    check("ss upstream with path+tls accepted", rc == 0, err)
    rc, _, err = cli("upstream-add", "upssbare", "--proto", "ss",
                     "--addr", "10.0.0.9", "--port", "8388",
                     "--password", "pw")
    check("bare ss upstream accepted", rc == 0, err)
    ssout_path = os.path.join(workdir, "ssout.json")
    rc, out, err = cli("render", "--out", ssout_path)
    ocfg = json.load(open(ssout_path)) if rc == 0 else {}
    by_tag = {o["tag"]: o for o in ocfg.get("outbounds", [])}
    wss_out = by_tag.get("up-default-upssw", {})
    bare_out = by_tag.get("up-default-upssbare", {})
    check("ss upstream with path+tls renders a WSS stream",
          wss_out.get("streamSettings", {}).get("network") == "ws"
          and wss_out["streamSettings"]["wsSettings"] == {"path": "/ss-ws"}
          and wss_out["streamSettings"].get("security") == "tls"
          and wss_out["streamSettings"]["tlsSettings"]
              == {"serverName": "cdn.example.com"},
          err + json.dumps(wss_out))
    check("bare ss upstream renders no streamSettings",
          bare_out.get("protocol") == "shadowsocks"
          and "streamSettings" not in bare_out,
          err + json.dumps(bare_out))
    rc, _, err = cli("upstream-remove", "upssw")
    rc2, _, err2 = cli("upstream-remove", "upssbare")
    check("ss test upstreams removed again", rc == 0 and rc2 == 0,
          err + err2)

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

    # ------------------------------------------ ssh: off by default
    # SSH support is opt-in via XMAGIC_ENABLE_SSH (this suite's env
    # sets it). Without it the engine refuses every SSH-shaped
    # operation and reports ssh_enabled false; non-SSH operations
    # and stored ssh state are unaffected.
    env_off = {k: v for k, v in env.items() if k != "XMAGIC_ENABLE_SSH"}

    def cli_off(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_off, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, out, err = cli_off("setkey", "alice",
                           "--ssh-key-file", key_base + ".pub")
    check("ssh off: setkey refused",
          rc != 0 and "XMAGIC_ENABLE_SSH" in err + out, err + out)
    rc, out, err = cli_off("add", "sshoff",
                           "--ssh-key-file", key_base + ".pub")
    check("ssh off: add with an ssh key refused",
          rc != 0 and "XMAGIC_ENABLE_SSH" in err + out, err + out)
    rc, _, err = cli_off("add", "sshoff")
    check("ssh off: add without a key still works", rc == 0, err)
    rc, out, err = cli_off("upstream-add", "upoff", "--proto", "ssh",
                           "--addr", "10.2.2.2", "--port", "22",
                           "--username", "tun", "--key-generate")
    check("ssh off: ssh upstream add refused",
          rc != 0 and "XMAGIC_ENABLE_SSH" in err + out, err + out)
    rc, out, _ = cli_off("--json", "settings")
    check("ssh off: settings report ssh_enabled false",
          json.loads(out)["ssh_enabled"] is False, out)
    rc, out, _ = cli("--json", "settings")
    check("ssh on: settings report ssh_enabled true",
          json.loads(out)["ssh_enabled"] is True, out)
    rc, _, err = cli_off("setkey", "alice", "--clear")
    check("ssh off: clearing a key still works", rc == 0, err)

    # Single-form tunnel rendering names the STAGED client-key copy
    # (under the pid dir on /tmp), never the data-dir original.
    rc, _, err = cli("upstream-add", "uptun", "--proto", "ssh",
                     "--addr", "10.3.3.3", "--port", "22",
                     "--username", "tun", "--key-generate")
    check("ssh upstream for staging checks", rc == 0, err)
    pid_dir = os.path.join(workdir, "run")
    tun_dir = os.path.join(workdir, "tunout")
    proc = subprocess.run([sys.executable, users_py, "render",
                           "--out", os.path.join(tun_dir, "config.json")],
                          env=dict(env, XMAGIC_PID_DIR=pid_dir),
                          capture_output=True, text=True)
    sp = os.path.join(tun_dir, "start-tunnels.sh")
    script = open(sp).read() if os.path.exists(sp) else ""
    check("single-form render points -i at the staged /tmp key copy",
          proc.returncode == 0
          and f"-i {pid_dir}/client_keys/uptun.key" in script,
          proc.stderr + script)
    # Rotating only the key CONTENT (same path) still counts as a
    # tunnels change, so apply relaunches them and re-stages.
    rc, _, err = cli("--json", "apply")
    check("apply settles before rotation check", rc == 0, err)
    rc, _, err = cli("upstream-edit", "uptun",
                     "--key-content-file", key_base)
    check("rotate tunnel key content", rc == 0, err)
    rc, out, err = cli("--json", "apply")
    applied = json.loads(out) if rc == 0 else {}
    check("key-content rotation relaunches tunnels on apply",
          applied.get("changed") == ["tunnels"], err + out)
    rc, _, _ = cli("upstream-remove", "uptun")

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
