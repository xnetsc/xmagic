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
    # --- protocol defaults: only the WS carriers render by default.
    # VMess-WS is on (self-encrypted); the bare-TCP forms (bare
    # VMess, bare SS, REALITY) and the HTTP proxy are opt-in.
    # REALITY stays an independent inbound with its own switch - it
    # must never drag the plaintext protocols back on.
    tags = [i["tag"] for i in vcfg["inbounds"]]
    st0 = json.loads(cli("--json", "settings")[1])
    user_uuids = [u["vless_uuid"]
                  for u in json.loads(cli("--json", "list")[1])]
    vmessws_in = next(
        (i for i in vcfg["inbounds"] if i["tag"] == "vmess-ws-0"), None)
    vmux_fb = [f for f in vcfg["inbounds"][0]["settings"]["fallbacks"]
               if f.get("path") == "/vmess-ws"]
    check("vmess-ws on by default: inbound + mux fallback, ids are the"
          " users' uuids, alterId 0",
          vmessws_in is not None
          and vmessws_in["protocol"] == "vmess"
          and vmessws_in["port"] == 12400
          and vmessws_in["streamSettings"]["wsSettings"]["path"]
          == "/vmess-ws"
          and [c.get("id") for c in
               vmessws_in["settings"]["clients"]] == user_uuids
          and all(c.get("alterId") == 0
                  for c in vmessws_in["settings"]["clients"])
          and vmux_fb and vmux_fb[0]["dest"] == 12400
          and st0["vmess_ws_paths"] == ["/vmess-ws"]
          and st0["vmess_ws_paths_from_db"] is False,
          json.dumps(tags))
    check("bare forms off by default: no vmess / ss / reality / http-in"
          " inbound, settings report all four off",
          "vmess" not in tags and "ss" not in tags
          and "reality" not in tags and "http-in" not in tags
          and st0["vmess_tcp_enabled"] is False
          and st0["ss_tcp_enabled"] is False
          and st0["http_enabled"] is False
          and st0["reality_enabled"] is False
          and st0["vless_enabled"] is False,
          json.dumps(tags) + json.dumps(st0))

    # each bare form renders once its own switch is on
    bare_path = os.path.join(workdir, "bare.json")
    rc, out, _ = cli("settings", "--vmess-tcp", "on")
    check("settings --vmess-tcp on", rc == 0
          and "vmess_tcp_enabled: True" in out, out)
    cli("render", "--out", bare_path)
    bcfg = json.load(open(bare_path))
    vmess_in = next((i for i in bcfg["inbounds"]
                     if i["tag"] == "vmess"), None)
    check("vmess bare inbound rendered once enabled: ids + alterId 0",
          vmess_in is not None and vmess_in["port"] == 18084
          and [c.get("id") for c in
               vmess_in["settings"]["clients"]] == user_uuids
          and all(c.get("alterId") == 0
                  for c in vmess_in["settings"]["clients"]),
          json.dumps(vmess_in))
    rc, out, _ = cli("settings", "--ss-tcp", "on")
    check("settings --ss-tcp on", rc == 0
          and "ss_tcp_enabled: True" in out, out)
    cli("render", "--out", bare_path)
    bcfg = json.load(open(bare_path))
    check("ss bare inbound rendered once enabled",
          any(i["tag"] == "ss" and i["port"] == 12003
              for i in bcfg["inbounds"]),
          json.dumps([i["tag"] for i in bcfg["inbounds"]]))
    rc, out, _ = cli("settings", "--http", "on")
    check("settings --http on", rc == 0
          and "http_enabled: True" in out, out)
    cli("render", "--out", bare_path)
    bcfg = json.load(open(bare_path))
    check("http inbound rendered once enabled",
          any(i["tag"] == "http-in" for i in bcfg["inbounds"]),
          json.dumps([i["tag"] for i in bcfg["inbounds"]]))
    rc, out, _ = cli("settings", "--reality", "on")
    check("settings --reality on", rc == 0
          and "reality_enabled: True" in out, out)
    cli("render", "--out", bare_path)
    bcfg = json.load(open(bare_path))
    reality_in = next((i for i in bcfg["inbounds"]
                       if i["tag"] == "reality"), None)
    check("reality renders once enabled while vless stays off:"
          " reality inbound, no vless-ws, mux clients empty",
          reality_in is not None
          and reality_in["protocol"] == "vless"
          and reality_in["streamSettings"]["security"] == "reality"
          and reality_in["streamSettings"]["realitySettings"]["target"]
          == "www.microsoft.com:443"
          and all(not i["tag"].startswith("vless-ws")
                  for i in bcfg["inbounds"])
          and bcfg["inbounds"][0]["settings"]["clients"] == [],
          json.dumps([i["tag"] for i in bcfg["inbounds"]]))
    check("reality inbound clients are the users, with vision flow",
          reality_in is not None
          and {c["id"] for c in reality_in["settings"]["clients"]}
              == set(user_uuids)
          and all(c["flow"] == "xtls-rprx-vision"
                  for c in reality_in["settings"]["clients"]),
          json.dumps(reality_in))
    # back to the defaults for the rest of the suite
    cli("settings", "--vmess-tcp", "off", "--ss-tcp", "off",
        "--http", "off", "--reality", "off")
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
    rc, out, err = cli("upstream-add", "badvmws", "--proto", "vmess-ws",
                       "--addr", "10.0.0.9", "--port", "443")
    check("upstream-add vmess-ws without --uuid fails",
          rc != 0, out + err)
    rc, out, err = cli("upstream-add", "badvm", "--proto", "vmess",
                       "--addr", "10.0.0.9", "--port", "10086",
                       "--uuid", "11111111-2222-3333-4444-555555555555")
    check("upstream-add bare vmess refused while vmess TCP is off",
          rc != 0 and "vmess-tcp" in err, out + err)
    rc, out, err = cli("upstream-add", "okvmws", "--proto", "vmess-ws",
                       "--addr", "10.0.0.9", "--port", "443",
                       "--uuid", "11111111-2222-3333-4444-555555555555")
    check("upstream-add vmess-ws is not gated by vmess TCP",
          rc == 0, out + err)
    cli("upstream-remove", "okvmws")
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
    rc, out, _ = cli("settings", "--vmess-ws-paths", "/m1,/m2")
    check("settings vmess-ws paths set via CLI",
          rc == 0 and "/m1" in out, out)
    rc, out, _ = cli("--json", "settings")
    check("settings --json shows db vmess-ws paths",
          json.loads(out)["vmess_ws_paths"] == ["/m1", "/m2"]
          and json.loads(out)["vmess_ws_paths_from_db"] is True, out)
    rc, out, err = cli("apply")
    applied_cfg = json.load(open(config_path)) if rc == 0 else {}
    mvws_tags = [i["tag"] for i in applied_cfg.get("inbounds", [])]
    mvws_paths = sorted(
        i["streamSettings"]["wsSettings"]["path"]
        for i in applied_cfg.get("inbounds", [])
        if i["tag"].startswith("vmess-ws-"))
    check("apply re-renders vmess-ws inbounds for the db paths",
          rc == 0 and mvws_tags.count("vmess-ws-0") == 1
          and "vmess-ws-1" in mvws_tags and mvws_paths == ["/m1", "/m2"],
          err + json.dumps(mvws_tags))
    rc, _, _ = cli("settings", "--vmess-ws-paths", "")
    check("settings vmess-ws paths cleared back to env", rc == 0)

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
    check("default render: no freedom finalRules while nobody holds"
          " a slice (all users keyless so far), private targets stay"
          " blocked",
          rules0 == [], json.dumps(direct))
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
    check("interconnect on by default: slices are claimed at add time,"
          " keyed users only (keyless alice/bob/carol hold none)",
          info.get("interconnect_off_groups") == []
          and info.get("interconnect_slices") == {
              "kdave": [20000, 20015], "kerin": [20016, 20031]}, out)
    rc, out, _ = cli("render", "--out", cfg_path)
    cfg = json.load(open(cfg_path))
    rules = cfg["routing"]["rules"]
    band = [r for r in rules if r.get("outboundTag") == "direct"
            and r.get("ip") == ["127.0.0.0/8"]]
    blocks = [r for r in rules if r.get("outboundTag") == "block"
              and r.get("ip") == ["127.0.0.0/8"]]
    direct = [o for o in cfg["outbounds"] if o.get("tag") == "direct"][0]
    by_port = {r.get("port"): r.get("user") for r in band}
    check("interconnect render: one slice rule per holder, dialers are"
          " the holder's groupmates, loopback block, loopback-only"
          " finalRule",
          len(band) == 2
          and by_port.get("20000-20015") == ["kdave", "kerin"]
          and by_port.get("20016-20031") == ["kdave", "kerin"]
          and set(by_port) == {"20000-20015", "20016-20031"}
          and len(blocks) == 1
          and direct.get("settings", {}).get("finalRules", [{}])[0].get("ip")
          == ["127.0.0.0/8"], json.dumps(rules))
    keys_out = os.path.join(workdir, "data", "authorized_keys")
    rc, out, _ = cli("render-keys", "--out", keys_out)
    ktext = open(keys_out).read()
    check("interconnect keys: every holder carries their own slice only",
          'permitlisten="127.0.0.1:20000"' in ktext
          and 'permitlisten="127.0.0.1:20016"' in ktext
          and ktext.count("permitlisten=") == 32, ktext[:160])
    if shutil.which("ssh-keygen"):
        derived = subprocess.run(["ssh-keygen", "-y", "-f", dave_key],
                                 capture_output=True, text=True).stdout
        check("kdave's registered pubkey is the one in authorized_keys",
              derived.split()[1] in ktext)
    rc, out, _ = cli("settings", "--interconnect-off-groups", "team")
    check("settings opt team out of interconnect",
          rc == 0 and "team" in out, out)
    rc, out, _ = cli("--json", "settings")
    check("opting a group out releases its members' slices",
          json.loads(out)["interconnect_slices"] == {}, out)
    rc, out, _ = cli("render", "--out", cfg_path)
    cfg = json.load(open(cfg_path))
    band = [r for r in cfg["routing"]["rules"]
            if r.get("outboundTag") == "direct"
            and r.get("ip") == ["127.0.0.0/8"]]
    check("opted-out group renders no slice rules",
          band == [], json.dumps(band))
    rc, out, _ = cli("settings", "--interconnect-off-groups", "")
    check("clearing the opt-out restores the default", rc == 0, out)
    rc, out, _ = cli("--json", "settings")
    check("re-enabled group regains its remembered blocks while they"
          " are still free (soft preference)",
          json.loads(out)["interconnect_slices"] == {
              "kdave": [20000, 20015], "kerin": [20016, 20031]}, out)

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
    check("a first key also claims a slice: config and keys change",
          applied.get("changed") == ["config", "keys"]
          and applied.get("restarted") == {"xray": True, "sshd": True}
          and exited("xray") and exited("sshd"),
          proc.stdout + proc.stderr)
    spawn("xray")
    spawn("sshd")
    pub2_path = os.path.join(workdir, "alice2.pub")
    with open(pub2_path, "w") as f:
        f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRotatedPidfileKey alice\n")
    rc, _, err = cli("setkey", "alice", "--ssh-key-file", pub2_path)
    check("rotate alice's key (slice unchanged)", rc == 0, err)
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

    # VMess upstreams mirror VLESS: vnext users carry the uuid with
    # alterId 0 / security auto; bare rides plain TCP (TLS optional),
    # vmess-ws rides the WS paths like the other WS families.
    rc, _, err = cli("settings", "--vmess-tcp", "on")
    check("vmess-tcp enabled for the bare upstream adds", rc == 0, err)
    rc, _, err = cli("upstream-add", "upvm", "--proto", "vmess",
                     "--addr", "10.0.0.9", "--port", "10086",
                     "--uuid", "11111111-2222-3333-4444-555555555555")
    check("bare vmess upstream accepted once enabled", rc == 0, err)
    rc, _, err = cli("upstream-add", "upvmws", "--proto", "vmess-ws",
                     "--addr", "cdn.example.com", "--port", "443",
                     "--uuid", "22222222-3333-4444-5555-666666666666",
                     "--tls")
    check("vmess-ws upstream with tls accepted", rc == 0, err)
    rc, out, err = cli("render", "--out", ssout_path)
    ocfg = json.load(open(ssout_path)) if rc == 0 else {}
    by_tag = {o["tag"]: o for o in ocfg.get("outbounds", [])}
    vm_out = by_tag.get("up-default-upvm", {})
    vm_user = (vm_out.get("settings", {}).get("vnext", [{}])[0]
               .get("users", [{}])[0])
    check("bare vmess outbound: vnext user id/alterId/security, tcp",
          vm_out.get("protocol") == "vmess"
          and vm_user.get("id")
              == "11111111-2222-3333-4444-555555555555"
          and vm_user.get("alterId") == 0
          and vm_user.get("security") == "auto"
          and vm_out.get("streamSettings", {}).get("network") == "tcp"
          and vm_out.get("streamSettings", {}).get("security") == "none",
          err + json.dumps(vm_out))
    vmws_out = by_tag.get("up-default-upvmws", {})
    vmws_ss = vmws_out.get("streamSettings", {})
    check("vmess-ws outbound: ws path + tls + serverName",
          vmws_out.get("protocol") == "vmess"
          and vmws_ss.get("network") == "ws"
          and vmws_ss.get("wsSettings", {}).get("path") == "/vmess-ws"
          and vmws_ss.get("security") == "tls"
          and vmws_ss.get("tlsSettings", {}).get("serverName")
              == "cdn.example.com",
          err + json.dumps(vmws_out))
    rc, _, err = cli("upstream-remove", "upvm")
    rc2, _, err2 = cli("upstream-remove", "upvmws")
    check("vmess test upstreams removed again", rc == 0 and rc2 == 0,
          err + err2)
    cli("settings", "--vmess-tcp", "off")

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
    rc, out, _ = cli_off("settings")
    check("ssh off: settings text marks interconnect unavailable",
          rc == 0
          and "interconnect: unavailable (SSH not enabled)" in out, out)
    rc, out, _ = cli_off("settings", "--interconnect-off-groups", "team")
    check("ssh off: interconnect opt-out still editable, shown with"
          " the unavailable mark",
          rc == 0 and "interconnect_off_groups: team" in out
          and "interconnect: unavailable (SSH not enabled)" in out, out)
    rc, out, _ = cli_off("--json", "settings")
    check("ssh off: stored interconnect opt-out survives in the payload",
          json.loads(out)["interconnect_off_groups"] == ["team"], out)
    rc, _, err = cli_off("settings", "--interconnect-off-groups", "")
    check("ssh off: clearing the interconnect opt-out still works",
          rc == 0, err)
    rc, out, _ = cli("settings")
    check("ssh on: settings text marks interconnect available",
          rc == 0 and "interconnect: available" in out
          and "unavailable" not in out, out)
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

    # ---- sqlite migration: an upstreams CHECK without 'vmess' is
    # rebuilt on first open and the stored rows survive
    mig_db = os.path.join(workdir, "mig.db")
    raw = sqlite3.connect(mig_db)
    raw.execute("""CREATE TABLE upstreams (
      id INTEGER PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      grp TEXT NOT NULL DEFAULT 'default',
      address TEXT NOT NULL,
      port INTEGER NOT NULL,
      protocol TEXT NOT NULL CHECK (protocol IN ('vless-ws', 'vless',
        'trojan-ws', 'ss', 'http', 'socks', 'ssh')),
      path TEXT, uuid TEXT, username TEXT, password TEXT,
      key_file TEXT,
      tls INTEGER NOT NULL DEFAULT 0,
      method TEXT NOT NULL DEFAULT 'aes-256-gcm',
      enabled INTEGER NOT NULL DEFAULT 1,
      note TEXT,
      created_at TEXT NOT NULL DEFAULT '')""")
    raw.execute("INSERT INTO upstreams (name, address, port, protocol)"
                " VALUES ('old', '10.0.0.1', 8388, 'ss')")
    raw.commit()
    raw.close()
    proc = subprocess.run([sys.executable, users_py, "--json", "list"],
                          env=dict(os.environ, PROXY_DB=mig_db),
                          capture_output=True, text=True)
    raw = sqlite3.connect(mig_db)
    mig_ddl = raw.execute("SELECT sql FROM sqlite_master WHERE name ="
                          " 'upstreams'").fetchone()[0]
    mig_rows = raw.execute("SELECT COUNT(*) FROM upstreams"
                           ).fetchone()[0]
    raw.close()
    check("migration: upstreams CHECK rebuilt with vmess, rows survive",
          proc.returncode == 0 and "'vmess'" in mig_ddl
          and mig_rows == 1, mig_ddl)

    # ---- interconnect capacity under the allocation-table model.
    # The limit is on slices HELD (100 blocks), not on user count:
    # claims happen on the write paths, releases return blocks to
    # the pool. Fresh DBs keep the counts exact; holders are seeded
    # directly (user rows with keys + allocation rows).
    cap_db = os.path.join(workdir, "cap.db")
    env_cap = dict(env, PROXY_DB=cap_db)

    def cli_cap(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_cap, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, _, err = cli_cap("init")
    raw = sqlite3.connect(cap_db)
    for i in range(1, 101):
        name = f"cap{i:03d}"
        raw.execute(
            "INSERT INTO users (username, vless_uuid, trojan_password,"
            " ss_password, ss_method, ssh_pubkey, upstream_group,"
            " created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, f"uuid-{i}", "pw", "pw", "aes-256-gcm",
             f"ssh-ed25519 AAAA {name}", "capped",
             f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.000000+00:00"))
        lo = 20000 + (i - 1) * 16
        raw.execute(
            "INSERT INTO interconnect_allocations (username, port_lo,"
            " port_hi) VALUES (?,?,?)", (name, lo, lo + 15))
    raw.commit()
    raw.close()
    kg1pub = os.path.join(keys_dir, "kg1.pub")
    check("capacity fixture: fresh db, 100 keyed holders seeded", rc == 0,
          err)
    rc, out, err = cli_cap("add", "late1", "--group", "capped",
                           "--ssh-key-file", kg1pub)
    check("full pool: a keyed add that would need a slice is refused",
          rc != 0 and "late1" in err + out and "capped" in err + out
          and "20000-21599" in err + out and "100" in err + out,
          err + out)
    rc, _, err = cli_cap("add", "late1", "--group", "capped")
    check("keyless users never need a slice: the 101st user is added",
          rc == 0, err)
    rc, out, err = cli_cap("setkey", "late1", "--ssh-key-file", kg1pub)
    check("full pool: setkey refused when the claim cannot be served",
          rc != 0 and "20000-21599" in err + out, err + out)
    rc, out, _ = cli_cap("--json", "list")
    late1_rec = [u for u in json.loads(out)
                 if u["username"] == "late1"][0]
    check("refused setkey left the user keyless (write rolled back)",
          late1_rec["ssh_key"] is False, out)
    rc, _, err = cli_cap("disable", "cap001")
    check("disable releases the holder's slice", rc == 0, err)
    rc, _, err = cli_cap("setkey", "late1", "--ssh-key-file", kg1pub)
    check("setkey claims once a block is free", rc == 0, err)
    rc, out, _ = cli_cap("--json", "settings")
    cap_info = json.loads(out)
    check("the claim takes the lowest free block; other holders do"
          " not drift",
          cap_info["interconnect_slices"].get("late1") == [20000, 20015]
          and cap_info["interconnect_slices"].get("cap002")
          == [20016, 20031], out)
    raw = sqlite3.connect(cap_db)
    n_alloc = raw.execute("SELECT COUNT(*) FROM interconnect_allocations"
                          ).fetchone()[0]
    raw.close()
    check("settings capacity summary matches the allocation table",
          cap_info["interconnect_capacity"] == {
              "total_blocks": 100, "claimed_blocks": n_alloc,
              "free_blocks": 100 - n_alloc}, out)
    rc, _, err = cli_cap("settings", "--interconnect-off-groups", "late")
    check("opt a fresh group out", rc == 0, err)
    rc, _, err = cli_cap("add", "late9", "--group", "late",
                         "--ssh-key-file", kg1pub)
    check("keyed add into an opted-out group claims nothing",
          rc == 0, err)
    rc, out, err = cli_cap("settings", "--interconnect-off-groups", "")
    check("turning a group on refused when its member cannot claim",
          rc != 0 and "group 'late'" in err + out
          and "cannot be served: late9" in err + out, err + out)
    rc, out, _ = cli_cap("--json", "settings")
    check("refused turn-on leaves the stored opt-out untouched",
          json.loads(out)["interconnect_off_groups"] == ["late"], out)
    rc, _, err = cli_cap("disable", "cap002")
    check("disable another holder to free a block", rc == 0, err)
    rc, _, err = cli_cap("settings", "--interconnect-off-groups", "")
    check("turning the group on succeeds once a block is free",
          rc == 0, err)
    rc, out, _ = cli_cap("--json", "settings")
    check("the waiting member claims the freed block (lowest free)",
          json.loads(out)["interconnect_slices"].get("late9")
          == [20016, 20031], out)

    # ---- group opt-out releases, remembered blocks, soft preference
    cap2_db = os.path.join(workdir, "cap2.db")
    env_cap2 = dict(env, PROXY_DB=cap2_db)

    def cli_cap2(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_cap2, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    cli_cap2("init")
    for user, grp in (("a1", "ga"), ("a2", "ga"), ("b1", "gb")):
        rc, _, err = cli_cap2("add", user, "--group", grp,
                              "--ssh-key-file", kg1pub)
        assert rc == 0, err
    rc, out, _ = cli_cap2("--json", "settings")
    check("claims land lowest-free in claim order",
          json.loads(out)["interconnect_slices"] == {
              "a1": [20000, 20015], "a2": [20016, 20031],
              "b1": [20032, 20047]}, out)
    rc, _, err = cli_cap2("settings", "--interconnect-off-groups", "ga")
    check("opt group ga out", rc == 0, err)
    rc, out, _ = cli_cap2("--json", "settings")
    check("opting a group out releases its members' slices",
          json.loads(out)["interconnect_slices"] == {"b1": [20032, 20047]},
          out)
    rc, _, err = cli_cap2("add", "c1", "--group", "gc",
                          "--ssh-key-file", kg1pub)
    check("another group's newcomer can claim a released block",
          rc == 0, err)
    rc, out, _ = cli_cap2("--json", "settings")
    check("the newcomer took the lowest free (a1's old) block",
          json.loads(out)["interconnect_slices"].get("c1")
          == [20000, 20015], out)
    rc, _, err = cli_cap2("settings", "--interconnect-off-groups", "")
    check("turn group ga back on", rc == 0, err)
    rc, out, _ = cli_cap2("--json", "settings")
    slices2 = json.loads(out)["interconnect_slices"]
    check("remembered block taken: members land on other free blocks,"
          " nobody else drifts",
          slices2.get("a1") == [20016, 20031]
          and slices2.get("a2") == [20048, 20063]
          and slices2.get("b1") == [20032, 20047]
          and slices2.get("c1") == [20000, 20015], out)
    cap2_cfg = os.path.join(workdir, "cap2-config.json")
    rc, out, _ = cli_cap2("render", "--out", cap2_cfg)
    cfg2 = json.load(open(cap2_cfg))
    band2 = {r.get("port"): r.get("user")
             for r in cfg2["routing"]["rules"]
             if r.get("outboundTag") == "direct"
             and r.get("ip") == ["127.0.0.0/8"]}
    check("rendered rules follow the re-claimed slices",
          band2.get("20016-20031") == ["a1", "a2"]
          and band2.get("20048-20063") == ["a1", "a2"], json.dumps(band2))
    rc, _, err = cli_cap2("settings", "--interconnect-off-groups", "gb")
    check("opt group gb out", rc == 0, err)
    rc, _, err = cli_cap2("settings", "--interconnect-off-groups", "")
    check("turn group gb back on", rc == 0, err)
    rc, out, _ = cli_cap2("--json", "settings")
    check("soft preference: an untouched remembered block is regained",
          json.loads(out)["interconnect_slices"].get("b1")
          == [20032, 20047], out)

    # ---- quantified turn-on shortfall + structured --json error.
    # 97 blocks held by group "full"; group "gx" has 5 keyed members
    # and is opted out, so turning it on needs 5 blocks with 3 free.
    cap3_db = os.path.join(workdir, "cap3.db")
    env_cap3 = dict(env, PROXY_DB=cap3_db)

    def cli_cap3(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_cap3, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    cli_cap3("init")
    raw = sqlite3.connect(cap3_db)
    for i in range(1, 98):
        name = f"full{i:03d}"
        raw.execute(
            "INSERT INTO users (username, vless_uuid, trojan_password,"
            " ss_password, ss_method, ssh_pubkey, upstream_group,"
            " created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, f"uuid-f{i}", "pw", "pw", "aes-256-gcm",
             f"ssh-ed25519 AAAA {name}", "full",
             f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.000000+00:00"))
        lo = 20000 + (i - 1) * 16
        raw.execute(
            "INSERT INTO interconnect_allocations (username, port_lo,"
            " port_hi) VALUES (?,?,?)", (name, lo, lo + 15))
    for i in range(1, 6):
        raw.execute(
            "INSERT INTO users (username, vless_uuid, trojan_password,"
            " ss_password, ss_method, ssh_pubkey, upstream_group,"
            " created_at) VALUES (?,?,?,?,?,?,?,?)",
            (f"gx{i}", f"uuid-g{i}", "pw", "pw", "aes-256-gcm",
             f"ssh-ed25519 AAAA gx{i}", "gx",
             f"2026-02-01T00:00:0{i}.000000+00:00"))
    raw.commit()
    raw.close()
    rc, _, err = cli_cap3("settings", "--interconnect-off-groups", "gx")
    check("quantified fixture: gx opted out", rc == 0, err)
    rc, out, err = cli_cap3("settings", "--interconnect-off-groups", "")
    check("turn-on shortfall error spells out N, free M and the gap",
          rc != 0
          and "cannot enable interconnect for group 'gx'" in err + out
          and "5 member(s) need a port slice (16 ports each, 80 ports"
              " in total)" in err + out
          and "only 3 free block(s) (48 ports)" in err + out
          and "short 2 block(s) (32 ports)" in err + out
          and "cannot be served: gx4, gx5" in err + out, err + out)
    rc, out, err = cli_cap3("--json", "settings",
                            "--interconnect-off-groups", "")
    try:
        eobj = json.loads(err)
    except ValueError:
        eobj = {}
    check("--json turn-on shortfall is a structured error object with"
          " the same figures",
          rc != 0 and eobj.get("code")
          == "interconnect_insufficient_ports"
          and eobj.get("group") == "gx"
          and eobj.get("needed_users")
          == ["gx1", "gx2", "gx3", "gx4", "gx5"]
          and eobj.get("needed_count") == 5
          and eobj.get("free_blocks") == 3
          and eobj.get("free_ports") == 48
          and eobj.get("shortfall_blocks") == 2
          and eobj.get("shortfall_ports") == 32
          and eobj.get("users_without_ports") == ["gx4", "gx5"]
          and "short 2 block(s) (32 ports)" in eobj.get("error", ""),
          err + out)
    rc, out, _ = cli_cap3("--json", "settings")
    info3 = json.loads(out)
    check("shortfall refusal is atomic: no new claims, setting kept",
          info3["interconnect_off_groups"] == ["gx"]
          and info3["interconnect_capacity"]["claimed_blocks"] == 97
          and not any(k.startswith("gx")
                      for k in info3["interconnect_slices"]), out)

    # ---- migration backfill: a database the static model served
    # (no allocations table, no last_interconnect_lo column) keeps
    # the legacy ports of every still-eligible holder.
    legacy_db = os.path.join(workdir, "legacy.db")
    raw = sqlite3.connect(legacy_db)
    raw.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT"
        " UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,"
        " vless_uuid TEXT NOT NULL, trojan_password TEXT NOT NULL,"
        " ss_password TEXT NOT NULL, ss_method TEXT NOT NULL DEFAULT"
        " 'aes-256-gcm', ssh_pubkey TEXT, upstream_group TEXT NOT NULL"
        " DEFAULT 'default', note TEXT, created_at TEXT NOT NULL)")
    raw.execute(
        "CREATE TABLE admin_settings (key TEXT PRIMARY KEY,"
        " value TEXT NOT NULL)")
    raw.execute(
        "INSERT INTO admin_settings (key, value) VALUES"
        " ('interconnect_off_groups', 'offg')")
    legacy_users = [
        ("old1", 1, "ssh-ed25519 AAAA old1", "default", "00:01"),
        ("old2", 1, "ssh-ed25519 AAAA old2", "default", "00:02"),
        ("old3", 1, "ssh-ed25519 AAAA old3", "offg", "00:03"),
        ("old4", 1, None, "default", "00:04"),
        ("old5", 1, "ssh-ed25519 AAAA old5", "default", "00:05"),
        ("old6", 0, "ssh-ed25519 AAAA old6", "default", "00:06"),
    ]
    for name, en, key, grp, ts in legacy_users:
        raw.execute(
            "INSERT INTO users (username, enabled, vless_uuid,"
            " trojan_password, ss_password, ssh_pubkey, upstream_group,"
            " created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, en, f"uuid-{name}", "pw", "pw", key, grp,
             f"2026-01-01T00:{ts}.000000+00:00"))
    raw.commit()
    raw.close()
    env_legacy = dict(env, PROXY_DB=legacy_db)

    def cli_legacy(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_legacy, capture_output=True,
                              text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, out, err = cli_legacy("--json", "settings")
    legacy_slices = json.loads(out)["interconnect_slices"] \
        if rc == 0 else {}
    check("migration backfill: eligible legacy holders keep their"
          " exact legacy blocks (old3 opted out, old4 keyless,"
          " old5 keeps block 4 uncompacted)",
          legacy_slices == {"old1": [20000, 20015],
                            "old2": [20016, 20031],
                            "old5": [20064, 20079]}, err + out)
    raw = sqlite3.connect(legacy_db)
    alloc_rows = raw.execute(
        "SELECT username, port_lo FROM interconnect_allocations"
        " ORDER BY port_lo").fetchall()
    raw.close()
    check("migration backfill wrote exactly the eligible rows",
          alloc_rows == [("old1", 20000), ("old2", 20016),
                         ("old5", 20064)], str(alloc_rows))
    rc, _, err = cli_legacy("add", "new1", "--ssh-key-file", kg1pub)
    check("post-migration keyed add claims the lowest free block",
          rc == 0, err)
    rc, out, _ = cli_legacy("--json", "settings")
    check("the new claim reuses a block the backfill left in the pool",
          json.loads(out)["interconnect_slices"].get("new1")
          == [20032, 20047], out)

    # ---- apply-time claim reconcile: users seeded directly (no
    # write path ever touched them) can sit claim-eligible yet
    # rowless; apply tops the table up before rendering, so their
    # slice rules and permitlisten appear. Ineligible seeded users
    # (keyless, opted-out group, disabled) stay rowless.
    rec_db = os.path.join(workdir, "rec.db")
    env_rec = dict(env, PROXY_DB=rec_db)

    def cli_rec(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_rec, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, _, err = cli_rec("init")
    check("reconcile fixture: fresh db", rc == 0, err)
    raw = sqlite3.connect(rec_db)
    seeded = [
        # name, enabled, key, group, created second, remembered block
        ("rec1", 1, "ssh-ed25519 AAAA rec1", "rec", "01", None),
        ("rec2", 1, "ssh-ed25519 AAAA rec2", "rec", "02", 20064),
        ("reckeyless", 1, None, "rec", "03", None),
        ("recoff", 1, "ssh-ed25519 AAAA recoff", "recoff", "04", None),
        ("recdis", 0, "ssh-ed25519 AAAA recdis", "rec", "05", None),
    ]
    for name, en, key, grp, sec, last_lo in seeded:
        raw.execute(
            "INSERT INTO users (username, enabled, vless_uuid,"
            " trojan_password, ss_password, ss_method, ssh_pubkey,"
            " upstream_group, created_at, last_interconnect_lo)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (name, en, f"uuid-{name}", "pw", "pw", "aes-256-gcm", key,
             grp, f"2026-03-01T00:00:{sec}.000000+00:00", last_lo))
    raw.execute(
        "INSERT INTO admin_settings (key, value) VALUES"
        " ('interconnect_off_groups', 'recoff')")
    raw.commit()
    raw.close()
    rc, out, _ = cli_rec("--json", "settings")
    check("seeded eligible users hold nothing before apply (the gap)",
          json.loads(out)["interconnect_slices"] == {}, out)
    rc, _, err = cli_rec("apply")
    check("apply runs clean over seeded data", rc == 0, err)
    rc, out, _ = cli_rec("--json", "settings")
    check("apply reconcile: eligible seeded users claim in creation"
          " order, the remembered block first when free; keyless,"
          " opted-out and disabled users stay rowless",
          json.loads(out)["interconnect_slices"] == {
              "rec1": [20000, 20015], "rec2": [20064, 20079]}, out)
    rec_cfg = json.load(open(os.path.join(workdir, "config.json")))
    rec_band = {r.get("port"): r.get("user")
                for r in rec_cfg["routing"]["rules"]
                if r.get("outboundTag") == "direct"
                and r.get("ip") == ["127.0.0.0/8"]}
    check("reconciled slices render as band rules for the group",
          rec_band.get("20000-20015") == ["rec1", "rec2"]
          and rec_band.get("20064-20079") == ["rec1", "rec2"],
          json.dumps(rec_band))
    rec_keys = open(os.path.join(workdir, "authorized_keys")).read()
    check("reconciled holders carry permitlisten, nobody else does",
          'permitlisten="127.0.0.1:20000"' in rec_keys
          and 'permitlisten="127.0.0.1:20064"' in rec_keys
          and rec_keys.count("permitlisten=") == 32,
          rec_keys[:160])
    rc, _, err = cli_rec("apply")
    rc, out, _ = cli_rec("--json", "settings")
    check("a second apply moves nothing (holders never drift)",
          rc == 0
          and json.loads(out)["interconnect_slices"] == {
              "rec1": [20000, 20015], "rec2": [20064, 20079]}, out)

    # ---- reconcile under a nearly full band: claims proceed in
    # order until the pool runs out; the rest stay rowless and
    # apply still succeeds (no refusal gate at apply time).
    recf_db = os.path.join(workdir, "recfull.db")
    env_recf = dict(env, PROXY_DB=recf_db)

    def cli_recf(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_recf, capture_output=True,
                              text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, _, err = cli_recf("init")
    raw = sqlite3.connect(recf_db)
    for i in range(1, 100):
        name = f"rh{i:03d}"
        raw.execute(
            "INSERT INTO users (username, vless_uuid, trojan_password,"
            " ss_password, ss_method, ssh_pubkey, upstream_group,"
            " created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, f"uuid-r{i}", "pw", "pw", "aes-256-gcm",
             f"ssh-ed25519 AAAA {name}", "pool",
             f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.000000+00:00"))
        lo = 20000 + (i - 1) * 16
        raw.execute(
            "INSERT INTO interconnect_allocations (username, port_lo,"
            " port_hi) VALUES (?,?,?)", (name, lo, lo + 15))
    for j, name in enumerate(("wait1", "wait2", "wait3"), start=1):
        raw.execute(
            "INSERT INTO users (username, vless_uuid, trojan_password,"
            " ss_password, ss_method, ssh_pubkey, upstream_group,"
            " created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, f"uuid-{name}", "pw", "pw", "aes-256-gcm",
             f"ssh-ed25519 AAAA {name}", "pool",
             f"2026-04-01T00:00:0{j}.000000+00:00"))
    raw.commit()
    raw.close()
    check("reconcile full-band fixture: 99 holders, 3 waiting",
          rc == 0, err)
    rc, _, err = cli_recf("apply")
    check("apply succeeds even when the band cannot serve everyone",
          rc == 0, err)
    rc, out, _ = cli_recf("--json", "settings")
    recf_info = json.loads(out)
    check("reconcile fills the last block in creation order and"
          " stops: wait1 holds it, wait2/wait3 stay rowless",
          recf_info["interconnect_slices"].get("wait1")
          == [21584, 21599]
          and "wait2" not in recf_info["interconnect_slices"]
          and "wait3" not in recf_info["interconnect_slices"], out)
    check("capacity after reconcile: band exactly full",
          recf_info["interconnect_capacity"] == {
              "total_blocks": 100, "claimed_blocks": 100,
              "free_blocks": 0}, out)

    # ---- apply-time release reconcile: holders who stopped being
    # eligible outside the write paths (direct edits: disabled, key
    # removed, group pushed onto the opt-out list) keep their rows
    # until an apply releases them - through the same path a write
    # would use, so the block is remembered the same way. Release
    # runs before the claim pass, so a block freed by this apply is
    # claimable in it.
    rec2_db = os.path.join(workdir, "rec2.db")
    env_rec2 = dict(env, PROXY_DB=rec2_db)

    def cli_rec2(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_rec2, capture_output=True,
                              text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, _, err = cli_rec2("init")
    check("release-reconcile fixture: fresh db", rc == 0, err)
    for user, grp in (("keeper", "keep"), ("victimdis", "keep"),
                      ("victimkey", "keep"), ("victimoff", "voff")):
        rc, _, err = cli_rec2("add", user, "--group", grp,
                              "--ssh-key-file", kg1pub)
        assert rc == 0, err
    raw = sqlite3.connect(rec2_db)
    raw.execute(
        "INSERT INTO users (username, enabled, vless_uuid,"
        " trojan_password, ss_password, ss_method, ssh_pubkey,"
        " upstream_group, created_at, last_interconnect_lo)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("waiter", 1, "uuid-waiter", "pw", "pw", "aes-256-gcm",
         "ssh-ed25519 AAAA waiter", "keep",
         "2026-05-01T00:00:00.000000+00:00", 20048))
    raw.commit()
    raw.close()
    rc, out, _ = cli_rec2("--json", "settings")
    check("release-reconcile fixture: four holders claimed on the"
          " write paths, the seeded waiter is rowless",
          json.loads(out)["interconnect_slices"] == {
              "keeper": [20000, 20015], "victimdis": [20016, 20031],
              "victimkey": [20032, 20047],
              "victimoff": [20048, 20063]}, out)
    raw = sqlite3.connect(rec2_db)
    raw.execute("UPDATE users SET enabled = 0"
                " WHERE username = 'victimdis'")
    raw.execute("UPDATE users SET ssh_pubkey = NULL"
                " WHERE username = 'victimkey'")
    raw.execute(
        "INSERT INTO admin_settings (key, value) VALUES"
        " ('interconnect_off_groups', 'voff')")
    raw.commit()
    raw.close()
    rc, _, err = cli_rec2("apply")
    check("apply runs clean over the dirtied table", rc == 0, err)
    rc, out, _ = cli_rec2("--json", "settings")
    check("apply release reconcile: the disabled, keyless and"
          " opted-out holders lose their rows; the eligible holder"
          " is unmoved; the waiter claims the block victimoff freed"
          " in this same apply (his remembered block, not the"
          " lowest free one)",
          json.loads(out)["interconnect_slices"] == {
              "keeper": [20000, 20015], "waiter": [20048, 20063]},
          out)
    raw = sqlite3.connect(rec2_db)
    remembered = dict(raw.execute(
        "SELECT username, last_interconnect_lo FROM users"
        " WHERE username LIKE 'victim%'").fetchall())
    n_alloc2 = raw.execute(
        "SELECT COUNT(*) FROM interconnect_allocations"
    ).fetchone()[0]
    raw.close()
    check("each released block is remembered on its user record,"
          " exactly as a write-path release records it; only the"
          " two eligible rows remain",
          remembered == {"victimdis": 20016, "victimkey": 20032,
                         "victimoff": 20048}
          and n_alloc2 == 2, str(remembered))
    rec2_keys = open(os.path.join(workdir, "authorized_keys")).read()
    check("the release reaches the rendered keys: only the two"
          " remaining holders carry permitlisten",
          rec2_keys.count("permitlisten=") == 32
          and 'permitlisten="127.0.0.1:20048"' in rec2_keys,
          rec2_keys[:160])
    rc, _, err = cli_rec2("apply")
    rc, out, _ = cli_rec2("--json", "settings")
    raw = sqlite3.connect(rec2_db)
    remembered2 = dict(raw.execute(
        "SELECT username, last_interconnect_lo FROM users"
        " WHERE username LIKE 'victim%'").fetchall())
    raw.close()
    check("a second apply is a no-op (rows and memories unchanged)",
          rc == 0
          and json.loads(out)["interconnect_slices"] == {
              "keeper": [20000, 20015], "waiter": [20048, 20063]}
          and remembered2 == remembered, out)

    # ---- three group states: on / paused / closed. Pausing keeps
    # the slices (rows stay, blocks stay claimed) but renders
    # nothing for the group; closing releases; resuming restores
    # holders as they were and claims for members who joined while
    # paused.
    trz_db = os.path.join(workdir, "trz.db")
    env_trz = dict(env, PROXY_DB=trz_db)

    def cli_trz(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_trz, capture_output=True,
                              text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, _, err = cli_trz("init")
    check("three-state fixture: fresh db", rc == 0, err)
    for user, grp in (("p1", "pz"), ("p2", "pz"), ("q1", "other")):
        rc, _, err = cli_trz("add", user, "--group", grp,
                             "--ssh-key-file", kg1pub)
        assert rc == 0, err
    rc, out, _ = cli_trz("--json", "settings")
    trz_info = json.loads(out)
    check("three-state baseline: claims in order, paused list"
          " empty and not from db",
          trz_info["interconnect_slices"] == {
              "p1": [20000, 20015], "p2": [20016, 20031],
              "q1": [20032, 20047]}
          and trz_info["interconnect_paused_groups"] == []
          and trz_info["interconnect_paused_groups_from_db"]
          is False, out)
    rc, out, err = cli_trz("settings",
                           "--interconnect-paused-groups", "pz")
    check("pause group pz via settings", rc == 0, err)
    rc, out, _ = cli_trz("settings")
    check("settings show lists the paused groups",
          "interconnect_paused_groups: pz (db)" in out, out)
    rc, out, _ = cli_trz("--json", "settings")
    trz_info = json.loads(out)
    check("paused: rows and capacity are untouched, the list is"
          " stored",
          trz_info["interconnect_slices"] == {
              "p1": [20000, 20015], "p2": [20016, 20031],
              "q1": [20032, 20047]}
          and trz_info["interconnect_capacity"] == {
              "total_blocks": 100, "claimed_blocks": 3,
              "free_blocks": 97}
          and trz_info["interconnect_paused_groups"] == ["pz"]
          and trz_info["interconnect_paused_groups_from_db"]
          is True, out)
    rc, out, _ = cli_trz("list")
    check("paused holders still show their slices in the user"
          " list",
          "p1" in out and "interconnect=20000-20015" in out, out)
    rc, _, err = cli_trz("add", "p3", "--group", "pz",
                         "--ssh-key-file", kg1pub)
    check("keyed add into a paused group succeeds but claims"
          " nothing", rc == 0, err)
    rc, out, _ = cli_trz("--json", "settings")
    check("the paused newcomer holds no slice",
          "p3" not in json.loads(out)["interconnect_slices"], out)
    rc, _, err = cli_trz("apply")
    check("apply runs clean with a paused group", rc == 0, err)
    rc, out, _ = cli_trz("--json", "settings")
    check("apply reconcile spares paused rows (hold) and does not"
          " claim for the paused newcomer (active)",
          json.loads(out)["interconnect_slices"] == {
              "p1": [20000, 20015], "p2": [20016, 20031],
              "q1": [20032, 20047]}, out)
    trz_cfg = json.load(open(os.path.join(workdir, "config.json")))
    trz_band = {r.get("port"): r.get("user")
                for r in trz_cfg["routing"]["rules"]
                if r.get("outboundTag") == "direct"
                and r.get("ip") == ["127.0.0.0/8"]}
    check("paused group renders no band rules; the on group keeps"
          " its",
          "20000-20015" not in trz_band
          and "20016-20031" not in trz_band
          and trz_band.get("20032-20047") == ["q1"],
          json.dumps(trz_band))
    trz_keys = open(os.path.join(workdir, "authorized_keys")).read()
    check("paused holders carry no permitlisten; the active"
          " holder keeps his",
          trz_keys.count("permitlisten=") == 16
          and 'permitlisten="127.0.0.1:20032"' in trz_keys,
          trz_keys[:160])
    rc, _, err = cli_trz("settings", "--interconnect-paused-groups",
                         "")
    check("resume group pz", rc == 0, err)
    rc, out, _ = cli_trz("--json", "settings")
    check("resume: kept rows are back exactly as they were; the"
          " member who joined while paused claims the lowest free"
          " block",
          json.loads(out)["interconnect_slices"] == {
              "p1": [20000, 20015], "p2": [20016, 20031],
              "q1": [20032, 20047], "p3": [20048, 20063]}, out)
    rc, _, err = cli_trz("settings",
                         "--interconnect-paused-groups", "pz")
    assert rc == 0, err
    rc, _, err = cli_trz("settings",
                         "--interconnect-paused-groups", "",
                         "--interconnect-off-groups", "pz")
    check("paused -> closed in one write releases every member",
          rc == 0, err)
    rc, out, _ = cli_trz("--json", "settings")
    trz_info = json.loads(out)
    check("after closing, only the untouched group still holds",
          trz_info["interconnect_slices"] == {"q1": [20032, 20047]}
          and trz_info["interconnect_off_groups"] == ["pz"]
          and trz_info["interconnect_paused_groups"] == [], out)
    rc, _, err = cli_trz("settings", "--interconnect-off-groups",
                         "")
    check("reopen the closed group", rc == 0, err)
    rc, out, _ = cli_trz("--json", "settings")
    check("reopened members re-claim their remembered blocks",
          json.loads(out)["interconnect_slices"] == {
              "p1": [20000, 20015], "p2": [20016, 20031],
              "q1": [20032, 20047], "p3": [20048, 20063]}, out)
    rc, _, err = cli_trz("settings",
                         "--interconnect-paused-groups", "pz")
    assert rc == 0, err
    rc, out, err = cli_trz("settings", "--interconnect-off-groups",
                           "pz")
    check("conflict: closing a stored-paused group is refused and"
          " names the group",
          rc != 0 and "'pz'" in err + out and "both" in err + out,
          err + out)
    rc, out, err = cli_trz("settings",
                           "--interconnect-off-groups", "pz",
                           "--interconnect-paused-groups", "pz")
    check("conflict: naming one group in both lists in a single"
          " write is refused too",
          rc != 0 and "'pz'" in err + out, err + out)
    rc, out, _ = cli_trz("--json", "settings")
    trz_info = json.loads(out)
    check("conflicts leave both stored lists untouched",
          trz_info["interconnect_off_groups"] == []
          and trz_info["interconnect_paused_groups"] == ["pz"],
          out)
    rc, _, err = cli_trz("settings",
                         "--interconnect-paused-groups", "")
    check("clear the paused list again (group back on, rows kept)",
          rc == 0, err)
    rc, out, _ = cli_trz("--json", "settings")
    check("state is fully restored after the conflict detour",
          json.loads(out)["interconnect_slices"] == {
              "p1": [20000, 20015], "p2": [20016, 20031],
              "q1": [20032, 20047], "p3": [20048, 20063]}, out)

    # ---- paused blocks still count: 99 on-group holders plus one
    # paused holder fill the band, so a new claim is refused even
    # though the paused slice is unusable; and the apply reconcile
    # (release = hold predicate) leaves the paused row in place.
    trz2_db = os.path.join(workdir, "trz2.db")
    env_trz2 = dict(env, PROXY_DB=trz2_db)

    def cli_trz2(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_trz2, capture_output=True,
                              text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, _, err = cli_trz2("init")
    raw = sqlite3.connect(trz2_db)
    for i in range(1, 100):
        name = f"ph{i:03d}"
        raw.execute(
            "INSERT INTO users (username, vless_uuid,"
            " trojan_password, ss_password, ss_method, ssh_pubkey,"
            " upstream_group, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, f"uuid-p{i}", "pw", "pw", "aes-256-gcm",
             f"ssh-ed25519 AAAA {name}", "pool",
             f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.000000+00:00"))
        lo = 20000 + (i - 1) * 16
        raw.execute(
            "INSERT INTO interconnect_allocations (username, port_lo,"
            " port_hi) VALUES (?,?,?)", (name, lo, lo + 15))
    raw.execute(
        "INSERT INTO users (username, vless_uuid, trojan_password,"
        " ss_password, ss_method, ssh_pubkey, upstream_group,"
        " created_at) VALUES (?,?,?,?,?,?,?,?)",
        ("pzhold", "uuid-pz", "pw", "pw", "aes-256-gcm",
         "ssh-ed25519 AAAA pzhold", "pz",
         "2026-01-02T00:00:00.000000+00:00"))
    raw.execute(
        "INSERT INTO interconnect_allocations (username, port_lo,"
        " port_hi) VALUES (?,?,?)", ("pzhold", 21584, 21599))
    raw.execute(
        "INSERT INTO users (username, vless_uuid, trojan_password,"
        " ss_password, ss_method, ssh_pubkey, upstream_group,"
        " created_at) VALUES (?,?,?,?,?,?,?,?)",
        ("waiter", "uuid-w", "pw", "pw", "aes-256-gcm",
         "ssh-ed25519 AAAA waiter", "pool",
         "2026-01-03T00:00:00.000000+00:00"))
    raw.execute(
        "INSERT INTO admin_settings (key, value) VALUES"
        " ('interconnect_paused_groups', 'pz')")
    raw.commit()
    raw.close()
    check("paused-pool fixture: fresh db, 100 rows seeded (one"
          " paused)", rc == 0, err)
    rc, out, _ = cli_trz2("--json", "settings")
    trz2_info = json.loads(out)
    check("the paused block counts as claimed: band exactly full",
          trz2_info["interconnect_capacity"] == {
              "total_blocks": 100, "claimed_blocks": 100,
              "free_blocks": 0}
          and trz2_info["interconnect_slices"].get("pzhold")
          == [21584, 21599]
          and trz2_info["interconnect_paused_groups"] == ["pz"],
          out)
    rc, out, err = cli_trz2("add", "newbie", "--group", "pool",
                            "--ssh-key-file", kg1pub)
    check("a new keyed add is refused: the paused block is not"
          " up for grabs",
          rc != 0 and "20000-21599" in err + out, err + out)
    rc, _, err = cli_trz2("apply")
    check("apply succeeds over the full, partly paused band",
          rc == 0, err)
    rc, out, _ = cli_trz2("--json", "settings")
    trz2_info = json.loads(out)
    check("reconcile leaves the paused row in place and the"
          " waiter rowless (band still full)",
          trz2_info["interconnect_slices"].get("pzhold")
          == [21584, 21599]
          and "waiter" not in trz2_info["interconnect_slices"]
          and trz2_info["interconnect_capacity"][
              "claimed_blocks"] == 100, out)

    # ---- resuming a paused group is a quantified gate over only
    # the members who still need a slice: holders kept theirs
    # across the pause and are not counted.
    trz3_db = os.path.join(workdir, "trz3.db")
    env_trz3 = dict(env, PROXY_DB=trz3_db)

    def cli_trz3(*args):
        proc = subprocess.run([sys.executable, users_py, *args],
                              env=env_trz3, capture_output=True,
                              text=True)
        return proc.returncode, proc.stdout, proc.stderr

    rc, _, err = cli_trz3("init")
    raw = sqlite3.connect(trz3_db)
    for i in range(1, 99):
        name = f"ph{i:03d}"
        raw.execute(
            "INSERT INTO users (username, vless_uuid,"
            " trojan_password, ss_password, ss_method, ssh_pubkey,"
            " upstream_group, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, f"uuid-p{i}", "pw", "pw", "aes-256-gcm",
             f"ssh-ed25519 AAAA {name}", "pool",
             f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}.000000+00:00"))
        lo = 20000 + (i - 1) * 16
        raw.execute(
            "INSERT INTO interconnect_allocations (username, port_lo,"
            " port_hi) VALUES (?,?,?)", (name, lo, lo + 15))
    for j, name in enumerate(("r1", "r2", "r3", "r4"), start=1):
        raw.execute(
            "INSERT INTO users (username, vless_uuid,"
            " trojan_password, ss_password, ss_method, ssh_pubkey,"
            " upstream_group, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, f"uuid-{name}", "pw", "pw", "aes-256-gcm",
             f"ssh-ed25519 AAAA {name}", "rz",
             f"2026-02-01T00:00:0{j}.000000+00:00"))
    for name, lo in (("r1", 21568), ("r2", 21584)):
        raw.execute(
            "INSERT INTO interconnect_allocations (username, port_lo,"
            " port_hi) VALUES (?,?,?)", (name, lo, lo + 15))
    raw.execute(
        "INSERT INTO admin_settings (key, value) VALUES"
        " ('interconnect_paused_groups', 'rz')")
    raw.commit()
    raw.close()
    check("resume fixture: fresh db, paused group with 2 holders"
          " and 2 waiting, band full", rc == 0, err)
    rc, out, err = cli_trz3("settings",
                            "--interconnect-paused-groups", "")
    check("resume refused, quantified over the waiting members"
          " only (holders across the pause are not counted)",
          rc != 0
          and "cannot enable interconnect for group 'rz'"
          in err + out
          and "2 member(s) need a port slice (16 ports each,"
              " 32 ports in total)" in err + out
          and "only 0 free block(s) (0 ports)" in err + out
          and "short 2 block(s) (32 ports)" in err + out
          and "cannot be served: r3, r4" in err + out, err + out)
    rc, out, err = cli_trz3("--json", "settings",
                            "--interconnect-paused-groups", "")
    try:
        eobj = json.loads(err)
    except ValueError:
        eobj = {}
    check("resume refusal is the structured error object with the"
          " same figures",
          rc != 0 and eobj.get("code")
          == "interconnect_insufficient_ports"
          and eobj.get("group") == "rz"
          and eobj.get("needed_users") == ["r3", "r4"]
          and eobj.get("needed_count") == 2
          and eobj.get("free_blocks") == 0
          and eobj.get("shortfall_blocks") == 2
          and eobj.get("shortfall_ports") == 32
          and eobj.get("users_without_ports") == ["r3", "r4"],
          err + out)
    rc, out, _ = cli_trz3("--json", "settings")
    trz3_info = json.loads(out)
    check("refused resume is atomic: group stays paused, nobody"
          " claimed",
          trz3_info["interconnect_paused_groups"] == ["rz"]
          and "r3" not in trz3_info["interconnect_slices"]
          and "r4" not in trz3_info["interconnect_slices"]
          and trz3_info["interconnect_slices"].get("r1")
          == [21568, 21583], out)
    rc, _, err = cli_trz3("disable", "ph001")
    assert rc == 0, err
    rc, _, err = cli_trz3("disable", "ph002")
    check("disable two pool holders to free two blocks",
          rc == 0, err)
    rc, _, err = cli_trz3("settings",
                          "--interconnect-paused-groups", "")
    check("resume succeeds once the waiting members fit", rc == 0,
          err)
    rc, out, _ = cli_trz3("--json", "settings")
    trz3_info = json.loads(out)
    check("the waiting members claim the freed blocks in order;"
          " the holders across the pause never moved",
          trz3_info["interconnect_slices"].get("r3")
          == [20000, 20015]
          and trz3_info["interconnect_slices"].get("r4")
          == [20016, 20031]
          and trz3_info["interconnect_slices"].get("r1")
          == [21568, 21583]
          and trz3_info["interconnect_slices"].get("r2")
          == [21584, 21599]
          and trz3_info["interconnect_paused_groups"] == [], out)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
