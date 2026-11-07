#!/usr/bin/env python3
"""Multi-database support: registry, switching, migration, dialects.

Covers the whole feature on every interface:
  A. the node CLI (users.py db-*) with several SQLite configs;
  B. the dialect translation layer (PostgreSQL / MySQL SQL rewriting)
     as pure unit checks;
  C. real PostgreSQL / MySQL servers, when XMAGIC_TEST_PG_DSN /
     XMAGIC_TEST_MYSQL_DSN point at reachable test databases
     (skipped otherwise - CI runs A, B and D);
  D. the web API and the remote CLI (xmagic.py db ...) against a real
     admin server, reusing test_client's server/login machinery.

The database configs themselves live in a local SQLite registry
(XMAGIC_LOCAL_DB); business data lives in the active database.

Run: python3 tests/test_databases.py
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# in-process imports (part B) need the env before users.py is imported
_B_DIR = tempfile.mkdtemp(prefix="xmagic-db-unit-")
os.environ["PROXY_DB"] = os.path.join(_B_DIR, "users.db")
os.environ["XMAGIC_LOCAL_DB"] = os.path.join(_B_DIR, "local.db")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import users as users_mod  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name
          + (f"  {extra}" if extra and not cond else ""))


USERS_PY = os.path.join(ROOT, "users.py")
XMAGIC_PY = os.path.join(ROOT, "xmagic.py")


def engine(env):
    def cli(*args):
        proc = subprocess.run([sys.executable, USERS_PY, *args],
                              env=env, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr
    return cli


def fresh_env(workdir):
    return dict(os.environ,
                PROXY_DB=os.path.join(workdir, "data", "users.db"),
                XMAGIC_LOCAL_DB=os.path.join(workdir, "data", "local.db"),
                XMAGIC_DOCKER_SOCK="/nonexistent.sock")


# ------------------------------------------------------------ part A: CLI
def part_a():
    workdir = tempfile.mkdtemp(prefix="xmagic-db-cli-")
    env = fresh_env(workdir)
    cli = engine(env)
    second = os.path.join(workdir, "data", "second.db")

    rc, _, err = cli("init")
    check("A init on implicit default", rc == 0, err)
    rc, _, err = cli("add", "alice")
    check("A add user on default", rc == 0, err)
    rc, out, _ = cli("--json", "db-list")
    cfgs = json.loads(out)
    check("A db-list shows only the implicit default, active",
          len(cfgs) == 1 and cfgs[0]["name"] == "default"
          and cfgs[0]["active"] and cfgs[0]["type"] == "sqlite", out)
    check("A local registry file created next to the database",
          os.path.exists(env["XMAGIC_LOCAL_DB"]))
    mode = os.stat(env["XMAGIC_LOCAL_DB"]).st_mode & 0o777
    check("A local registry file is 0600", mode == 0o600, oct(mode))

    rc, out, err = cli("db-add", "second", "--type", "sqlite",
                       "--path", second, "--note", "second store")
    check("A db-add second sqlite config", rc == 0, err)
    rc, out, _ = cli("--json", "db-list")
    cfgs = json.loads(out)
    check("A db-list shows default (active) + second",
          [c["name"] for c in cfgs] == ["default", "second"]
          and cfgs[0]["active"] and not cfgs[1]["active"], out)
    rc, out, err = cli("--json", "db-test", "second")
    tables = json.loads(out)["tables"] if rc == 0 else {}
    check("A db-test creates the schema in the empty target",
          rc == 0 and tables.get("users") == 0
          and tables.get("admin_sessions") == 0, err + out)

    rc, _, err = cli("db-switch", "second")
    check("A db-switch to second", rc == 0, err)
    rc, out, _ = cli("--json", "list")
    check("A second database starts empty (data isolation)",
          json.loads(out) == [], out)
    rc, out, err = cli("db-migrate", "default", "second")
    check("A migrate default -> second", rc == 0 and "users=1" in out,
          err + out)
    rc, out, _ = cli("--json", "list")
    check("A migrated user visible on second",
          [u["username"] for u in json.loads(out)] == ["alice"], out)
    rc, _, err = cli("db-migrate", "default", "second")
    check("A migrate into non-empty target refused", rc != 0
          and "not empty" in err, err)
    rc, out, err = cli("db-migrate", "default", "second", "--replace")
    check("A migrate with --replace overwrites", rc == 0, err)
    rc, _, err = cli("db-remove", "second")
    check("A removing the active config refused", rc != 0
          and "active" in err, err)
    rc, _, err = cli("db-switch", "default")
    check("A switch back to default", rc == 0, err)
    rc, _, err = cli("db-remove", "second")
    check("A remove inactive config", rc == 0, err)

    rc, out, err = cli("db-add", "ext", "--type", "postgres",
                       "--dsn", "postgresql://u:secretpw@db.internal:5432/x")
    rc2, out2, _ = cli("--json", "db-list")
    check("A DSN password masked in db-list output",
          rc == 0 and "secretpw" not in out and "secretpw" not in out2
          and "***" in out2, out + out2)
    rc, _, err = cli("db-test", "ext")
    check("A db-test on unreachable server fails cleanly (no traceback)",
          rc != 0 and "Traceback" not in err, err)
    rc, _, err = cli("db-add", "bad name!", "--type", "sqlite",
                     "--path", "/tmp/x.db")
    check("A invalid config name refused", rc != 0, err)
    rc, _, err = cli("db-add", "bad2", "--type", "sqlite",
                     "--dsn", "postgresql://u:p@h/db")
    check("A mismatched target refused", rc != 0, err)
    rc, _, err = cli("db-edit", "ext", "--note", "external pg")
    rc2, out2, _ = cli("--json", "db-list")
    notes = {c["name"]: c["note"] for c in json.loads(out2)} \
        if rc2 == 0 else {}
    check("A db-edit note", rc == 0 and notes.get("ext") == "external pg",
          err + out2)
    rc, _, err = cli("db-remove", "ext")
    check("A remove ext", rc == 0, err)


# ------------------------------------------------- part B: dialect units
def part_b():
    sess_sql = ("INSERT OR REPLACE INTO admin_sessions"
                " (sid, key, client_pub, server_pub, kind, label,"
                " created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)")
    pg = users_mod.DB(None, "postgres")._translate(sess_sql)
    check("B pg session upsert translation",
          "ON CONFLICT (sid) DO UPDATE SET" in pg
          and "excluded.kind" in pg and "%s" in pg and "?" not in pg, pg)
    my = users_mod.DB(None, "mysql")._translate(sess_sql)
    check("B mysql session upsert translation",
          "ON DUPLICATE KEY UPDATE" in my and "kind = VALUES(kind)" in my,
          my)
    cred_sql = ("INSERT OR REPLACE INTO admin_credentials"
                " (id, credential_id, public_key_x, public_key_y,"
                " sign_count, label, created_at) VALUES (?,?,?,?,?,?,?)")
    pg = users_mod.DB(None, "postgres")._translate(cred_sql)
    check("B pg credential upsert translation",
          "ON CONFLICT (id) DO UPDATE SET" in pg
          and "excluded.credential_id" in pg, pg)
    set_sql = ("INSERT INTO admin_settings (key, value) VALUES (?, ?)"
               " ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    my = users_mod.DB(None, "mysql")._translate(set_sql)
    check("B mysql settings upsert + reserved-word quoting",
          "ON DUPLICATE KEY UPDATE value = VALUES(value)" in my
          and "(`key`, value)" in my, my)
    sel = users_mod.DB(None, "mysql")._translate(
        "SELECT value FROM admin_settings WHERE key = ?")
    check("B mysql settings select quotes key",
          "WHERE `key` = %s" in sel, sel)
    ddl_pg = users_mod.DB._translate_ddl(users_mod.SCHEMA, "postgres")
    check("B pg identity DDL",
          "GENERATED BY DEFAULT AS IDENTITY" in ddl_pg, ddl_pg[:200])
    cred_pg = users_mod.DB._translate_ddl(
        users_mod.CREDENTIALS_SCHEMA, "postgres")
    check("B pg credentials DDL keeps the singleton CHECK",
          "CHECK (id = 1)" in cred_pg
          and "GENERATED" not in cred_pg, cred_pg)
    ddl_my = users_mod.DB._translate_ddl(users_mod.SCHEMA, "mysql")
    check("B mysql auto-increment + varchar keys",
          "AUTO_INCREMENT" in ddl_my
          and "username VARCHAR(255) UNIQUE NOT NULL" in ddl_my, ddl_my[:300])
    set_my = users_mod.DB._translate_ddl(users_mod.SETTINGS_SCHEMA, "mysql")
    check("B mysql settings key becomes VARCHAR",
          "`key` VARCHAR(255) PRIMARY KEY" in set_my, set_my)
    sess_my = users_mod.DB._translate_ddl(users_mod.SESSIONS_SCHEMA, "mysql")
    check("B mysql session id becomes VARCHAR",
          "sid VARCHAR(255) PRIMARY KEY" in sess_my, sess_my)
    masked = users_mod.mask_target(
        "postgres", "postgresql://u:secretpw@h:5432/db")
    check("B mask_target hides the DSN password",
          masked == "postgresql://u:***@h:5432/db", masked)
    check("B mask_target leaves sqlite paths alone",
          users_mod.mask_target("sqlite", "/data/users.db") == "/data/users.db")
    parts = users_mod._split_sql("CREATE TABLE a (x TEXT);"
                                  " INSERT INTO a VALUES ('a;b');")
    check("B _split_sql respects string literals", len(parts) == 2,
          repr(parts))


# ------------------------------------------- part C: real PG / MySQL
def part_c():
    cases = []
    if os.environ.get("XMAGIC_TEST_PG_DSN"):
        cases.append(("postgres", os.environ["XMAGIC_TEST_PG_DSN"]))
    if os.environ.get("XMAGIC_TEST_MYSQL_DSN"):
        cases.append(("mysql", os.environ["XMAGIC_TEST_MYSQL_DSN"]))
    for typ, dsn in cases:
        workdir = tempfile.mkdtemp(prefix=f"xmagic-db-{typ}-")
        env = fresh_env(workdir)
        cli = engine(env)
        cli("init")
        cli("add", "alice")
        rc, _, err = cli("db-add", "srv", "--type", typ, "--dsn", dsn)
        check(f"C {typ}: db-add server config", rc == 0, err)
        rc, out, err = cli("--json", "db-test", "srv")
        check(f"C {typ}: schema auto-created on the empty server database",
              rc == 0 and "users" in json.loads(out)["tables"], err + out)
        rc, out, err = cli("db-migrate", "default", "srv", "--replace")
        check(f"C {typ}: migrate sqlite -> server", rc == 0
              and "users=1" in out, err + out)
        rc, _, err = cli("db-switch", "srv")
        check(f"C {typ}: switch to server", rc == 0, err)
        rc, out, _ = cli("--json", "list")
        check(f"C {typ}: migrated user served from the server",
              [u["username"] for u in json.loads(out)] == ["alice"], out)
        rc, _, err = cli("add", "bob")
        check(f"C {typ}: add user directly on the server "
              "(identity sequence sane after migration)", rc == 0, err)
        rc, _, err = cli("settings", "--upstream-strategy", "leastPing")
        rc2, out2, _ = cli("--json", "status")
        check(f"C {typ}: settings upsert round-trip on the server",
              rc == 0 and rc2 == 0, err)
        back = os.path.join(workdir, "data", "back.db")
        cli("db-add", "back", "--type", "sqlite", "--path", back)
        rc, out, err = cli("db-migrate", "srv", "back")
        check(f"C {typ}: migrate server -> sqlite", rc == 0
              and "users=2" in out, err + out)
        cli("db-switch", "back")
        rc, out, _ = cli("--json", "list")
        check(f"C {typ}: both users present after the round trip",
              sorted(u["username"] for u in json.loads(out))
              == ["alice", "bob"], out)
        cli("db-switch", "default")


# --------------------------------------- part D: web API + remote CLI
def part_d():
    import test_client as tc
    from test_admin import Authenticator

    port = 18103
    workdir = tempfile.mkdtemp(prefix="xmagic-db-web-")
    server, _ = tc.start_server(port, os.path.join(workdir, "node"))
    origin = f"http://localhost:{port}"
    browser = tc.Browser(port)
    auth = Authenticator()
    cli_home = os.path.join(workdir, "home")
    env = dict(os.environ, XMAGIC_HOME=cli_home)

    def cli(*args):
        proc = subprocess.run([sys.executable, XMAGIC_PY, *args], env=env,
                              capture_output=True, text=True, timeout=30)
        return proc.returncode, proc.stdout, proc.stderr

    try:
        _, opts = browser.options("register")
        status, body = browser.verify(
            "register", auth.attestation(opts["challenge"], "localhost",
                                         origin))
        check("D register admin passkey", status == 200, str(body))

        status, body = browser.call("GET", "/api/databases")
        dbs = body.get("databases", [])
        check("D web lists the implicit default database",
              status == 200 and len(dbs) == 1 and dbs[0]["active"], str(body))
        second = os.path.join(workdir, "node", "data", "second.db")
        status, body = browser.call("POST", "/api/databases", {
            "name": "second", "type": "sqlite", "target": second})
        check("D web adds a database config",
              status == 201 and body["database"]["name"] == "second",
              str(body))
        status, body = browser.call("POST", "/api/users",
                                    {"username": "webuser"})
        check("D web adds a user on default", status == 201, str(body))
        status, body = browser.call("POST", "/api/databases/migrate",
                                    {"from": "default", "to": "second"})
        check("D web migrates default -> second",
              status == 200
              and body["migration"]["tables"]["users"] == 1, str(body))
        status, body = browser.call("POST", "/api/databases/second/test", {})
        check("D web tests a database config",
              status == 200 and body["test"]["tables"]["users"] == 1,
              str(body))
        status, body = browser.call("POST", "/api/databases/second/switch",
                                    {})
        check("D web switches the active database",
              status == 200 and body["database"]["active"], str(body))
        status, body = browser.call("GET", "/api/users")
        check("D after the switch the web serves the migrated user",
              [u["username"] for u in body["users"]] == ["webuser"],
              str(body))
        status, body = browser.call("POST", "/api/databases/second/remove",
                                    {})
        check("D web refuses to remove the active config",
              status == 400, str(body))

        rc, out, err = cli("node", "add", "n", "--url", origin, "--use")
        check("D remote CLI node add", rc == 0, err)
        rc, out, err = tc.drive_login(cli_home, port, auth)
        check("D remote CLI login", rc == 0, err + out)
        rc, out, err = cli("--json", "db", "list")
        names = [d["name"] for d in json.loads(out)["databases"]] \
            if rc == 0 else []
        check("D remote CLI db list (second active)",
              names == ["default", "second"], err + out)
        third = os.path.join(workdir, "node", "data", "third.db")
        rc, out, err = cli("db", "add", "third", "--type", "sqlite",
                           "--path", third)
        check("D remote CLI db add", rc == 0, err + out)
        rc, out, err = cli("db", "migrate", "second", "third")
        check("D remote CLI db migrate", rc == 0 and "users=1" in out,
              err + out)
        rc, out, err = cli("db", "switch", "third")
        check("D remote CLI db switch", rc == 0, err + out)
        rc, out, err = cli("--json", "users", "list")
        check("D remote CLI sees the user on the switched database",
              [u["username"] for u in json.loads(out)["users"]]
              == ["webuser"], err + out)
        rc, out, err = cli("db", "switch", "default")
        check("D remote CLI switch back to default", rc == 0, err + out)
        # sessions live in the active database: the CLI session was
        # minted while "second" was active and default does not hold
        # it, so the CLI is signed out by the switch and logs in again
        rc, out, err = tc.drive_login(cli_home, port, auth)
        check("D remote CLI re-login on the switched-back database",
              rc == 0, err + out)
        rc2, out2, err2 = cli("db", "remove", "third")
        check("D remote CLI remove", rc2 == 0, err2 + out2)
    finally:
        server.terminate()


def main():
    part_a()
    part_b()
    part_c()
    part_d()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", *FAIL, sep="\n  ")
        sys.exit(1)


if __name__ == "__main__":
    main()
