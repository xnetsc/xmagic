#!/usr/bin/env python3
"""SQLite-backed user manager for the single-port Xray gateway.

The SQLite database is the single source of truth for identity. Xray's
config.json is a build artifact rendered from it; sshd's authorized_keys
likewise. Credential model per user (one identity, several protocol secrets):

  * VLESS uuid                 -- for the VLESS-WS inbound;
  * one password               -- shared by the Trojan-WS, HTTP-proxy
    (CONNECT) and SOCKS5 inbounds, all of which speak username+password;
  * a separate Shadowsocks password (+method) -- SS clients pair it with
    the method, so it stays its own secret;
  * an optional OpenSSH public key -- for the node's real SSH entry:
    sshd on the same host accepts the key, `ssh -D` gives a SOCKS5 proxy.

A first-byte dispatcher (sniff.py) owns the single public port and routes
each connection by its opening bytes: "SSH-" banner -> sshd; 0x05 ->
SOCKS5 inbound; HTTP CONNECT / absolute-form -> HTTP-proxy inbound;
HTTP with a WebSocket Upgrade -> the Xray fallback mux (WS paths, then
bare Shadowsocks as the default); anything else -> the mux as well
(VLESS-TCP direct, bare Shadowsocks).

Usage:
  users.py init
  users.py add USER [--ssh-key-file id.pub] [--note TEXT]
  users.py passwd USER                 rotate Trojan + Shadowsocks passwords
  users.py setkey USER --ssh-key-file id.pub
  users.py enable USER | disable USER | remove USER
  users.py list
  users.py render [--out config.json]  write Xray config from enabled users
  users.py render-keys [--out authorized_keys]

Environment:
  PROXY_DB        database path        (default ./data/users.db)
  XRAY_PORT       public listen port (the dispatcher binds this; 8080)
  XRAY_MUX_PORT   loopback port of the Xray fallback mux (default 18080)
  BE_HTTP_PORT    loopback HTTP-proxy inbound   (default 18081)
  BE_SOCKS_PORT   loopback SOCKS5 inbound       (default 18082)
  SS_BE_PORT      loopback Shadowsocks backend  (default 12003)
  VLESS_BE_BASE   first loopback VLESS-WS backend port  (default 12100)
  TROJAN_BE_BASE  first loopback Trojan-WS backend port (default 12200)
  SSH_TUNNEL_BASE first local port for ssh upstreams    (default 13000)
  VLESS_WS_PATHS  comma-separated WS paths for VLESS (default /vless-ws)
  TROJAN_WS_PATHS comma-separated WS paths for Trojan (default /trojan-ws)
                  Xray fallback paths are exact-match only (no wildcards);
                  run `users.py gen-paths N` to mint random alias paths -
                  every listed path is live at once, one backend inbound
                  per path, all sharing the same user list.
  SS_METHOD       default aes-256-gcm
  UPSTREAM_STRATEGY  balancer strategy when upstreams exist:
                     random | roundRobin | leastPing | leastLoad
                     (default roundRobin)

Cascade: this node can itself be a client of other nodes. `upstream-add`
records an upstream plus the credential its operator issued (same auth
model on both sides). Upstream protocol may be anything this node can
speak as a client: vless-ws, vless (plain TCP), trojan-ws, ss, http
(CONNECT, optional Basic auth), socks (optional user/pass), or ssh - for
ssh the render maps the upstream to a loopback SOCKS port and writes
ssh-tunnels.json (+ start-tunnels.sh) next to the config; an ssh client
process holds `ssh -N -D` to the upstream host with the recorded key
file, and Xray dials the local tunnel port as a socks outbound. Users
belong to an upstream group (default "default"); each group's pool is
load-balanced with UPSTREAM_STRATEGY. With no upstreams, egress is
direct.

Destination routing: `route-add` records a rule that sends traffic for a
target pattern (domain suffix / full domain / keyword / regexp / IP or
CIDR) to a chosen group pool, to direct egress, or to block, optionally
scoped to one user. Route rules render ahead of the per-user group
rules: user-scoped routes first, then global routes, then group rules,
then the catch-all.

The database holds protocol secrets in recoverable form (Xray needs them),
so keep the file at mode 600 on a root-only path. `add` prints the new
user's credentials once; store them in your password manager.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import string
import sys
import time
import uuid
from datetime import datetime, timezone

JSON_OUT = False  # set by the global --json flag: machine-readable output

DB_PATH = os.environ.get("PROXY_DB", "./data/users.db")
PUBLIC_PORT = int(os.environ.get("XRAY_PORT", "8080"))
VLESS_WS_PATH = os.environ.get("VLESS_WS_PATH", "/vless-ws")
TROJAN_WS_PATH = os.environ.get("TROJAN_WS_PATH", "/trojan-ws")
SS_METHOD = os.environ.get("SS_METHOD", "aes-256-gcm")
SS_METHODS = ("aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
              "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
              "2022-blake3-chacha20-poly1305")
MUX_PORT = int(os.environ.get("XRAY_MUX_PORT", "18080"))
BE_HTTP = int(os.environ.get("BE_HTTP_PORT", "18081"))
BE_SOCKS = int(os.environ.get("BE_SOCKS_PORT", "18082"))
BE_SS = int(os.environ.get("SS_BE_PORT", "12003"))
BE_VLESS_BASE = int(os.environ.get("VLESS_BE_BASE", "12100"))
BE_TROJAN_BASE = int(os.environ.get("TROJAN_BE_BASE", "12200"))
SSH_TUNNEL_BASE = int(os.environ.get("SSH_TUNNEL_BASE", "13000"))


def _parse_paths(raw, default):
    paths, seen = [], set()
    for p in raw.split(","):
        p = p.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        if p not in seen:
            seen.add(p)
            paths.append(p)
    return paths or [default]


def path_list(plural_env, singular_env, default):
    raw = os.environ.get(plural_env) or os.environ.get(singular_env) or default
    return _parse_paths(raw, default)


def vless_paths(conn=None):
    # A DB setting (admin_settings.vless_ws_paths) wins over the env -
    # that is what makes the paths manageable from web/CLI at runtime.
    if conn is not None:
        raw = get_setting(conn, "vless_ws_paths")
        if raw:
            return _parse_paths(raw, "/vless-ws")
    return path_list("VLESS_WS_PATHS", "VLESS_WS_PATH", "/vless-ws")


def trojan_paths(conn=None):
    if conn is not None:
        raw = get_setting(conn, "trojan_ws_paths")
        if raw:
            return _parse_paths(raw, "/trojan-ws")
    return path_list("TROJAN_WS_PATHS", "TROJAN_WS_PATH", "/trojan-ws")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  vless_uuid TEXT NOT NULL,
  trojan_password TEXT NOT NULL,
  ss_password TEXT NOT NULL,
  ss_method TEXT NOT NULL DEFAULT 'aes-256-gcm',
  ssh_pubkey TEXT,
  upstream_group TEXT NOT NULL DEFAULT 'default',
  note TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS upstreams (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  grp TEXT NOT NULL DEFAULT 'default',
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('vless-ws', 'vless', 'trojan-ws', 'ss', 'http', 'socks', 'ssh')),
  path TEXT,
  uuid TEXT,
  username TEXT,
  password TEXT,
  key_file TEXT,
  tls INTEGER NOT NULL DEFAULT 0,
  method TEXT NOT NULL DEFAULT 'aes-256-gcm',
  enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS routes (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('domain', 'full', 'keyword', 'regexp', 'ip')),
  pattern TEXT NOT NULL,
  target TEXT NOT NULL,
  username TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT,
  created_at TEXT NOT NULL
);
"""

STRATEGIES = ("random", "roundRobin", "leastPing", "leastLoad")
UPSTREAM_STRATEGY = os.environ.get("UPSTREAM_STRATEGY", "roundRobin")
if UPSTREAM_STRATEGY not in STRATEGIES:
    sys.exit(f"UPSTREAM_STRATEGY must be one of {STRATEGIES}, got {UPSTREAM_STRATEGY!r}")


def db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(users)")]
    if cols and "upstream_group" not in cols:  # migrate pre-group databases
        conn.execute("ALTER TABLE users ADD COLUMN upstream_group TEXT NOT NULL DEFAULT 'default'")
    ucols = [r[1] for r in conn.execute("PRAGMA table_info(upstreams)")]
    if ucols and "username" not in ucols:  # migrate pre-http/socks databases
        conn.execute("ALTER TABLE upstreams ADD COLUMN username TEXT")
    if ucols and "key_file" not in ucols:  # migrate pre-ssh databases
        conn.execute("ALTER TABLE upstreams ADD COLUMN key_file TEXT")
    if ucols and "tls" not in ucols:  # migrate pre-tls databases
        conn.execute("ALTER TABLE upstreams ADD COLUMN tls INTEGER NOT NULL DEFAULT 0")
    if ucols:
        # SQLite cannot alter a CHECK constraint; rebuild the table if the
        # protocol whitelist predates 'ssh' or the bare 'vless' protocol
        # ('vless-ws' in the DDL does not contain the quoted 'vless').
        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='upstreams'"
        ).fetchone()[0]
        if "'ssh'" not in ddl or "'vless'" not in ddl:
            cols = ("id, name, grp, address, port, protocol, path, uuid, username,"
                    " password, key_file, tls, method, enabled, note, created_at")
            body = SCHEMA.split("CREATE TABLE IF NOT EXISTS upstreams (")[1]
            conn.executescript(
                "ALTER TABLE upstreams RENAME TO upstreams_old;"
                "CREATE TABLE upstreams (" + body
                + f"INSERT INTO upstreams ({cols}) SELECT {cols} FROM upstreams_old;"
                + "DROP TABLE upstreams_old;"
            )
    return conn


def gen_password(n=24):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def get_user(conn, username):
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        sys.exit(f"no such user: {username}")
    return row


def cmd_init(_):
    with db() as conn:
        conn.commit()
    os.chmod(DB_PATH, 0o600)
    print(f"initialized {DB_PATH}")


def cmd_add(args):
    pubkey = None
    if args.ssh_key_file:
        with open(args.ssh_key_file) as f:
            pubkey = f.read().strip()
    user_uuid = str(uuid.uuid4())
    trojan_pw, ss_pw = gen_password(), gen_password()
    method = SS_METHOD
    with db() as conn:
        method = default_ss_method(conn)
        try:
            conn.execute(
                "INSERT INTO users (username, vless_uuid, trojan_password, ss_password,"
                " ss_method, ssh_pubkey, upstream_group, note, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (args.user, user_uuid, trojan_pw, ss_pw, method, pubkey,
                 args.group, args.note, datetime.now(timezone.utc).isoformat()),
            )
        except sqlite3.IntegrityError:
            sys.exit(f"user already exists: {args.user}")
    if JSON_OUT:
        print(json.dumps({"username": args.user, "vless_uuid": user_uuid,
                          "password": trojan_pw, "ss_method": method,
                          "ss_password": ss_pw, "group": args.group,
                          "ssh_key": bool(pubkey)}, indent=2))
        return
    print(f"user:            {args.user}")
    print(f"vless uuid:      {user_uuid}")
    print(f"password (trojan/http/socks): {trojan_pw}")
    print(f"ss:              {method} / {ss_pw}")
    print(f"ssh key:         {'registered' if pubkey else '(none)'}")
    print("shown once - store it now, then run: users.py render")


def cmd_passwd(args):
    trojan_pw, ss_pw = gen_password(), gen_password()
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("UPDATE users SET trojan_password = ?, ss_password = ? WHERE username = ?",
                     (trojan_pw, ss_pw, args.user))
    if JSON_OUT:
        print(json.dumps({"username": args.user, "password": trojan_pw,
                          "ss_password": ss_pw}, indent=2))
        return
    print(f"password (trojan/http/socks): {trojan_pw}")
    print(f"ss password:     {ss_pw}")
    print("run: users.py render")


def cmd_setkey(args):
    if getattr(args, "clear", False):
        pubkey = None
    elif args.ssh_key_file:
        with open(args.ssh_key_file) as f:
            pubkey = f.read().strip()
    else:
        sys.exit("setkey needs --ssh-key-file FILE or --clear")
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("UPDATE users SET ssh_pubkey = ? WHERE username = ?", (pubkey, args.user))
    print(f"ssh key {'cleared for' if pubkey is None else 'updated for'} {args.user}")


def cmd_rotate_uuid(args):
    new_uuid = str(uuid.uuid4())
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("UPDATE users SET vless_uuid = ? WHERE username = ?",
                     (new_uuid, args.user))
    if JSON_OUT:
        print(json.dumps({"username": args.user, "vless_uuid": new_uuid}, indent=2))
        return
    print(f"vless uuid:      {new_uuid}")
    print("run: users.py render")


def cmd_setmethod(args):
    if args.method not in SS_METHODS:
        sys.exit(f"ss method must be one of {SS_METHODS}, got {args.method!r}")
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("UPDATE users SET ss_method = ? WHERE username = ?",
                     (args.method, args.user))
    print(f"{args.user}: ss method = {args.method}; run: users.py render")


def cmd_setnote(args):
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("UPDATE users SET note = ? WHERE username = ?",
                     (args.note or None, args.user))
    print(f"{args.user}: note updated; run: users.py render")


def cmd_flag(args, value):
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("UPDATE users SET enabled = ? WHERE username = ?", (value, args.user))
    print(f"{args.user}: enabled = {bool(value)}; run: users.py render")


def cmd_remove(args):
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("DELETE FROM users WHERE username = ?", (args.user,))
    print(f"removed {args.user}; run: users.py render")


def cmd_list(_):
    with db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    if JSON_OUT:
        print(json.dumps([{"username": r["username"], "enabled": bool(r["enabled"]),
                           "group": r["upstream_group"], "ssh_key": bool(r["ssh_pubkey"]),
                           "created_at": r["created_at"]} for r in rows], indent=2))
        return
    if not rows:
        print("(no users)")
    for r in rows:
        print(f"{r['username']:<20} enabled={bool(r['enabled'])!s:<5} group={r['upstream_group']:<10} "
              f"ssh_key={'yes' if r['ssh_pubkey'] else 'no':<3} created={r['created_at']}")


def cmd_setgroup(args):
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("UPDATE users SET upstream_group = ? WHERE username = ?",
                     (args.group, args.user))
    print(f"{args.user}: upstream_group = {args.group}; run: users.py render")


# ---------------------------------------------------------------- upstreams
# This node is also a client: each upstream is another node of the same
# service, and the credential stored here is one that node's operator issued
# from their own users table - the auth model is the same on both sides.

def get_upstream(conn, name):
    row = conn.execute("SELECT * FROM upstreams WHERE name = ?", (name,)).fetchone()
    if row is None:
        sys.exit(f"no such upstream: {name}")
    return row


def cmd_upstream_add(args):
    if args.proto in ("vless-ws", "vless") and not args.uuid:
        sys.exit(f"{args.proto} upstream needs --uuid (the uuid the upstream operator issued you)")
    if args.proto in ("trojan-ws", "ss") and not args.password:
        sys.exit(f"{args.proto} upstream needs --password")
    if args.proto in ("http", "socks") and args.username and not args.password:
        sys.exit(f"{args.proto} upstream with --username also needs --password")
    if args.proto == "ssh" and not (args.username and args.key_file):
        sys.exit("ssh upstream needs --username (ssh user) and --key-file (private key path)")
    with db() as conn:
        try:
            conn.execute(
                "INSERT INTO upstreams (name, grp, address, port, protocol, path, uuid,"
                " username, password, key_file, tls, method, note, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (args.name, args.group, args.addr, args.port, args.proto, args.path,
                 args.uuid, args.username, args.password, args.key_file, 1 if args.tls else 0,
                 args.method, args.note, datetime.now(timezone.utc).isoformat()),
            )
        except sqlite3.IntegrityError:
            sys.exit(f"upstream already exists: {args.name}")
    if JSON_OUT:
        with db() as conn:
            r = get_upstream(conn, args.name)
        print(json.dumps({k: r[k] for k in r.keys()}, indent=2, default=str))
        return
    print(f"upstream {args.name} added (group {args.group}, {args.proto} "
          f"{args.addr}:{args.port}); run: users.py render")


def cmd_upstream_list(_):
    with db() as conn:
        rows = conn.execute("SELECT * FROM upstreams ORDER BY grp, name").fetchall()
    if JSON_OUT:
        print(json.dumps([{k: r[k] for k in r.keys()} for r in rows],
                         indent=2, default=str))
        return
    if not rows:
        print("(no upstreams - this node egresses directly)")
    for r in rows:
        print(f"{r['name']:<16} group={r['grp']:<10} enabled={bool(r['enabled'])!s:<5} "
              f"{r['protocol']:<9} {r['address']}:{r['port']}{r['path'] or ''}")


def cmd_upstream_flag(args, value):
    with db() as conn:
        get_upstream(conn, args.name)
        conn.execute("UPDATE upstreams SET enabled = ? WHERE name = ?", (value, args.name))
    print(f"upstream {args.name}: enabled = {bool(value)}; run: users.py render")


def cmd_upstream_remove(args):
    with db() as conn:
        get_upstream(conn, args.name)
        conn.execute("DELETE FROM upstreams WHERE name = ?", (args.name,))
    print(f"removed upstream {args.name}; run: users.py render")


UPSTREAM_FIELDS = ("grp", "address", "port", "protocol", "path", "uuid",
                   "username", "password", "key_file", "tls", "method", "note")
UPSTREAM_PROTOCOLS = ("vless-ws", "vless", "trojan-ws", "ss", "http", "socks", "ssh")


def validate_upstream_values(values):
    """Check a full upstream record (add, or the merge of an edit)."""
    proto = values.get("protocol")
    if proto not in UPSTREAM_PROTOCOLS:
        raise ValueError(f"protocol must be one of {UPSTREAM_PROTOCOLS}, got {proto!r}")
    if proto in ("vless-ws", "vless") and not values.get("uuid"):
        raise ValueError(f"{proto} upstream needs a uuid")
    if proto in ("trojan-ws", "ss") and not values.get("password"):
        raise ValueError(f"{proto} upstream needs a password")
    if proto in ("http", "socks") and values.get("username") and not values.get("password"):
        raise ValueError(f"{proto} upstream with a username also needs a password")
    if proto == "ssh" and not (values.get("username") and values.get("key_file")):
        raise ValueError("ssh upstream needs a username and a key_file")


def update_upstream(conn, name, changes):
    """Partial edit: keys in `changes` with value None are left alone;
    empty string is a real value (clears path/username/etc.)."""
    row = get_upstream(conn, name)
    merged = {k: row[k] for k in row.keys()}
    applied = {}
    for key, value in changes.items():
        if key not in UPSTREAM_FIELDS:
            raise ValueError(f"unknown upstream field {key!r}")
        if value is None:
            continue
        if key == "tls":
            value = 1 if value else 0
        if key == "port":
            value = int(value)
        merged[key] = value
        applied[key] = value
    validate_upstream_values(merged)
    if applied:
        sets = ", ".join(f"{k} = ?" for k in applied)
        conn.execute(f"UPDATE upstreams SET {sets} WHERE name = ?",
                     [*applied.values(), name])
    return get_upstream(conn, name)


def cmd_upstream_edit(args):
    changes = {"grp": args.group, "address": args.addr, "port": args.port,
               "protocol": args.proto, "path": args.path, "uuid": args.uuid,
               "username": args.username, "password": args.password,
               "key_file": args.key_file, "method": args.method, "note": args.note}
    if args.tls:
        changes["tls"] = True
    elif args.no_tls:
        changes["tls"] = False
    with db() as conn:
        try:
            row = update_upstream(conn, args.name, changes)
        except ValueError as exc:
            sys.exit(str(exc))
    if JSON_OUT:
        print(json.dumps({k: row[k] for k in row.keys()}, indent=2, default=str))
        return
    print(f"upstream {args.name} updated; run: users.py render")


# ---------------------------------------------------------------- routes
# Destination-based upstream selection: a route maps a target pattern to
# an upstream group pool, to direct egress, or to block. Kinds: domain
# (suffix match), full (exact domain), keyword, regexp, ip (address or
# CIDR). A route may be scoped to one user; user-scoped routes render
# before global ones, and all routes render before the per-user group
# rules, so a destination rule wins over the user's group assignment.

ROUTE_KINDS = ("domain", "full", "keyword", "regexp", "ip")


def get_route(conn, rid):
    row = conn.execute("SELECT * FROM routes WHERE id = ?", (rid,)).fetchone()
    if row is None:
        sys.exit(f"no such route: {rid}")
    return row


def validate_route_fields(kind, pattern):
    if kind not in ROUTE_KINDS:
        raise ValueError(f"kind must be one of {ROUTE_KINDS}, got {kind!r}")
    if not pattern:
        raise ValueError("pattern must be non-empty")
    if kind == "ip":
        try:
            ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            raise ValueError(f"invalid IP/CIDR pattern: {pattern}")
    else:
        if any(c.isspace() for c in pattern) or "://" in pattern:
            raise ValueError(f"invalid {kind} pattern: {pattern!r} (bare pattern, no scheme)")
        if kind in ("domain", "full") and "/" in pattern:
            raise ValueError(f"invalid {kind} pattern: {pattern!r} (no path component)")


def cmd_route_add(args):
    try:
        validate_route_fields(args.kind, args.pattern)
    except ValueError as exc:
        sys.exit(str(exc))
    with db() as conn:
        if args.user:
            get_user(conn, args.user)
        known = {r[0] for r in conn.execute("SELECT DISTINCT grp FROM upstreams")}
        cur = conn.execute(
            "INSERT INTO routes (kind, pattern, target, username, note, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (args.kind, args.pattern, args.to, args.user, args.note,
             datetime.now(timezone.utc).isoformat()))
        rid = cur.lastrowid
    if JSON_OUT:
        with db() as conn:
            r = get_route(conn, rid)
        print(json.dumps({k: r[k] for k in r.keys()}, indent=2, default=str))
        return
    warn = ""
    if args.to not in ("direct", "block") and args.to not in known:
        warn = (f" (warning: no upstreams in group {args.to!r} yet - "
                "the rule stays inert until one is added)")
    print(f"route #{rid} added: {args.kind} {args.pattern} -> {args.to}"
          + (f" (user {args.user})" if args.user else "") + warn
          + "; run: users.py render")


def cmd_route_list(_):
    with db() as conn:
        rows = conn.execute("SELECT * FROM routes ORDER BY id").fetchall()
    if JSON_OUT:
        print(json.dumps([{k: r[k] for k in r.keys()} for r in rows],
                         indent=2, default=str))
        return
    if not rows:
        print("(no routes - selection is by user group only)")
    for r in rows:
        print(f"#{r['id']:<4} enabled={bool(r['enabled'])!s:<5} {r['kind']:<8} "
              f"{r['pattern']:<28} -> {r['target']:<10} "
              f"user={r['username'] or '*':<10} {r['note'] or ''}")


def cmd_route_flag(args, value):
    with db() as conn:
        get_route(conn, args.id)
        conn.execute("UPDATE routes SET enabled = ? WHERE id = ?", (value, args.id))
    print(f"route #{args.id}: enabled = {bool(value)}; run: users.py render")


def cmd_route_remove(args):
    with db() as conn:
        get_route(conn, args.id)
        conn.execute("DELETE FROM routes WHERE id = ?", (args.id,))
    print(f"removed route #{args.id}; run: users.py render")


ROUTE_FIELDS = ("kind", "pattern", "target", "username", "note")


def update_route(conn, rid, changes):
    """Partial edit of a route; None values are left alone, an empty
    username clears the per-user scope."""
    row = get_route(conn, rid)
    merged = {k: row[k] for k in row.keys()}
    applied = {}
    for key, value in changes.items():
        if key not in ROUTE_FIELDS:
            raise ValueError(f"unknown route field {key!r}")
        if value is None:
            continue
        if key == "username" and value == "":
            value = None
        merged[key] = value
        applied[key] = value
    validate_route_fields(merged["kind"], merged["pattern"])
    if merged["username"]:
        get_user(conn, merged["username"])
    if applied:
        sets = ", ".join(f"{k} = ?" for k in applied)
        conn.execute(f"UPDATE routes SET {sets} WHERE id = ?",
                     [*applied.values(), rid])
    return get_route(conn, rid)


def cmd_route_edit(args):
    changes = {"kind": args.kind, "pattern": args.pattern, "target": args.to,
               "username": args.user, "note": args.note}
    with db() as conn:
        try:
            row = update_route(conn, args.id, changes)
        except ValueError as exc:
            sys.exit(str(exc))
    if JSON_OUT:
        print(json.dumps({k: row[k] for k in row.keys()}, indent=2, default=str))
        return
    print(f"route #{args.id} updated; run: users.py render")


def enabled_users(conn):
    return conn.execute("SELECT * FROM users WHERE enabled = 1 ORDER BY username").fetchall()


def _ws_stream(u, default_paths):
    ws = {"network": "ws", "wsSettings": {"path": u["path"] or default_paths[0]}}
    if "tls" in u.keys() and u["tls"]:
        ws["security"] = "tls"
        ws["tlsSettings"] = {"serverName": u["address"]}
    return ws


def upstream_outbound(u, tunnel_port=None, vpaths=None, tpaths=None):
    tag = f"up-{u['grp']}-{u['name']}"
    if u["protocol"] == "vless":
        stream = {"network": "tcp", "security": "none"}
        if "tls" in u.keys() and u["tls"]:
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": u["address"]}
        return {"tag": tag, "protocol": "vless",
                "settings": {"vnext": [{"address": u["address"], "port": u["port"],
                                         "users": [{"id": u["uuid"], "encryption": "none"}]}]},
                "streamSettings": stream}
    if u["protocol"] == "vless-ws":
        return {"tag": tag, "protocol": "vless",
                "settings": {"vnext": [{"address": u["address"], "port": u["port"],
                                         "users": [{"id": u["uuid"], "encryption": "none"}]}]},
                "streamSettings": _ws_stream(u, vpaths or vless_paths())}
    if u["protocol"] == "trojan-ws":
        return {"tag": tag, "protocol": "trojan",
                "settings": {"servers": [{"address": u["address"], "port": u["port"],
                                           "password": u["password"]}]},
                "streamSettings": _ws_stream(u, tpaths or trojan_paths())}
    if u["protocol"] == "ss":
        return {"tag": tag, "protocol": "shadowsocks",
                "settings": {"servers": [{"address": u["address"], "port": u["port"],
                                           "password": u["password"], "method": u["method"]}]}}
    if u["protocol"] == "http":
        # Xray's http outbound takes flat settings (docs: address/port/user/pass),
        # NOT the servers[]+users[] shape - that shape belongs to socks.
        settings = {"address": u["address"], "port": u["port"]}
        if u["username"]:
            settings["user"] = u["username"]
            settings["pass"] = u["password"]
        return {"tag": tag, "protocol": "http", "settings": settings}
    if u["protocol"] == "socks":
        server = {"address": u["address"], "port": u["port"]}
        if u["username"]:
            server["users"] = [{"user": u["username"], "pass": u["password"]}]
        return {"tag": tag, "protocol": "socks", "settings": {"servers": [server]}}
    if u["protocol"] == "ssh":
        # No native SSH outbound exists; a local ssh client holds
        # `ssh -N -D 127.0.0.1:tunnel_port` to the upstream host (see the
        # ssh-tunnels.json written by render) and Xray dials that SOCKS.
        return {"tag": tag, "protocol": "socks",
                "settings": {"servers": [{"address": "127.0.0.1", "port": tunnel_port}]}}
    return {"tag": tag, "protocol": "shadowsocks",
            "settings": {"servers": [{"address": u["address"], "port": u["port"],
                                       "password": u["password"], "method": u["method"]}]}}


_ROUTE_PREFIX = {"domain": "domain", "full": "full", "keyword": "keyword", "regexp": "regexp"}


def target_route_rules(conn, pool_groups):
    """Field rules from the routes table: destination -> pool/direct/block.

    User-scoped rules render before global ones; within each class, by id.
    A rule whose target pool has no enabled upstream is skipped with a
    warning rather than breaking the whole config.
    """
    rows = conn.execute(
        "SELECT * FROM routes WHERE enabled = 1 ORDER BY (username IS NULL), id"
    ).fetchall()
    rules, need_block = [], False
    for r in rows:
        if r["kind"] == "ip":
            rule = {"type": "field", "ip": [r["pattern"]]}
        else:
            rule = {"type": "field",
                    "domain": [f"{_ROUTE_PREFIX[r['kind']]}:{r['pattern']}"]}
        if r["username"]:
            rule["user"] = [r["username"]]
        t = r["target"]
        if t == "direct":
            rule["outboundTag"] = "direct"
        elif t == "block":
            rule["outboundTag"] = "block"
            need_block = True
        elif t in pool_groups:
            rule["balancerTag"] = f"pool-{t}"
        else:
            print(f"warning: route #{r['id']} ({r['kind']} {r['pattern']} -> {t}) "
                  "skipped: target pool has no enabled upstreams", file=sys.stderr)
            continue
        rules.append(rule)
    return rules, need_block


def build_egress(conn, users):
    """Outbounds + routing for the cascade. No upstreams -> direct freedom.

    Rule order: destination routes (user-scoped first, then global), then
    per-user upstream-group rules, then the catch-all (default pool, or
    direct when there is no default pool).
    """
    ups = conn.execute("SELECT * FROM upstreams WHERE enabled = 1 ORDER BY grp, name").fetchall()
    groups = sorted({u["grp"] for u in ups})
    route_rules, need_block = target_route_rules(conn, set(groups))
    vpaths, tpaths = vless_paths(conn), trojan_paths(conn)
    outbounds = []
    ssh_idx = 0
    for u in ups:
        if u["protocol"] == "ssh":
            outbounds.append(upstream_outbound(u, SSH_TUNNEL_BASE + ssh_idx, vpaths, tpaths))
            ssh_idx += 1
        else:
            outbounds.append(upstream_outbound(u, None, vpaths, tpaths))
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    if need_block:
        outbounds.append({"tag": "block", "protocol": "blackhole"})
    if not ups and not route_rules:
        return outbounds, None, 0
    balancers = [{"tag": f"pool-{g}", "selector": [f"up-{g}-"],
                  "strategy": {"type": upstream_strategy(conn)}} for g in groups]
    rules = list(route_rules)
    for g in groups:
        if g == "default":
            continue
        members = [u["username"] for u in users if u["upstream_group"] == g]
        if members:
            rules.append({"type": "field", "user": members, "balancerTag": f"pool-{g}"})
    if "default" in groups:
        rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "pool-default"})
    else:
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})
    routing = {"rules": rules}
    if balancers:
        routing["balancers"] = balancers
    return outbounds, routing, len(ups)


def render_config(conn):
    users = enabled_users(conn)
    vpaths, tpaths = vless_paths(conn), trojan_paths(conn)
    fallbacks = ([{"path": p, "dest": BE_VLESS_BASE + i} for i, p in enumerate(vpaths)]
                 + [{"path": p, "dest": BE_TROJAN_BASE + i} for i, p in enumerate(tpaths)]
                 + [{"dest": BE_SS}])
    accounts = [{"user": u["username"], "pass": u["trojan_password"]} for u in users]
    inbounds = [
        {
            "tag": "main", "listen": "127.0.0.1", "port": MUX_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": u["vless_uuid"], "email": u["username"]} for u in users],
                "decryption": "none", "fallbacks": fallbacks},
            "streamSettings": {"network": "tcp", "security": "none"},
        },
        {
            "tag": "http-in", "listen": "127.0.0.1", "port": BE_HTTP,
            "protocol": "http",
            "settings": {"accounts": accounts, "allowTransparent": False},
        },
        {
            "tag": "socks-in", "listen": "127.0.0.1", "port": BE_SOCKS,
            "protocol": "socks",
            "settings": {"auth": "password", "accounts": accounts, "udp": True},
        },
    ]
    for i, p in enumerate(vpaths):
        inbounds.append({
            "tag": f"vless-ws-{i}", "listen": "127.0.0.1", "port": BE_VLESS_BASE + i,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": u["vless_uuid"], "email": u["username"]} for u in users],
                "decryption": "none",
            },
            "streamSettings": {"network": "ws", "wsSettings": {"path": p}},
        })
    for i, p in enumerate(tpaths):
        inbounds.append({
            "tag": f"trojan-ws-{i}", "listen": "127.0.0.1", "port": BE_TROJAN_BASE + i,
            "protocol": "trojan",
            "settings": {
                "clients": [{"password": u["trojan_password"], "email": u["username"]}
                            for u in users],
            },
            "streamSettings": {"network": "ws", "wsSettings": {"path": p}},
        })
    inbounds.append({
        "tag": "ss", "listen": "127.0.0.1", "port": BE_SS,
        "protocol": "shadowsocks",
        "settings": {
            "clients": [{"password": u["ss_password"], "method": u["ss_method"],
                         "email": u["username"]} for u in users],
            "network": "tcp,udp",
        },
    })
    cfg = {"log": {"loglevel": "warning"}, "inbounds": inbounds}
    outbounds, routing, n_up = build_egress(conn, users)
    cfg["outbounds"] = outbounds
    if routing:
        cfg["routing"] = routing
    return cfg, len(users), n_up


def ssh_tunnels(conn):
    ups = conn.execute(
        "SELECT * FROM upstreams WHERE enabled = 1 AND protocol = 'ssh' ORDER BY grp, name"
    ).fetchall()
    tunnels = []
    for i, u in enumerate(ups):
        port = SSH_TUNNEL_BASE + i
        tunnels.append({
            "name": u["name"], "group": u["grp"], "local_socks_port": port,
            "ssh_command": ["ssh", "-N",
                            "-D", f"127.0.0.1:{port}",
                            "-i", u["key_file"],
                            "-p", str(u["port"]),
                            "-o", "BatchMode=yes",
                            "-o", "StrictHostKeyChecking=accept-new",
                            "-o", "ExitOnForwardFailure=yes",
                            "-o", "ServerAliveInterval=30",
                            f"{u['username']}@{u['address']}"],
        })
    return tunnels


def cmd_render(args):
    with db() as conn:
        cfg, n, n_up = render_config(conn)
        tunnels = ssh_tunnels(conn)
        vp, tp, strat = vless_paths(conn), trojan_paths(conn), upstream_strategy(conn)
    out = args.out or "./data/config.json"
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, out)
    if tunnels:
        tpath = os.path.join(os.path.dirname(os.path.abspath(out)), "ssh-tunnels.json")
        with open(tpath, "w") as f:
            json.dump(tunnels, f, indent=2)
        spath = os.path.join(os.path.dirname(os.path.abspath(out)), "start-tunnels.sh")
        with open(spath, "w") as f:
            f.write("#!/bin/sh\n# Hold one ssh -D tunnel per ssh upstream. Run under a\n"
                    "# supervisor (systemd / compose sidecar) so tunnels restart.\nset -e\n")
            for t in tunnels:
                f.write(" ".join(t["ssh_command"]) + " &\n")
            f.write("wait\n")
        os.chmod(spath, 0o755)
    egress = (f"{n_up} upstream(s), strategy {strat}" if n_up
              else "direct (no upstreams)")
    print(f"wrote {out}: dispatcher port {PUBLIC_PORT} -> mux {MUX_PORT}, "
          f"http-in {BE_HTTP}, socks-in {BE_SOCKS}, {n} enabled user(s), "
          f"vless paths {vp}, trojan paths {tp}, "
          f"default fallback -> shadowsocks, egress: {egress}"
          + (f", ssh tunnels: {len(tunnels)} (see ssh-tunnels.json)" if tunnels else ""))


_PATH_PREFIXES = ("/assets", "/static", "/api", "/cdn", "/media", "/dist", "/res")


def cmd_gen_paths(args):
    for _ in range(args.count):
        token = "".join(secrets.choice(string.ascii_lowercase + string.digits)
                        for _ in range(secrets.choice((6, 8, 10))))
        print(f"{secrets.choice(_PATH_PREFIXES)}/{token}")


def cmd_render_keys(args):
    with db() as conn:
        rows = conn.execute(
            "SELECT username, ssh_pubkey FROM users WHERE enabled = 1 AND ssh_pubkey IS NOT NULL"
            " ORDER BY username").fetchall()
    out = args.out or "./data/authorized_keys"
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            key = r["ssh_pubkey"].strip()
            if not key.endswith(r["username"]):
                key = f"{key} {r['username']}"
            f.write(key + "\n")
    os.replace(tmp, out)
    os.chmod(out, 0o600)
    print(f"wrote {out}: {len(rows)} key(s)")


# ------------------------------------------------------------ apply/status
# The web console and this CLI are two frontends over the same engine:
# every mutation either side makes lands in the same DB, and "apply" is
# the same operation in both - render config.json + authorized_keys next
# to the database, then restart the gateway containers over the Docker
# socket when it is available.

DOCKER_SOCK = os.environ.get("XMAGIC_DOCKER_SOCK", "/var/run/docker.sock")
XRAY_CONTAINER = os.environ.get("XMAGIC_XRAY_CONTAINER", "proxy-xray")
SSHD_CONTAINER = os.environ.get("XMAGIC_SSHD_CONTAINER", "proxy-sshd")

# ------------------------------------------------------------ settings
# Console settings live in the same DB (admin_settings key/value table)
# so the web console and both CLIs read and write the same values.

SETTINGS_SCHEMA = ("CREATE TABLE IF NOT EXISTS admin_settings"
                   " (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
SESSION_TTL_HOURS_DEFAULT = 168  # one week
SESSION_TTL_HOURS_MIN, SESSION_TTL_HOURS_MAX = 1, 2160  # 1h .. 90d


def get_setting(conn, key, default=None):
    try:
        row = conn.execute("SELECT value FROM admin_settings WHERE key = ?",
                           (key,)).fetchone()
    except sqlite3.OperationalError:
        return default
    return row[0] if row else default


def set_setting(conn, key, value):
    conn.execute(SETTINGS_SCHEMA)
    conn.execute("INSERT INTO admin_settings (key, value) VALUES (?, ?)"
                 " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, str(value)))


def delete_setting(conn, key):
    conn.execute(SETTINGS_SCHEMA)
    conn.execute("DELETE FROM admin_settings WHERE key = ?", (key,))


def upstream_strategy(conn=None):
    if conn is not None:
        raw = get_setting(conn, "upstream_strategy")
        if raw in STRATEGIES:
            return raw
    return UPSTREAM_STRATEGY


def default_ss_method(conn=None):
    if conn is not None:
        raw = get_setting(conn, "ss_method")
        if raw in SS_METHODS:
            return raw
    return SS_METHOD


def settings_info(conn):
    return {
        "session_ttl_hours": session_ttl_hours(conn),
        "vless_ws_paths": vless_paths(conn),
        "vless_ws_paths_from_db": get_setting(conn, "vless_ws_paths") is not None,
        "trojan_ws_paths": trojan_paths(conn),
        "trojan_ws_paths_from_db": get_setting(conn, "trojan_ws_paths") is not None,
        "upstream_strategy": upstream_strategy(conn),
        "upstream_strategy_from_db": get_setting(conn, "upstream_strategy") is not None,
        "ss_method": default_ss_method(conn),
        "ss_method_from_db": get_setting(conn, "ss_method") is not None,
    }


def session_ttl_hours(conn):
    try:
        hours = int(get_setting(conn, "session_ttl_hours",
                                SESSION_TTL_HOURS_DEFAULT))
    except (TypeError, ValueError):
        hours = SESSION_TTL_HOURS_DEFAULT
    return max(SESSION_TTL_HOURS_MIN, min(SESSION_TTL_HOURS_MAX, hours))


def cmd_settings(args):
    with db() as conn:
        if args.session_ttl_hours is not None:
            if not (SESSION_TTL_HOURS_MIN <= args.session_ttl_hours
                    <= SESSION_TTL_HOURS_MAX):
                sys.exit(f"session ttl must be {SESSION_TTL_HOURS_MIN}.."
                         f"{SESSION_TTL_HOURS_MAX} hours")
            set_setting(conn, "session_ttl_hours", args.session_ttl_hours)
        for key, value in (("vless_ws_paths", args.vless_ws_paths),
                           ("trojan_ws_paths", args.trojan_ws_paths),
                           ("upstream_strategy", args.upstream_strategy),
                           ("ss_method", args.ss_method)):
            if value is None:
                continue
            if value == "":  # empty string clears back to the env default
                delete_setting(conn, key)
                continue
            if key == "upstream_strategy" and value not in STRATEGIES:
                sys.exit(f"upstream strategy must be one of {STRATEGIES}")
            if key == "ss_method" and value not in SS_METHODS:
                sys.exit(f"ss method must be one of {SS_METHODS}")
            if key.endswith("_paths"):
                value = ",".join(_parse_paths(value, "/unused"))
            set_setting(conn, key, value)
        conn.commit()
        info = settings_info(conn)
    if JSON_OUT:
        print(json.dumps(info, indent=2))
        return
    src = {True: "db", False: "env"}
    print(f"session_ttl_hours: {info['session_ttl_hours']} "
          f"({info['session_ttl_hours'] / 24:g} days, new sessions only)")
    print(f"vless_ws_paths: {','.join(info['vless_ws_paths'])} "
          f"({src[info['vless_ws_paths_from_db']]})")
    print(f"trojan_ws_paths: {','.join(info['trojan_ws_paths'])} "
          f"({src[info['trojan_ws_paths_from_db']]})")
    print(f"upstream_strategy: {info['upstream_strategy']} "
          f"({src[info['upstream_strategy_from_db']]})")
    print(f"ss_method (new users): {info['ss_method']} "
          f"({src[info['ss_method_from_db']]})")


def render_all(out_dir):
    """Render config.json (+ ssh tunnel files) and authorized_keys."""
    os.makedirs(out_dir, exist_ok=True)
    with db() as conn:
        cfg, n_users, n_up = render_config(conn)
        tunnels = ssh_tunnels(conn)
    config_path = os.path.join(out_dir, "config.json")
    tmp = config_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, config_path)
    if tunnels:
        with open(os.path.join(out_dir, "ssh-tunnels.json"), "w") as f:
            json.dump(tunnels, f, indent=2)
        spath = os.path.join(out_dir, "start-tunnels.sh")
        with open(spath, "w") as f:
            f.write("#!/bin/sh\nset -e\n")
            for t in tunnels:
                f.write(" ".join(t["ssh_command"]) + " &\n")
            f.write("wait\n")
        os.chmod(spath, 0o755)
    with db() as conn:
        rows = conn.execute(
            "SELECT username, ssh_pubkey FROM users WHERE enabled = 1"
            " AND ssh_pubkey IS NOT NULL ORDER BY username").fetchall()
    keys_path = os.path.join(out_dir, "authorized_keys")
    tmp = keys_path + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            key = r["ssh_pubkey"].strip()
            if not key.endswith(r["username"]):
                key = f"{key} {r['username']}"
            f.write(key + "\n")
    os.replace(tmp, keys_path)
    os.chmod(keys_path, 0o600)
    return {"users": n_users, "upstreams": n_up, "ssh_keys": len(rows),
            "ssh_tunnels": len(tunnels)}


def docker_restart(name):
    """POST /containers/<name>/restart over the unix socket. None = no sock."""
    if not os.path.exists(DOCKER_SOCK):
        return None
    request = (f"POST /containers/{name}/restart?t=5 HTTP/1.1\r\n"
               "Host: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(15)
            sock.connect(DOCKER_SOCK)
            sock.sendall(request.encode())
            status_line = sock.recv(4096).decode("latin1").splitlines()[0]
        return " 204 " in status_line or " 200 " in status_line
    except OSError:
        return False


def apply_changes():
    out_dir = os.path.dirname(os.path.abspath(DB_PATH))
    result = render_all(out_dir)
    restarted = {}
    for label, container in (("xray", XRAY_CONTAINER), ("sshd", SSHD_CONTAINER)):
        outcome = docker_restart(container)
        if outcome is not None:
            restarted[label] = outcome
    result["restarted"] = restarted
    result["restart_skipped"] = not restarted
    return result


def cmd_apply(_):
    result = apply_changes()
    if JSON_OUT:
        print(json.dumps(result, indent=2))
        return
    line = (f"applied: rendered {result['users']} user(s), "
            f"{result['upstreams']} upstream(s), {result['ssh_keys']} ssh key(s)")
    if result["restart_skipped"]:
        line += "; no docker socket - restart xray/sshd manually to apply"
    else:
        line += "; restarts: " + ", ".join(
            f"{k}={'ok' if v else 'FAILED'}" for k, v in result["restarted"].items())
    print(line)


def cmd_status(_):
    with db() as conn:
        info = {
            "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "users_enabled": conn.execute(
                "SELECT COUNT(*) FROM users WHERE enabled = 1").fetchone()[0],
            "upstreams": conn.execute("SELECT COUNT(*) FROM upstreams").fetchone()[0],
            "upstreams_enabled": conn.execute(
                "SELECT COUNT(*) FROM upstreams WHERE enabled = 1").fetchone()[0],
            "routes": conn.execute("SELECT COUNT(*) FROM routes").fetchone()[0],
            "routes_enabled": conn.execute(
                "SELECT COUNT(*) FROM routes WHERE enabled = 1").fetchone()[0],
        }
        try:
            cred = conn.execute(
                "SELECT created_at, label FROM admin_credentials WHERE id = 1").fetchone()
        except sqlite3.OperationalError:
            cred = None
    info["admin_registered"] = cred is not None
    info["admin_created_at"] = cred["created_at"] if cred else None
    info["admin_label"] = cred["label"] if cred else None
    info["docker_socket"] = os.path.exists(DOCKER_SOCK)
    info["public_port"] = PUBLIC_PORT
    info["db"] = DB_PATH
    if JSON_OUT:
        print(json.dumps(info, indent=2))
        return
    print(f"db: {info['db']}")
    print(f"users: {info['users_enabled']}/{info['users']} enabled; "
          f"upstreams: {info['upstreams_enabled']}/{info['upstreams']} enabled; "
          f"routes: {info['routes_enabled']}/{info['routes']} enabled")
    print(f"admin console: {'registered ' + str(info['admin_created_at']) if cred else 'NOT registered'}"
          f"; docker socket: {'available' if info['docker_socket'] else 'absent'}"
          f"; public port: {info['public_port']}")


# ------------------------------------------------------------ sessions
# Login sessions (web console and remote CLI alike) are rows in
# admin_sessions, keyed by the SHA-256 of the bearer token: the raw
# token is never stored, so a database leak does not hand out live
# sessions. One admin may hold many sessions at once (several browsers
# and CLI logins); every management interface can list and revoke them.

SESSIONS_SCHEMA = ("CREATE TABLE IF NOT EXISTS admin_sessions"
                   " (token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL,"
                   "  label TEXT, created_at INTEGER NOT NULL,"
                   "  expires_at INTEGER NOT NULL)")


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def session_id_of(token):
    return token_hash(token)[:12]


def mint_session(conn, token, kind, label, ttl_seconds):
    conn.execute(SESSIONS_SCHEMA)
    now = int(time.time())
    conn.execute(
        "INSERT OR REPLACE INTO admin_sessions"
        " (token_hash, kind, label, created_at, expires_at) VALUES (?,?,?,?,?)",
        (token_hash(token), kind, label, now, now + int(ttl_seconds)))


def find_session(conn, token):
    if not token:
        return None
    try:
        row = conn.execute("SELECT * FROM admin_sessions WHERE token_hash = ?",
                           (token_hash(token),)).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    if row["expires_at"] <= int(time.time()):
        conn.execute("DELETE FROM admin_sessions WHERE token_hash = ?",
                     (token_hash(token),))
        return None
    return row


def list_session_rows(conn):
    conn.execute(SESSIONS_SCHEMA)
    conn.execute("DELETE FROM admin_sessions WHERE expires_at <= ?",
                 (int(time.time()),))
    return conn.execute(
        "SELECT * FROM admin_sessions ORDER BY created_at").fetchall()


def session_row_dict(row):
    return {"id": row["token_hash"][:12], "kind": row["kind"],
            "label": row["label"], "created_at": row["created_at"],
            "expires_at": row["expires_at"]}


def revoke_token(conn, token):
    conn.execute(SESSIONS_SCHEMA)
    cur = conn.execute("DELETE FROM admin_sessions WHERE token_hash = ?",
                       (token_hash(token),))
    return cur.rowcount > 0


def revoke_session_by_id(conn, id_prefix):
    matches = [r for r in list_session_rows(conn)
               if r["token_hash"].startswith(id_prefix)]
    if len(matches) != 1:
        return None
    conn.execute("DELETE FROM admin_sessions WHERE token_hash = ?",
                 (matches[0]["token_hash"],))
    return matches[0]


def revoke_other_sessions(conn, keep_token):
    conn.execute(SESSIONS_SCHEMA)
    cur = conn.execute("DELETE FROM admin_sessions WHERE token_hash != ?",
                       (token_hash(keep_token),))
    return cur.rowcount


def revoke_all_sessions(conn):
    conn.execute(SESSIONS_SCHEMA)
    cur = conn.execute("DELETE FROM admin_sessions")
    return cur.rowcount


def _fmt_ts(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def cmd_sessions(_):
    with db() as conn:
        rows = [session_row_dict(r) for r in list_session_rows(conn)]
    if JSON_OUT:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("(no live sessions)")
    for r in rows:
        print(f"{r['id']}  {r['kind']:<4} created={_fmt_ts(r['created_at'])} "
              f"expires={_fmt_ts(r['expires_at'])}  {r['label'] or ''}")


def cmd_sessions_revoke(args):
    with db() as conn:
        row = revoke_session_by_id(conn, args.id)
    if row is None:
        sys.exit(f"no unique live session with id prefix {args.id!r}")
    print(f"revoked session {row['token_hash'][:12]} ({row['kind']}, "
          f"created {_fmt_ts(row['created_at'])})")


def cmd_sessions_revoke_all(_):
    with db() as conn:
        n = revoke_all_sessions(conn)
    print(f"revoked {n} session(s) - every web and CLI login is signed out")


def cmd_admin_reset(_):
    """Break-glass for the admin console: drop the registered passkey so a
    new one can be registered. Host access is the authority here - anyone
    who can run this already owns the box and the database."""
    conn = db()
    try:
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS admin_credentials ("
            " id INTEGER PRIMARY KEY CHECK (id = 1), credential_id TEXT UNIQUE NOT NULL,"
            " public_key_x TEXT NOT NULL, public_key_y TEXT NOT NULL,"
            " sign_count INTEGER NOT NULL DEFAULT 0, label TEXT, created_at TEXT NOT NULL);")
        cur = conn.execute("DELETE FROM admin_credentials")
        conn.commit()
    finally:
        conn.close()
    print("admin passkey cleared - the console is in setup mode again"
          if cur.rowcount else "no admin passkey was registered")


def main():
    p = argparse.ArgumentParser(prog="users.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--json", action="store_true",
                   help="machine-readable output (data commands)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("apply").set_defaults(fn=cmd_apply)
    a = sub.add_parser("settings")
    a.add_argument("--session-ttl-hours", type=int)
    a.add_argument("--vless-ws-paths", help="comma-separated; empty string = back to env")
    a.add_argument("--trojan-ws-paths", help="comma-separated; empty string = back to env")
    a.add_argument("--upstream-strategy")
    a.add_argument("--ss-method", help="default method for new users")
    a.set_defaults(fn=cmd_settings)
    sub.add_parser("sessions").set_defaults(fn=cmd_sessions)
    a = sub.add_parser("sessions-revoke"); a.add_argument("id")
    a.set_defaults(fn=cmd_sessions_revoke)
    sub.add_parser("sessions-revoke-all").set_defaults(fn=cmd_sessions_revoke_all)
    sub.add_parser("admin-reset").set_defaults(fn=cmd_admin_reset)
    a = sub.add_parser("add"); a.add_argument("user")
    a.add_argument("--ssh-key-file"); a.add_argument("--note")
    a.add_argument("--group", default="default", help="upstream group for this user")
    a.set_defaults(fn=cmd_add)
    a = sub.add_parser("passwd"); a.add_argument("user"); a.set_defaults(fn=cmd_passwd)
    a = sub.add_parser("setkey"); a.add_argument("user")
    a.add_argument("--ssh-key-file"); a.add_argument("--clear", action="store_true",
                   help="remove the user's ssh key instead of setting one")
    a.set_defaults(fn=cmd_setkey)
    a = sub.add_parser("rotate-uuid"); a.add_argument("user")
    a.set_defaults(fn=cmd_rotate_uuid)
    a = sub.add_parser("setmethod"); a.add_argument("user"); a.add_argument("method")
    a.set_defaults(fn=cmd_setmethod)
    a = sub.add_parser("setnote"); a.add_argument("user")
    a.add_argument("note", nargs="?", help="omit or pass empty to clear")
    a.set_defaults(fn=cmd_setnote)
    a = sub.add_parser("setgroup"); a.add_argument("user"); a.add_argument("group")
    a.set_defaults(fn=cmd_setgroup)
    a = sub.add_parser("enable"); a.add_argument("user")
    a.set_defaults(fn=lambda args: cmd_flag(args, 1))
    a = sub.add_parser("disable"); a.add_argument("user")
    a.set_defaults(fn=lambda args: cmd_flag(args, 0))
    a = sub.add_parser("remove"); a.add_argument("user"); a.set_defaults(fn=cmd_remove)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    a = sub.add_parser("upstream-add"); a.add_argument("name")
    a.add_argument("--addr", required=True); a.add_argument("--port", type=int, required=True)
    a.add_argument("--proto", required=True,
                   choices=("vless-ws", "vless", "trojan-ws", "ss", "http", "socks", "ssh"))
    a.add_argument("--group", default="default")
    a.add_argument("--path"); a.add_argument("--uuid")
    a.add_argument("--username"); a.add_argument("--password")
    a.add_argument("--key-file", help="ssh upstream: path to the private key file")
    a.add_argument("--tls", action="store_true",
                   help="vless-ws/vless/trojan-ws upstream: dial with TLS (SNI = address);"
                        " required by Xray for plaintext protocols to public IPs")
    a.add_argument("--method", default="aes-256-gcm"); a.add_argument("--note")
    a.set_defaults(fn=cmd_upstream_add)
    a = sub.add_parser("upstream-edit"); a.add_argument("name")
    a.add_argument("--addr"); a.add_argument("--port", type=int)
    a.add_argument("--proto", choices=("vless-ws", "vless", "trojan-ws", "ss", "http", "socks", "ssh"))
    a.add_argument("--group"); a.add_argument("--path"); a.add_argument("--uuid")
    a.add_argument("--username"); a.add_argument("--password"); a.add_argument("--key-file")
    a.add_argument("--tls", action="store_true"); a.add_argument("--no-tls", action="store_true")
    a.add_argument("--method"); a.add_argument("--note")
    a.set_defaults(fn=cmd_upstream_edit)
    sub.add_parser("upstream-list").set_defaults(fn=cmd_upstream_list)
    a = sub.add_parser("upstream-enable"); a.add_argument("name")
    a.set_defaults(fn=lambda args: cmd_upstream_flag(args, 1))
    a = sub.add_parser("upstream-disable"); a.add_argument("name")
    a.set_defaults(fn=lambda args: cmd_upstream_flag(args, 0))
    a = sub.add_parser("upstream-remove"); a.add_argument("name")
    a.set_defaults(fn=cmd_upstream_remove)
    a = sub.add_parser("route-add")
    a.add_argument("--kind", required=True, choices=ROUTE_KINDS,
                   help="domain = suffix match, full = exact domain, keyword, regexp, ip = address/CIDR")
    a.add_argument("--pattern", required=True)
    a.add_argument("--to", required=True,
                   help="target: an upstream group name, or direct, or block")
    a.add_argument("--user", help="scope this route to one user (default: all users)")
    a.add_argument("--note")
    a.set_defaults(fn=cmd_route_add)
    a = sub.add_parser("route-edit"); a.add_argument("id", type=int)
    a.add_argument("--kind", choices=ROUTE_KINDS); a.add_argument("--pattern")
    a.add_argument("--to", dest="to"); a.add_argument("--user"); a.add_argument("--note")
    a.set_defaults(fn=cmd_route_edit)
    sub.add_parser("route-list").set_defaults(fn=cmd_route_list)
    a = sub.add_parser("route-enable"); a.add_argument("id", type=int)
    a.set_defaults(fn=lambda args: cmd_route_flag(args, 1))
    a = sub.add_parser("route-disable"); a.add_argument("id", type=int)
    a.set_defaults(fn=lambda args: cmd_route_flag(args, 0))
    a = sub.add_parser("route-remove"); a.add_argument("id", type=int)
    a.set_defaults(fn=cmd_route_remove)
    a = sub.add_parser("gen-paths"); a.add_argument("count", type=int, nargs="?", default=5)
    a.set_defaults(fn=cmd_gen_paths)
    a = sub.add_parser("render"); a.add_argument("--out"); a.set_defaults(fn=cmd_render)
    a = sub.add_parser("render-keys"); a.add_argument("--out")
    a.set_defaults(fn=cmd_render_keys)
    args = p.parse_args()
    global JSON_OUT
    JSON_OUT = args.json
    args.fn(args)


if __name__ == "__main__":
    main()
