#!/usr/bin/env python3
"""User manager for the single-port Xray gateway.

The business database is the single source of truth for identity:
SQLite by default, PostgreSQL or MySQL when configured (the db-*
commands manage named database configs - several parameter sets, one
active, switchable at any time, with data migration between them; the
configs themselves live in a local SQLite registry next to the default
database, never inside a managed database). Xray's
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
each connection by its opening bytes: "SSH-" banner -> sshd; a
well-formed SOCKS5 greeting -> SOCKS5 inbound (only when
XMAGIC_ENABLE_SOCKS5=1 - SOCKS5 is plaintext and off by default);
HTTP CONNECT / absolute-form -> HTTP-proxy inbound; HTTP with a
WebSocket Upgrade -> the Xray fallback mux (WS paths, then bare
Shadowsocks as the default); origin-form HTTP -> the admin console;
anything else -> the mux as well (bare Shadowsocks, and VLESS-TCP
direct only when VLESS is enabled - it is off by default).

Usage:
  users.py init
  users.py add USER [--ssh-key-file id.pub] [--note TEXT]
  users.py passwd USER                 rotate Trojan + Shadowsocks passwords
  users.py setkey USER --ssh-key-file id.pub
  users.py enable USER | disable USER | remove USER
  users.py list
  users.py render [--out config.json]  write Xray config from enabled users
  users.py render-keys [--out authorized_keys]
  users.py db-list | db-add NAME --type sqlite|postgres|mysql (--path P | --dsn D)
  users.py db-edit NAME | db-remove NAME | db-test NAME
  users.py db-switch NAME              make a config the active database
  users.py db-migrate SRC DST [--replace]   copy all business tables

Environment:
  PROXY_DB        default sqlite database path (default ./data/users.db)
  XMAGIC_LOCAL_DB local registry of database configs
                  (default: local.db next to PROXY_DB)
  XMAGIC_PID_DIR  directory of <name>.pid files for the gateway
                  processes (single-container form); when set, apply
                  restarts by signalling them, which restarts the
                  container as a whole
  DIRECT_ALLOW_PRIVATE  1 allows direct egress to private/LAN addresses
                  (default off; a DB setting wins over the env)
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
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import signal
import string
import struct
import sys
import time
import urllib.parse
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


# ------------------------------------------------------------ database layer
# Business data (users, upstreams, routes, console settings, sessions,
# the admin credential) lives in the ACTIVE database: SQLite by default,
# PostgreSQL or MySQL when configured. The database configurations
# themselves - the named connection parameter sets and which one is
# active - are node-local bootstrap data: they live in a small SQLite
# file next to the default database (LOCAL_DB_PATH), never inside a
# managed database, so the node can always find a working database and
# switch between them. Web console, node CLI and remote CLI all manage
# the same registry.

BUSINESS_TABLES = ("users", "upstreams", "routes", "admin_settings",
                   "admin_credentials", "admin_sessions")
DB_TYPES = ("sqlite", "postgres", "mysql")
LOCAL_DB_PATH = os.environ.get(
    "XMAGIC_LOCAL_DB",
    os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), "local.db"))
DEFAULT_CONFIG_NAME = "default"


class DBError(Exception):
    """A database-layer failure the caller can report as-is."""


class IntegrityError(DBError):
    """Uniqueness/constraint violation, on any dialect."""


class OperationalError(DBError):
    """Operational failure (missing table, unreachable server, ...)."""


class Row:
    """One result row: row[0], row["col"] and row.keys() all work on
    every dialect (sqlite3.Row only exists for SQLite)."""

    __slots__ = ("_cols", "_vals", "_map")

    def __init__(self, cols, vals):
        self._cols = tuple(cols)
        self._vals = tuple(vals)
        self._map = dict(zip(self._cols, self._vals))

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return self._vals[key]
        return self._map[key]

    def get(self, key, default=None):
        return self._map.get(key, default)

    def keys(self):
        return list(self._cols)

    def __contains__(self, key):
        return key in self._map

    def __iter__(self):
        return iter(self._vals)

    def __len__(self):
        return len(self._vals)

    def __repr__(self):
        return f"Row({self._map!r})"


class Cursor:
    """Driver cursor wrapper returning Row objects; iterable like a
    sqlite3 cursor."""

    def __init__(self, raw):
        self._raw = raw

    def _wrap(self, raw_row):
        if raw_row is None:
            return None
        cols = [d[0] for d in (self._raw.description or ())]
        return Row(cols, raw_row)

    def fetchone(self):
        return self._wrap(self._raw.fetchone())

    def fetchall(self):
        return [self._wrap(r) for r in self._raw.fetchall()]

    def __iter__(self):
        for r in self._raw:
            yield self._wrap(r)

    @property
    def lastrowid(self):
        return getattr(self._raw, "lastrowid", None)

    @property
    def rowcount(self):
        return self._raw.rowcount


_REPLACE_PK = {"admin_sessions": "token_hash", "admin_credentials": "id"}
_REPLACE_RE = re.compile(
    r"INSERT OR REPLACE INTO (\w+) \(([^)]*)\) VALUES \(([^)]*)\)",
    re.IGNORECASE)


def _split_sql(script):
    """Split a DDL script on semicolons outside string literals (the
    non-SQLite drivers refuse multi-statement executes)."""
    parts, buf, in_q = [], [], False
    for ch in script:
        buf.append(ch)
        if ch == "'":
            in_q = not in_q
        elif ch == ";" and not in_q:
            parts.append("".join(buf))
            buf = []
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p.strip()]


class DB:
    """Uniform connection over sqlite3 / psycopg / PyMySQL.

    SQL in this codebase is written in the SQLite dialect with ?
    placeholders; the wrapper translates the placeholders, the
    identity-column DDL, INSERT OR REPLACE upserts and the settings
    ON CONFLICT upsert for PostgreSQL and MySQL, and normalizes driver
    exceptions into IntegrityError / OperationalError.
    """

    def __init__(self, raw, dialect):
        self.raw = raw
        self.dialect = dialect

    # -- translation --------------------------------------------------
    def _translate(self, sql):
        if self.dialect == "sqlite":
            return sql
        out = sql
        m = _REPLACE_RE.search(out)
        if m and m.group(1).lower() in _REPLACE_PK:
            table = m.group(1)
            cols = [c.strip() for c in m.group(2).split(",")]
            pk = _REPLACE_PK[table.lower()]
            rest = [c for c in cols if c != pk]
            if self.dialect == "postgres":
                upd = ", ".join(f"{c} = excluded.{c}" for c in rest)
                repl = (f"INSERT INTO {table} ({m.group(2)})"
                        f" VALUES ({m.group(3)})"
                        f" ON CONFLICT ({pk}) DO UPDATE SET {upd}")
            else:  # mysql
                upd = ", ".join(f"{c} = VALUES({c})" for c in rest)
                repl = (f"INSERT INTO {table} ({m.group(2)})"
                        f" VALUES ({m.group(3)})"
                        f" ON DUPLICATE KEY UPDATE {upd}")
            out = out[:m.start()] + repl + out[m.end():]
        if self.dialect == "mysql":
            out = out.replace(
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                "ON DUPLICATE KEY UPDATE value = VALUES(value)")
            # `key` (the admin_settings column) is a reserved word in
            # MySQL - quote it, except inside the DUPLICATE KEY keyword
            # and where the DDL translation already quoted it.
            out = re.sub(r"(?<!DUPLICATE )(?<!`)\bkey\b(?!`)", "`key`", out)
        return out.replace("?", "%s")

    @staticmethod
    def _translate_ddl(sql, dialect):
        if dialect == "postgres":
            return sql.replace(
                "id INTEGER PRIMARY KEY,",
                "id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,")
        if dialect == "mysql":
            sql = sql.replace(
                "id INTEGER PRIMARY KEY,",
                "id INTEGER PRIMARY KEY AUTO_INCREMENT,")
            # MySQL keys cannot be bare TEXT columns (error 1170):
            # the keyed text columns become VARCHARs of a safe length.
            sql = sql.replace("key TEXT PRIMARY KEY",
                              "`key` VARCHAR(255) PRIMARY KEY")
            sql = sql.replace("token_hash TEXT PRIMARY KEY",
                              "token_hash VARCHAR(255) PRIMARY KEY")
            sql = sql.replace("username TEXT UNIQUE NOT NULL",
                              "username VARCHAR(255) UNIQUE NOT NULL")
            sql = sql.replace("name TEXT UNIQUE NOT NULL",
                              "name VARCHAR(255) UNIQUE NOT NULL")
            sql = sql.replace("credential_id TEXT UNIQUE NOT NULL",
                              "credential_id VARCHAR(512) UNIQUE NOT NULL")
            return sql
        return sql

    @staticmethod
    def _map_error(exc):
        if isinstance(exc, DBError):
            return exc
        # match on the whole MRO: psycopg raises subclasses such as
        # UniqueViolation whose own name is not "IntegrityError"
        names = {c.__name__ for c in type(exc).__mro__}
        if "IntegrityError" in names:
            return IntegrityError(str(exc))
        if names & {"OperationalError", "ProgrammingError", "InterfaceError",
                    "InternalError", "DatabaseError"} or \
                type(exc).__module__.startswith(("psycopg", "pymysql")):
            return OperationalError(str(exc))
        return DBError(str(exc))

    # -- DB-API surface the codebase uses ------------------------------
    def execute(self, sql, params=()):
        sql = self._translate(self._translate_ddl(sql, self.dialect))
        try:
            cur = self.raw.cursor()
            cur.execute(sql, tuple(params) if params else ())
            return Cursor(cur)
        except Exception as exc:
            if self.dialect == "postgres":
                # a failed statement aborts the transaction; roll back so
                # the connection stays usable for the caller's fallback
                try:
                    self.raw.rollback()
                except Exception:
                    pass
            raise self._map_error(exc) from exc

    def executemany(self, sql, seq):
        sql = self._translate(self._translate_ddl(sql, self.dialect))
        try:
            cur = self.raw.cursor()
            cur.executemany(sql, [tuple(p) for p in seq])
            return Cursor(cur)
        except Exception as exc:
            if self.dialect == "postgres":
                try:
                    self.raw.rollback()
                except Exception:
                    pass
            raise self._map_error(exc) from exc

    def executescript(self, script):
        script = self._translate_ddl(script, self.dialect)
        if self.dialect == "sqlite":
            try:
                self.raw.executescript(script)
            except Exception as exc:
                raise self._map_error(exc) from exc
            return
        for stmt in _split_sql(script):
            self.execute(stmt)

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        return False

    # -- dialect helpers ------------------------------------------------
    def insert_id(self, sql, params=()):
        """INSERT and return the new row's id (PostgreSQL has no
        lastrowid, so it goes through RETURNING)."""
        if self.dialect == "postgres":
            stmt = sql.rstrip().rstrip(";") + " RETURNING id"
            return self.execute(stmt, params).fetchone()[0]
        return self.execute(sql, params).lastrowid

    def columns(self, table):
        """Column names of a table, in declaration order ([] if the
        table does not exist)."""
        if self.dialect == "sqlite":
            return [r[1] for r in self.execute(f"PRAGMA table_info({table})")]
        if self.dialect == "mysql":
            rows = self.execute(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_schema = DATABASE() AND table_name = ?"
                " ORDER BY ordinal_position", (table,)).fetchall()
        else:
            rows = self.execute(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_name = ? ORDER BY ordinal_position",
                (table,)).fetchall()
        return [r[0] for r in rows]


CREDENTIALS_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS admin_credentials ("
    " id INTEGER PRIMARY KEY CHECK (id = 1), credential_id TEXT UNIQUE NOT NULL,"
    " public_key_x TEXT NOT NULL, public_key_y TEXT NOT NULL,"
    " sign_count INTEGER NOT NULL DEFAULT 0, label TEXT, created_at TEXT NOT NULL)")


def ensure_schema(conn):
    """Create every business table if missing (this is what rebuilds
    the schema when the node is pointed at a brand-new database) and
    apply the additive column migrations older databases need."""
    conn.executescript(SCHEMA)
    conn.execute(SETTINGS_SCHEMA)
    conn.execute(SESSIONS_SCHEMA)
    conn.execute(CREDENTIALS_SCHEMA)
    cols = conn.columns("users")
    if cols and "upstream_group" not in cols:  # migrate pre-group databases
        conn.execute("ALTER TABLE users ADD COLUMN upstream_group"
                     " TEXT NOT NULL DEFAULT 'default'")
    ucols = conn.columns("upstreams")
    if ucols and "username" not in ucols:  # migrate pre-http/socks databases
        conn.execute("ALTER TABLE upstreams ADD COLUMN username TEXT")
    if ucols and "key_file" not in ucols:  # migrate pre-ssh databases
        conn.execute("ALTER TABLE upstreams ADD COLUMN key_file TEXT")
    if ucols and "tls" not in ucols:  # migrate pre-tls databases
        conn.execute("ALTER TABLE upstreams ADD COLUMN tls"
                     " INTEGER NOT NULL DEFAULT 0")
    if ucols and conn.dialect == "sqlite":
        # SQLite cannot alter a CHECK constraint; rebuild the table if the
        # protocol whitelist predates 'ssh' or the bare 'vless' protocol
        # ('vless-ws' in the DDL does not contain the quoted 'vless').
        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table'"
            " AND name='upstreams'").fetchone()[0]
        if "'ssh'" not in ddl or "'vless'" not in ddl:
            cols = ("id, name, grp, address, port, protocol, path, uuid,"
                    " username, password, key_file, tls, method, enabled,"
                    " note, created_at")
            body = SCHEMA.split("CREATE TABLE IF NOT EXISTS upstreams (")[1]
            conn.executescript(
                "ALTER TABLE upstreams RENAME TO upstreams_old;"
                "CREATE TABLE upstreams (" + body
                + f"INSERT INTO upstreams ({cols}) SELECT {cols}"
                + " FROM upstreams_old;"
                + "DROP TABLE upstreams_old;"
            )
    conn.commit()


def _mysql_connect(dsn):
    import pymysql
    u = urllib.parse.urlparse(dsn)
    if u.scheme not in ("mysql", "mysql+pymysql") or not u.path.lstrip("/"):
        raise DBError(f"invalid MySQL DSN {dsn!r}"
                      " (want mysql://user:pass@host:port/dbname)")
    try:
        return pymysql.connect(
            host=u.hostname or "127.0.0.1", port=u.port or 3306,
            user=urllib.parse.unquote(u.username or ""),
            password=urllib.parse.unquote(u.password or ""),
            database=urllib.parse.unquote(u.path.lstrip("/")),
            charset="utf8mb4", autocommit=False)
    except Exception as exc:
        raise DBError(f"cannot connect to MySQL at {u.hostname}: {exc}")


def connect_config(cfg):
    """Open the business database a config describes and make sure the
    full schema exists in it."""
    typ, target = cfg["type"], cfg["target"]
    if typ == "sqlite":
        os.makedirs(os.path.dirname(os.path.abspath(target)),
                    exist_ok=True)
        conn = DB(sqlite3.connect(target), "sqlite")
    elif typ == "postgres":
        try:
            import psycopg
        except ImportError:
            raise DBError("PostgreSQL support needs the psycopg package:"
                          " pip install 'psycopg[binary]'")
        try:
            raw = psycopg.connect(target)
        except Exception as exc:
            raise DBError(f"cannot connect to PostgreSQL: {exc}")
        conn = DB(raw, "postgres")
    elif typ == "mysql":
        try:
            import pymysql  # noqa: F401
        except ImportError:
            raise DBError("MySQL support needs the pymysql package:"
                          " pip install pymysql")
        conn = DB(_mysql_connect(target), "mysql")
    else:
        raise DBError(f"unknown database type: {typ!r}")
    ensure_schema(conn)
    return conn


# ------------------------------------------------------------ local registry
# The registry itself: named database configs in a local SQLite file.

def _local_conn():
    os.makedirs(os.path.dirname(os.path.abspath(LOCAL_DB_PATH)),
                exist_ok=True)
    fresh = not os.path.exists(LOCAL_DB_PATH)
    conn = sqlite3.connect(LOCAL_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS db_configs ("
        " name TEXT PRIMARY KEY, type TEXT NOT NULL, target TEXT NOT NULL,"
        " note TEXT, is_active INTEGER NOT NULL DEFAULT 0,"
        " created_at TEXT NOT NULL)")
    if fresh:
        try:
            os.chmod(LOCAL_DB_PATH, 0o600)
        except OSError:
            pass
    return conn


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def mask_target(typ, target):
    """A config target safe to display: DSN passwords are hidden (the
    SQLite path holds no secret and is shown as-is)."""
    if typ == "sqlite":
        return target
    try:
        u = urllib.parse.urlparse(target)
        if u.password:
            netloc = u.hostname or ""
            if u.port:
                netloc += f":{u.port}"
            if u.username:
                netloc = f"{u.username}:***@{netloc}"
            return urllib.parse.urlunparse(
                (u.scheme, netloc, u.path, "", u.query, ""))
    except Exception:
        pass
    return target


def _default_cfg():
    return {"name": DEFAULT_CONFIG_NAME, "type": "sqlite", "target": DB_PATH,
            "note": None, "active": True}


def _stored_configs():
    with _local_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM db_configs ORDER BY created_at, name")]


def _public_cfg(cfg):
    return {"name": cfg["name"], "type": cfg["type"],
            "target": mask_target(cfg["type"], cfg["target"]),
            "note": cfg.get("note"), "active": bool(cfg.get("active"))}


def list_db_configs():
    """Every configured database (targets masked), active one flagged.
    With nothing stored, the implicit default - SQLite at PROXY_DB -
    is the one and only config."""
    rows = _stored_configs()
    if not rows:
        return [_public_cfg(_default_cfg())]
    any_active = any(r["is_active"] for r in rows)
    out = []
    for r in rows:
        active = bool(r["is_active"]) or (
            not any_active and r["name"] == DEFAULT_CONFIG_NAME)
        out.append(_public_cfg({**r, "active": active}))
    return out


def resolve_db_config(name):
    """The raw (unmasked) config for a name; DBError if unknown."""
    rows = _stored_configs()
    for r in rows:
        if r["name"] == name:
            return {"name": r["name"], "type": r["type"],
                    "target": r["target"], "note": r["note"]}
    if not rows and name == DEFAULT_CONFIG_NAME:
        cfg = _default_cfg()
        return {"name": cfg["name"], "type": cfg["type"],
                "target": cfg["target"], "note": None}
    raise DBError(f"no such database config: {name}")


def active_db_config():
    """The raw config of the database the node currently runs on."""
    rows = _stored_configs()
    for r in rows:
        if r["is_active"]:
            return {"name": r["name"], "type": r["type"],
                    "target": r["target"], "note": r["note"]}
    return _default_cfg()


def _materialize_default(conn):
    """Persist the implicit default config so it can be switched back
    to, edited and migrated like any other config."""
    n = conn.execute("SELECT COUNT(*) FROM db_configs").fetchone()[0]
    if n == 0:
        cfg = _default_cfg()
        conn.execute(
            "INSERT INTO db_configs (name, type, target, note, is_active,"
            " created_at) VALUES (?,?,?,?,1,?)",
            (cfg["name"], cfg["type"], cfg["target"], None, _now_iso()))


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


def _validate_config(name, typ, target):
    if not _NAME_RE.match(name or ""):
        raise DBError(f"invalid config name {name!r}"
                      " (letters, digits, - and _, max 32 chars)")
    if typ not in DB_TYPES:
        raise DBError(f"database type must be one of {DB_TYPES}, got {typ!r}")
    if not target:
        raise DBError("a target is required (sqlite: file path;"
                      " postgres/mysql: DSN)")
    if typ == "sqlite" and "://" in target:
        raise DBError("a sqlite target is a file path, not a DSN")
    if typ == "postgres" and not target.startswith(
            ("postgresql://", "postgres://")):
        raise DBError("PostgreSQL target must be a DSN like"
                      " postgresql://user:pass@host:5432/dbname")
    if typ == "mysql" and not target.startswith("mysql://"):
        raise DBError("MySQL target must be a DSN like"
                      " mysql://user:pass@host:3306/dbname")


def add_db_config(name, typ, target, note=None):
    _validate_config(name, typ, target)
    with _local_conn() as conn:
        _materialize_default(conn)
        if conn.execute("SELECT 1 FROM db_configs WHERE name = ?",
                        (name,)).fetchone():
            raise DBError(f"database config already exists: {name}")
        conn.execute(
            "INSERT INTO db_configs (name, type, target, note, is_active,"
            " created_at) VALUES (?,?,?,?,0,?)",
            (name, typ, target, note, _now_iso()))
    return _public_cfg({**resolve_db_config(name), "active": False})


def edit_db_config(name, target=None, note=None):
    cfg = resolve_db_config(name)
    if target is not None:
        _validate_config(name, cfg["type"], target)
    with _local_conn() as conn:
        _materialize_default(conn)
        if target is not None:
            conn.execute("UPDATE db_configs SET target = ? WHERE name = ?",
                         (target, name))
        if note is not None:
            conn.execute("UPDATE db_configs SET note = ? WHERE name = ?",
                         (note or None, name))
    active = active_db_config()["name"] == name
    return _public_cfg({**resolve_db_config(name), "active": active})


def remove_db_config(name):
    if active_db_config()["name"] == name:
        raise DBError(f"cannot remove the active database config {name!r}"
                      " - switch to another one first")
    with _local_conn() as conn:
        cur = conn.execute("DELETE FROM db_configs WHERE name = ?", (name,))
        if cur.rowcount == 0:
            raise DBError(f"no such database config: {name}")


def test_db_config(name):
    """Connect to a configured database (creating the full schema in
    it if it is still empty) and report its business-table row counts."""
    cfg = resolve_db_config(name)
    conn = connect_config(cfg)
    try:
        tables = {t: conn.execute(
            f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in BUSINESS_TABLES}
    finally:
        conn.close()
    return {"name": name, "type": cfg["type"],
            "target": mask_target(cfg["type"], cfg["target"]),
            "tables": tables}


def switch_db_config(name):
    """Make a config the active database. The target is connected to
    first (schema auto-created) so a switch never strands the node on
    an unreachable database."""
    cfg = resolve_db_config(name)
    conn = connect_config(cfg)
    conn.close()
    with _local_conn() as conn:
        _materialize_default(conn)
        conn.execute("UPDATE db_configs SET is_active = (name = ?)", (name,))
    return _public_cfg({**cfg, "active": True})


def migrate_db_config(src_name, dst_name, replace=False):
    """Copy every business table from one configured database to
    another (schema auto-created on the target). Refuses to write into
    a non-empty target unless replace is set."""
    if src_name == dst_name:
        raise DBError("source and target are the same database config")
    src = connect_config(resolve_db_config(src_name))
    try:
        dst = connect_config(resolve_db_config(dst_name))
    except Exception:
        src.close()
        raise
    try:
        dst_counts = {t: dst.execute(
            f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in BUSINESS_TABLES}
        nonempty = {t: c for t, c in dst_counts.items() if c}
        if nonempty and not replace:
            raise DBError(
                "target database is not empty ("
                + ", ".join(f"{t}={c}" for t, c in nonempty.items())
                + "); pass replace to overwrite it")
        if replace:
            for t in BUSINESS_TABLES:
                dst.execute(f"DELETE FROM {t}")
        copied = {}
        for t in BUSINESS_TABLES:
            cols = [c for c in src.columns(t) if c in dst.columns(t)]
            rows = src.execute(
                f"SELECT {', '.join(cols)} FROM {t}").fetchall()
            if rows:
                ph = ", ".join("?" * len(cols))
                dst.executemany(
                    f"INSERT INTO {t} ({', '.join(cols)}) VALUES ({ph})",
                    [tuple(r[c] for c in cols) for r in rows])
            copied[t] = len(rows)
        if dst.dialect == "postgres":
            # explicit ids were copied in; move each identity sequence
            # past the largest copied id so new rows do not collide
            for t in ("users", "upstreams", "routes"):
                if copied[t]:
                    dst.execute(
                        f"SELECT setval(pg_get_serial_sequence('{t}', 'id'),"
                        f" (SELECT MAX(id) FROM {t}))")
        dst.commit()
        for t in BUSINESS_TABLES:
            got = dst.execute(
                f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            if got != copied[t]:
                raise DBError(f"migration verification failed for {t}:"
                              f" copied {copied[t]}, target holds {got}")
        return {"from": src_name, "to": dst_name, "tables": copied}
    finally:
        src.close()
        dst.close()


def db():
    """Connect to the active business database."""
    return connect_config(active_db_config())


def gen_password(n=24):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def get_user(conn, username):
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        sys.exit(f"no such user: {username}")
    return row


def cmd_init(_):
    cfg = active_db_config()
    with db() as conn:
        conn.commit()
    if cfg["type"] == "sqlite":
        try:
            os.chmod(cfg["target"], 0o600)
        except OSError:
            pass
    print(f"initialized {cfg['name']} "
          f"({cfg['type']}: {mask_target(cfg['type'], cfg['target'])})")


def cmd_keygen(args):
    os.makedirs(args.out_dir, exist_ok=True)
    priv = os.path.join(args.out_dir, args.name)
    if os.path.exists(priv) or os.path.exists(priv + ".pub"):
        sys.exit(f"refusing to overwrite an existing key: {priv}")
    pub, fp = write_generated_key(priv, args.comment or args.name)
    with open(priv + ".pub", "w") as f:
        f.write(pub + "\n")
    if JSON_OUT:
        print(json.dumps({"private_key": priv, "public_key_file": priv + ".pub",
                          "public_key": pub, "fingerprint": fp}, indent=2))
        return
    print(f"private key: {priv} (0600 - keep it secret)")
    print(f"public key:  {priv}.pub")
    print(f"fingerprint: {fp}")
    print(pub)


def cmd_add(args):
    pubkey = None
    gen_fp = None
    if getattr(args, "ssh_key_generate", None):
        pubkey, gen_fp = write_generated_key(args.ssh_key_generate, args.user)
    elif args.ssh_key_file:
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
        except IntegrityError:
            sys.exit(f"user already exists: {args.user}")
    if JSON_OUT:
        print(json.dumps({"username": args.user, "vless_uuid": user_uuid,
                          "password": trojan_pw, "ss_method": method,
                          "ss_password": ss_pw, "group": args.group,
                          "ssh_key": bool(pubkey),
                          "ssh_private_key_file": (args.ssh_key_generate
                                                   if gen_fp else None),
                          "ssh_fingerprint": gen_fp}, indent=2))
        return
    print(f"user:            {args.user}")
    print(f"vless uuid:      {user_uuid}")
    print(f"password (trojan/http/socks): {trojan_pw}")
    print(f"ss:              {method} / {ss_pw}")
    print(f"ssh key:         {'registered' if pubkey else '(none)'}")
    if gen_fp:
        print(f"ssh private key: {args.ssh_key_generate} ({gen_fp})"
              " - yours to keep; the node stores only the public key")
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
    gen_fp = None
    if getattr(args, "clear", False):
        pubkey = None
    elif getattr(args, "ssh_key_generate", None):
        pubkey, gen_fp = write_generated_key(args.ssh_key_generate, args.user)
    elif args.ssh_key_file:
        with open(args.ssh_key_file) as f:
            pubkey = f.read().strip()
    else:
        sys.exit("setkey needs --ssh-key-file FILE, --ssh-key-generate PATH"
                 " or --clear")
    with db() as conn:
        get_user(conn, args.user)
        conn.execute("UPDATE users SET ssh_pubkey = ? WHERE username = ?", (pubkey, args.user))
    print(f"ssh key {'cleared for' if pubkey is None else 'updated for'} {args.user}")
    if gen_fp:
        print(f"ssh private key: {args.ssh_key_generate} ({gen_fp})"
              " - yours to keep; the node stores only the public key")


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


# ------------------------------------------------- ssh upstream private keys
# An ssh upstream's private key may be supplied as content (console
# upload/paste, or a CLI file flag): it is stored on the node in the
# ssh_client_keys directory next to the database, and the upstream row
# records the runtime path /keys/<file> - the tunnels processes see
# that directory mounted at /keys (compose form) or symlinked there
# (single-container form). A key_file given as a plain path keeps its
# original meaning: a file the operator provisioned themselves.
KEYS_DIR_NAME = "ssh_client_keys"
MANAGED_KEY_PREFIX = "/keys/"
MAX_KEY_BYTES = 65536


def keys_dir():
    return os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), KEYS_DIR_NAME)


def managed_key_path(name):
    """The runtime path recorded for an uploaded key (pure - no I/O)."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name).lstrip(".") or "upstream"
    return MANAGED_KEY_PREFIX + safe + ".key"


def validate_key_content(content):
    """Return the normalized key text, or raise ValueError."""
    text = (content or "").strip()
    if "PRIVATE KEY-----" not in text:
        raise ValueError("key content is not a PEM private key")
    if len(text.encode()) > MAX_KEY_BYTES:
        raise ValueError("key content is too large")
    return text


def write_upstream_key(name, content):
    """Store an uploaded private key on the node (0600, atomic)."""
    text = validate_key_content(content)
    d = keys_dir()
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, os.path.basename(managed_key_path(name)))
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def delete_managed_key(key_file):
    """Remove a node-stored key file; plain operator paths are untouched."""
    if key_file and key_file.startswith(MANAGED_KEY_PREFIX):
        try:
            os.unlink(os.path.join(keys_dir(), os.path.basename(key_file)))
        except OSError:
            pass


def _read_key_content_arg(args):
    """The --key-content-file flag: a private key read from a local
    file, to be stored on the node. None when the flag is absent."""
    path = getattr(args, "key_content_file", None)
    if not path:
        return None
    try:
        with open(path) as f:
            content = f.read()
    except OSError as exc:
        sys.exit(f"cannot read key file {path}: {exc.strerror or exc}")
    try:
        validate_key_content(content)
    except ValueError as exc:
        sys.exit(str(exc))
    return content


def validate_ss_method(method):
    """Reject SS methods xray does not know - a typo'd free-text method
    otherwise lands in the database and only fails at render time."""
    if method and method not in SS_METHODS:
        raise ValueError(
            f"ss method must be one of {', '.join(SS_METHODS)};"
            f" got {method!r}")


def cmd_upstream_add(args):
    key_content = _read_key_content_arg(args)
    if getattr(args, "key_generate", False):
        if key_content is not None or args.key_file:
            sys.exit("--key-generate replaces --key-file/--key-content-file")
        key_content = generate_ed25519_keypair(
            f"xmagic upstream {args.name}")[0]
    if args.proto in ("vless-ws", "vless") and not args.uuid:
        sys.exit(f"{args.proto} upstream needs --uuid (the uuid the upstream operator issued you)")
    if args.proto in ("trojan-ws", "ss") and not args.password:
        sys.exit(f"{args.proto} upstream needs --password")
    if args.proto in ("http", "socks") and args.username and not args.password:
        sys.exit(f"{args.proto} upstream with --username also needs --password")
    if args.proto == "ssh" and not (args.username and (args.key_file or key_content is not None)):
        sys.exit("ssh upstream needs --username (ssh user) and a key: --key-file"
                 " (path on the node) or --key-content-file (a local key file,"
                 " stored on the node)")
    key_file = managed_key_path(args.name) if key_content is not None else args.key_file
    with db() as conn:
        if args.proto in ("vless-ws", "vless") and not vless_enabled(conn):
            sys.exit("vless upstreams are disabled together with the vless"
                     " protocol (run: users.py settings --vless on)")
        try:
            validate_ss_method(args.method)
        except ValueError as exc:
            sys.exit(str(exc))
        try:
            conn.execute(
                "INSERT INTO upstreams (name, grp, address, port, protocol, path, uuid,"
                " username, password, key_file, tls, method, note, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (args.name, args.group, args.addr, args.port, args.proto, args.path,
                 args.uuid, args.username, args.password, key_file, 1 if args.tls else 0,
                 args.method, args.note, datetime.now(timezone.utc).isoformat()),
            )
        except IntegrityError:
            sys.exit(f"upstream already exists: {args.name}")
    if key_content is not None:
        write_upstream_key(args.name, key_content)
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
        row = get_upstream(conn, args.name)
        conn.execute("DELETE FROM upstreams WHERE name = ?", (args.name,))
    delete_managed_key(row["key_file"])
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
    empty string is a real value (clears path/username/etc.).
    `key_content` is not a column: it stores a private key on the node
    and points key_file at the stored copy (/keys/<name>.key)."""
    validate_ss_method(changes.get("method"))
    if (changes.get("protocol") in ("vless-ws", "vless")
            and not vless_enabled(conn)):
        raise ValueError("vless upstreams are disabled together with the"
                         " vless protocol (enable vless first)")
    row = get_upstream(conn, name)
    merged = {k: row[k] for k in row.keys()}
    applied = {}
    key_content = changes.get("key_content")
    for key, value in changes.items():
        if key == "key_content":
            continue
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
    if key_content:
        validate_key_content(key_content)
        merged["key_file"] = managed_key_path(name)
        applied["key_file"] = merged["key_file"]
    validate_upstream_values(merged)
    if key_content:
        write_upstream_key(name, key_content)
    if applied:
        sets = ", ".join(f"{k} = ?" for k in applied)
        conn.execute(f"UPDATE upstreams SET {sets} WHERE name = ?",
                     [*applied.values(), name])
    if row["key_file"] != merged["key_file"]:
        delete_managed_key(row["key_file"])
    return get_upstream(conn, name)


def cmd_upstream_edit(args):
    changes = {"grp": args.group, "address": args.addr, "port": args.port,
               "protocol": args.proto, "path": args.path, "uuid": args.uuid,
               "username": args.username, "password": args.password,
               "key_file": args.key_file, "method": args.method, "note": args.note,
               "key_content": _read_key_content_arg(args)}
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


# ------------------------------------------------------- ssh key generation
# Pure-stdlib ed25519 keypair generation in OpenSSH formats, so every
# management surface can mint keys in place: no ssh-keygen dependency
# and no external tool for operators. Generation only - the private
# half is handed to the caller and never kept by this module (upstream
# keys are the exception: they live on the node by design, stored via
# write_upstream_key).

_ED_Q = 2 ** 255 - 19
_ED_D = (-121665 * pow(121666, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)


def _ed_xrecover(y):
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_Q - 2, _ED_Q) % _ED_Q
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = (x * _ED_I) % _ED_Q
    if x % 2 != 0:
        x = _ED_Q - x
    return x


_ED_BY = (4 * pow(5, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = (_ED_BX, _ED_BY, 1, (_ED_BX * _ED_BY) % _ED_Q)
_ED_IDENTITY = (0, 1, 1, 0)


def _ed_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _ED_Q
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _ED_Q
    C = 2 * _ED_D * P[3] * Q[3] % _ED_Q
    D = 2 * P[2] * Q[2] % _ED_Q
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _ED_Q, G * H % _ED_Q, F * G % _ED_Q, E * H % _ED_Q)


def _ed_double(P):
    A = P[0] * P[0] % _ED_Q
    B = P[1] * P[1] % _ED_Q
    C = 2 * P[2] * P[2] % _ED_Q
    D = (-A) % _ED_Q
    E = ((P[0] + P[1]) * (P[0] + P[1]) - A - B) % _ED_Q
    G, F, H = D + B, (D + B) - C, D - B
    return (E * F % _ED_Q, G * H % _ED_Q, F * G % _ED_Q, E * H % _ED_Q)


def _ed_scalarmult(P, e):
    R = _ED_IDENTITY
    while e > 0:
        if e & 1:
            R = _ed_add(R, P)
        P = _ed_double(P)
        e >>= 1
    return R


def _ssh_str(b):
    return struct.pack(">I", len(b)) + b


def generate_ed25519_keypair(comment=""):
    """-> (private_pem, public_line, fingerprint). Pure stdlib."""
    seed = os.urandom(32)
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    a = int.from_bytes(h, "little")
    P = _ed_scalarmult(_ED_B, a)
    zi = pow(P[2], _ED_Q - 2, _ED_Q)
    x, y = P[0] * zi % _ED_Q, P[1] * zi % _ED_Q
    pub = (y | ((x & 1) << 255)).to_bytes(32, "little")
    blob = _ssh_str(b"ssh-ed25519") + _ssh_str(pub)
    check = struct.unpack(">I", os.urandom(4))[0]
    section = struct.pack(">II", check, check)
    section += _ssh_str(b"ssh-ed25519") + _ssh_str(pub)
    section += _ssh_str(seed + pub) + _ssh_str(comment.encode())
    pad = 8 - (len(section) % 8) or 8
    section += bytes(range(1, pad + 1))
    raw = b"openssh-key-v1\x00"
    raw += _ssh_str(b"none") + _ssh_str(b"none") + _ssh_str(b"")
    raw += struct.pack(">I", 1) + _ssh_str(blob) + _ssh_str(section)
    b64 = base64.b64encode(raw).decode()
    pem = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
           + "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70))
           + "\n-----END OPENSSH PRIVATE KEY-----\n")
    pub_line = "ssh-ed25519 " + base64.b64encode(blob).decode()
    if comment:
        pub_line += " " + comment
    return pem, pub_line, pubkey_fingerprint(pub_line)


def pubkey_fingerprint(line):
    """SHA256: fingerprint of an authorized_keys-style public key line,
    or None when the line does not parse."""
    parts = (line or "").strip().split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1])
    except Exception:
        return None
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode().rstrip("=")


def write_generated_key(priv_path, comment):
    """Generate a keypair and write the private half to priv_path
    (exclusive create, 0600). -> (public_line, fingerprint)."""
    pem, pub, fp = generate_ed25519_keypair(comment)
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(pem)
    return pub, fp


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
        rid = conn.insert_id(
            "INSERT INTO routes (kind, pattern, target, username, note, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (args.kind, args.pattern, args.to, args.user, args.note,
             datetime.now(timezone.utc).isoformat()))
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
    icon = interconnect_groups_members(conn)
    allow_priv = allow_private_direct(conn)
    vpaths, tpaths = vless_paths(conn), trojan_paths(conn)
    outbounds = []
    ssh_idx = 0
    for u in ups:
        if u["protocol"] == "ssh":
            outbounds.append(upstream_outbound(u, SSH_TUNNEL_BASE + ssh_idx, vpaths, tpaths))
            ssh_idx += 1
        else:
            outbounds.append(upstream_outbound(u, None, vpaths, tpaths))
    direct = {"tag": "direct", "protocol": "freedom"}
    if allow_priv:
        # operator opt-in: an allow finalRule ahead of Xray's default
        # block-private rule, for nodes that must reach their own LAN
        direct["settings"] = {"finalRules": [
            {"action": "allow", "ip": list(PRIVATE_CIDRS)}]}
    elif icon:
        # interconnect needs only the loopback through freedom; the
        # band rule below is its only sender
        direct["settings"] = {"finalRules": [
            {"action": "allow", "ip": ["127.0.0.0/8"]}]}
    outbounds.append(direct)
    if need_block or (icon and not allow_priv):
        outbounds.append({"tag": "block", "protocol": "blackhole"})
    if not ups and not route_rules and not icon:
        return outbounds, None, 0
    balancers = [{"tag": f"pool-{g}", "selector": [f"up-{g}-"],
                  "strategy": {"type": upstream_strategy(conn)}} for g in groups]
    rules = []
    if icon:
        # per group, one rule per member scoped to that member's own
        # slice: dialers are the slice owner's groupmates only, and a
        # group that opts out loses its rules entirely
        for gname in sorted(icon):
            members = sorted(icon[gname])
            for name in members:
                lo, hi = icon[gname][name]
                rules.append({"type": "field", "user": members,
                              "ip": ["127.0.0.0/8"], "port": f"{lo}-{hi}",
                              "outboundTag": "direct"})
        if not allow_priv:
            rules.append({"type": "field", "ip": ["127.0.0.0/8"],
                          "outboundTag": "block"})
    rules += route_rules
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
    v_on = vless_enabled(conn)
    if not v_on:
        # VLESS off: no WS paths routed, and the mux keeps an empty
        # client list - fallbacks (Trojan-WS, bare SS) still work,
        # VLESS itself authenticates nobody (verified against xray).
        vpaths = []
    vless_clients = ([{"id": u["vless_uuid"], "email": u["username"]}
                      for u in users] if v_on else [])
    fallbacks = ([{"path": p, "dest": BE_VLESS_BASE + i} for i, p in enumerate(vpaths)]
                 + [{"path": p, "dest": BE_TROJAN_BASE + i} for i, p in enumerate(tpaths)]
                 + [{"dest": BE_SS}])
    accounts = [{"user": u["username"], "pass": u["trojan_password"]} for u in users]
    inbounds = [
        {
            "tag": "main", "listen": "127.0.0.1", "port": MUX_PORT,
            "protocol": "vless",
            "settings": {
                "clients": vless_clients,
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
                "clients": vless_clients,
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
            f.write("#!/bin/sh\nset -e\n"
                    "# The ssh children must die with this script: an apply\n"
                    "# restarts the tunnels process on its own and expects\n"
                    "# the old tunnels gone.\n"
                    "trap 'kill $(jobs -p) 2>/dev/null; exit 0' TERM INT\n")
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
        slices = (interconnect_slices(conn)
                  if interconnect_members(conn) else {})
    out = args.out or "./data/authorized_keys"
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            key = r["ssh_pubkey"].strip()
            if not key.endswith(r["username"]):
                key = f"{key} {r['username']}"
            if r["username"] in slices:
                lo, hi = slices[r["username"]]
                # permitlisten takes one port per option (no ranges),
                # so the slice is spelled out option by option
                opts = ",".join(f'permitlisten="127.0.0.1:{p}"'
                                for p in range(lo, hi + 1))
                key = opts + " " + key
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
TUNNELS_CONTAINER = os.environ.get("XMAGIC_TUNNELS_CONTAINER", "proxy-tunnels")
# Single-container form: when set, this directory holds one <name>.pid
# file per gateway process (written by the container entrypoint), and
# apply restarts a process by writing a restart-<name>.req marker and
# signalling it - the entrypoint relaunches just that process. An exit
# without a marker still takes the whole container down, which is also
# the fallback when a targeted restart cannot be requested.
PID_DIR = os.environ.get("XMAGIC_PID_DIR", "")

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
    except OperationalError:
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


PRIVATE_CIDRS = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                 "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
                 "::1/128", "fc00::/7", "fe80::/10")
DIRECT_ALLOW_PRIVATE = os.environ.get("DIRECT_ALLOW_PRIVATE", "")
VLESS_ENABLED = os.environ.get("VLESS_ENABLED", "")


# ------------------------------------------------------------ interconnect
# Same-group interconnect (on by default; groups can opt out). A user
# exposes a local service by holding a reverse forward to the gateway
# loopback (ssh -R); each member owns a 16-port slice of 20000-21599,
# enforced per key by an authorized_keys permitlisten option. Members
# dial the band through the proxy like any destination; the routing
# rules below send the band to direct for members only and (unless
# direct_allow_private is on) block every other loopback destination,
# so the gateway's own loopback services stay unreachable.

INTERCONNECT_PORT_BASE = 20000
INTERCONNECT_PORTS_PER_USER = 16
INTERCONNECT_MAX_USERS = 100


def normalize_group_list(raw):
    """Comma-separated group names -> canonical stored form."""
    names = []
    for part in str(raw or "").split(","):
        name = part.strip()
        if name and name not in names:
            names.append(name)
    if len(names) > 32 or any(len(n) > 64 for n in names):
        raise ValueError("interconnect groups: at most 32 names,"
                         " each at most 64 characters")
    return ",".join(names)


def interconnect_off_groups(conn):
    """Groups whose members may NOT interconnect. Interconnect is on
    by default for every group; this list is the opt-out."""
    raw = get_setting(conn, "interconnect_off_groups") or ""
    return {g.strip() for g in raw.split(",") if g.strip()}


def interconnect_slices(conn):
    """{username: (first_port, last_port)} for every enabled user, in
    creation order - stable across renders and group toggles."""
    rows = conn.execute(
        "SELECT username FROM users WHERE enabled = 1"
        " ORDER BY created_at, username").fetchall()
    out = {}
    for i, r in enumerate(rows):
        if i >= INTERCONNECT_MAX_USERS:
            break
        start = INTERCONNECT_PORT_BASE + i * INTERCONNECT_PORTS_PER_USER
        out[r["username"]] = (start, start + INTERCONNECT_PORTS_PER_USER - 1)
    return out


def interconnect_groups_members(conn):
    """{group: {username: (first_port, last_port)}} - interconnect is
    same-group only: a group's members may dial each other's slices,
    never another group's."""
    off = interconnect_off_groups(conn)
    slices = interconnect_slices(conn)
    rows = conn.execute(
        "SELECT username, upstream_group FROM users WHERE enabled = 1"
    ).fetchall()
    groups = {}
    for r in rows:
        if r["upstream_group"] not in off and r["username"] in slices:
            groups.setdefault(r["upstream_group"], {})[r["username"]] = \
                slices[r["username"]]
    return groups


def interconnect_members(conn):
    """Flat {username: (first_port, last_port)} across all groups -
    who holds a slice at all (console display, key rendering)."""
    out = {}
    for members in interconnect_groups_members(conn).values():
        out.update(members)
    return out


def vless_enabled(conn=None):
    """Whether the VLESS inbounds are rendered at all.

    VLESS carries no encryption of its own (its design delegates that
    to a TLS layer this gateway does not terminate), so the VLESS-WS
    and VLESS-TCP inbounds are OFF by default; Trojan (TLS by design),
    Shadowsocks (built-in cipher) and the HTTP proxy (rides the outer
    HTTPS) stay. A DB setting wins over the VLESS_ENABLED env."""
    if conn is not None:
        raw = get_setting(conn, "vless_enabled")
        if raw is not None:
            return raw == "1"
    return VLESS_ENABLED.lower() in ("1", "true", "yes", "on")


def allow_private_direct(conn=None):
    """Whether direct egress may reach private / LAN addresses.

    Xray's freedom outbound blackholes private targets for requests
    arriving over the remote protocols (vless / trojan / shadowsocks -
    an anti-SSRF default), so even a destination route to "direct"
    cannot reach the node's own LAN unless the operator allows it.
    A DB setting wins over the DIRECT_ALLOW_PRIVATE env."""
    if conn is not None:
        raw = get_setting(conn, "direct_allow_private")
        if raw is not None:
            return raw == "1"
    return DIRECT_ALLOW_PRIVATE.lower() in ("1", "true", "yes", "on")


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
        "vless_enabled": vless_enabled(conn),
        "vless_enabled_from_db":
            get_setting(conn, "vless_enabled") is not None,
        "direct_allow_private": allow_private_direct(conn),
        "direct_allow_private_from_db":
            get_setting(conn, "direct_allow_private") is not None,
        "interconnect_off_groups": sorted(interconnect_off_groups(conn)),
        "interconnect_off_groups_from_db":
            get_setting(conn, "interconnect_off_groups") is not None,
        "interconnect_slices": {
            name: list(span) for name, span
            in interconnect_members(conn).items()},
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
        if getattr(args, "interconnect_off_groups", None) is not None:
            if args.interconnect_off_groups == "":
                delete_setting(conn, "interconnect_off_groups")
            else:
                try:
                    set_setting(conn, "interconnect_off_groups",
                                normalize_group_list(
                                    args.interconnect_off_groups))
                except ValueError as exc:
                    sys.exit(str(exc))
        if getattr(args, "vless", None) is not None:
            if args.vless == "":
                delete_setting(conn, "vless_enabled")
            else:
                set_setting(conn, "vless_enabled",
                            "1" if args.vless == "on" else "0")
        if args.direct_allow_private is not None:
            if args.direct_allow_private == "":
                delete_setting(conn, "direct_allow_private")
            else:
                set_setting(conn, "direct_allow_private",
                            "1" if args.direct_allow_private == "on" else "0")
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
    print(f"vless_enabled: {info['vless_enabled']} "
          f"({src[info['vless_enabled_from_db']]})")
    print(f"direct_allow_private: {info['direct_allow_private']} "
          f"({src[info['direct_allow_private_from_db']]})")
    print(f"interconnect_off_groups: "
          f"{','.join(info['interconnect_off_groups']) or '(none)'} "
          f"({src[info['interconnect_off_groups_from_db']]})")


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
            f.write("#!/bin/sh\nset -e\n"
                    "# The ssh children must die with this script: an apply\n"
                    "# restarts the tunnels process on its own and expects\n"
                    "# the old tunnels gone.\n"
                    "trap 'kill $(jobs -p) 2>/dev/null; exit 0' TERM INT\n")
            for t in tunnels:
                f.write(" ".join(t["ssh_command"]) + " &\n")
            f.write("wait\n")
        os.chmod(spath, 0o755)
    with db() as conn:
        rows = conn.execute(
            "SELECT username, ssh_pubkey FROM users WHERE enabled = 1"
            " AND ssh_pubkey IS NOT NULL ORDER BY username").fetchall()
        # when interconnect is armed, EVERY user gets a permitlisten
        # for their own slice: a non-member must not be able to squat
        # on a member's ports and intercept the group's traffic
        slices = (interconnect_slices(conn)
                  if interconnect_members(conn) else {})
    keys_path = os.path.join(out_dir, "authorized_keys")
    tmp = keys_path + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            key = r["ssh_pubkey"].strip()
            if not key.endswith(r["username"]):
                key = f"{key} {r['username']}"
            if r["username"] in slices:
                lo, hi = slices[r["username"]]
                # permitlisten takes one port per option (no ranges),
                # so the slice is spelled out option by option
                opts = ",".join(f'permitlisten="127.0.0.1:{p}"'
                                for p in range(lo, hi + 1))
                key = opts + " " + key
            f.write(key + "\n")
    os.replace(tmp, keys_path)
    # 0644, not 0600: sshd opens authorized_keys as the login user
    # (temporarily_use_uid), so a root-owned 0600 file is unreadable
    # to it and every SSH login is refused. Root-owned 0644 passes
    # StrictModes (owner is root, not group/world-writable).
    os.chmod(keys_path, 0o644)
    return {"users": n_users, "upstreams": n_up, "ssh_keys": len(rows),
            "ssh_tunnels": len(tunnels)}


def _artifact_hashes(out_dir):
    """Content hash of each rendered artifact (None when absent).

    Comparing the hashes before and after a render decides which
    gateway processes actually need a restart - apply restarts only
    the minimal set whose inputs changed."""
    hashes = {}
    for fname in ("config.json", "authorized_keys", "ssh-tunnels.json",
                  "start-tunnels.sh"):
        try:
            with open(os.path.join(out_dir, fname), "rb") as f:
                hashes[fname] = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            hashes[fname] = None
    return hashes


# Which gateway process each rendered artifact feeds:
# (artifact file, change label, process name).
ARTIFACT_PROCESS = (("config.json", "config", "xray"),
                    ("authorized_keys", "keys", "sshd"),
                    ("ssh-tunnels.json", "tunnels", "tunnels"),
                    ("start-tunnels.sh", "tunnels", "tunnels"))


def docker_restart(name, missing_ok=False):
    """POST /containers/<name>/restart over the unix socket.

    True = restarted, False = attempted and failed, None = no docker
    socket - or, with missing_ok, no such container (the tunnels
    container is optional, so its absence is not a failure)."""
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
        code = int(status_line.split()[1])
    except (OSError, ValueError, IndexError):
        return False
    if code in (200, 204):
        return True
    if missing_ok and code == 404:
        return None
    return False


def pidfile_signal(name, marker):
    """SIGTERM the process recorded in <PID_DIR>/<name>.pid.

    With marker=True a restart request (restart-<name>.req, holding
    the pid) is written first: the single-container entrypoint
    relaunches just that process when it sees the request, so an
    apply-requested exit does not take the container down. Without a
    marker the exit counts as a crash and the entrypoint tears the
    whole container down - the fallback when a targeted restart
    cannot even be requested. True also when the process is already
    gone (a marker still gets it relaunched). None = pidfile channel
    not configured."""
    if not PID_DIR:
        return None
    try:
        with open(os.path.join(PID_DIR, name + ".pid")) as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return False
    if marker:
        try:
            with open(os.path.join(PID_DIR, f"restart-{name}.req"), "w") as f:
                f.write(str(pid))
        except OSError:
            return False
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return True


def restart_channel():
    """How apply restarts the gateway: 'container', 'docker' or None."""
    if PID_DIR:
        return "container"
    if os.path.exists(DOCKER_SOCK):
        return "docker"
    return None


def apply_changes():
    out_dir = os.path.dirname(os.path.abspath(DB_PATH))
    before = _artifact_hashes(out_dir)
    result = render_all(out_dir)
    after = _artifact_hashes(out_dir)
    changed, needed = [], []
    for fname, label, proc in ARTIFACT_PROCESS:
        if before[fname] != after[fname]:
            if label not in changed:
                changed.append(label)
            if proc not in needed:
                needed.append(proc)
    restarted = {}
    container_restart = False
    if needed and PID_DIR:
        for name in ("xray", "sshd", "tunnels"):
            try:
                os.unlink(os.path.join(PID_DIR, f"restart-{name}.req"))
            except OSError:
                pass
        for name in needed:
            restarted[name] = pidfile_signal(name, marker=True)
        if any(v is False for v in restarted.values()):
            # A targeted restart could not even be requested - fall
            # back: clear the markers and signal without them, so the
            # entrypoint takes the whole container down and the
            # runtime restarts it on the freshly rendered config.
            container_restart = True
            for name in ("xray", "sshd", "tunnels"):
                try:
                    os.unlink(os.path.join(PID_DIR, f"restart-{name}.req"))
                except OSError:
                    pass
                pidfile_signal(name, marker=False)
    elif needed:
        targets = {"xray": (XRAY_CONTAINER, False),
                   "sshd": (SSHD_CONTAINER, False),
                   "tunnels": (TUNNELS_CONTAINER, True)}
        for name in needed:
            container, missing_ok = targets[name]
            outcome = docker_restart(container, missing_ok=missing_ok)
            if outcome is not None:
                restarted[name] = outcome
        if any(v is False for v in restarted.values()):
            # Escalate to bouncing every gateway service container.
            for name, (container, missing_ok) in targets.items():
                if name not in restarted:
                    outcome = docker_restart(container, missing_ok=missing_ok)
                    if outcome is not None:
                        restarted[name] = outcome
    result["changed"] = changed
    result["restarted"] = restarted
    result["container_restart"] = container_restart
    result["restart_skipped"] = bool(needed) and not restarted
    return result


def _applied_line(result):
    line = (f"applied: rendered {result['users']} user(s), "
            f"{result['upstreams']} upstream(s), {result['ssh_keys']} ssh key(s)")
    if result["restart_skipped"]:
        line += "; no restart channel - restart xray/sshd manually to apply"
    elif result.get("container_restart"):
        line += "; a targeted restart failed - the whole container is restarting"
    elif not result["restarted"]:
        line += "; rendered output unchanged - nothing restarted"
    else:
        line += "; restarts: " + ", ".join(
            f"{k}={'ok' if v else 'FAILED'}" for k, v in result["restarted"].items())
    return line


def cmd_apply(_):
    result = apply_changes()
    if JSON_OUT:
        print(json.dumps(result, indent=2))
        return
    print(_applied_line(result))


# ------------------------------------------------------------ database admin
# The db-* commands manage the local registry of database configs:
# several named parameter sets, one active at a time, switchable at any
# moment, with data migration between any two of them.

def _db_target_arg(args):
    return args.target or args.dsn or args.path


def cmd_db_list(_):
    configs = list_db_configs()
    if JSON_OUT:
        print(json.dumps(configs, indent=2))
        return
    for c in configs:
        mark = "*" if c["active"] else " "
        print(f"{mark} {c['name']:<16} {c['type']:<9} {c['target']}"
              + (f"  ({c['note']})" if c["note"] else ""))


def cmd_db_add(args):
    cfg = add_db_config(args.name, args.type, _db_target_arg(args), args.note)
    if JSON_OUT:
        print(json.dumps(cfg, indent=2))
        return
    print(f"database config {cfg['name']} added: {cfg['type']} {cfg['target']}"
          f"; check it with: users.py db-test {cfg['name']}")


def cmd_db_edit(args):
    if _db_target_arg(args) is None and args.note is None:
        sys.exit("nothing to edit: pass --target/--dsn/--path or --note")
    cfg = edit_db_config(args.name, target=_db_target_arg(args),
                         note=args.note)
    if JSON_OUT:
        print(json.dumps(cfg, indent=2))
        return
    print(f"database config {cfg['name']} updated: "
          f"{cfg['type']} {cfg['target']}"
          + (" (active)" if cfg["active"] else ""))


def cmd_db_remove(args):
    remove_db_config(args.name)
    print(f"database config {args.name} removed")


def cmd_db_test(args):
    info = test_db_config(args.name)
    if JSON_OUT:
        print(json.dumps(info, indent=2))
        return
    counts = ", ".join(f"{t}={c}" for t, c in info["tables"].items())
    print(f"{info['name']}: reachable ({info['type']}: {info['target']});"
          f" tables: {counts}")


def cmd_db_switch(args):
    cfg = switch_db_config(args.name)
    applied = apply_changes()
    if JSON_OUT:
        print(json.dumps({"database": cfg, "applied": applied}, indent=2))
        return
    print(f"active database: {cfg['name']} ({cfg['type']}: {cfg['target']})")
    print(_applied_line(applied))


def cmd_db_migrate(args):
    result = migrate_db_config(args.src, args.dst, replace=args.replace)
    if JSON_OUT:
        print(json.dumps(result, indent=2))
        return
    counts = ", ".join(f"{t}={c}" for t, c in result["tables"].items())
    print(f"migrated {args.src} -> {args.dst}: {counts}")
    if active_db_config()["name"] != args.dst:
        print(f"note: the active database is still "
              f"{active_db_config()['name']}; switch with:"
              f" users.py db-switch {args.dst}")


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
        except OperationalError:
            cred = None
    info["admin_registered"] = cred is not None
    info["admin_created_at"] = cred["created_at"] if cred else None
    info["admin_label"] = cred["label"] if cred else None
    info["docker_socket"] = os.path.exists(DOCKER_SOCK)
    info["restart_via"] = restart_channel()
    info["public_port"] = PUBLIC_PORT
    _cfg = active_db_config()
    info["db"] = mask_target(_cfg["type"], _cfg["target"])
    info["db_name"] = _cfg["name"]
    info["db_type"] = _cfg["type"]
    if JSON_OUT:
        print(json.dumps(info, indent=2))
        return
    print(f"db: {info['db_name']} ({info['db_type']}: {info['db']})")
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
    except OperationalError:
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
    a.add_argument("--interconnect-off-groups",
                   help="comma-separated user groups whose members may NOT"
                        " interconnect (interconnect is on by default);"
                        " empty string = nobody opted out")
    a.add_argument("--vless", choices=("on", "off", ""),
                   help="render the VLESS inbounds (off by default:"
                        " VLESS has no encryption of its own);"
                        " empty string = back to env")
    a.add_argument("--direct-allow-private", choices=("on", "off", ""),
                   help="allow direct egress to private/LAN addresses;"
                        " empty string = back to env")
    a.set_defaults(fn=cmd_settings)
    sub.add_parser("sessions").set_defaults(fn=cmd_sessions)
    a = sub.add_parser("sessions-revoke"); a.add_argument("id")
    a.set_defaults(fn=cmd_sessions_revoke)
    sub.add_parser("sessions-revoke-all").set_defaults(fn=cmd_sessions_revoke_all)
    sub.add_parser("admin-reset").set_defaults(fn=cmd_admin_reset)
    a = sub.add_parser("keygen"); a.add_argument("name")
    a.add_argument("--out-dir", default=".",
                   help="directory for NAME and NAME.pub (default: .)")
    a.add_argument("--comment", help="key comment (default: the name)")
    a.set_defaults(fn=cmd_keygen)
    a = sub.add_parser("add"); a.add_argument("user")
    a.add_argument("--ssh-key-file")
    a.add_argument("--ssh-key-generate", metavar="PATH",
                   help="generate a fresh ed25519 keypair: the public key is"
                        " registered, the private key written to PATH (0600)")
    a.add_argument("--note")
    a.add_argument("--group", default="default", help="upstream group for this user")
    a.set_defaults(fn=cmd_add)
    a = sub.add_parser("passwd"); a.add_argument("user"); a.set_defaults(fn=cmd_passwd)
    a = sub.add_parser("setkey"); a.add_argument("user")
    a.add_argument("--ssh-key-file")
    a.add_argument("--ssh-key-generate", metavar="PATH",
                   help="generate a fresh ed25519 keypair: the public key is"
                        " registered, the private key written to PATH (0600)")
    a.add_argument("--clear", action="store_true",
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
    a.add_argument("--key-content-file",
                   help="ssh upstream: read the private key from this local file"
                        " and store it on the node (key_file becomes /keys/<name>.key)")
    a.add_argument("--tls", action="store_true",
                   help="vless-ws/vless/trojan-ws upstream: dial with TLS (SNI = address);"
                        " required by Xray for plaintext protocols to public IPs")
    a.add_argument("--key-generate", action="store_true",
                   help="ssh upstream: generate a fresh ed25519 keypair on"
                        " the node and store the private key as this"
                        " upstream's managed key")
    a.add_argument("--method", default="aes-256-gcm"); a.add_argument("--note")
    a.set_defaults(fn=cmd_upstream_add)
    a = sub.add_parser("upstream-edit"); a.add_argument("name")
    a.add_argument("--addr"); a.add_argument("--port", type=int)
    a.add_argument("--proto", choices=("vless-ws", "vless", "trojan-ws", "ss", "http", "socks", "ssh"))
    a.add_argument("--group"); a.add_argument("--path"); a.add_argument("--uuid")
    a.add_argument("--username"); a.add_argument("--password"); a.add_argument("--key-file")
    a.add_argument("--key-content-file",
                   help="ssh upstream: replace the key with this local file's"
                        " content, stored on the node")
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
    sub.add_parser("db-list").set_defaults(fn=cmd_db_list)
    a = sub.add_parser("db-add"); a.add_argument("name")
    a.add_argument("--type", required=True, choices=DB_TYPES)
    a.add_argument("--target", help="sqlite: file path; postgres/mysql: DSN")
    a.add_argument("--dsn", help="alias of --target, for postgres/mysql")
    a.add_argument("--path", help="alias of --target, for sqlite")
    a.add_argument("--note")
    a.set_defaults(fn=cmd_db_add)
    a = sub.add_parser("db-edit"); a.add_argument("name")
    a.add_argument("--target"); a.add_argument("--dsn"); a.add_argument("--path")
    a.add_argument("--note", help="empty string clears the note")
    a.set_defaults(fn=cmd_db_edit)
    a = sub.add_parser("db-remove"); a.add_argument("name")
    a.set_defaults(fn=cmd_db_remove)
    a = sub.add_parser("db-test"); a.add_argument("name")
    a.set_defaults(fn=cmd_db_test)
    a = sub.add_parser("db-switch"); a.add_argument("name")
    a.set_defaults(fn=cmd_db_switch)
    a = sub.add_parser("db-migrate"); a.add_argument("src"); a.add_argument("dst")
    a.add_argument("--replace", action="store_true",
                   help="clear the target's business tables before copying")
    a.set_defaults(fn=cmd_db_migrate)
    args = p.parse_args()
    global JSON_OUT
    JSON_OUT = args.json
    try:
        args.fn(args)
    except DBError as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
