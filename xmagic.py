#!/usr/bin/env python3
"""xmagic - operator-side CLI for managing gateway nodes remotely.

Two management interfaces, one feature set: the web console (admin.py,
on the node) and this CLI (on your own machine). Both talk to the same
admin API on each node; the on-node users.py CLI drives the same engine
directly when you are on the host. Nothing here touches a node except
through its admin console API.

Configuration:
  ~/.xmagic/config.json         node registry (name -> admin console URL)
  Resolution order is: command line > environment > config file.
    --node NAME / --url URL     pick the target (args win)
    XMAGIC_NODE / XMAGIC_URL    same, via environment
    config "current"            the node chosen by `xmagic node use`
  --config PATH (or XMAGIC_CONFIG) reads a different config file.
  XMAGIC_HOME changes the base directory (default ~/.xmagic).

Login:
  `xmagic login` opens the browser on the node's /cli-auth page; the
  Passkey ceremony happens there (first visit can also register the
  admin passkey). The page hands a one-time code back to a loopback
  listener this CLI runs, the CLI exchanges it for a session token, and
  the token is stored - never in a URL, never in the config file.
  Sessions live in ~/.xmagic/sessions/<node>.json (mode 600).
  --session-file PATH on `login` saves elsewhere; the same flag (or
  XMAGIC_SESSION_FILE) on any other command selects which stored
  session to use - that is what makes batch management of many nodes
  scriptable: one session file per node, chosen per invocation.

Exit codes: 0 ok, 1 API/server error, 2 config/usage error,
3 not logged in / session expired (run `xmagic login`).
"""
import argparse
import hashlib
import http.server
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

EXIT_API, EXIT_CONFIG, EXIT_AUTH = 1, 2, 3


def die(code, message):
    print(f"xmagic: {message}", file=sys.stderr)
    sys.exit(code)


# ------------------------------------------------------------ paths/config

def base_dir():
    return os.environ.get("XMAGIC_HOME") or os.path.join(os.path.expanduser("~"), ".xmagic")


def config_path(args):
    return (getattr(args, "config", None) or os.environ.get("XMAGIC_CONFIG")
            or os.path.join(base_dir(), "config.json"))


def load_config(args):
    path = config_path(args)
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f), path
        except ValueError:
            die(EXIT_CONFIG, f"config file is not valid JSON: {path}")
    return {"current": None, "nodes": {}}, path


def save_config(args, cfg):
    path = config_path(args)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)
    return path


def resolve_node(args, cfg):
    """-> (name_or_None, url). Command line beats env beats config."""
    url = getattr(args, "url", None) or os.environ.get("XMAGIC_URL")
    name = getattr(args, "node", None) or os.environ.get("XMAGIC_NODE")
    if url:
        # an ad-hoc URL still maps to a registered node when it matches one
        for n, spec in cfg.get("nodes", {}).items():
            if spec.get("url", "").rstrip("/") == url.rstrip("/"):
                return n, url
        return name, url
    if not name:
        name = cfg.get("current")
    if not name and len(cfg.get("nodes", {})) == 1:
        name = next(iter(cfg["nodes"]))
    if name:
        spec = cfg.get("nodes", {}).get(name)
        if spec is None:
            die(EXIT_CONFIG, f"unknown node {name!r} (see: xmagic node list)")
        return name, spec["url"]
    die(EXIT_CONFIG, "no node selected: register one with "
                     "`xmagic node add NAME --url URL`, or pass --url")


def session_path(args, name, url):
    explicit = getattr(args, "session_file", None) or os.environ.get("XMAGIC_SESSION_FILE")
    if explicit:
        return explicit
    key = name or "url-" + hashlib.sha256(url.encode()).hexdigest()[:12]
    return os.path.join(base_dir(), "sessions", key + ".json")


def load_session(args, name, url):
    path = session_path(args, name, url)
    if not os.path.exists(path):
        die(EXIT_AUTH, f"no stored session for {name or url} - run: xmagic login")
    with open(path) as f:
        session = json.load(f)
    if session.get("expires_at", 0) < time.time():
        die(EXIT_AUTH, f"stored session for {name or url} expired - run: xmagic login")
    return session


def save_session(args, name, url, token, expires_at):
    path = session_path(args, name, url)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"node": name, "url": url, "token": token,
                   "expires_at": expires_at}, f, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return path


# ------------------------------------------------------------ API client

class Api:
    def __init__(self, url, token=None):
        self.url = url.rstrip("/")
        self.token = token

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Cookie", f"xmagic_session={self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read()).get("error", exc.reason)
            except Exception:
                message = exc.reason
            if exc.code == 401:
                die(EXIT_AUTH, f"session rejected by the node ({message}) - "
                               "run: xmagic login")
            die(EXIT_API, f"{method} {path} -> HTTP {exc.code}: {message}")
        except urllib.error.URLError as exc:
            die(EXIT_API, f"cannot reach {self.url}: {exc.reason}")


def authed_api(args):
    cfg, _ = load_config(args)
    name, url = resolve_node(args, cfg)
    session = load_session(args, name, url)
    return Api(url, session["token"]), name, url


def emit(args, payload, human):
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(human)


def applied_line(applied):
    if not applied:
        return ""
    line = (f"applied: {applied['users']} user(s), {applied['upstreams']} upstream(s), "
            f"{applied['ssh_keys']} ssh key(s)")
    if applied.get("restart_skipped"):
        line += "; no docker socket on the node - restart xray/sshd there to apply"
    else:
        line += "; restarts: " + ", ".join(
            f"{k}={'ok' if v else 'FAILED'}"
            for k, v in applied.get("restarted", {}).items())
    return line


# ------------------------------------------------------------ login/logout

class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    result = None

    def do_GET(self):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        _CallbackHandler.result = {k: v[0] for k, v in query.items()}
        body = ("<!DOCTYPE html><meta charset=utf-8><title>xmagic</title>"
                "<p>登录完成，可以关闭这个页面，回到命令行。</p>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def cmd_login(args):
    cfg, _ = load_config(args)
    name, url = resolve_node(args, cfg)
    state = secrets.token_urlsafe(16)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CallbackHandler)
    port = server.server_address[1]
    callback = f"http://127.0.0.1:{port}/callback"
    auth_url = (url.rstrip("/") + "/cli-auth?" + urllib.parse.urlencode(
        {"callback": callback, "state": state}))
    opened = False
    if not args.no_browser:
        opened = webbrowser.open(auth_url)
    if not opened:
        print(f"在浏览器打开这个地址完成 Passkey 登录：\n{auth_url}", flush=True)
    print("等待浏览器完成 Passkey 验证（5 分钟超时）…", file=sys.stderr, flush=True)
    deadline = time.time() + 300
    server.timeout = 1
    while _CallbackHandler.result is None and time.time() < deadline:
        server.handle_request()
    server.server_close()
    result = _CallbackHandler.result
    if result is None:
        die(EXIT_AUTH, "timed out waiting for the browser login")
    if result.get("state") != state:
        die(EXIT_AUTH, "state mismatch in the login callback - aborting")
    if not result.get("code"):
        die(EXIT_AUTH, f"login callback carried no code: {result}")
    exchanged = Api(url).call("POST", "/api/cli-exchange", {
        "code": result["code"],
        "label": f"xmagic-cli on {socket.gethostname()}"})
    path = save_session(args, name, url, exchanged["token"], exchanged["expires_at"])
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(exchanged["expires_at"]))
    print(f"logged in to {name or url}; session saved to {path} (expires {when})")


def cmd_logout(args):
    cfg, _ = load_config(args)
    name, url = resolve_node(args, cfg)
    path = session_path(args, name, url)
    if os.path.exists(path):
        try:
            with open(path) as f:
                token = json.load(f).get("token")
            if token:
                Api(url, token).call("POST", "/api/logout", {})
        except SystemExit:
            pass
        os.remove(path)
        print(f"logged out of {name or url}; removed {path}")
    else:
        print(f"no stored session for {name or url}")


# ------------------------------------------------------------ node registry

def cmd_node_add(args):
    cfg, _ = load_config(args)
    cfg.setdefault("nodes", {})[args.name] = {"url": args.url.rstrip("/")}
    if args.use or not cfg.get("current"):
        cfg["current"] = args.name
    path = save_config(args, cfg)
    print(f"node {args.name} -> {args.url.rstrip('/')} (config: {path})")


def cmd_node_list(args):
    cfg, _ = load_config(args)
    nodes = cfg.get("nodes", {})
    if args.json:
        print(json.dumps(cfg, indent=2, ensure_ascii=False))
        return
    if not nodes:
        print("(no nodes - add one: xmagic node add NAME --url URL)")
    for name, spec in sorted(nodes.items()):
        marker = "*" if name == cfg.get("current") else " "
        sess = session_path(args, name, spec["url"])
        print(f"{marker} {name:<16} {spec['url']:<40} session: "
              f"{'stored' if os.path.exists(sess) else 'none'}")


def cmd_node_use(args):
    cfg, _ = load_config(args)
    if args.name not in cfg.get("nodes", {}):
        die(EXIT_CONFIG, f"unknown node {args.name!r}")
    cfg["current"] = args.name
    save_config(args, cfg)
    print(f"current node: {args.name}")


def cmd_node_remove(args):
    cfg, _ = load_config(args)
    if cfg.get("nodes", {}).pop(args.name, None) is None:
        die(EXIT_CONFIG, f"unknown node {args.name!r}")
    if cfg.get("current") == args.name:
        cfg["current"] = None
    save_config(args, cfg)
    print(f"removed node {args.name} (stored session, if any, is kept)")


# ------------------------------------------------------------ management
# Same operations as the web console, one-to-one.

def cmd_status(args):
    api, name, url = authed_api(args)
    state = api.call("GET", "/api/state")
    human = (f"node: {name or url}\n"
             f"users: {state['enabled_users']} enabled; "
             f"upstreams: {state['enabled_upstreams']} enabled; "
             f"routes: {state['enabled_routes']} enabled\n"
             f"admin passkey: registered {state['admin_created_at']}; "
             f"docker socket: {'available' if state['docker_socket'] else 'absent'}; "
             f"public port: {state['public_port']}")
    emit(args, state, human)


def cmd_apply(args):
    api, _, _ = authed_api(args)
    result = api.call("POST", "/api/apply", {})
    emit(args, result, applied_line(result.get("applied")))


def cmd_settings_show(args):
    api, _, _ = authed_api(args)
    payload = api.call("GET", "/api/settings")
    emit(args, payload,
         f"session_ttl_hours: {payload['session_ttl_hours']} "
         f"({payload['session_ttl_hours'] / 24:g} days)")


def _fmt_ts(epoch):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch))


def cmd_sessions_list(args):
    api, _, _ = authed_api(args)
    payload = api.call("GET", "/api/sessions")
    lines = []
    for s in payload["sessions"]:
        lines.append(f"{s['id']}  {s['kind']:<4} created={_fmt_ts(s['created_at'])} "
                     f"expires={_fmt_ts(s['expires_at'])}"
                     f"{'  CURRENT' if s['current'] else ''}  {s['label'] or ''}")
    emit(args, payload, "\n".join(lines) if lines else "(no live sessions)")


def cmd_sessions_revoke(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", f"/api/sessions/{args.id}/revoke", {})
    emit(args, payload, f"revoked session {payload['revoked']}")


def cmd_sessions_revoke_others(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/sessions/revoke-others", {})
    emit(args, payload, f"revoked {payload['revoked_others']} other session(s)")


def cmd_settings_set(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/settings",
                       {"session_ttl_hours": args.session_ttl_hours})
    emit(args, payload,
         f"session_ttl_hours: {payload['session_ttl_hours']} "
         "(applies to newly issued sessions)")


def _read_key(args):
    if getattr(args, "ssh_key_file", None):
        with open(args.ssh_key_file) as f:
            return f.read().strip()
    return getattr(args, "ssh_pubkey", None)


def cmd_users_list(args):
    api, _, _ = authed_api(args)
    payload = api.call("GET", "/api/users")
    lines = []
    for u in payload["users"]:
        lines.append(
            f"{u['username']:<16} group={u['group']:<10} "
            f"enabled={u['enabled']!s:<5} uuid={u['vless_uuid']}\n"
            f"{'':<16} password={u['password']}  ss={u['ss_method']}/{u['ss_password']}"
            + ("  ssh-key=yes" if u["ssh_key"] else ""))
    emit(args, payload, "\n".join(lines) if lines else "(no users)")


def cmd_users_add(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/users", {
        "username": args.user, "group": args.group,
        "ssh_pubkey": _read_key(args), "note": args.note})
    u = payload["user"]
    human = (f"user:            {u['username']}\n"
             f"vless uuid:      {u['vless_uuid']}\n"
             f"password (trojan/http/socks): {u['password']}\n"
             f"ss:              {u['ss_method']} / {u['ss_password']}\n"
             + applied_line(payload.get("applied")))
    emit(args, payload, human)


def cmd_users_action(args):
    api, _, _ = authed_api(args)
    body = {}
    if args.action == "setkey":
        body["ssh_pubkey"] = _read_key(args)
    elif args.action == "setgroup":
        body["group"] = args.group
    payload = api.call("POST", f"/api/users/{args.user}/{args.action}", body)
    human = applied_line(payload.get("applied")) or f"{args.user}: {args.action} done"
    if args.action == "passwd" and payload.get("user"):
        u = payload["user"]
        human = (f"password (trojan/http/socks): {u['password']}\n"
                 f"ss password:     {u['ss_password']}\n" + human)
    emit(args, payload, human)


def cmd_upstreams_list(args):
    api, _, _ = authed_api(args)
    payload = api.call("GET", "/api/upstreams")
    lines = [f"{u['name']:<16} group={u['group']:<10} enabled={u['enabled']!s:<5} "
             f"{u['protocol']:<9} {u['address']}:{u['port']}{u['path'] or ''}"
             f"{' +tls' if u['tls'] else ''}" for u in payload["upstreams"]]
    emit(args, payload, "\n".join(lines) if lines else "(no upstreams - direct egress)")


def cmd_upstreams_add(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/upstreams", {
        "name": args.name, "address": args.addr, "port": args.port,
        "protocol": args.proto, "group": args.group, "path": args.path,
        "uuid": args.uuid, "username": args.username, "password": args.password,
        "key_file": args.key_file, "tls": args.tls, "method": args.method,
        "note": args.note})
    emit(args, payload,
         f"upstream {args.name} added\n" + applied_line(payload.get("applied")))


def cmd_upstreams_action(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", f"/api/upstreams/{args.name}/{args.action}", {})
    emit(args, payload, applied_line(payload.get("applied"))
         or f"{args.name}: {args.action} done")


def cmd_routes_list(args):
    api, _, _ = authed_api(args)
    payload = api.call("GET", "/api/routes")
    lines = [f"#{r['id']:<4} enabled={r['enabled']!s:<5} {r['kind']:<8} "
             f"{r['pattern']:<28} -> {r['target']:<10} user={r['username'] or '*'}"
             for r in payload["routes"]]
    emit(args, payload, "\n".join(lines) if lines else "(no routes)")


def cmd_routes_add(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/routes", {
        "kind": args.kind, "pattern": args.pattern, "to": args.to,
        "username": args.user, "note": args.note})
    r = payload["route"]
    emit(args, payload,
         f"route #{r['id']} added: {r['kind']} {r['pattern']} -> {r['target']}\n"
         + applied_line(payload.get("applied")))


def cmd_routes_action(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", f"/api/routes/{args.id}/{args.action}", {})
    emit(args, payload, applied_line(payload.get("applied"))
         or f"route #{args.id}: {args.action} done")


# ------------------------------------------------------------ main

def main():
    # Global options exist on the main parser AND (with SUPPRESS
    # defaults, so they never clobber an earlier value) on every
    # subparser: `xmagic --node b users list`, `xmagic users list
    # --node b` and `xmagic users --node b list` are all the same.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS)
    common.add_argument("--node", default=argparse.SUPPRESS)
    common.add_argument("--url", default=argparse.SUPPRESS)
    common.add_argument("--session-file", default=argparse.SUPPRESS)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS)

    p = argparse.ArgumentParser(prog="xmagic", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", help="config file (default ~/.xmagic/config.json)")
    p.add_argument("--node", help="target node name (overrides config current)")
    p.add_argument("--url", help="target admin console URL (overrides config)")
    p.add_argument("--session-file", help="session file to use/save "
                                          "(default ~/.xmagic/sessions/<node>.json)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="cmd", required=True)
    C = [common]

    a = sub.add_parser("login", parents=C,
                       help="browser Passkey login to the node console")
    a.add_argument("--no-browser", action="store_true",
                   help="print the login URL instead of opening a browser")
    a.set_defaults(fn=cmd_login)
    sub.add_parser("logout", parents=C).set_defaults(fn=cmd_logout)

    n = sub.add_parser("node", parents=C, help="manage the local node registry")
    nsub = n.add_subparsers(dest="node_cmd", required=True)
    # node add has its own --url (the new node's address) - no parents.
    a = nsub.add_parser("add"); a.add_argument("name"); a.add_argument("--url", required=True)
    a.add_argument("--use", action="store_true"); a.set_defaults(fn=cmd_node_add)
    nsub.add_parser("list", parents=C).set_defaults(fn=cmd_node_list)
    a = nsub.add_parser("use", parents=C); a.add_argument("name")
    a.set_defaults(fn=cmd_node_use)
    a = nsub.add_parser("remove", parents=C); a.add_argument("name")
    a.set_defaults(fn=cmd_node_remove)

    sub.add_parser("status", parents=C).set_defaults(fn=cmd_status)
    sub.add_parser("apply", parents=C).set_defaults(fn=cmd_apply)

    ss = sub.add_parser("sessions", parents=C, help="login sessions on the node")
    ssub = ss.add_subparsers(dest="sessions_cmd", required=True)
    ssub.add_parser("list", parents=C).set_defaults(fn=cmd_sessions_list)
    a = ssub.add_parser("revoke", parents=C); a.add_argument("id")
    a.set_defaults(fn=cmd_sessions_revoke)
    ssub.add_parser("revoke-others", parents=C).set_defaults(fn=cmd_sessions_revoke_others)

    s = sub.add_parser("settings", parents=C, help="console settings")
    ssub = s.add_subparsers(dest="settings_cmd", required=True)
    ssub.add_parser("show", parents=C).set_defaults(fn=cmd_settings_show)
    a = ssub.add_parser("set", parents=C)
    a.add_argument("--session-ttl-hours", type=int, required=True)
    a.set_defaults(fn=cmd_settings_set)

    u = sub.add_parser("users", parents=C, help="gateway users")
    usub = u.add_subparsers(dest="users_cmd", required=True)
    usub.add_parser("list", parents=C).set_defaults(fn=cmd_users_list)
    a = usub.add_parser("add", parents=C); a.add_argument("user")
    a.add_argument("--group"); a.add_argument("--ssh-key-file"); a.add_argument("--ssh-pubkey")
    a.add_argument("--note"); a.set_defaults(fn=cmd_users_add)
    for action in ("passwd", "enable", "disable", "remove"):
        a = usub.add_parser(action, parents=C); a.add_argument("user")
        a.set_defaults(fn=cmd_users_action, action=action)
    a = usub.add_parser("setkey", parents=C); a.add_argument("user")
    a.add_argument("--ssh-key-file"); a.add_argument("--ssh-pubkey")
    a.set_defaults(fn=cmd_users_action, action="setkey")
    a = usub.add_parser("setgroup", parents=C); a.add_argument("user"); a.add_argument("group")
    a.set_defaults(fn=cmd_users_action, action="setgroup")

    up = sub.add_parser("upstreams", parents=C, help="upstream nodes")
    upsub = up.add_subparsers(dest="upstreams_cmd", required=True)
    upsub.add_parser("list", parents=C).set_defaults(fn=cmd_upstreams_list)
    a = upsub.add_parser("add", parents=C); a.add_argument("name")
    a.add_argument("--addr", required=True); a.add_argument("--port", type=int, required=True)
    a.add_argument("--proto", required=True,
                   choices=("vless-ws", "vless", "trojan-ws", "ss", "http", "socks", "ssh"))
    a.add_argument("--group"); a.add_argument("--path"); a.add_argument("--uuid")
    a.add_argument("--username"); a.add_argument("--password"); a.add_argument("--key-file")
    a.add_argument("--tls", action="store_true"); a.add_argument("--method")
    a.add_argument("--note"); a.set_defaults(fn=cmd_upstreams_add)
    for action in ("enable", "disable", "remove"):
        a = upsub.add_parser(action, parents=C); a.add_argument("name")
        a.set_defaults(fn=cmd_upstreams_action, action=action)

    r = sub.add_parser("routes", parents=C, help="destination routes")
    rsub = r.add_subparsers(dest="routes_cmd", required=True)
    rsub.add_parser("list", parents=C).set_defaults(fn=cmd_routes_list)
    a = rsub.add_parser("add", parents=C)
    a.add_argument("--kind", required=True,
                   choices=("domain", "full", "keyword", "regexp", "ip"))
    a.add_argument("--pattern", required=True); a.add_argument("--to", required=True)
    a.add_argument("--user"); a.add_argument("--note"); a.set_defaults(fn=cmd_routes_add)
    for action in ("enable", "disable", "remove"):
        a = rsub.add_parser(action, parents=C); a.add_argument("id", type=int)
        a.set_defaults(fn=cmd_routes_action, action=action)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
