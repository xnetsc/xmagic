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

Keys:
  `xmagic keys list` shows the SSH keys usable in this environment
  (~/.ssh pairs, keys this CLI generated under ~/.xmagic/keys, and
  ssh-agent identities); `xmagic keys generate` mints a fresh ed25519
  pair there. `users add/setkey --ssh-key NAME|FINGERPRINT` registers
  one of them as a gateway user's credential; `--ssh-key-generate`
  mints and registers in one step.

Update:
  `xmagic update` replaces this file with the latest version from
  the repository (XMAGIC_UPDATE_URL or --from overrides the source).
  The download is version-checked and self-tested (--version probe)
  before it lands; the previous file is kept next to it as .bak.

Exit codes: 0 ok, 1 API/server error, 2 config/usage error,
3 not logged in / session expired (run `xmagic login`).
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import tempfile
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
        line += "; changes pending - no restart channel on the node," \
                " restart the gateway processes there to apply"
    elif applied.get("container_restart"):
        line += "; a targeted restart failed on the node" \
                " - the whole container is restarting"
    elif not applied.get("restarted"):
        line += "; rendered output unchanged - nothing restarted"
    else:
        line += "; restarts: " + ", ".join(
            f"{k}={'ok' if v else 'FAILED'}"
            for k, v in applied.get("restarted", {}).items())
    return line


# ------------------------------------------------------------ login/logout

class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    result = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = {k: v[0] for k, v in
                 urllib.parse.parse_qs(parsed.query).items()}
        if parsed.path != "/callback" or "code" not in query \
                or "state" not in query:
            # Not the handoff: a favicon fetch, a browser probe, a
            # restored completion tab re-requesting its page. Answer
            # and keep waiting - a stray request must not pose as the
            # callback and abort the login as a "state mismatch".
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = ("<!DOCTYPE html><meta charset=utf-8><title>xmagic</title>"
                "<p>登录完成，可以关闭这个页面，回到命令行。</p>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        # Publish the result only after the response is fully written:
        # the main thread may exit the process the moment it sees the
        # result (on a state mismatch it does), which would otherwise
        # race this handler thread and clip the page body.
        _CallbackHandler.result = query

    def log_message(self, *a):
        pass


def cmd_login(args):
    cfg, _ = load_config(args)
    name, url = resolve_node(args, cfg)
    state = secrets.token_urlsafe(16)
    _CallbackHandler.result = None
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


def cmd_passkey_replace(args):
    """Replace the node's admin passkey. The CLI cannot run a WebAuthn
    ceremony itself, so it asks the node for a one-time ticket, opens
    the browser at the node's /cli-replace page (fresh login with the
    current passkey, then registration of the new one) and polls the
    ticket status. On success every session except this CLI session
    and the browser's fresh one has been revoked server-side."""
    api, name, url = authed_api(args)
    issued = api.call("POST", "/api/cli-replace-ticket", {})
    replace_url = url + "/cli-replace?" + urllib.parse.urlencode(
        {"ticket": issued["ticket"]})
    opened = False
    if not args.no_browser:
        opened = webbrowser.open(replace_url)
    if not opened:
        print(f"在浏览器打开这个地址更换 Passkey：\n{replace_url}", flush=True)
    print("等待浏览器完成 Passkey 更换（5 分钟超时）…", file=sys.stderr,
          flush=True)
    deadline = time.time() + issued.get("expires_in", 300) + 30
    while time.time() < deadline:
        status = api.call("POST", "/api/cli-replace-status",
                          {"ticket": issued["ticket"]})
        if status.get("done"):
            print(f"passkey on {name or url} replaced; all other sessions "
                  "were revoked (this CLI session was kept)")
            return
        time.sleep(2)
    die(EXIT_AUTH, "timed out waiting for the browser passkey replacement")


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
    src = {True: "db", False: "env"}
    emit(args, payload, "\n".join([
        f"session_ttl_hours: {payload['session_ttl_hours']} "
        f"({payload['session_ttl_hours'] / 24:g} days, new sessions only)",
        f"vless_ws_paths: {','.join(payload['vless_ws_paths'])} "
        f"({src[payload['vless_ws_paths_from_db']]})",
        f"trojan_ws_paths: {','.join(payload['trojan_ws_paths'])} "
        f"({src[payload['trojan_ws_paths_from_db']]})",
        f"upstream_strategy: {payload['upstream_strategy']} "
        f"({src[payload['upstream_strategy_from_db']]})",
        f"ss_method (new users): {payload['ss_method']} "
        f"({src[payload['ss_method_from_db']]})",
        f"vless_enabled: {payload['vless_enabled']} "
        f"({src[payload['vless_enabled_from_db']]})",
        f"direct_allow_private: {payload['direct_allow_private']} "
        f"({src[payload['direct_allow_private_from_db']]})",
        f"interconnect_off_groups: "
        f"{','.join(payload['interconnect_off_groups']) or '(none)'} "
        f"({src[payload['interconnect_off_groups_from_db']]})",
    ]))


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
    body = {}
    for key in ("session_ttl_hours", "vless_ws_paths", "trojan_ws_paths",
                "upstream_strategy", "ss_method", "interconnect_off_groups"):
        if getattr(args, key) is not None:
            body[key] = getattr(args, key)
    if getattr(args, "vless_enabled", None) is not None:
        body["vless_enabled"] = args.vless_enabled
    if getattr(args, "direct_allow_private", None) is not None:
        body["direct_allow_private"] = args.direct_allow_private
    if not body:
        die(2, "nothing to set: pass at least one --option (empty string "
            "clears a value back to the env default)")
    payload = api.call("POST", "/api/settings", body)
    emit(args, payload,
         f"settings saved; session_ttl_hours={payload['session_ttl_hours']}, "
         f"strategy={payload['upstream_strategy']}, "
         f"ss_method={payload['ss_method']}, "
         f"interconnect_off_groups="
         f"{','.join(payload['interconnect_off_groups']) or '(none)'}\n"
         + applied_line(payload.get("applied")))


def _read_key(args):
    if getattr(args, "ssh_key_file", None):
        with open(args.ssh_key_file) as f:
            return f.read().strip()
    if getattr(args, "ssh_key", None):
        return resolve_env_key(args.ssh_key)
    if getattr(args, "ssh_key_generate", None) is not None:
        name = args.ssh_key_generate or getattr(args, "user", None) or "xmagic"
        priv = os.path.join(base_dir(), "keys", name)
        if os.path.exists(priv) or os.path.exists(priv + ".pub"):
            die(2, f"key already exists: {priv}"
                   " - pass --ssh-key-generate NAME for a fresh one")
        os.makedirs(os.path.dirname(priv), exist_ok=True)
        pub, fp = _save_keypair(priv, name)
        print(f"generated ssh key {priv} ({fp}); the node stores only"
              " the public key", file=sys.stderr)
        return pub
    return getattr(args, "ssh_pubkey", None)


def cmd_users_list(args):
    api, _, _ = authed_api(args)
    payload = api.call("GET", "/api/users")
    off = "" if payload.get("vless_enabled") else " (off)"
    lines = []
    for u in payload["users"]:
        lines.append(
            f"{u['username']:<16} group={u['group']:<10} "
            f"enabled={u['enabled']!s:<5} vless uuid={u['vless_uuid']}{off}\n"
            f"{'':<16} password={u['password']}  ss={u['ss_method']}/{u['ss_password']}"
            + ("  ssh-key=yes" if u["ssh_key"] else ""))
    emit(args, payload, "\n".join(lines) if lines else "(no users)")


def cmd_users_add(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/users", {
        "username": args.user, "group": args.group,
        "ssh_pubkey": _read_key(args), "note": args.note})
    u = payload["user"]
    off = "" if payload.get("vless_enabled") else " (VLESS inbounds off)"
    human = (f"user:            {u['username']}\n"
             f"vless uuid:      {u['vless_uuid']}{off}\n"
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
    elif args.action == "setmethod":
        body["method"] = args.method
    elif args.action == "setnote":
        body["note"] = args.note
    payload = api.call("POST", f"/api/users/{args.user}/{args.action}", body)
    human = applied_line(payload.get("applied")) or f"{args.user}: {args.action} done"
    if args.action == "passwd" and payload.get("user"):
        u = payload["user"]
        human = (f"password (trojan/http/socks): {u['password']}\n"
                 f"ss password:     {u['ss_password']}\n" + human)
    if args.action == "rotate-uuid" and payload.get("user"):
        off = "" if payload.get("vless_enabled") else " (VLESS inbounds off)"
        human = f"vless uuid:      {payload['user']['vless_uuid']}{off}\n" + human
    emit(args, payload, human)


def cmd_upstreams_list(args):
    api, _, _ = authed_api(args)
    payload = api.call("GET", "/api/upstreams")
    lines = [f"{u['name']:<16} group={u['group']:<10} enabled={u['enabled']!s:<5} "
             f"{u['protocol']:<9} {u['address']}:{u['port']}{u['path'] or ''}"
             f"{' +tls' if u['tls'] else ''}" for u in payload["upstreams"]]
    emit(args, payload, "\n".join(lines) if lines else "(no upstreams - direct egress)")


def _key_upload_content(args):
    """--key-upload: a private key file on THIS machine. Its content is
    sent to the node, which stores it (the upstream row then records
    /keys/<name>.key). None when the flag is absent."""
    path = getattr(args, "key_upload", None)
    if not path:
        return None
    try:
        with open(path) as f:
            return f.read()
    except OSError as exc:
        die(2, f"cannot read key file {path}: {exc.strerror or exc}")


# ------------------------------------------------------------ self-update

VERSION = "1.1.0"
CLI_DOWNLOAD_PATH = "/cli/xmagic.py"  # served by every deployed node


def _vkey(v):
    parts = []
    for p in str(v).split("."):
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def cmd_update(args):
    """Sync this file with the CLI copy bundled in the deployed node.

    The default source is the selected node itself: it serves the exact
    xmagic.py it was deployed with, so an installed CLI can never drift
    from the service it manages (comparison is by content hash, not by
    version number alone). --from / XMAGIC_UPDATE_URL still allow an
    arbitrary source; a downgrade from those needs --force, while the
    node's own copy is authoritative and aligning to it never does.
    The download must carry a VERSION, compile, and pass a --version
    probe before anything is replaced; the old file stays as .bak.
    No session is needed - the node serves the file publicly."""
    target = os.path.realpath(__file__)
    custom = (getattr(args, "update_url", None)
              or os.environ.get("XMAGIC_UPDATE_URL"))
    if custom:
        url, from_node = custom, False
    else:
        cfg, _ = load_config(args)
        _name, node_url = resolve_node(args, cfg)
        url = node_url.rstrip("/") + CLI_DOWNLOAD_PATH
        from_node = True
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": f"xmagic/{VERSION}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
    except (urllib.error.URLError, OSError) as exc:
        die(1, f"update download failed: {exc}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        die(1, "downloaded file is not valid UTF-8 - refusing to install")
    m = re.search(r'^VERSION = "([^"]+)"', text, re.M)
    if not m or "gateway" not in text[:2000]:
        die(1, "downloaded file does not look like xmagic.py"
               " - refusing to install")
    remote = m.group(1)
    with open(target, "rb") as f:
        own = f.read()
    if hashlib.sha256(data).digest() == hashlib.sha256(own).digest():
        emit(args, {"updated": False, "version": VERSION, "identical": True},
             f"already identical to the {'node' if from_node else 'source'}"
             f" copy (xmagic {VERSION})")
        return
    if (_vkey(remote) < _vkey(VERSION) and not from_node
            and not getattr(args, "force", False)):
        die(1, f"remote version {remote} is older than this {VERSION}"
               " - pass --force to downgrade")
    if getattr(args, "check", False):
        if remote == VERSION:
            msg = (f"same version {VERSION}, but the content differs from"
                   f" the {'node' if from_node else 'source'} copy"
                   " - run: xmagic update, to match it exactly")
        else:
            msg = (f"update available: {VERSION} -> {remote}"
                   " (run: xmagic update)")
        emit(args, {"updated": False, "version": VERSION,
                    "available": remote}, msg)
        return
    directory = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".xmagic-update-",
                               suffix=".py")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            compile(text, tmp, "exec")
        except SyntaxError as exc:
            die(1, f"downloaded file does not compile: {exc}"
                  " - refusing to install")
        probe = subprocess.run([sys.executable, tmp, "--version"],
                               capture_output=True, text=True, timeout=15)
        if probe.returncode != 0 or remote not in probe.stdout:
            die(1, "downloaded file failed its --version self-check"
                   " - refusing to install")
        backup = target + ".bak"
        try:
            with open(target, "rb") as f:
                old = f.read()
            with open(backup, "wb") as f:
                f.write(old)
            os.chmod(tmp, 0o755)
            os.replace(tmp, target)
        except OSError as exc:
            die(1, f"cannot replace {target}: {exc}")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    emit(args, {"updated": True, "from": VERSION, "to": remote,
                "path": target, "backup": backup},
         f"updated {target}: {VERSION} -> {remote}"
         f" (previous version kept at {backup})")


# ------------------------------------------------------------ ssh key tools
# Pure-stdlib ed25519 keypair generation (OpenSSH formats) plus a scan
# of the SSH keys already usable in this environment (~/.ssh pairs,
# keys this CLI generated, ssh-agent identities), so a key can be
# minted or picked where it is used - no external tools needed.

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


def pubkey_fingerprint(line):
    parts = (line or "").strip().split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1])
    except Exception:
        return None
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode().rstrip("=")


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


def _save_keypair(priv_path, comment):
    """Write a fresh keypair (private 0600, exclusive create) and its
    .pub next to it. -> (public_line, fingerprint)."""
    pem, pub, fp = generate_ed25519_keypair(comment)
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(pem)
    with open(priv_path + ".pub", "w") as f:
        f.write(pub + "\n")
    return pub, fp


def _read_pub_line(path):
    try:
        with open(path) as f:
            line = f.read().strip().splitlines()[0].strip()
    except (OSError, IndexError):
        return None
    return line if pubkey_fingerprint(line) else None


def scan_env_keys():
    """SSH keys usable in this environment. File pairs in ~/.ssh and
    in ~/.xmagic/keys, plus ssh-agent identities when an agent answers.
    Entries: {name, type, fingerprint, comment, source, pubkey,
    priv_path} - deduplicated by fingerprint, files before agent."""
    entries, seen = [], set()

    def add(name, line, source, priv_path):
        fp = pubkey_fingerprint(line)
        if not fp or fp in seen:
            return
        seen.add(fp)
        parts = line.split()
        entries.append({"name": name, "type": parts[0], "fingerprint": fp,
                        "comment": parts[2] if len(parts) > 2 else "",
                        "source": source, "pubkey": line,
                        "priv_path": priv_path})

    for directory, source in ((os.path.join(os.path.expanduser("~"), ".ssh"),
                               "file"),
                              (os.path.join(base_dir(), "keys"), "xmagic")):
        if os.path.isdir(directory):
            for fn in sorted(os.listdir(directory)):
                if fn.endswith(".pub"):
                    line = _read_pub_line(os.path.join(directory, fn))
                    if line:
                        priv = os.path.join(directory, fn[:-4])
                        add(fn[:-4], line, source,
                            priv if os.path.exists(priv) else None)
    if os.environ.get("SSH_AUTH_SOCK"):
        try:
            out = subprocess.run(["ssh-add", "-L"], capture_output=True,
                                 text=True, timeout=5)
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    line = line.strip()
                    if pubkey_fingerprint(line):
                        parts = line.split()
                        add(parts[2] if len(parts) > 2 else "agent-key",
                            line, "agent", None)
        except (OSError, subprocess.SubprocessError):
            pass
    return entries


def resolve_env_key(selector):
    """Resolve a key selector - a .pub file path, a name from the
    environment scan, or a (prefix of a) SHA256 fingerprint - to a
    public key line. Dies with a config error when unmatched/ambiguous."""
    if os.path.isfile(selector):
        line = _read_pub_line(selector)
        if line:
            return line
        die(2, f"{selector} does not contain a usable public key")
    hits = [e for e in scan_env_keys()
            if e["name"] == selector or e["fingerprint"] == selector
            or e["fingerprint"].startswith(selector)
            or e["fingerprint"].split(":", 1)[1].startswith(selector)]
    if len(hits) == 1:
        return hits[0]["pubkey"]
    if not hits:
        die(2, f"no environment key matches {selector!r}"
               " - see: xmagic keys list")
    die(2, f"key selector {selector!r} matches {len(hits)} keys"
           " - use a full fingerprint")


def cmd_keys_list(args):
    entries = scan_env_keys()
    lines = [f"{e['fingerprint']}  {e['type']:<11} {e['source']:<6} "
             f"{e['name']:<20} "
             + (e["priv_path"] or "(public key only)")
             for e in entries]
    emit(args, {"keys": entries},
         "\n".join(lines) if lines else
         "(no ssh keys found - create one: xmagic keys generate)")


def cmd_keys_generate(args):
    name = args.name or "xmagic"
    priv = os.path.join(base_dir(), "keys", name)
    if os.path.exists(priv) or os.path.exists(priv + ".pub"):
        die(2, f"key already exists: {priv} - pick another name")
    os.makedirs(os.path.dirname(priv), exist_ok=True)
    pub, fp = _save_keypair(priv, name)
    emit(args, {"private_key": priv, "public_key_file": priv + ".pub",
                "public_key": pub, "fingerprint": fp},
         f"private key: {priv} (0600 - keep it secret)\n"
         f"public key:  {priv}.pub\n"
         f"fingerprint: {fp}\n{pub}\n"
         f"register it: xmagic users add <user> --ssh-key {name}")


def cmd_keys_show(args):
    line = resolve_env_key(args.selector)
    emit(args, {"selector": args.selector, "public_key": line,
                "fingerprint": pubkey_fingerprint(line)}, line)


def cmd_upstreams_add(args):
    if getattr(args, "key_generate", False) and (args.key_file or args.key_upload):
        die(2, "--key-generate replaces --key-file/--key-upload")
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/upstreams", {
        "name": args.name, "address": args.addr, "port": args.port,
        "protocol": args.proto, "group": args.group, "path": args.path,
        "uuid": args.uuid, "username": args.username, "password": args.password,
        "key_file": args.key_file, "key_content": _key_upload_content(args),
        "key_generate": bool(getattr(args, "key_generate", False)),
        "tls": args.tls, "method": args.method,
        "note": args.note})
    emit(args, payload,
         f"upstream {args.name} added\n" + applied_line(payload.get("applied")))


def cmd_upstreams_action(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", f"/api/upstreams/{args.name}/{args.action}", {})
    emit(args, payload, applied_line(payload.get("applied"))
         or f"{args.name}: {args.action} done")


def cmd_upstreams_edit(args):
    api, _, _ = authed_api(args)
    body = {}
    for key, attr in (("address", "addr"), ("port", "port"),
                      ("protocol", "proto"), ("group", "group"),
                      ("path", "path"), ("uuid", "uuid"),
                      ("username", "username"), ("password", "password"),
                      ("key_file", "key_file"), ("method", "method"),
                      ("note", "note")):
        if getattr(args, attr) is not None:
            body[key] = getattr(args, attr)
    if args.tls:
        body["tls"] = True
    elif args.no_tls:
        body["tls"] = False
    content = _key_upload_content(args)
    if content is not None:
        body["key_content"] = content
    if getattr(args, "key_generate", False):
        if content is not None or body.get("key_file"):
            die(2, "--key-generate replaces --key-upload/--key-file")
        body["key_generate"] = True
    if not body:
        die(2, "nothing to change: pass at least one --option")
    payload = api.call("POST", f"/api/upstreams/{args.name}/update", body)
    emit(args, payload, f"upstream {args.name} updated\n"
         + applied_line(payload.get("applied")))


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


def cmd_routes_edit(args):
    api, _, _ = authed_api(args)
    body = {}
    for key, attr in (("kind", "kind"), ("pattern", "pattern"),
                      ("to", "to"), ("username", "user"), ("note", "note")):
        if getattr(args, attr) is not None:
            body[key] = getattr(args, attr)
    if not body:
        die(2, "nothing to change: pass at least one --option")
    payload = api.call("POST", f"/api/routes/{args.id}/update", body)
    r = payload["route"]
    emit(args, payload,
         f"route #{r['id']} updated: {r['kind']} {r['pattern']} -> {r['target']}\n"
         + applied_line(payload.get("applied")))


# ------------------------------------------------------------ main


def _db_line(d):
    return (f"{'*' if d['active'] else ' '} {d['name']:<16} {d['type']:<9} "
            f"{d['target']}" + (f"  ({d['note']})" if d.get("note") else ""))


def cmd_db_list(args):
    api, _, _ = authed_api(args)
    payload = api.call("GET", "/api/databases")
    lines = [_db_line(d) for d in payload["databases"]]
    emit(args, payload, "\n".join(lines) if lines else "(no database configs)")


def cmd_db_add(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/databases", {
        "name": args.name, "type": args.type,
        "target": args.target or args.dsn or args.path, "note": args.note})
    d = payload["database"]
    emit(args, payload,
         f"database config {d['name']} added: {d['type']} {d['target']}")


def cmd_db_edit(args):
    api, _, _ = authed_api(args)
    body = {}
    target = args.target or args.dsn or args.path
    if target is not None:
        body["target"] = target
    if args.note is not None:
        body["note"] = args.note
    if not body:
        die(2, "nothing to edit: pass --target/--dsn/--path or --note")
    payload = api.call("POST", f"/api/databases/{args.name}/edit", body)
    d = payload["database"]
    emit(args, payload,
         f"database config {d['name']} updated: {d['type']} {d['target']}")


def cmd_db_action(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", f"/api/databases/{args.name}/{args.action}", {})
    if args.action == "test":
        t = payload["test"]
        counts = ", ".join(f"{k}={v}" for k, v in t["tables"].items())
        human = (f"{t['name']}: reachable ({t['type']}: {t['target']});"
                 f" tables: {counts}")
    elif args.action == "switch":
        human = (f"active database: {payload['database']['name']}\n"
                 + applied_line(payload.get("applied")))
    else:  # remove
        human = f"database config {args.name} removed"
    emit(args, payload, human)


def cmd_db_migrate(args):
    api, _, _ = authed_api(args)
    payload = api.call("POST", "/api/databases/migrate", {
        "from": args.src, "to": args.dst, "replace": args.replace})
    m = payload["migration"]
    counts = ", ".join(f"{k}={v}" for k, v in m["tables"].items())
    emit(args, payload, f"migrated {m['from']} -> {m['to']}: {counts}")

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
    p.add_argument("--version", action="version",
                   version=f"xmagic {VERSION}")
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

    pk = sub.add_parser("passkey", parents=C, help="admin passkey")
    pksub = pk.add_subparsers(dest="passkey_cmd", required=True)
    a = pksub.add_parser("replace", parents=C,
                         help="replace the admin passkey via a browser ceremony")
    a.add_argument("--no-browser", action="store_true",
                   help="print the replace URL instead of opening a browser")
    a.set_defaults(fn=cmd_passkey_replace)

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
    a.add_argument("--session-ttl-hours", type=int)
    a.add_argument("--vless-ws-paths", help="comma-separated; empty string = env default")
    a.add_argument("--trojan-ws-paths", help="comma-separated; empty string = env default")
    a.add_argument("--upstream-strategy")
    a.add_argument("--ss-method")
    a.add_argument("--direct-allow-private", dest="direct_allow_private",
                   action="store_true", default=None,
                   help="allow direct egress to private/LAN addresses")
    a.add_argument("--interconnect-off-groups",
                   help="comma-separated user groups whose members may NOT"
                        " interconnect (on by default); empty string ="
                        " nobody opted out")
    a.add_argument("--no-direct-allow-private", dest="direct_allow_private",
                   action="store_false",
                   help="disallow direct egress to private/LAN addresses")
    a.add_argument("--vless-enabled", dest="vless_enabled",
                   action="store_true", default=None,
                   help="render the VLESS inbounds (off by default)")
    a.add_argument("--no-vless-enabled", dest="vless_enabled",
                   action="store_false",
                   help="do not render the VLESS inbounds")
    a.set_defaults(fn=cmd_settings_set)

    a = sub.add_parser("update", parents=C,
                       help="sync this CLI with the deployed node's"
                            " bundled copy")
    a.add_argument("--check", action="store_true",
                   help="only report whether an update is available")
    a.add_argument("--force", action="store_true",
                   help="allow a downgrade from a custom --from source")
    a.add_argument("--from", dest="update_url", metavar="URL",
                   help="download from this URL instead of the node")
    a.set_defaults(fn=cmd_update)

    k = sub.add_parser("keys", parents=C,
                       help="ssh keys available in this environment")
    ksub = k.add_subparsers(dest="keys_cmd", required=True)
    ksub.add_parser("list", parents=C).set_defaults(fn=cmd_keys_list)
    a = ksub.add_parser("generate", parents=C)
    a.add_argument("name", nargs="?", default="xmagic",
                   help="key name under ~/.xmagic/keys (default: xmagic)")
    a.set_defaults(fn=cmd_keys_generate)
    a = ksub.add_parser("show", parents=C); a.add_argument("selector")
    a.set_defaults(fn=cmd_keys_show)

    u = sub.add_parser("users", parents=C, help="gateway users")
    usub = u.add_subparsers(dest="users_cmd", required=True)
    usub.add_parser("list", parents=C).set_defaults(fn=cmd_users_list)
    a = usub.add_parser("add", parents=C); a.add_argument("user")
    a.add_argument("--group"); a.add_argument("--ssh-key-file"); a.add_argument("--ssh-pubkey")
    a.add_argument("--ssh-key", metavar="SELECTOR",
                   help="public key from this environment: a name or"
                        " fingerprint from `xmagic keys list`, or a .pub path")
    a.add_argument("--ssh-key-generate", nargs="?", const="", metavar="NAME",
                   help="generate a fresh ed25519 keypair under"
                        " ~/.xmagic/keys (default name: the username) and"
                        " register its public key")
    a.add_argument("--note"); a.set_defaults(fn=cmd_users_add)
    for action in ("passwd", "enable", "disable", "remove", "rotate-uuid"):
        a = usub.add_parser(action, parents=C); a.add_argument("user")
        a.set_defaults(fn=cmd_users_action, action=action)
    a = usub.add_parser("setkey", parents=C); a.add_argument("user")
    a.add_argument("--ssh-key-file"); a.add_argument("--ssh-pubkey")
    a.add_argument("--ssh-key", metavar="SELECTOR",
                   help="public key from this environment: a name or"
                        " fingerprint from `xmagic keys list`, or a .pub path")
    a.add_argument("--ssh-key-generate", nargs="?", const="", metavar="NAME",
                   help="generate a fresh ed25519 keypair under"
                        " ~/.xmagic/keys (default name: the username) and"
                        " register its public key")
    a.set_defaults(fn=cmd_users_action, action="setkey")
    a = usub.add_parser("setgroup", parents=C); a.add_argument("user"); a.add_argument("group")
    a.set_defaults(fn=cmd_users_action, action="setgroup")
    a = usub.add_parser("setmethod", parents=C); a.add_argument("user"); a.add_argument("method")
    a.set_defaults(fn=cmd_users_action, action="setmethod")
    a = usub.add_parser("setnote", parents=C); a.add_argument("user")
    a.add_argument("note", nargs="?")
    a.set_defaults(fn=cmd_users_action, action="setnote")

    up = sub.add_parser("upstreams", parents=C, help="upstream nodes")
    upsub = up.add_subparsers(dest="upstreams_cmd", required=True)
    upsub.add_parser("list", parents=C).set_defaults(fn=cmd_upstreams_list)
    a = upsub.add_parser("add", parents=C); a.add_argument("name")
    a.add_argument("--addr", required=True); a.add_argument("--port", type=int, required=True)
    a.add_argument("--proto", required=True,
                   choices=("vless-ws", "vless", "trojan-ws", "ss", "http", "socks", "ssh"))
    a.add_argument("--group"); a.add_argument("--path"); a.add_argument("--uuid")
    a.add_argument("--username"); a.add_argument("--password"); a.add_argument("--key-file")
    a.add_argument("--key-upload", help="ssh upstream: upload this local private key"
                                        " file; the node stores it")
    a.add_argument("--key-generate", action="store_true",
                   help="ssh upstream: the node generates a fresh ed25519"
                        " keypair and stores the private key for this upstream")
    a.add_argument("--tls", action="store_true"); a.add_argument("--method")
    a.add_argument("--note"); a.set_defaults(fn=cmd_upstreams_add)
    for action in ("enable", "disable", "remove"):
        a = upsub.add_parser(action, parents=C); a.add_argument("name")
        a.set_defaults(fn=cmd_upstreams_action, action=action)
    a = upsub.add_parser("edit", parents=C); a.add_argument("name")
    a.add_argument("--addr"); a.add_argument("--port", type=int)
    a.add_argument("--proto", choices=("vless-ws", "vless", "trojan-ws", "ss", "http", "socks", "ssh"))
    a.add_argument("--group"); a.add_argument("--path"); a.add_argument("--uuid")
    a.add_argument("--username"); a.add_argument("--password"); a.add_argument("--key-file")
    a.add_argument("--key-upload", help="ssh upstream: replace the key with this"
                                        " local file; the node stores it")
    a.add_argument("--key-generate", action="store_true",
                   help="ssh upstream: replace the key with a fresh node-"
                        "generated ed25519 keypair")
    a.add_argument("--tls", action="store_true"); a.add_argument("--no-tls", action="store_true")
    a.add_argument("--method"); a.add_argument("--note")
    a.set_defaults(fn=cmd_upstreams_edit)

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
    a = rsub.add_parser("edit", parents=C); a.add_argument("id", type=int)
    a.add_argument("--kind", choices=("domain", "full", "keyword", "regexp", "ip"))
    a.add_argument("--pattern"); a.add_argument("--to"); a.add_argument("--user")
    a.add_argument("--note"); a.set_defaults(fn=cmd_routes_edit)

    d = sub.add_parser("db", parents=C, help="database configs on the node")
    dsub = d.add_subparsers(dest="db_cmd", required=True)
    dsub.add_parser("list", parents=C).set_defaults(fn=cmd_db_list)
    a = dsub.add_parser("add", parents=C); a.add_argument("name")
    a.add_argument("--type", required=True, choices=("sqlite", "postgres", "mysql"))
    a.add_argument("--target", help="sqlite: file path; postgres/mysql: DSN")
    a.add_argument("--dsn", help="alias of --target, for postgres/mysql")
    a.add_argument("--path", help="alias of --target, for sqlite")
    a.add_argument("--note"); a.set_defaults(fn=cmd_db_add)
    a = dsub.add_parser("edit", parents=C); a.add_argument("name")
    a.add_argument("--target"); a.add_argument("--dsn"); a.add_argument("--path")
    a.add_argument("--note"); a.set_defaults(fn=cmd_db_edit)
    for action in ("remove", "test", "switch"):
        a = dsub.add_parser(action, parents=C); a.add_argument("name")
        a.set_defaults(fn=cmd_db_action, action=action)
    a = dsub.add_parser("migrate", parents=C)
    a.add_argument("src"); a.add_argument("dst")
    a.add_argument("--replace", action="store_true",
                   help="clear the target's business tables before copying")
    a.set_defaults(fn=cmd_db_migrate)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
