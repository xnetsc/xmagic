# xmagic: single-port multi-protocol proxy gateway

[中文](README.zh-CN.md) | **English**

In one line: **one public port, dispatched by the first bytes of each
connection**, serving SSH, HTTP proxy (CONNECT), Trojan-WS and bare
Shadowsocks at the same time. Protocols with no encryption of their
own are off by default: VLESS-WS / bare VLESS (enable in Settings)
and public SOCKS5 (`XMAGIC_ENABLE_SOCKS5=1`); HTTP stays because it
rides the outer HTTPS, Trojan mandates TLS by design, and
Shadowsocks carries its own cipher.
A node can also cascade to multiple upstreams: whatever protocol it
accepts inbound, it can also speak outbound. The upstream for a
connection is chosen by user group, or by destination domain/IP via
routing rules.

Two management interfaces with identical capabilities: a **web console**
(Passkey sign-in) and **command lines** (`users.py` on the node, the
remote CLI `xmagic.py` on your own machine). All three drive the same
identity engine, so a change made in one shows up in the others.

## Architecture

```
                        public port XRAY_PORT (the only exposed port)
                                   |
                     sniff.py first-byte dispatcher (routes by content)
        +----------+--------+-----------+-------------+---------------+
    "SSH-"      0x05    CONNECT /     WebSocket    origin-form HTTP  anything
     banner    (opt-in)  absolute-form   Upgrade      (a browser)      else
        |          |       HTTP            |              |             |
       sshd    SOCKS5     HTTP      Xray fallback mux -----+        admin
    (key auth)  inbound   inbound    |- path hit -> VLESS-WS backends (multi-path, opt-in)
                                     |- path hit -> Trojan-WS backends (multi-path)
                                     +- default fallback -> bare Shadowsocks
                                   |
              egress: direct, or an upstream pool (per-user groups, balancing)
```

- There is exactly one exposed port (the dispatcher's). Every backend
  listens on 127.0.0.1 only - including the admin console, which shares
  the one public port with the proxy: the dispatcher routes origin-form
  HTTP (a browser opening the console) to it and proxy-form traffic to
  the proxy (see the classification above).
- Identity has a single source of truth: **the business database**
  (SQLite by default, `data/users.db`; PostgreSQL / MySQL are also
  supported, see "Database"). Xray's `config.json` and sshd's
  `authorized_keys` are rendered from it.
- All loopback backend ports can be overridden by env (required when
  running several nodes on one host for testing).

## Protocols and authentication (inbound / upstream symmetric)

| Protocol | Client -> this node (inbound) | This node -> upstream (outbound) | Auth |
| --- | --- | --- | --- |
| SSH | sshd; `ssh -D` gives SOCKS5 | `ssh -N -D` tunnel mapped to a local SOCKS outbound | public key (both directions) |
| SOCKS5 | Xray socks inbound (public branch **off by default**: plaintext, `XMAGIC_ENABLE_SOCKS5=1` to enable) | Xray socks outbound | username + password (may be empty) |
| HTTP proxy | Xray http inbound (CONNECT) | Xray http outbound | Basic (may be empty) |
| VLESS-WS | WS path dispatch -> backend (**off by default**: VLESS has no encryption of its own; enable in Settings) | same | uuid |
| VLESS (bare TCP) | dispatcher -> mux main inbound (**off by default**) | same | uuid |
| Trojan-WS | WS path dispatch -> backend | same | password |
| Shadowsocks | default fallback -> backend | same | per-user password + method |

Each user holds one credential set in the database: a VLESS uuid
(used when VLESS is enabled), one shared password (Trojan / HTTP /
SOCKS), a separate Shadowsocks
password, and an optional SSH public key. Upstreams are stored with
the credentials the upstream node issued under the same model -
**two independent auth legs**: users authenticate to this node with
this node's credentials (terminated here); this node authenticates to
an upstream with the upstream's credentials (stored in the upstream
record). Users in the same group appear as one identity at the
upstream - that is inherent to cascading; give a user their own group
and upstream records to keep them distinct upstream.

## Management interface 1: web console (Passkey)

- The console is part of the deployment (the `admin` container) - no
  scripts need to run on the host. It shares the `data/` volume with
  the gateway, re-renders after every change, and restarts only the
  affected containers (xray / sshd / tunnels) through the Docker
  socket (without the socket it renders only, and the UI says so
  honestly). When the rendered output does not change, nothing is
  restarted.
- **Exactly one admin account, Passkey only**: the first Passkey
  registered becomes the admin and registration then closes
  permanently. No passwords or other sign-in methods. User
  verification (UV) is required.
- The console has no public port of its own: open
  `http://<node>:<XRAY_PORT>/` in a browser (the dispatcher splits
  origin-form from absolute-form traffic, see Architecture). Behind a
  domain + HTTPS, set `XMAGIC_ADMIN_RPID` / `XMAGIC_ADMIN_ORIGINS` to
  that domain so Passkeys are issued for it.
- A lost Passkey has no web recovery: run `users.py admin-reset` on
  the node to clear the credential and register again - anyone with
  host access owns the machine anyway; this break-glass path is
  deliberate. While signed in, you can also **replace the Passkey**
  (Settings): the moment the replacement completes, every other
  session is revoked and this page continues on the new session.
- **Scope is all business data, not just creation**: proxy users
  (change password, rotate UUID, SSH key / group / SS method / note,
  enable/disable, delete), upstreams (every field editable in place),
  destination routes (editable), settings and sign-in sessions - in
  the web console and both CLIs alike.

### Sign-in sessions

- The admin can hold several sessions at once (multiple browsers,
  CLI logins from multiple machines).
- **Sessions last 1 week by default**, adjustable in Settings
  (1-2160 hours) from web or CLI; it only affects newly issued
  sessions.
- Sessions are stored as SHA-256 hashes of the token (never the raw
  token). The console's Sessions page lists each session's id, type
  (web/cli), origin, creation and expiry, and can **revoke one** or
  **revoke all others**; the CLIs can too (below).

### Settings (including render-level configuration)

Besides the session lifetime, Settings holds the render-level options
that otherwise only exist in `.env`: the VLESS / Trojan WS path lists,
the upstream pool strategy, the default SS method for new users,
whether direct egress to private addresses is allowed, and the
group opt-out list for same-group interconnect (on by default - see
"Same-group interconnect" below). A value stored
in the database wins; clearing it falls back to the `.env` deployment
default; saving re-renders and applies at once. Port configuration is
not here - ports belong to the dispatcher / sshd processes and stay in
`.env` + compose.

Two plaintext-by-default protocols are off unless the operator
opts in: the VLESS inbounds (Settings -> "Enable VLESS inbounds",
or `VLESS_ENABLED=1`; VLESS delegates encryption to a TLS layer
this gateway does not terminate) and the dispatcher's public
SOCKS5 branch (env `XMAGIC_ENABLE_SOCKS5=1`; SOCKS5 is plaintext
and, not being HTTP, cannot ride the outer HTTPS either).

"Allow direct egress to private addresses" is off by default: traffic
arriving over VLESS / Trojan / Shadowsocks cannot reach the node's own
or LAN addresses when going direct (Xray freedom's default blocking
rule, an anti-SSRF measure). Turn it on when the node must reach its
own LAN services; the rendered freedom outbound then carries an allow
finalRule for the private ranges.

## Management interface 2: command line (identical to web)

### On the node: users.py (the engine's own CLI)

Runs through the admin container; the host needs no Python:

```bash
docker compose run --rm admin python3 users.py add alice --ssh-key-file ~/.ssh/id_ed25519.pub
docker compose run --rm admin python3 users.py upstream-add b1 --addr 1.2.3.4 --port 8080 --proto ss --password ...
docker compose run --rm admin python3 users.py route-add --kind domain --pattern github.com --to intl
docker compose run --rm admin python3 users.py upstream-edit b1 --port 8443   # upstreams/routes are editable
docker compose run --rm admin python3 users.py route-edit 1 --to direct
docker compose run --rm admin python3 users.py rotate-uuid alice              # also setmethod / setnote / setkey --clear
docker compose run --rm admin python3 users.py settings --vless-ws-paths /a,/b  # render-level config (empty = back to .env)
docker compose run --rm admin python3 users.py apply      # render + restart (same action as saving in the web UI)
docker compose run --rm admin python3 users.py status
docker compose run --rm admin python3 users.py sessions   # list sessions; sessions-revoke <id> to revoke
docker compose run --rm admin python3 users.py settings --session-ttl-hours 48
docker compose run --rm admin python3 users.py --json list   # machine-readable output for automation
```

### On your own machine: xmagic.py (remote CLI, manages many nodes)

Install the single-file CLI (Python standard library only, no pip) from
any deployed node: the node serves the exact CLI copy it was deployed
with, so the CLI always matches the service. The same command, already
pointing at that node, is shown with a copy button in its web console:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://<node-address>/cli/xmagic.py -o ~/.local/bin/xmagic && chmod +x ~/.local/bin/xmagic
```

`xmagic update` likewise syncs the installed CLI with the selected
node's bundled copy (byte for byte), never with a separate source.

```bash
python3 xmagic.py node add tokyo --url http://<node-address>:8080   # console and proxy share the public port
python3 xmagic.py login            # opens the browser for Passkey; the session is stored locally
python3 xmagic.py users add alice
python3 xmagic.py --node tokyo routes add --kind ip --pattern 1.1.1.1 --to intl
python3 xmagic.py passkey replace  # opens the browser: verify with the current passkey, register the new one; this CLI session is kept, all others are revoked
python3 xmagic.py sessions list    # all sign-in sessions on this node
python3 xmagic.py sessions revoke <id>
python3 xmagic.py upstreams edit b1 --port 8443      # same API as the web editor
python3 xmagic.py users rotate-uuid alice
python3 xmagic.py settings set --session-ttl-hours 24
python3 xmagic.py settings set --upstream-strategy random --ss-method chacha20-ietf-poly1305
python3 xmagic.py keys list        # SSH keys usable here: ~/.ssh, ~/.xmagic/keys, ssh-agent
python3 xmagic.py keys generate alice   # mint an ed25519 pair under ~/.xmagic/keys
python3 xmagic.py users add alice --ssh-key alice   # register one of those keys as her credential
python3 xmagic.py users add bob --ssh-key-generate  # mint + register in one step
python3 xmagic.py update           # update this CLI to the latest version from the repo
```

- The node registry lives in `~/.xmagic/config.json`. Target
  resolution order: **CLI flags > environment > config file**
  (`--node` / `--url` > `XMAGIC_NODE` / `XMAGIC_URL` > the config's
  current). Global flags are accepted before or after the subcommand.
- Login flow: the CLI starts a temporary loopback listener and sends
  the browser to the node's `/cli-auth` page for the Passkey ceremony;
  the page returns a one-time code, which the CLI exchanges for the
  real session token - the token never appears in any URL.
- Sessions are stored in `~/.xmagic/sessions/<node>.json` (0600) by
  default; `login --session-file <path>` stores to a chosen file and
  other commands select it with the same flag (or
  `XMAGIC_SESSION_FILE`) - one session per file, switch per node in
  scripts, suited to managing many nodes.
- SSH keys never need external tools, and a USER's private key is
  only ever generated on the client side: in the web page itself or
  in this CLI - never on the server, which only receives the public
  half (users.py cannot generate user keys at all). Node-side
  generation exists only for node-owned keys: for an SSH upstream
  the generated key is stored on the node as its managed key. On the
  console, a user with a registered key shows the ready-made
  `ssh -D 1080 -N -i xmagic-<user>.key -p <port> proxy@<node>` command
  (the sshd login name is always `proxy`; the key says which gateway
  user you are) - a plain SSH
  client is a working proxy client.
- `xmagic update` syncs with the selected node's bundled copy: the
  download is hash-compared and self-tested before it replaces the
  running file, and the previous version is kept as `xmagic.py.bak`
  (`--check` only reports, `--from URL` overrides the source).
- Exit codes: 0 success, 1 API error, 2 config/usage error,
  3 not signed in or session expired - scripts can re-run `login`
  based on them.

## Database

Business data (users, upstreams, routes, settings, admin credential,
sign-in sessions) lives in SQLite by default (`./data/users.db`) and
can also run on PostgreSQL or MySQL:

- **Several configs, switchable at any time**: each database is a set
  of named parameters (a file path for sqlite, a DSN for
  postgres / mysql). Exactly one is active; switching re-renders and
  applies immediately.
- **Schema auto-creation**: switching to (or testing) an empty
  database with no tables creates all business tables in the current
  shape - no migration scripts to run by hand.
- **Migration between any two configs**: copies every business table
  (including the admin credential and sign-in sessions). A non-empty
  target is refused by default; overwriting requires an explicit
  choice.
- **The configs themselves stay local**: database configs are
  bootstrap data and live in a local SQLite file on the node
  (`./data/local.db` by default, movable with `XMAGIC_LOCAL_DB`),
  never inside a managed database - so the node can always find all
  of its configs no matter which database is active.
- Identical in all three interfaces: the web console's "Database"
  section; the node CLI `users.py db-list | db-add | db-edit |
  db-remove | db-test | db-switch | db-migrate`; the remote CLI
  `xmagic.py db list | add | edit | remove | test | switch | migrate`.
- DSN passwords are masked in every list and output. The postgres /
  mysql drivers (psycopg / PyMySQL) are baked into the admin image;
  running users.py outside Docker needs `pip install "psycopg[binary]"
  pymysql` - SQLite alone needs nothing.

Note: sign-in sessions live in the business database too. A migration
copies them along; a bare switch to a database that does not hold your
session signs the web console and the remote CLI out - by design.

## WS multi-path

Xray fallback paths are **exact matches - no wildcards or regex**.
The equivalent: a list of paths, one fallback entry + one backend
inbound per path (all sharing the same user table), all live at once:

```bash
python3 users.py gen-paths 8         # mint random paths, e.g. /assets/x3kf9a
# Put them in Settings (web console "Settings" or
# users.py settings --vless-ws-paths ... - rendered and live at once);
# write VLESS_WS_PATHS / TROJAN_WS_PATHS in .env only to pin them at
# deploy time.
```

## Cascade: multiple upstreams, groups, selection strategy

```bash
python3 users.py upstream-add b1 --addr 1.2.3.4 --port 8080 --proto ss --password ...
python3 users.py upstream-add b2 --addr node2.example.com --port 8080 --proto vless-ws --uuid ...
python3 users.py upstream-add inet --addr proxy.corp:3128 --proto http --username u --password p
python3 users.py upstream-add b3 --addr node3.example.com --port 22 --proto ssh \
    --username proxy --key-file ./data/ssh_client_keys/b3_key
python3 users.py setgroup alice team-b    # alice egresses via the team-b pool; unset = default pool
```

- `--proto` is one of vless-ws / vless / trojan-ws / ss / http /
  socks / ssh. An ssh upstream renders as a local SOCKS port plus
  `data/ssh-tunnels.json` and `data/start-tunnels.sh`, held open by
  the compose `tunnels` sidecar (`--profile cascade`) running
  `ssh -N -D`.
- An ssh upstream's private key can be given three ways: `--key-file`
  with a path to a file already on the node; or by content - pasted
  into the console or picked as a local file there (remote CLI:
  `--key-upload <file>`; node CLI: `--key-content-file <file>`). The
  node stores the content in `data/ssh_client_keys/` (mode 0600),
  the upstream row records `/keys/<name>.key`, and removing the
  upstream deletes the stored file. A user's SSH public key can
  likewise be pasted or picked as a file in the console.
- Several upstreams in one group form a pool. The strategy comes from
  env `UPSTREAM_STRATEGY`: `roundRobin` (default) / `random` /
  `leastPing` / `leastLoad`, chosen per connection.
- With no upstreams at all, egress is direct (freedom).

## Destination routing (choose the upstream by target)

On top of per-user groups: route by destination domain/IP to a named
pool, direct, or block:

```bash
python3 users.py route-add --kind domain --pattern github.com --to intl
python3 users.py route-add --kind ip --pattern 1.1.1.1 --to intl
python3 users.py route-add --kind domain --pattern example.org --to block
python3 users.py route-add --kind full --pattern example.com --to intl --user carol
```

- `--kind`: `domain` (suffix match, includes subdomains) / `full`
  (exact domain) / `keyword` / `regexp` / `ip` (single IP or CIDR).
- `--to`: an upstream group name (into that pool), `direct`, or
  `block`.
- `--user` (optional): the rule applies to that user only; user rules
  outrank global ones.
- Decision order: user destination rules -> global destination rules
  -> per-user group rules -> fallback (default pool or direct). A rule
  pointing at a group with no enabled upstream is skipped at render
  time with a warning instead of breaking the whole config.

## Same-group interconnect

Users in the same group can reach each other's services through the
gateway, LAN-style. It is **on by default**; Settings (or
`settings --interconnect-off-groups`) lists the groups that opt out.

- Expose: a user holds a reverse forward to the gateway loopback,
  e.g. `ssh -R 127.0.0.1:20005:127.0.0.1:8080 -N -i <keyfile> -p <port> proxy@<node>`
  publishes their local port 8080. Each user owns a fixed slice of
  16 ports (20000-21599, shown in the console's user list); sshd
  enforces the slice per key (`permitlisten` in authorized_keys), so
  nobody can squat on another user's ports.
- Visit: any member of the group dials `127.0.0.1:<port>` through
  their proxy like any other destination. Routing sends a member's
  slice only to members of the group; every other loopback
  destination is blocked at the gateway, so the node's own loopback
  services stay unreachable.
- Scope: TCP only, and only services a user explicitly forwards -
  this is gateway-mediated reachability, not a virtual LAN (no
  virtual IPs, no UDP, no discovery).

## Images and CI

GitHub Actions builds the images and pushes them to GHCR
(amd64 + arm64):

| Image | Contents |
| --- | --- |
| `ghcr.io/xnetsc/xmagic-xray` | Upstream Xray core, re-tagged at the version pinned in `versions.env` (contents unchanged) |
| `ghcr.io/xnetsc/xmagic-dispatcher` | sniff.py first-byte dispatcher |
| `ghcr.io/xnetsc/xmagic-sshd` | SSH entry (key-only) |
| `ghcr.io/xnetsc/xmagic-admin` | Admin console + users.py engine |
| `ghcr.io/xnetsc/xmagic-single` | The single-container form (all processes in one image, see "Single-container form") |

- The `build` workflow runs the `tests/` suites first (console
  protocol, CLI parity, remote CLI, dispatcher routing, multi-dialect
  database tests); images are built and pushed only when they pass.
  After the build, an `e2e` job boots the built images for real - in
  both the compose and single-container forms - and runs the full
  functional checks (add user, apply, fetch through every protocol,
  SSH login).
- The `upstream-check` workflow checks XTLS/Xray-core releases daily;
  on a new release it bumps the pin in `versions.env`, commits, and
  triggers `build` - watchtower on the deployment then pulls the new
  images, so the chain is unattended.
- Upstream base images (python:3.12-alpine, alpine) are not pinned;
  every build takes their latest.

## Deployment

Platform reality, stated plainly: **do not deploy on Railway** - its
AUP explicitly prohibits operating proxies / anonymization services,
its official answer to self-use requests of this kind is no, and it
runs automated detection; do not put other projects in the same
workspace at risk. This project offers no Railway deploy entry.
**Vercel cannot run it**: it has a functions-only runtime - no
long-lived container and no raw-TCP ingress - so there is no deploy
button for it either. **Heroku can run a degraded single-container
form** (see "One-click deploy"): its router only lets HTTP(S) in, so
the raw-TCP protocols are unavailable there. For the full gateway use
a VPS or Oracle Cloud's free tier with compose.

Preferred: Oracle Cloud Always Free (current allowance: ARM 2 OCPU /
12 GB; sign-up requires a real card in your own name, and the home
region cannot be changed later). Any VPS that permits a self-use
proxy works too.

```bash
git clone https://github.com/xnetsc/xmagic && cd xmagic
cp .env.example .env                 # set at least XRAY_PORT and the WS paths
docker compose up -d                 # on first boot the console renders an empty config to start from
# Open http://<node-address>:8080 - register the admin Passkey, then add users
# (console and proxy share this one port; every change re-renders and restarts)
# In the cloud firewall, open only XRAY_PORT.
```

Self-update: watchtower checks daily and auto-updates only the
labeled xray and dispatcher images; sshd / admin update manually via
`docker compose pull` (the management plane does not restart itself).

### Single-container form (where docker compose is unavailable)

`Dockerfile.single` packs every process into one image: the
entrypoint starts admin / xray / sshd / dispatcher / tunnels, there
is still only one exposed port (XRAY_PORT), and all state lives in
the single `/data` volume. There is no process supervision: **if any
critical process exits on its own, the entrypoint takes the rest
down with it and the container exits with that process's status**,
to be revived as a whole by the runtime's restart policy - so it
must run with a restart policy. Config changes (apply) work
differently: apply compares the rendered artifacts before and
after, and asks the entrypoint to relaunch only the affected
processes in place (user / upstream / route changes restart xray
only, SSH public key changes sshd only, ssh upstream changes the
tunnels process), leaving the rest uninterrupted. If a relaunched
process dies again right away (the restart failed), the whole
container still goes down and the runtime revives it.

```bash
docker build -f Dockerfile.single -t xmagic-single .
docker run -d --name xmagic --restart unless-stopped \
  -p 8080:8080 -v xmagic-data:/data xmagic-single
# Open http://<node-address>:8080 - register the admin Passkey, then add users
```

The compose form remains the recommended deployment (independent
update cadences and restart boundaries per container); the single
image is a compatibility form for environments that can only run one
image / a bare `docker run`. Configuration is the same as compose
(see `.env.example`), passed with `docker run -e`.

Platform adaptation (Heroku-style environments): when `PORT` is
present in the environment it becomes the public port (overriding
`XRAY_PORT`); when `DATABASE_URL` is present, the entrypoint
registers it as a postgres config named `heroku` and activates it -
identity data then never touches the platform's ephemeral filesystem
and dyno restarts lose no users.

### One-click deploy (Heroku, single-container form)

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/xnetsc/xmagic)

The button uses the repo's `app.json` + `heroku.yml` to launch the
single-container image and provisions a Heroku Postgres (the business
database - see the platform adaptation above). After the deploy
finishes, set two environment variables to your app's domain and
restart the dyno, so the console's Passkey is issued for that domain:
`XMAGIC_ADMIN_RPID=<app domain>` and
`XMAGIC_ADMIN_ORIGINS=https://<app domain>`.

The degraded scope, stated plainly: Heroku's router passes only
HTTP(S), so what works is **the console, the HTTP proxy, and
VLESS-WS / Trojan-WS**; SOCKS5, SSH, bare Shadowsocks and bare
VLESS-TCP cannot get in. Heroku also has no free tier anymore (dyno
and Postgres are billed monthly) and its router times out idle
connections, so idle long-lived connections get cut - this form
suits light self-use; for the full gateway use a VPS + compose.

## Notes

- Xray 26.x marks the WebSocket transport, Trojan and Shadowsocks as
  deprecated ("might be removed"): they work in the current version;
  a future major version removing them would require migrating (the
  VLESS side can move to XHTTP/Reality).
- **Xray 26 plaintext policy**: VLESS / Trojan have no transport
  encryption of their own, and Xray refuses to dial them in plaintext
  to any public address (IP or domain - rejected while building the
  config); dialing private/loopback addresses, or going through SSH
  tunnels / overlays, is not restricted. For node-to-node links over
  the public internet use ss or ssh upstreams, or add `--tls` to
  vless / vless-ws / trojan-ws upstreams (SNI is the upstream address;
  the upstream must terminate TLS in front). Symmetrically, this
  node's WS inbounds are positioned for intranet / in-tunnel use; on
  the public internet prefer SS / SOCKS / HTTP / SSH.
- `data/users.db` holds recoverable protocol secrets (Xray needs
  them), mode 600; when backing up the machine, treat it and
  `data/ssh_client_keys/` as key material - do not share them.
  Session tokens are stored hashed only and are not in this category.
- The `proxy` account in the sshd container is unlocked but permits
  public-key login only (`passwd -u` in the Dockerfile).

## File inventory

- `admin.py` - web admin console (Passkey, session management, config API; stdlib only, includes the WebAuthn verification implementation)
- `users.py` - identity engine + node CLI (users / upstreams / routes / databases / render / apply / settings / sessions)
- `xmagic.py` - remote CLI (node registry, browser Passkey login, session files, multi-node batch management)
- `sniff.py` - first-byte protocol dispatcher (stdlib only)
- `docker-compose.yml` - xray / dispatcher / sshd / admin / tunnels (optional) / watchtower
- `Dockerfile.xray`, `Dockerfile.dispatcher`, `Dockerfile.sshd`, `Dockerfile.admin`, `sshd_config`
- `Dockerfile.single`, `single-entrypoint.sh`, `single-tunnels.sh` - the single-container form (for environments without compose; any critical process exiting on its own takes the whole container down)
- `app.json`, `heroku.yml` - Heroku one-click deploy descriptors (single-container form + Postgres business database)
- `versions.env` - upstream pin (Xray version, maintained automatically by the upstream-check workflow)
- `.github/workflows/` - `build.yml` (tests + build + push to GHCR + e2e), `upstream-check.yml` (automatic upstream version tracking)
- `tests/` - test_admin.py (console protocol and sessions), test_cli.py (two-interface parity), test_client.py (remote CLI end to end), test_dispatch.py (dispatcher routing), test_databases.py (multi-database: registry / switch / migrate / dialects), ci_e2e.sh (full functional test of the built images in CI, compose and single-container forms)
- `.env.example` - configuration template
