#!/bin/sh
# Single-container entrypoint: prepare the data directory, start every
# gateway process, and stay as PID 1. There is deliberately no process
# supervisor: if a critical process exits on its own, the rest are
# killed and this script exits with that process's status, so the
# whole container goes down as one unit (the runtime's restart policy
# brings it back). The one exception is an apply-requested restart:
# apply writes a restart-<name>.req marker holding the pid and then
# signals exactly the processes whose config changed; the watch loop
# below relaunches a marked process in place. If the relaunched
# process dies again (no marker), the restart counts as failed and
# the container goes down as a whole, as before.
set -e
# Platforms that assign the public port (Heroku-style) set PORT; when
# present it wins - the gateway must listen on exactly that port.
if [ -n "${PORT:-}" ]; then
  XRAY_PORT="$PORT"
  export XRAY_PORT
fi
# Boot diagnostics: one timestamped prefix for every line this script
# logs, so a failing deployment's log shows which process started,
# which is still alive seconds later, and which one died (or whether
# the script was signalled instead). Children's own output stays on
# the same stream, unprefixed.
BOOT_TS=$(date +%s)
xlog() { echo "xmagic: $(date '+%H:%M:%S') $*" >&2; }
DATA_DIR=$(dirname "${PROXY_DB:-/data/users.db}")
PID_DIR="${XMAGIC_PID_DIR:-/tmp/xmagic-run}"
mkdir -p "$DATA_DIR/ssh_host_keys" "$DATA_DIR/ssh_client_keys" \
         "$PID_DIR"
# Runtime state lives under /tmp, not in system directories: a
# serverless runtime may not let the image write to /run or /etc at
# all, while /tmp is writable in every runtime. (sshd's privilege-
# separation directory is the one exception - it is compiled in and
# the image package provides it; create the common path best-effort.)
mkdir -p /run/sshd 2>/dev/null || true
chmod 755 /run/sshd 2>/dev/null || true
rm -f "$PID_DIR"/*.pid "$PID_DIR"/*.req
# Optional processes are chosen by the environment at image start.
# SSH support (the sshd entry and the ssh-tunnels holder) is off
# unless XMAGIC_ENABLE_SSH=1: with it off those processes are never
# started (no host keys are generated either), and the engine
# refuses every SSH-shaped operation, so a feature that is not
# running cannot be configured either.
SSH_ON=0
case "$(printf '%s' "${XMAGIC_ENABLE_SSH:-}" | tr 'A-Z' 'a-z')" in
  1|true|yes|on) SSH_ON=1 ;;
esac
# Uploaded ssh-upstream private keys live in the data dir; the tunnels'
# ssh commands reference them as /keys/<file>, the same path the
# compose form's /keys mount provides. Best effort: on a runtime whose
# root filesystem is not writable (serverless) the link cannot be
# created - that must not stop the gateway, and users.py's tunnel
# render then falls back to the keys' real data-dir path.
ln -sfn "$DATA_DIR/ssh_client_keys" /keys 2>/dev/null || true

# sshd host keys persist in the data volume and are generated here on
# first boot. sshd never reads them from there directly: every sshd
# (re)start stages local copies under /tmp and names them with -h
# (see start_sshd) - a data filesystem that does not preserve Unix
# permissions (an object-storage mount presents every file as 0777)
# would otherwise make sshd refuse the keys as too open and exit.
if [ "$SSH_ON" = 1 ]; then
  for t in rsa ecdsa ed25519; do
    key="$DATA_DIR/ssh_host_keys/ssh_host_${t}_key"
    [ -f "$key" ] || ssh-keygen -t "$t" -f "$key" -N ''
  done
fi

# Platforms that hand the app a database URL (Heroku-style DATABASE_URL)
# get a persistent business database: register it as the "heroku" config
# and activate it, so identity survives the platform's ephemeral
# filesystem and restarts. Best effort - without it the node simply
# stays on the default local SQLite.
if [ -n "${DATABASE_URL:-}" ]; then
  python3 - <<'EOF' || true
import os
import sys

sys.path.insert(0, "/app")
import users

url = os.environ["DATABASE_URL"]
if url.startswith("postgres://"):
    url = "postgresql://" + url[len("postgres://"):]
if "sslmode=" not in url:
    url += ("&" if "?" in url else "?") + "sslmode=require"
try:
    names = [c["name"] for c in users.list_db_configs()]
    if "heroku" not in names:
        users.add_db_config("heroku", "postgres", url,
                            "from DATABASE_URL")
    elif users.resolve_db_config("heroku")["target"] != url:
        users.edit_db_config("heroku", target=url)
    if users.active_db_config()["name"] != "heroku":
        users.switch_db_config("heroku")
except Exception as exc:  # noqa: BLE001
    # Type only: driver messages can embed the DSN (and its password).
    print(f"DATABASE_URL setup failed ({type(exc).__name__}); "
          "staying on the default database", file=sys.stderr)
EOF
fi

# First boot: render an initial (empty but valid) gateway config so
# xray has a file to start with. Best effort only - the admin console
# also renders on its own first boot and after every change.
if [ -f "$DATA_DIR/config.json" ]; then
  xlog "boot: config.json already present in $DATA_DIR"
else
  xlog "boot: no config.json in $DATA_DIR; rendering initial config"
fi
if [ ! -f "$DATA_DIR/config.json" ]; then
  python3 - <<'EOF' || true
import os
import sys

sys.path.insert(0, "/app")
import users

users.render_all(os.path.dirname(os.path.abspath(users.DB_PATH)))
EOF
fi

cd /app
chmod 0755 "$PID_DIR" # pidfiles/markers + the staged client keys live here

# Each gateway process has a start function so the watch loop can
# relaunch it in place for an apply-requested restart.
start_admin() {
  xlog "starting admin"
  python3 /app/admin.py &
  echo $! > "$PID_DIR/admin.pid"
}
start_xray() {
  xlog "starting xray"
  /usr/local/bin/xray run -c "$DATA_DIR/config.json" &
  echo $! > "$PID_DIR/xray.pid"
}
start_sshd() {
  xlog "starting sshd"
  # authorized_keys is NOT handed to sshd as a file at all. sshd's
  # StrictModes walks every directory above the file it is pointed
  # at, and both candidate homes fail that walk somewhere: the data
  # dir may be a bind mount owned by an unprivileged host user or a
  # filesystem without Unix modes ("bad ownership or modes for
  # directory /data"), and /tmp is world-writable (1777), which the
  # walk rejects just the same. So sshd runs a root-owned command
  # that cats the canonical file from the data dir - only the
  # command's own path (/bin/cat, system-owned with a clean parent
  # chain) is permission-checked, the data file's modes are not.
  # The command runs per login attempt, so key changes take effect
  # with no sshd restart at all.
  # Host keys are staged as copies, for the mirror-image reason:
  # sshd refuses a private host key that others can access, and the
  # persistent copies in $DATA_DIR may sit on a filesystem that does
  # not preserve Unix permissions (an object-storage mount presents
  # every file as 0777 - linking sshd at them made it ignore every
  # host key and exit). Stage root-owned 0600 copies under /tmp -
  # writable in every runtime, including serverless ones whose system
  # directories are not - and name them on the command line with -h
  # instead of leaving sshd to a default location. The staging
  # runs at every sshd (re)start: image start and every
  # apply-requested relaunch alike.
  HOSTKEY_DIR=/tmp/xmagic-hostkeys
  mkdir -p "$HOSTKEY_DIR"
  chmod 700 "$HOSTKEY_DIR"
  for t in rsa ecdsa ed25519; do
    cp "$DATA_DIR/ssh_host_keys/ssh_host_${t}_key" \
       "$HOSTKEY_DIR/ssh_host_${t}_key"
    chown root:root "$HOSTKEY_DIR/ssh_host_${t}_key"
    chmod 0600 "$HOSTKEY_DIR/ssh_host_${t}_key"
    if [ -f "$DATA_DIR/ssh_host_keys/ssh_host_${t}_key.pub" ]; then
      cp "$DATA_DIR/ssh_host_keys/ssh_host_${t}_key.pub" \
         "$HOSTKEY_DIR/ssh_host_${t}_key.pub"
      chmod 0644 "$HOSTKEY_DIR/ssh_host_${t}_key.pub"
    fi
  done
  /usr/sbin/sshd -D -e -p "${SSH_BE_PORT:-12222}" \
    -h "$HOSTKEY_DIR/ssh_host_rsa_key" \
    -h "$HOSTKEY_DIR/ssh_host_ecdsa_key" \
    -h "$HOSTKEY_DIR/ssh_host_ed25519_key" \
    -o "AuthorizedKeysFile=none" \
    -o "AuthorizedKeysCommand=/bin/cat $DATA_DIR/authorized_keys" \
    -o "AuthorizedKeysCommandUser=root" &
  echo $! > "$PID_DIR/sshd.pid"
}
start_dispatcher() {
  xlog "starting dispatcher"
  XMAGIC_XRAY_CONFIG="$DATA_DIR/config.json" python3 /app/sniff.py &
  echo $! > "$PID_DIR/dispatcher.pid"
}
start_tunnels() {
  xlog "starting tunnels"
  # Stage the ssh client keys next to the pidfiles (local /tmp):
  # the canonical copies live in the data dir, but the ssh client
  # refuses a private key whose file looks world-readable, and a
  # data filesystem that does not preserve Unix permissions (an
  # object-storage mount presents every file as 0777) makes every
  # stored key look that way. users.py renders the tunnels with -i
  # pointing at these staged copies. Staging runs here - at every
  # tunnels (re)start, boot and apply relaunch alike - so a config
  # update (including a key rotation, which apply counts as a
  # tunnels change) always re-stages before the new tunnels read
  # the keys. Staged copies whose source vanished are dropped.
  mkdir -p "$PID_DIR/client_keys"
  chmod 700 "$PID_DIR/client_keys" 2>/dev/null || true
  for f in "$DATA_DIR"/ssh_client_keys/*; do
    [ -f "$f" ] || continue
    cp "$f" "$PID_DIR/client_keys/${f##*/}"
    chmod 600 "$PID_DIR/client_keys/${f##*/}"
  done
  for f in "$PID_DIR"/client_keys/*; do
    [ -f "$f" ] || continue
    [ -f "$DATA_DIR/ssh_client_keys/${f##*/}" ] || rm -f "$f"
  done
  sh /app/single-tunnels.sh &
  echo $! > "$PID_DIR/tunnels.pid"
}

# One-shot boot probe (not a supervised process): a few seconds
# after start, and once more later, record which processes are
# alive and whether the admin backend actually accepts connections.
# This is what tells "admin died" apart from "admin is alive but
# never listened" in a deployment log.
probe_state() {
  _aport="${ADMIN_BE_PORT:-${XMAGIC_ADMIN_PORT:-18090}}"
  for _n in $NAMES; do
    _p=$(cat "$PID_DIR/$_n.pid" 2>/dev/null || echo "")
    if [ -n "$_p" ] && kill -0 "$_p" 2>/dev/null; then
      xlog "probe: $_n (pid $_p) alive"
    else
      xlog "probe: $_n (pid ${_p:-none}) NOT RUNNING"
    fi
  done
  if python3 -c 'import socket, sys; s = socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$_aport" 2>/dev/null; then
    xlog "probe: admin port $_aport LISTENING"
  else
    xlog "probe: admin port $_aport NOT LISTENING"
  fi
}

if [ "$SSH_ON" = 1 ]; then
  NAMES="admin xray sshd dispatcher tunnels"
else
  NAMES="admin xray dispatcher"
fi
xlog "boot: data_dir=$DATA_DIR pid_dir=$PID_DIR ssh_on=$SSH_ON xray_port=${XRAY_PORT:-8080} admin_port=${XMAGIC_ADMIN_PORT:-8090}"
_mnt=$(grep ' /data ' /proc/mounts 2>/dev/null || true)
[ -n "$_mnt" ] && xlog "boot: /data mount: $_mnt"
if touch "$DATA_DIR/.xmagic-probe" 2>/dev/null; then
  rm -f "$DATA_DIR/.xmagic-probe"
  xlog "boot: data dir is writable"
else
  xlog "boot: data dir is NOT writable"
fi
ls -la "$DATA_DIR" 2>/dev/null | while IFS= read -r _line; do xlog "boot: data: $_line"; done
start_admin
start_xray
# Hold public traffic until the admin backend listens. The
# dispatcher accepting a connection is what a platform in front
# treats as "ready"; if a browser request lands before the admin
# is up it can only be dropped or 503'd, and on invoke-driven
# runtimes the dropped form is reported as the process having
# died mid-request, which recycles the instance and restarts the
# admin's startup from zero. Bounded: if the admin has not
# listened within 50s the dispatcher starts anyway (its own log
# and the boot probe keep the failure visible).
_admin_port="${ADMIN_BE_PORT:-${XMAGIC_ADMIN_PORT:-18090}}"
_wait_admin=0
while [ "$_wait_admin" -lt 50 ]; do
  if python3 -c 'import socket, sys; s = socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)' "$_admin_port" 2>/dev/null; then
    xlog "boot: admin port $_admin_port listening after ${_wait_admin}s"
    break
  fi
  sleep 2
  _wait_admin=$((_wait_admin + 2))
  case $_wait_admin in
    10|20|30|40) xlog "boot: still waiting for admin port (${_wait_admin}s)" ;;
  esac
done
if [ "$_wait_admin" -ge 50 ]; then
  xlog "boot: admin port NOT listening after 50s; starting dispatcher anyway"
fi
[ "$SSH_ON" = 1 ] && start_sshd
start_dispatcher
[ "$SSH_ON" = 1 ] && start_tunnels
( sleep 4; probe_state; sleep 11; probe_state ) &

kill_all() {
  sig="${1:-TERM}"
  for n in $NAMES; do
    [ -f "$PID_DIR/$n.pid" ] && kill "-$sig" "$(cat "$PID_DIR/$n.pid")" 2>/dev/null || true
  done
}

shutdown() {
  xlog "shutdown requested (signal received); stopping all processes"
  kill_all TERM
  exit "${1:-0}"
}
trap 'shutdown 0' TERM INT

# Watch: a process whose exit carries a matching restart request
# (written by apply, holding its pid) is relaunched in place - that is
# how a config change restarts only the processes it affects. Any
# other exit - including a relaunched process dying again, i.e. the
# requested restart failed - takes the whole container down.
# (`wait` returns the child's status as its own exit code, so it must
# be guarded with || - under `set -e` an unguarded non-zero wait would
# kill this script silently before the teardown runs.)
while :; do
  for name in $NAMES; do
    pid=$(cat "$PID_DIR/$name.pid" 2>/dev/null) || continue
    [ -n "$pid" ] || continue
    if ! kill -0 "$pid" 2>/dev/null; then
      req="$PID_DIR/restart-$name.req"
      if [ -f "$req" ] && [ "$(cat "$req" 2>/dev/null)" = "$pid" ]; then
        rm -f "$req"
        xlog "restarting $name (apply requested)"
        start_$name
        continue
      fi
      code=0
      wait "$pid" 2>/dev/null || code=$?
      xlog "process $name ($pid) exited (status $code) after $(( $(date +%s) - BOOT_TS ))s; shutting down"
      kill_all TERM
      sleep 1
      kill_all KILL
      exit "$code"
    fi
  done
  sleep 1
done
