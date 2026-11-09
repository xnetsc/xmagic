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
  python3 /app/admin.py &
  echo $! > "$PID_DIR/admin.pid"
}
start_xray() {
  /usr/local/bin/xray run -c "$DATA_DIR/config.json" &
  echo $! > "$PID_DIR/xray.pid"
}
start_sshd() {
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
  python3 /app/sniff.py &
  echo $! > "$PID_DIR/dispatcher.pid"
}
start_tunnels() {
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

if [ "$SSH_ON" = 1 ]; then
  NAMES="admin xray sshd dispatcher tunnels"
else
  NAMES="admin xray dispatcher"
fi
start_admin
start_xray
[ "$SSH_ON" = 1 ] && start_sshd
start_dispatcher
[ "$SSH_ON" = 1 ] && start_tunnels

kill_all() {
  sig="${1:-TERM}"
  for n in $NAMES; do
    [ -f "$PID_DIR/$n.pid" ] && kill "-$sig" "$(cat "$PID_DIR/$n.pid")" 2>/dev/null || true
  done
}

shutdown() {
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
        echo "xmagic: restarting $name (apply requested)" >&2
        start_$name
        continue
      fi
      code=0
      wait "$pid" 2>/dev/null || code=$?
      echo "xmagic: process $name ($pid) exited (status $code); shutting down" >&2
      kill_all TERM
      sleep 1
      kill_all KILL
      exit "$code"
    fi
  done
  sleep 1
done
