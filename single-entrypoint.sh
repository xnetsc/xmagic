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
PID_DIR="${XMAGIC_PID_DIR:-/run/xmagic}"
mkdir -p "$DATA_DIR/ssh_host_keys" "$DATA_DIR/ssh_client_keys" \
         "$PID_DIR" /etc/ssh/keys /run/sshd
chmod 755 /run/sshd 2>/dev/null || true
rm -f "$PID_DIR"/*.pid "$PID_DIR"/*.req
# Uploaded ssh-upstream private keys live in the data dir; the tunnels'
# ssh commands reference them as /keys/<file>, the same path the
# compose form's /keys mount provides.
ln -sfn "$DATA_DIR/ssh_client_keys" /keys

# sshd host keys persist in the data volume (sshd_config points at
# /etc/ssh/keys - link the persistent copies in).
for t in rsa ecdsa ed25519; do
  key="$DATA_DIR/ssh_host_keys/ssh_host_${t}_key"
  [ -f "$key" ] || ssh-keygen -t "$t" -f "$key" -N ''
  ln -sf "$key" "/etc/ssh/keys/ssh_host_${t}_key"
  ln -sf "$key.pub" "/etc/ssh/keys/ssh_host_${t}_key.pub"
done

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
chmod 0755 "$PID_DIR" # sshd traverses this dir as the login user

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
  # sshd's StrictModes requires every directory above AuthorizedKeysFile
  # to be owned by root or the login user. $DATA_DIR may be a bind mount
  # owned by an unprivileged host user, which sshd refuses outright
  # ("bad ownership or modes for directory /data"), so sshd reads a
  # root-owned copy staged in the pid dir. The copy is re-staged at
  # every sshd (re)start, so key changes take effect with an
  # sshd-only restart.
  SSHD_KEYS="$PID_DIR/authorized_keys"
  if [ -f "$DATA_DIR/authorized_keys" ]; then
    cp "$DATA_DIR/authorized_keys" "$SSHD_KEYS"
    chown root:root "$SSHD_KEYS"; chmod 0644 "$SSHD_KEYS"
  else
    rm -f "$SSHD_KEYS"
  fi
  /usr/sbin/sshd -D -e -p "${SSH_BE_PORT:-12222}" \
    -o "AuthorizedKeysFile=$SSHD_KEYS" &
  echo $! > "$PID_DIR/sshd.pid"
}
start_dispatcher() {
  python3 /app/sniff.py &
  echo $! > "$PID_DIR/dispatcher.pid"
}
start_tunnels() {
  sh /app/single-tunnels.sh &
  echo $! > "$PID_DIR/tunnels.pid"
}

NAMES="admin xray sshd dispatcher tunnels"
start_admin
start_xray
start_sshd
start_dispatcher
start_tunnels

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
