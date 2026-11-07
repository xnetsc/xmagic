#!/bin/sh
# Single-container entrypoint: prepare the data directory, start every
# gateway process, and stay as PID 1. There is deliberately no process
# supervisor: if ANY critical process exits, the rest are killed and
# this script exits with that process's status, so the whole container
# goes down as one unit (the runtime's restart policy brings it back).
# Each process records its pid in $XMAGIC_PID_DIR/<name>.pid - that is
# how apply restarts the gateway in this form: it signals xray / sshd /
# tunnels, their exit is fatal here, and the container restarts whole
# on the freshly rendered config.
set -e
DATA_DIR=$(dirname "${PROXY_DB:-/data/users.db}")
PID_DIR="${XMAGIC_PID_DIR:-/run/xmagic}"
mkdir -p "$DATA_DIR/ssh_host_keys" "$DATA_DIR/ssh_client_keys" \
         "$PID_DIR" /etc/ssh/keys /run/sshd
chmod 755 /run/sshd 2>/dev/null || true
rm -f "$PID_DIR"/*.pid

# sshd host keys persist in the data volume (sshd_config points at
# /etc/ssh/keys - link the persistent copies in).
for t in rsa ecdsa ed25519; do
  key="$DATA_DIR/ssh_host_keys/ssh_host_${t}_key"
  [ -f "$key" ] || ssh-keygen -t "$t" -f "$key" -N ''
  ln -sf "$key" "/etc/ssh/keys/ssh_host_${t}_key"
  ln -sf "$key.pub" "/etc/ssh/keys/ssh_host_${t}_key.pub"
done

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
python3 /app/admin.py &
echo $! > "$PID_DIR/admin.pid"
/usr/local/bin/xray run -c "$DATA_DIR/config.json" &
echo $! > "$PID_DIR/xray.pid"
/usr/sbin/sshd -D -e -p "${SSH_BE_PORT:-12222}" \
  -o "AuthorizedKeysFile=$DATA_DIR/authorized_keys" &
echo $! > "$PID_DIR/sshd.pid"
python3 /app/sniff.py &
echo $! > "$PID_DIR/dispatcher.pid"
sh /app/single-tunnels.sh &
echo $! > "$PID_DIR/tunnels.pid"

PIDS=$(cat "$PID_DIR"/*.pid)

shutdown() {
  kill $PIDS 2>/dev/null || true
  exit "${1:-0}"
}
trap 'shutdown 0' TERM INT

# Watch: the first process to exit takes the container with it.
# (`wait` returns the child's status as its own exit code, so it must
# be guarded with || - under `set -e` an unguarded non-zero wait would
# kill this script silently before the teardown runs.)
while :; do
  for pid in $PIDS; do
    if ! kill -0 "$pid" 2>/dev/null; then
      code=0
      wait "$pid" 2>/dev/null || code=$?
      echo "xmagic: process $pid exited (status $code); shutting down" >&2
      kill $PIDS 2>/dev/null || true
      sleep 1
      kill -9 $PIDS 2>/dev/null || true
      exit "$code"
    fi
  done
  sleep 1
done
