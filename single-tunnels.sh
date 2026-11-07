#!/bin/sh
# Holds the `ssh -N -D` tunnels for `ssh` upstreams. users.py renders
# start-tunnels.sh next to the database on every apply; when it does
# not exist there are no ssh upstreams, so idle - an apply restarts
# this program (via supervisor) and the new script is picked up then.
DATA_DIR=$(dirname "${PROXY_DB:-/data/users.db}")
if [ -f "$DATA_DIR/start-tunnels.sh" ]; then
  exec sh "$DATA_DIR/start-tunnels.sh"
fi
exec sleep 2147483647
