#!/usr/bin/env bash
# End-to-end test of the BUILT container images, in both deployment
# forms. CI runs this after the build job pushes the images (see the
# e2e job in build.yml); it is also runnable on any Docker host:
#
#   E2E_FORM=compose bash tests/ci_e2e.sh
#   E2E_FORM=single  bash tests/ci_e2e.sh
#
# Knobs: E2E_IMAGE_PREFIX (default ghcr.io/xnetsc), E2E_IMAGE_TAG
# (default latest), E2E_KEEP=1 keeps the temp dir and containers for
# debugging. The checks, identical for both forms: admin console on
# the one public port, add-user + apply taking effect, HTTP CONNECT,
# SOCKS5, VLESS-WS, bare Shadowsocks and VLESS-TCP through a client
# Xray, SSH key login + `ssh -D`, and a second user added afterwards.
set -u

# No ambient proxy may leak into the checks: the proxied fetches pass
# their proxy explicitly (curl -x / --socks5-hostname), and an
# inherited http_proxy would hijack the direct ones. Do NOT reach for
# --noproxy '*' instead: it suppresses explicitly requested proxies
# too, which silently turns every proxied fetch into a direct one.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

FORM="${E2E_FORM:?set E2E_FORM=compose or E2E_FORM=single}"
PREFIX="${E2E_IMAGE_PREFIX:-ghcr.io/xnetsc}"
TAG="${E2E_IMAGE_TAG:-latest}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/xmagic-e2e.XXXXXX)"
STUB_PORT=19099
CLI_PORT=19101
SSH_D_PORT=19110
BODY="XMAGIC-E2E-TARGET"
case "$FORM" in
  compose) PUB=19080; TARGET="http://127.0.0.1:$STUB_PORT/" ;;
  single)  PUB=19081; TARGET="http://host.docker.internal:$STUB_PORT/" ;;
  *) echo "unknown E2E_FORM: $FORM" >&2; exit 2 ;;
esac

PASS=0; FAIL=0
check() { # check <name> <ok=0/1>
  if [ "$2" = 0 ]; then PASS=$((PASS+1)); echo "PASS $1";
  else FAIL=$((FAIL+1)); echo "FAIL $1"; fi
}
dump_logs() {
  echo "----- gateway logs (tail) -----"
  if [ "$FORM" = compose ]; then
    (cd "$WORK/compose" && docker compose logs --tail 40) 2>&1 | tail -80
  else
    docker logs --tail 60 xmagic-e2e-single 2>&1 | tail -80
  fi
  [ -f "$WORK/client.log" ] && tail -20 "$WORK/client.log"
}
cleanup() {
  local rc=$?
  [ -n "${STUB_PID:-}" ] && kill "$STUB_PID" 2>/dev/null
  [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" 2>/dev/null
  [ -n "${SSH_PID:-}" ] && kill "$SSH_PID" 2>/dev/null
  if [ "$FORM" = compose ]; then
    (cd "$WORK/compose" 2>/dev/null && docker compose down -v) >/dev/null 2>&1
  else
    docker rm -f xmagic-e2e-single >/dev/null 2>&1
  fi
  # The single-form container runs as root and leaves root-owned files
  # (SSH host keys, the database) in the bind-mounted work dir, which
  # the invoking user cannot unlink. Fall back to sudo, then to a
  # root container wiping the contents. Cleanup must never change the
  # run's result, hence the saved rc and the || true chain.
  if [ "${E2E_KEEP:-}" != 1 ]; then
    rm -rf "$WORK" 2>/dev/null \
      || sudo -n rm -rf "$WORK" 2>/dev/null \
      || { docker run --rm -v "$WORK:/w" alpine \
             sh -c 'rm -rf /w/* /w/.[!.]*' >/dev/null 2>&1; \
           rm -rf "$WORK" 2>/dev/null; } \
      || true
  fi
  exit "$rc"
}
trap cleanup EXIT

# ------------------------------------------------------------ helpers

fetch_admin() { # 0 once the console answers 200 on the public port
  curl --noproxy '*' -sf -o /dev/null "http://127.0.0.1:$PUB/"
}
wait_admin() { # wait_admin <seconds>
  local i=0
  while [ $i -lt "$1" ]; do fetch_admin && return 0; sleep 2; i=$((i+2)); done
  return 1
}
fetch_retry() { # fetch_retry <curl-args...> : body on stdout, retries
  local i out
  for i in 1 2 3 4 5 6 7 8; do
    out=$(curl -s --max-time 10 "$@" 2>/dev/null) \
      && [ "$out" = "$BODY" ] && { printf '%s' "$out"; return 0; }
    sleep 2
  done
  printf '%s' "$out"; return 1
}
jget() { python3 -c "import json,sys; print(json.load(open('$1'))['$2'])"; }

gw() { # gw <users.py args...> : run the engine CLI inside the stack
  if [ "$FORM" = compose ]; then
    (cd "$WORK/compose" && docker compose exec -T admin python3 /app/users.py "$@")
  else
    docker exec xmagic-e2e-single python3 /app/users.py "$@"
  fi
}
add_user() { # add_user <name> [extra users.py args...]
  local name="$1"; shift
  gw --json add "$name" "$@" > "$WORK/$name.json" 2>"$WORK/$name.err"
}
apply_and_wait() { # apply, then wait for the console to answer again
  gw apply > "$WORK/apply.log" 2>&1
  wait_admin 120
}

client_config() { # client_config <proto> <alice.json> -> config path
  python3 - "$1" "$2" "$PUB" "$CLI_PORT" "$WORK" <<'EOF'
import json, sys
proto, creds_path = sys.argv[1], sys.argv[2]
pub, cli, work = int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
creds = json.load(open(creds_path))
if proto == "ss":
    out = {"protocol": "shadowsocks",
           "settings": {"servers": [{"address": "127.0.0.1", "port": pub,
                       "method": creds["ss_method"],
                       "password": creds["ss_password"]}]}}
else:
    out = {"protocol": "vless",
           "settings": {"vnext": [{"address": "127.0.0.1", "port": pub,
                       "users": [{"id": creds["vless_uuid"],
                                  "encryption": "none"}]}]}}
    if proto == "vless-ws":
        out["streamSettings"] = {"network": "ws",
                                 "wsSettings": {"path": "/vless-ws"}}
cfg = {"log": {"loglevel": "warning"},
       "inbounds": [{"listen": "127.0.0.1", "port": cli,
                     "protocol": "socks",
                     "settings": {"auth": "noauth", "udp": False}}],
       "outbounds": [out]}
path = f"{work}/client-{proto}.json"
json.dump(cfg, open(path, "w"), indent=1)
print(path)
EOF
}
check_via_client() { # check_via_client <proto>
  local proto="$1" cfg out rc
  cfg=$(client_config "$proto" "$WORK/alice.json")
  "$WORK/xray" run -c "$cfg" > "$WORK/client.log" 2>&1 &
  CLIENT_PID=$!
  sleep 2
  out=$(fetch_retry --socks5-hostname "127.0.0.1:$CLI_PORT" "$TARGET"); rc=$?
  kill "$CLIENT_PID" 2>/dev/null; CLIENT_PID=""
  check "client xray $proto -> target" "$rc"
}

# ------------------------------------------------------------ setup

mkdir -p "$WORK/stub"
printf '%s' "$BODY" > "$WORK/stub/index.html"
python3 -m http.server "$STUB_PORT" --bind 0.0.0.0 \
  --directory "$WORK/stub" > "$WORK/stub.log" 2>&1 &
STUB_PID=$!

ssh-keygen -t ed25519 -f "$WORK/alice_key" -N '' -q

# Client Xray (pinned, same version as the server images).
# shellcheck disable=SC1091
. "$ROOT/versions.env"
curl -fsSL -o "$WORK/xray.zip" \
  "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"
(cd "$WORK" && unzip -o -q xray.zip xray && chmod +x xray)

export DIRECT_ALLOW_PRIVATE=1
# VLESS and public SOCKS5 are opt-in now (plaintext-by-default
# protocols); the e2e enables both to keep exercising their paths.
export VLESS_ENABLED=1
export XMAGIC_ENABLE_SOCKS5=1
if [ "$FORM" = compose ]; then
  export XRAY_PORT=$PUB
  for img in xray dispatcher sshd admin; do
    docker pull "$PREFIX/xmagic-$img:$TAG" >/dev/null 2>&1 || true
  done
  mkdir -p "$WORK/compose/data"
  cp "$ROOT/docker-compose.yml" "$ROOT/sshd_config" "$WORK/compose/"
  cp "$WORK/alice_key.pub" "$WORK/compose/data/alice.pub"
  (cd "$WORK/compose" && docker compose up -d xray dispatcher sshd admin) \
    > "$WORK/up.log" 2>&1
  check "compose stack starts" "$?"
else
  docker pull "$PREFIX/xmagic-single:$TAG" >/dev/null 2>&1 || true
  mkdir -p "$WORK/single-data"
  cp "$WORK/alice_key.pub" "$WORK/single-data/alice.pub"
  docker run -d --name xmagic-e2e-single --restart unless-stopped \
    --add-host host.docker.internal:host-gateway \
    -p "$PUB:8080" -v "$WORK/single-data:/data" \
    -e DIRECT_ALLOW_PRIVATE=1 \
    -e VLESS_ENABLED=1 \
    -e XMAGIC_ENABLE_SOCKS5=1 \
    "$PREFIX/xmagic-single:$TAG" > "$WORK/up.log" 2>&1
  check "single container starts" "$?"
fi

wait_admin 120
check "admin console answers on the public port" "$?"

# ------------------------------------------------------------ checks

add_user alice --ssh-key-file /data/alice.pub
check "add alice" "$?"
apply_and_wait
check "apply takes effect (console back)" "$?"
ALICE_PW=$(jget "$WORK/alice.json" password)

out=$(fetch_retry -x "http://alice:$ALICE_PW@127.0.0.1:$PUB" "$TARGET")
check "HTTP CONNECT (alice) -> target" "$?"
out=$(fetch_retry --socks5-hostname "alice:$ALICE_PW@127.0.0.1:$PUB" "$TARGET")
check "SOCKS5 (alice) -> target" "$?"

check_via_client vless-ws
check_via_client ss
check_via_client vless-tcp

ssh -D "$SSH_D_PORT" -N -i "$WORK/alice_key" -p "$PUB" \
  -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null proxy@127.0.0.1 \
  > "$WORK/ssh.log" 2>&1 &
SSH_PID=$!
sleep 2
out=$(fetch_retry --socks5-hostname "127.0.0.1:$SSH_D_PORT" "$TARGET")
check "ssh -D (alice key) -> target" "$?"
kill "$SSH_PID" 2>/dev/null; SSH_PID=""

# The proxy account is forwarding-only: a key must never yield a shell
# or a remote command (ForceCommand + /bin/false shell in the images).
out=$(ssh -i "$WORK/alice_key" -p "$PUB" \
  -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null proxy@127.0.0.1 \
  "echo SHOULD_NOT_PRINT" 2>/dev/null)
[ -z "$out" ]
check "ssh exec is refused (forwarding-only account)" "$?"
out=$(ssh -i "$WORK/alice_key" -p "$PUB" \
  -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null proxy@127.0.0.1 \
  </dev/null 2>/dev/null)
[ -z "$out" ]
check "ssh interactive shell is refused" "$?"

add_user bob
check "add bob" "$?"
apply_and_wait
check "second apply takes effect" "$?"
BOB_PW=$(jget "$WORK/bob.json" password)
out=$(fetch_retry -x "http://bob:$BOB_PW@127.0.0.1:$PUB" "$TARGET")
check "HTTP CONNECT (bob, added later) -> target" "$?"
out=$(fetch_retry -x "http://alice:$ALICE_PW@127.0.0.1:$PUB" "$TARGET")
check "alice still works after second apply" "$?"

echo "e2e ($FORM): $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] || dump_logs
[ "$FAIL" = 0 ]
