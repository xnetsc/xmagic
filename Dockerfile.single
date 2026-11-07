# All-in-one form: every gateway process in ONE container, for hosts
# and panels that can run a single image / plain `docker run` but not
# docker compose. The entrypoint starts the same pieces the compose
# file wires as separate containers - admin, xray, sshd, dispatcher
# (the only public listener) and the ssh-tunnels holder - and there is
# no process supervisor: if any critical process exits, the entrypoint
# takes the whole container down with it, and the runtime's restart
# policy brings it back as one unit. Config changes apply the same
# way: apply renders, then signals the gateway processes (pidfiles in
# /run/xmagic), whose exit restarts the container whole on the new
# config - so run it with a restart policy:
#
#   docker build -f Dockerfile.single -t xmagic-single .
#   docker run -d --name xmagic --restart unless-stopped \
#     -p 8080:8080 -v xmagic-data:/data xmagic-single
#   # open http://<host>:8080 - register the admin passkey, add users
#
# The compose deployment remains the recommended form: separate
# containers keep separate update cadences and restart boundaries.
# This image trades that for one-command startup.
#
# All state lives in /data (identity DB + local DB registry, rendered
# config.json / authorized_keys, sshd host keys, ssh client keys) -
# mount a volume there. Configuration is the same environment as
# compose (see .env.example), read at container start; changing
# XRAY_PORT means changing the -p mapping to match. Platform
# adaptation: when PORT is set (Heroku-style) it becomes the public
# port, and when DATABASE_URL is set the entrypoint registers it as
# the business database (see single-entrypoint.sh) - that is what the
# Heroku one-click deploy (app.json + heroku.yml) relies on.
ARG XRAY_VERSION=26.10.31
FROM ghcr.io/xtls/xray-core:${XRAY_VERSION} AS xray-core

FROM python:3.12-alpine
RUN apk add --no-cache openssh-server openssh-client \
 && adduser -D -s /bin/sh proxy \
 && passwd -u proxy \
 && mkdir -p /home/proxy/.ssh /etc/ssh/keys \
 && chown proxy:proxy /home/proxy/.ssh && chmod 700 /home/proxy/.ssh
# psycopg / pymysql are the optional PostgreSQL / MySQL business-
# database drivers (SQLite is in the standard library).
RUN pip install --no-cache-dir "psycopg[binary]" "pymysql"
COPY --from=xray-core /usr/local/bin/xray /usr/local/bin/xray
COPY users.py admin.py sniff.py /app/
COPY sshd_config /etc/ssh/sshd_config
COPY single-entrypoint.sh single-tunnels.sh /app/
RUN chmod +x /app/single-entrypoint.sh /app/single-tunnels.sh
WORKDIR /app
ENV XRAY_PORT=8080 \
    XRAY_MUX_PORT=18080 \
    BE_HTTP_PORT=18081 \
    BE_SOCKS_PORT=18082 \
    SS_BE_PORT=12003 \
    VLESS_BE_BASE=12100 \
    TROJAN_BE_BASE=12200 \
    SSH_BE_PORT=12222 \
    ADMIN_BE_PORT=18090 \
    SSH_TUNNEL_BASE=13000 \
    VLESS_WS_PATHS=/vless-ws \
    TROJAN_WS_PATHS=/trojan-ws \
    SS_METHOD=aes-256-gcm \
    UPSTREAM_STRATEGY=roundRobin \
    PROXY_DB=/data/users.db \
    XMAGIC_ADMIN_BIND=127.0.0.1 \
    XMAGIC_ADMIN_PORT=18090 \
    XMAGIC_ADMIN_RPID=localhost \
    XMAGIC_ADMIN_ORIGINS=http://localhost:8080,http://127.0.0.1:8080 \
    XMAGIC_PID_DIR=/run/xmagic
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/app/single-entrypoint.sh"]
