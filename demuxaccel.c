/* _demuxaccel - native accelerator for the dispatcher's SS-WS
 * termination (sniff.py). The hot loop runs here, on the module's own
 * threads, with the GIL released: WebSocket termination + Mux.Cool
 * demultiplexing for one client connection at a time
 * (demux_serve). A fixed pool of worker threads (bounded, one per
 * CPU by default) runs everything: each connection is pinned to one
 * worker, which drives it and all its backend sessions from a
 * single poll loop - no thread per session, no locks on any data
 * path; the only synchronization is each worker's private intake
 * queue, touched once per new connection. Sockets, classification
 * and every other connection stay in Python; when this module is
 * absent sniff.py runs the same semantics in pure Python.
 *
 * Also exports the pure frame codecs the serve loop is built from
 * (parse_ws_frames / parse_mux_frames / build_ws_frame /
 * build_mux_frame) so tests can differential-check them against the
 * wire formats directly.
 *
 * Wire formats (implemented from spec, mirroring sniff.py):
 *   WS frame: FIN/opcode byte, mask+len byte, ext len, mask key,
 *   payload (RFC 6455). Mux.Cool frame: u16 metaLen, then meta =
 *   u16 session id, u8 status (1 New / 2 Keep / 3 End / 4 KeepAlive),
 *   u8 option (0x01 = data follows, 0x02 = error), target only on
 *   New; then, iff option & 0x01: u16 dataLen + data.
 */
#define _GNU_SOURCE
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define WS_MAX_PAYLOAD (1u << 24)   /* mirrors sniff.py's frame cap */
#define MUX_META_MAX 4096
#define MUX_CHUNK 60000
#define COALESCE_MAX 262144

/* ---------- growable byte buffer with a read cursor ---------- */
typedef struct { uint8_t *data; size_t len, cap, off; } buf_t;

static int buf_reserve(buf_t *b, size_t extra) {
    if (b->len + extra <= b->cap) return 0;
    size_t nc = b->cap ? b->cap : 8192;
    while (nc < b->len + extra) nc *= 2;
    uint8_t *nd = realloc(b->data, nc);
    if (!nd) return -1;
    b->data = nd; b->cap = nc;
    return 0;
}
static int buf_append(buf_t *b, const void *p, size_t n) {
    if (buf_reserve(b, n) < 0) return -1;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}
static void buf_consume(buf_t *b, size_t n) {   /* drop n parsed bytes */
    b->off += n;
    if (b->off == b->len) { b->off = b->len = 0; return; }
    if (b->off >= 65536) {
        memmove(b->data, b->data + b->off, b->len - b->off);
        b->len -= b->off; b->off = 0;
    }
}
static void buf_free(buf_t *b) { free(b->data); b->data = NULL; b->len = b->cap = b->off = 0; }

/* ---------- WebSocket frame codec ----------
 * Parse one frame from b at its cursor. Returns 1 with the frame
 * filled (payload copied, unmasked), 0 when more bytes are needed,
 * -1 on a protocol error. */
typedef struct { int fin, opcode; buf_t payload; } ws_frame_t;

static int ws_parse_one(buf_t *b, ws_frame_t *f) {
    size_t avail = b->len - b->off;
    if (avail < 2) return 0;
    const uint8_t *p = b->data + b->off;
    int fin = (p[0] & 0x80) != 0, opcode = p[0] & 0x0F;
    int masked = (p[1] & 0x80) != 0;
    uint64_t len = p[1] & 0x7F;
    size_t pos = 2;
    if (len == 126) {
        if (avail < pos + 2) return 0;
        len = ((uint64_t)p[pos] << 8) | p[pos + 1]; pos += 2;
    } else if (len == 127) {
        if (avail < pos + 8) return 0;
        len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | p[pos + i];
        pos += 8;
    }
    if (len > WS_MAX_PAYLOAD) return -1;
    const uint8_t *mask = NULL;
    if (masked) { if (avail < pos + 4) return 0; mask = p + pos; pos += 4; }
    if (avail - pos < len) return 0;
    buf_free(&f->payload);
    if (buf_append(&f->payload, p + pos, (size_t)len) < 0) return -1;
    if (mask) for (size_t i = 0; i < len; i++) f->payload.data[i] ^= mask[i & 3];
    f->fin = fin; f->opcode = opcode;
    buf_consume(b, pos + (size_t)len);
    return 1;
}

/* Build one WS frame into out. mask_key != NULL -> client style. */
static int ws_build(buf_t *out, int opcode, const uint8_t *payload,
                    size_t len, const uint8_t *mask_key) {
    uint8_t hdr[14]; size_t h = 0;
    hdr[h++] = (uint8_t)(0x80 | opcode);
    uint8_t mbit = mask_key ? 0x80 : 0x00;
    if (len < 126) hdr[h++] = (uint8_t)(mbit | len);
    else if (len <= 0xFFFF) { hdr[h++] = (uint8_t)(mbit | 126); hdr[h++] = (uint8_t)(len >> 8); hdr[h++] = (uint8_t)len; }
    else { hdr[h++] = (uint8_t)(mbit | 127); for (int i = 7; i >= 0; i--) hdr[h++] = (uint8_t)(len >> (8 * i)); }
    if (mask_key) { memcpy(hdr + h, mask_key, 4); h += 4; }
    if (buf_append(out, hdr, h) < 0) return -1;
    if (!mask_key) return buf_append(out, payload, len);
    size_t start = out->len;
    if (buf_append(out, payload, len) < 0) return -1;
    for (size_t i = 0; i < len; i++) out->data[start + i] ^= mask_key[i & 3];
    return 0;
}

static void rand4(uint8_t k[4]) {
    if (getrandom(k, 4, 0) != 4) { uint32_t x = (uint32_t)time(NULL) ^ (uint32_t)getpid(); memcpy(k, &x, 4); }
}

/* ---------- non-blocking WS message reader (one per socket) ----
 * The owner thread recv()s into raw whenever its poll loop fires,
 * then pulls complete messages out with ws_extract(). */
typedef void (*ping_fn)(void *ctx, const uint8_t *payload, size_t len);
typedef struct {
    buf_t raw;          /* unparsed bytes */
    buf_t frag;         /* reassembly buffer while frag_on */
    int frag_on, frag_op;
    ping_fn on_ping; void *ping_ctx;
} ws_reader_t;

/* Extract the next complete message from the buffered bytes.
 * 1 = message in *out (caller owns), 0 = need more bytes,
 * -1 = protocol error, -2 = peer closed (close frame). Control
 * frames are handled inline (ping -> on_ping or ignored, pong
 * skipped), mirroring sniff.py's _WSReader.read_message. */
static int ws_extract(ws_reader_t *r, buf_t *out) {
    buf_free(out);
    for (;;) {
        ws_frame_t f = {0, 0, {NULL, 0, 0, 0}};
        int st = ws_parse_one(&r->raw, &f);
        if (st == 0) { buf_free(&f.payload); return 0; }
        if (st < 0) { buf_free(&f.payload); return -1; }
        if (f.opcode == 8) { buf_free(&f.payload); return -2; }
        if (f.opcode == 9) {
            if (r->on_ping) r->on_ping(r->ping_ctx, f.payload.data, f.payload.len);
            buf_free(&f.payload); continue;
        }
        if (f.opcode == 10) { buf_free(&f.payload); continue; }
        if (f.opcode == 0) {
            if (!r->frag_on) { buf_free(&f.payload); return -1; }
            if (buf_append(&r->frag, f.payload.data, f.payload.len) < 0 ||
                r->frag.len > WS_MAX_PAYLOAD) { buf_free(&f.payload); return -1; }
            buf_free(&f.payload);
            if (!f.fin) continue;
            r->frag_on = 0;
            *out = r->frag; memset(&r->frag, 0, sizeof r->frag);
            return 1;
        }
        if (r->frag_on) { buf_free(&f.payload); return -1; }
        if (f.fin) { *out = f.payload; return 1; }
        r->frag_on = 1; r->frag_op = f.opcode;
        r->frag = f.payload;
    }
}

/* ---------- Mux.Cool codec ----------
 * Parse one frame from b at its cursor. Returns 1 (frame filled,
 * target bytes consumed and dropped), 0 need-more, -1 malformed. */
typedef struct { uint16_t sid; int status; int has_data; buf_t data; } mux_frame_t;

static int mux_parse_one(buf_t *b, mux_frame_t *f) {
    size_t avail = b->len - b->off;
    if (avail < 2) return 0;
    const uint8_t *p = b->data + b->off;
    size_t meta_len = ((size_t)p[0] << 8) | p[1];
    if (meta_len < 4 || meta_len > MUX_META_MAX) return -1;
    size_t head = 2 + meta_len;
    if (avail < head) return 0;
    const uint8_t *m = p + 2;
    f->sid = (uint16_t)((m[0] << 8) | m[1]);
    f->status = m[2];
    int option = m[3];
    f->has_data = 0; buf_free(&f->data);
    size_t total = head;
    if (option & 0x01) {
        if (avail < head + 2) return 0;
        size_t dlen = ((size_t)p[head] << 8) | p[head + 1];
        if (avail < head + 2 + dlen) return 0;
        if (buf_append(&f->data, p + head + 2, dlen) < 0) return -1;
        f->has_data = 1;
        total = head + 2 + dlen;
    }
    buf_consume(b, total);
    return 1;
}

static int mux_build(buf_t *out, uint16_t sid, int status,
                     const uint8_t *data, size_t len) {
    if (len > MUX_CHUNK) return -1;
    uint8_t hdr[8]; size_t h = 0;
    hdr[h++] = 0; hdr[h++] = 4;                       /* metaLen */
    hdr[h++] = (uint8_t)(sid >> 8); hdr[h++] = (uint8_t)sid;
    hdr[h++] = (uint8_t)status;
    hdr[h++] = len ? 0x01 : 0x00;                     /* OptionData */
    hdr[h++] = (uint8_t)(len >> 8); hdr[h++] = (uint8_t)len;
    if (buf_append(out, hdr, h) < 0) return -1;
    if (len) return buf_append(out, data, len);
    return 0;
}

/* ---------- pooled, event-driven demux core ----------
 * A fixed set of worker threads; each connection is pinned to one
 * worker and driven, with all its backend sessions, from that
 * worker's poll loop. Session state is only ever touched by its
 * owning worker, so the data path takes no locks at all. The one
 * lock in the design guards each worker's intake queue and is held
 * for a pointer swap, once per new connection. */
#include <sys/eventfd.h>

#define OUT_PAUSE (4u << 20)      /* stop reading the peer beyond this */
#define HEAD_CAP 65536
#define HS_TIMEOUT 10             /* backend handshake deadline, sec */

typedef struct session session_t;
typedef struct conn conn_t;
typedef struct worker worker_t;

struct session {
    uint16_t sid;
    int fd;
    int state;                    /* 0 = handshake, 1 = active */
    time_t deadline;
    size_t hs_len;                /* upgrade-request bytes in to_be */
    ws_reader_t rd;
    buf_t to_be;                  /* request head, then framed data */
    buf_t pending;                /* coalescing toward the client */
    conn_t *conn;
    session_t *next;
};

struct conn {
    int fd;
    int be_port;
    char path[1024];
    ws_reader_t rd;
    buf_t muxbuf;
    buf_t to_client;
    session_t *sessions;
    conn_t *next;
};

struct worker {
    pthread_t th;
    int wake;
    pthread_mutex_t qmu;
    conn_t *q_head, *q_tail;
    conn_t *conns;
};

static worker_t *g_workers;
static int g_nworkers;
static unsigned g_rr;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

/* Flush as much of *b (from its cursor) as the socket takes.
 * 0 = fine (maybe partially), -1 = hard error. */
static int flush_out(int fd, buf_t *b) {
    while (b->len > b->off) {
        ssize_t n = send(fd, b->data + b->off, b->len - b->off,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        b->off += (size_t)n;
    }
    b->len = b->off = 0;
    return 0;
}

/* Flush only up to an absolute byte limit of the buffer (the
 * handshake request may leave before the 101 arrives; session
 * data queued behind it must not - a real WS server aborts the
 * upgrade when frames precede its response). */
static int flush_out_n(int fd, buf_t *b, size_t limit) {
    if (limit > b->len) limit = b->len;
    while (b->off < limit) {
        ssize_t n = send(fd, b->data + b->off, limit - b->off,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        b->off += (size_t)n;
    }
    if (b->off == b->len) b->len = b->off = 0;
    return 0;
}

/* recv until EAGAIN into raw. 1 = read something, 0 = EOF,
 * -1 = error, 2 = nothing available. */
static int sock_feed(int fd, buf_t *raw) {
    int got = 0;
    for (int i = 0; i < 64; i++) {
        uint8_t tmp[65536];
        ssize_t n = recv(fd, tmp, sizeof tmp, MSG_DONTWAIT);
        if (n == 0) return got ? 1 : 0;
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return got ? 1 : 2;
            return -1;
        }
        if (buf_append(raw, tmp, (size_t)n) < 0) return -1;
        got = 1;
    }
    return 1;
}

static void append_client_frame(conn_t *c, int opcode,
                                const uint8_t *payload, size_t len) {
    buf_t tmp = {NULL, 0, 0, 0};
    if (ws_build(&tmp, opcode, payload, len, NULL) == 0)
        buf_append(&c->to_client, tmp.data, tmp.len);
    buf_free(&tmp);
}

/* Mux frames to the client with sniff.py's send_frame byte shape:
 * option 0x01 only for a non-empty payload, the u16 data length
 * present for every chunk including the empty one, 60000 chunks. */
static void append_mux(conn_t *c, uint16_t sid, int status,
                       const uint8_t *data, size_t len) {
    size_t off = 0;
    for (;;) {
        size_t chunk = len - off;
        if (chunk > MUX_CHUNK) chunk = MUX_CHUNK;
        buf_t frame = {NULL, 0, 0, 0};
        if (mux_build(&frame, sid, status, chunk ? data + off : NULL,
                      chunk) == 0)
            append_client_frame(c, 0x2, frame.data, frame.len);
        buf_free(&frame);
        off += chunk;
        if (off >= len) break;
    }
}

static void client_pong_cb(void *ctx, const uint8_t *payload, size_t len) {
    append_client_frame((conn_t *)ctx, 0xA, payload, len);
}

static void free_session(session_t *s) {
    if (s->fd >= 0) close(s->fd);
    buf_free(&s->rd.raw); buf_free(&s->rd.frag);
    buf_free(&s->to_be); buf_free(&s->pending);
    free(s);
}

static void close_session(conn_t *c, session_t *s, int send_end) {
    if (send_end) append_mux(c, s->sid, 3, NULL, 0);
    session_t **pp = &c->sessions;
    while (*pp && *pp != s) pp = &(*pp)->next;
    if (*pp) *pp = s->next;
    free_session(s);
}

static session_t *find_session(conn_t *c, uint16_t sid) {
    for (session_t *s = c->sessions; s; s = s->next)
        if (s->sid == sid) return s;
    return NULL;
}

static void destroy_conn(worker_t *w, conn_t *c) {
    conn_t **pp = &w->conns;
    while (*pp && *pp != c) pp = &(*pp)->next;
    if (*pp) *pp = c->next;
    while (c->sessions) {
        session_t *s = c->sessions;
        c->sessions = s->next;
        free_session(s);
    }
    close(c->fd);
    buf_free(&c->rd.raw); buf_free(&c->rd.frag);
    buf_free(&c->muxbuf); buf_free(&c->to_client);
    free(c);
}

static session_t *new_session(conn_t *c, uint16_t sid) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)c->be_port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = connect(fd, (struct sockaddr *)&a, sizeof a);
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return NULL; }
    session_t *s = calloc(1, sizeof *s);
    if (!s) { close(fd); return NULL; }
    s->sid = sid; s->fd = fd; s->state = 0;
    s->deadline = time(NULL) + HS_TIMEOUT;
    s->conn = c; s->rd.on_ping = NULL;
    /* The upgrade request rides the out queue; any session data
     * delivered during the handshake queues behind it, in order. */
    uint8_t rawkey[16];
    if (getrandom(rawkey, 16, 0) != 16) memset(rawkey, 0xA5, 16);
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char key[25]; int ki = 0;
    for (int i = 0; i < 16; i += 3) {
        int rem = 16 - i; uint32_t v = (uint32_t)rawkey[i] << 16;
        if (rem > 1) v |= (uint32_t)rawkey[i + 1] << 8;
        if (rem > 2) v |= rawkey[i + 2];
        key[ki++] = b64[(v >> 18) & 63]; key[ki++] = b64[(v >> 12) & 63];
        key[ki++] = rem > 1 ? b64[(v >> 6) & 63] : '=';
        key[ki++] = rem > 2 ? b64[v & 63] : '=';
    }
    key[ki] = 0;
    char req[1400];
    int rl = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n", c->path, c->be_port, key);
    if (rl < 0 || rl >= (int)sizeof req ||
        buf_append(&s->to_be, req, (size_t)rl) < 0) {
        close(fd); free(s); return NULL;
    }
    s->hs_len = (size_t)rl;
    s->next = c->sessions; c->sessions = s;
    return s;
}

/* Frame client data as one masked WS message onto the session's
 * out queue (mirrors _deliver; a hard write error ends it). */
static void deliver_data(conn_t *c, session_t *s,
                         const uint8_t *data, size_t len) {
    uint8_t mask[4]; rand4(mask);
    buf_t frame = {NULL, 0, 0, 0};
    if (ws_build(&frame, 0x2, data, len, mask) == 0)
        buf_append(&s->to_be, frame.data, frame.len);
    buf_free(&frame);
    int fr = s->state == 0 ? flush_out_n(s->fd, &s->to_be, s->hs_len)
                           : flush_out(s->fd, &s->to_be);
    if (fr < 0) close_session(c, s, 1);
}

static void mux_dispatch(conn_t *c, mux_frame_t *f) {
    if (f->status == 1) {                                     /* New */
        session_t *old = find_session(c, f->sid);
        if (old) close_session(c, old, 1);
        session_t *s = new_session(c, f->sid);
        if (!s) { append_mux(c, f->sid, 3, NULL, 0); return; }
        if (f->has_data && f->data.len) deliver_data(c, s, f->data.data, f->data.len);
    } else if (f->status == 2) {                              /* Keep */
        session_t *s = find_session(c, f->sid);
        if (s && f->has_data && f->data.len)
            deliver_data(c, s, f->data.data, f->data.len);
    } else if (f->status == 3) {                              /* End */
        session_t *s = find_session(c, f->sid);
        if (s) close_session(c, s, 1);
    }
    /* KeepAlive and unknown statuses carry nothing to do. */
}

static int conn_pump(worker_t *w, conn_t *c);

static void handle_client(worker_t *w, conn_t *c, short revents) {
    if (revents & POLLNVAL) { destroy_conn(w, c); return; }
    if ((revents & POLLOUT) && flush_out(c->fd, &c->to_client) < 0) {
        destroy_conn(w, c); return;
    }
    if (!(revents & (POLLIN | POLLHUP | POLLERR))) return;
    int fr = sock_feed(c->fd, &c->rd.raw);
    if (fr == 0 || fr == -1) { destroy_conn(w, c); return; }
    if (fr == 2) return;
    if (conn_pump(w, c) < 0) return;         /* conn already destroyed */
    if (c->to_client.len > c->to_client.off &&
        flush_out(c->fd, &c->to_client) < 0)
        destroy_conn(w, c);
}

/* Drain the mux stream and every complete client message already
 * buffered. Runs at intake on the seeded prefix/rest (parity with
 * the Python serve loop, which drains before its first read) and
 * after each client feed. -1 = the connection was destroyed. */
static int conn_pump(worker_t *w, conn_t *c) {
    for (;;) {
        for (;;) {
            mux_frame_t mf = {0, 0, 0, {NULL, 0, 0, 0}};
            int mst = mux_parse_one(&c->muxbuf, &mf);
            if (mst == 0) { buf_free(&mf.data); break; }
            if (mst < 0) { buf_free(&mf.data); destroy_conn(w, c); return -1; }
            mux_dispatch(c, &mf);
            buf_free(&mf.data);
        }
        buf_t msg = {NULL, 0, 0, 0};
        int st = ws_extract(&c->rd, &msg);
        if (st == 0) return 0;
        if (st < 0) { buf_free(&msg); destroy_conn(w, c); return -1; }
        buf_append(&c->muxbuf, msg.data, msg.len);
        buf_free(&msg);
    }
}

static void handle_session(worker_t *w, conn_t *c, session_t *s,
                           short revents) {
    (void)w;
    if (revents & POLLNVAL) { close_session(c, s, 1); return; }
    if (s->state == 0) {
        if ((revents & POLLOUT) &&
            flush_out_n(s->fd, &s->to_be, s->hs_len) < 0) {
            close_session(c, s, 1); return;
        }
        if (!(revents & (POLLIN | POLLHUP | POLLERR))) return;
        int fr = sock_feed(s->fd, &s->rd.raw);
        if (fr == 0 || fr == -1) { close_session(c, s, 1); return; }
        if (fr == 2) return;
        const uint8_t *base = s->rd.raw.data; size_t total = s->rd.raw.len;
        size_t head_end = 0;
        for (size_t i = 0; i + 3 < total; i++)
            if (memcmp(base + i, "\r\n\r\n", 4) == 0) { head_end = i + 4; break; }
        if (!head_end) {
            if (total > HEAD_CAP) close_session(c, s, 1);
            return;
        }
        const uint8_t *eol = memchr(base, '\n', head_end);
        size_t line = eol ? (size_t)(eol - base) : head_end;
        if (line < 5 || memmem(base, line, " 101 ", 5) == NULL) {
            close_session(c, s, 1); return;
        }
        memmove(s->rd.raw.data, base + head_end, total - head_end);
        s->rd.raw.len = total - head_end; s->rd.raw.off = 0;
        s->state = 1;
        flush_out(s->fd, &s->to_be);
        if (!s->rd.raw.len) return;
        /* fall through: bytes past the head are backend messages */
    }
    if ((revents & POLLOUT) && s->to_be.len > s->to_be.off &&
        flush_out(s->fd, &s->to_be) < 0) {
        close_session(c, s, 1); return;
    }
    if (!(revents & (POLLIN | POLLHUP | POLLERR))) return;
    int fr = sock_feed(s->fd, &s->rd.raw);
    if (fr == 0 || fr == -1) { close_session(c, s, 1); return; }
    /* fr == 2 (nothing new) still falls through: the handshake
     * path above may have buffered complete messages already. */
    for (;;) {
        buf_t msg = {NULL, 0, 0, 0};
        int st = ws_extract(&s->rd, &msg);
        if (st == 0) break;
        if (st < 0) { buf_free(&msg); close_session(c, s, 1); return; }
        buf_append(&s->pending, msg.data, msg.len);
        buf_free(&msg);
        if (s->pending.len >= COALESCE_MAX) {
            append_mux(c, s->sid, 2, s->pending.data, s->pending.len);
            s->pending.len = s->pending.off = 0;
        }
    }
    if (s->pending.len) {
        append_mux(c, s->sid, 2, s->pending.data, s->pending.len);
        s->pending.len = s->pending.off = 0;
    }
    if (c->to_client.len > c->to_client.off)
        flush_out(c->fd, &c->to_client);
}

static void *worker_loop(void *arg) {
    worker_t *w = arg;
    for (;;) {
        int n = 1;
        for (conn_t *c = w->conns; c; c = c->next) {
            n++;
            for (session_t *s = c->sessions; s; s = s->next) n++;
        }
        struct pollfd *pf = malloc((size_t)n * sizeof *pf);
        int *kind = malloc((size_t)n * sizeof *kind);
        conn_t **pc = malloc((size_t)n * sizeof *pc);
        session_t **ps = malloc((size_t)n * sizeof *ps);
        if (!pf || !kind || !pc || !ps) {
            free(pf); free(kind); free(pc); free(ps);
            struct timespec ts = {0, 50 * 1000 * 1000};
            nanosleep(&ts, NULL);
            continue;
        }
        int i = 0;
        pf[i] = (struct pollfd){.fd = w->wake, .events = POLLIN};
        kind[i] = 0; pc[i] = NULL; ps[i] = NULL; i++;
        for (conn_t *c = w->conns; c; c = c->next) {
            int be_backlog = 0;
            for (session_t *s = c->sessions; s; s = s->next)
                if (s->to_be.len - s->to_be.off >= OUT_PAUSE) be_backlog = 1;
            short ev = 0;
            if (!be_backlog) ev |= POLLIN;
            if (c->to_client.len > c->to_client.off) ev |= POLLOUT;
            pf[i] = (struct pollfd){.fd = c->fd, .events = ev};
            kind[i] = 1; pc[i] = c; ps[i] = NULL; i++;
            for (session_t *s = c->sessions; s; s = s->next) {
                short sev;
                if (s->state == 0) {
                    sev = POLLIN;
                    if (s->to_be.off < s->hs_len) sev |= POLLOUT;
                }
                else {
                    sev = 0;
                    if (c->to_client.len - c->to_client.off < OUT_PAUSE)
                        sev |= POLLIN;
                    if (s->to_be.len > s->to_be.off) sev |= POLLOUT;
                }
                pf[i] = (struct pollfd){.fd = s->fd, .events = sev};
                kind[i] = 2; pc[i] = c; ps[i] = s; i++;
            }
        }
        int rc = poll(pf, (nfds_t)i, 200);
        time_t now = time(NULL);
        if (rc > 0) {
            if (pf[0].revents & POLLIN) {
                uint64_t v; ssize_t r = read(w->wake, &v, sizeof v);
                (void)r;
                pthread_mutex_lock(&w->qmu);
                conn_t *q = w->q_head;
                w->q_head = w->q_tail = NULL;
                pthread_mutex_unlock(&w->qmu);
                while (q) {
                    conn_t *nx = q->next;
                    q->next = w->conns; w->conns = q;
                    conn_pump(w, q);
                    q = nx;
                }
            }
            for (int j = 1; j < i; j++) {
                if (!pf[j].revents) continue;
                /* An earlier event in this batch may have destroyed
                 * the conn or session: re-validate by pointer
                 * identity against the live lists before touching. */
                conn_t *c = pc[j];
                conn_t *live = w->conns;
                while (live && live != c) live = live->next;
                if (!live) continue;
                if (kind[j] == 1) { handle_client(w, c, pf[j].revents); continue; }
                session_t *s = ps[j];
                session_t *sl = c->sessions;
                while (sl && sl != s) sl = sl->next;
                if (sl) handle_session(w, c, s, pf[j].revents);
            }
        }
        for (conn_t *c = w->conns, *cn; c; c = cn) {
            cn = c->next;
            for (session_t *s = c->sessions, *sn; s; s = sn) {
                sn = s->next;
                if (s->state == 0 && now > s->deadline)
                    close_session(c, s, 1);
            }
        }
        free(pf); free(kind); free(pc); free(ps);
    }
    return NULL;
}

static void pool_init(void) {
    int n = 0;
    const char *env = getenv("XMAGIC_DEMUX_THREADS");
    if (env) n = atoi(env);
    if (n <= 0) {
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);
        n = cpus < 1 ? 1 : (int)cpus;
    }
    if (n > 8) n = 8;
    g_workers = calloc((size_t)n, sizeof(worker_t));
    if (!g_workers) { g_nworkers = 0; return; }
    int made = 0;
    for (int i = 0; i < n; i++) {
        worker_t *w = &g_workers[i];
        w->wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (w->wake < 0) break;
        pthread_mutex_init(&w->qmu, NULL);
        if (pthread_create(&w->th, NULL, worker_loop, w) != 0) break;
        made++;
    }
    g_nworkers = made;
}

/* ---------- Python exports ---------- */
static PyObject *py_parse_ws_frames(PyObject *self, PyObject *arg) {
    const uint8_t *p; Py_ssize_t n;
    if (PyBytes_AsStringAndSize(arg, (char **)&p, &n) < 0) return NULL;
    buf_t b = {NULL, 0, 0, 0};
    if (buf_append(&b, p, (size_t)n) < 0) return PyErr_NoMemory();
    PyObject *list = PyList_New(0);
    if (!list) { buf_free(&b); return NULL; }
    for (;;) {
        ws_frame_t f = {0, 0, {NULL, 0, 0, 0}};
        int st = ws_parse_one(&b, &f);
        if (st == 0) { buf_free(&f.payload); break; }
        if (st < 0) {
            buf_free(&f.payload); buf_free(&b); Py_DECREF(list);
            return PyErr_Format(PyExc_ValueError, "malformed WebSocket frame");
        }
        PyObject *t = Py_BuildValue("(iiy#)", f.fin, f.opcode,
                                    f.payload.data ? (const char *)f.payload.data : "",
                                    (Py_ssize_t)f.payload.len);
        buf_free(&f.payload);
        if (!t || PyList_Append(list, t) < 0) {
            Py_XDECREF(t); buf_free(&b); Py_DECREF(list); return NULL;
        }
        Py_DECREF(t);
    }
    Py_ssize_t consumed = n - (Py_ssize_t)(b.len - b.off);
    buf_free(&b);
    return Py_BuildValue("(Ni)", list, consumed);
}

static PyObject *py_parse_mux_frames(PyObject *self, PyObject *arg) {
    const uint8_t *p; Py_ssize_t n;
    if (PyBytes_AsStringAndSize(arg, (char **)&p, &n) < 0) return NULL;
    buf_t b = {NULL, 0, 0, 0};
    if (buf_append(&b, p, (size_t)n) < 0) return PyErr_NoMemory();
    PyObject *list = PyList_New(0);
    if (!list) { buf_free(&b); return NULL; }
    for (;;) {
        mux_frame_t f = {0, 0, 0, {NULL, 0, 0, 0}};
        int st = mux_parse_one(&b, &f);
        if (st == 0) { buf_free(&f.data); break; }
        if (st < 0) {
            buf_free(&f.data); buf_free(&b); Py_DECREF(list);
            return PyErr_Format(PyExc_ValueError, "malformed mux frame");
        }
        PyObject *t = Py_BuildValue("(iiiy#)", f.sid, f.status, f.has_data,
                                    f.data.data ? (const char *)f.data.data : "",
                                    (Py_ssize_t)f.data.len);
        buf_free(&f.data);
        if (!t || PyList_Append(list, t) < 0) {
            Py_XDECREF(t); buf_free(&b); Py_DECREF(list); return NULL;
        }
        Py_DECREF(t);
    }
    Py_ssize_t consumed = n - (Py_ssize_t)(b.len - b.off);
    buf_free(&b);
    return Py_BuildValue("(Ni)", list, consumed);
}

static PyObject *py_build_ws_frame(PyObject *self, PyObject *args) {
    int opcode; const uint8_t *p; Py_ssize_t n; PyObject *masko = Py_None;
    if (!PyArg_ParseTuple(args, "iy#|O", &opcode, &p, &n, &masko)) return NULL;
    const uint8_t *mask = NULL; uint8_t mk[4];
    if (masko != Py_None) {
        const uint8_t *mp; Py_ssize_t mn;
        if (PyBytes_AsStringAndSize(masko, (char **)&mp, &mn) < 0) return NULL;
        if (mn != 4) return PyErr_Format(PyExc_ValueError, "mask key must be 4 bytes");
        memcpy(mk, mp, 4); mask = mk;
    }
    buf_t out = {NULL, 0, 0, 0};
    if (ws_build(&out, opcode, p, (size_t)n, mask) < 0) { buf_free(&out); return PyErr_NoMemory(); }
    PyObject *r = PyBytes_FromStringAndSize((char *)out.data, (Py_ssize_t)out.len);
    buf_free(&out);
    return r;
}

static PyObject *py_build_mux_frame(PyObject *self, PyObject *args) {
    int sid, status; const uint8_t *p; Py_ssize_t n;
    if (!PyArg_ParseTuple(args, "iiy#", &sid, &status, &p, &n)) return NULL;
    buf_t out = {NULL, 0, 0, 0};
    if (mux_build(&out, (uint16_t)sid, status, p, (size_t)n) < 0) {
        buf_free(&out);
        return PyErr_Format(PyExc_ValueError, "payload too large for one mux frame");
    }
    PyObject *r = PyBytes_FromStringAndSize((char *)out.data, (Py_ssize_t)out.len);
    buf_free(&out);
    return r;
}

/* demux_submit(fd, be_port, path, mux_prefix, raw_rest) -> bool
 * Hands one mux-verdict client connection to the worker pool
 * (async: the pool owns it from here). Returns False when the
 * pool is unavailable, so the caller can run the pure-Python
 * demuxer instead. */
static PyObject *py_demux_submit(PyObject *self, PyObject *args) {
    int fd, be_port; const char *path;
    const uint8_t *prefix; Py_ssize_t plen;
    const uint8_t *rest; Py_ssize_t rlen;
    if (!PyArg_ParseTuple(args, "iisy#y#", &fd, &be_port, &path,
                          &prefix, &plen, &rest, &rlen)) return NULL;
    pthread_once(&g_once, pool_init);
    if (!g_nworkers) Py_RETURN_FALSE;
    int cfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (cfd < 0) Py_RETURN_FALSE;
    int flags = fcntl(cfd, F_GETFL, 0);
    fcntl(cfd, F_SETFL, flags | O_NONBLOCK);
    conn_t *c = calloc(1, sizeof *c);
    if (!c) { close(cfd); Py_RETURN_FALSE; }
    c->fd = cfd; c->be_port = be_port;
    snprintf(c->path, sizeof c->path, "%s", path);
    c->rd.on_ping = client_pong_cb; c->rd.ping_ctx = c;
    if (buf_append(&c->rd.raw, rest, (size_t)rlen) < 0 ||
        buf_append(&c->muxbuf, prefix, (size_t)plen) < 0) {
        buf_free(&c->rd.raw); buf_free(&c->muxbuf);
        close(cfd); free(c); Py_RETURN_FALSE;
    }
    unsigned slot = __sync_fetch_and_add(&g_rr, 1) % (unsigned)g_nworkers;
    worker_t *w = &g_workers[slot];
    pthread_mutex_lock(&w->qmu);
    c->next = NULL;
    if (w->q_tail) w->q_tail->next = c; else w->q_head = c;
    w->q_tail = c;
    pthread_mutex_unlock(&w->qmu);
    uint64_t one_v = 1;
    ssize_t wr = write(w->wake, &one_v, sizeof one_v);
    (void)wr;
    Py_RETURN_TRUE;
}

static PyMethodDef methods[] = {
    {"parse_ws_frames", py_parse_ws_frames, METH_O,
     "parse_ws_frames(buf) -> ([(fin, opcode, payload)], consumed)"},
    {"parse_mux_frames", py_parse_mux_frames, METH_O,
     "parse_mux_frames(buf) -> ([(sid, status, has_data, data)], consumed)"},
    {"build_ws_frame", py_build_ws_frame, METH_VARARGS,
     "build_ws_frame(opcode, payload, mask=None) -> bytes"},
    {"build_mux_frame", py_build_mux_frame, METH_VARARGS,
     "build_mux_frame(sid, status, data) -> bytes"},
    {"demux_submit", py_demux_submit, METH_VARARGS,
     "demux_submit(fd, be_port, path, mux_prefix, raw_rest) -> bool"},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef mod = {PyModuleDef_HEAD_INIT, "_demuxaccel",
                                 "Native SS-WS termination accelerator.", -1, methods};
PyMODINIT_FUNC PyInit__demuxaccel(void) { return PyModule_Create(&mod); }
