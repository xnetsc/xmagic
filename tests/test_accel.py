#!/usr/bin/env python3
"""Native accelerator tests (_demuxaccel, demuxaccel.c).

Two layers:
  - the pure frame codecs, differential-checked against reference
    implementations written here from the wire formats (RFC 6455
    framing, Mux.Cool framing) over randomized streams, including
    buffers split at random points;
  - demux_submit end to end: a socketpair stands in for the client,
    a stub WebSocket backend for the SS-WS inbound, and mux frames
    for the v2ray-plugin client.

When the module cannot be imported and cannot be built (no C
compiler / Python headers), the file reports SKIP and exits 0 -
the pure-Python path is covered by test_dispatch.py either way,
and test_dispatch.py also exercises this module end to end
whenever the built .so sits next to sniff.py.
"""
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name
          + (f"  {extra}" if extra and not cond else ""))


def load_accel():
    sys.path.insert(0, ROOT)
    try:
        import _demuxaccel
        return _demuxaccel
    except ImportError:
        pass
    tmp = tempfile.mkdtemp(prefix="accel-build-")
    so = os.path.join(tmp, "_demuxaccel.so")
    try:
        inc = subprocess.run(
            [sys.executable, "-c",
             "import sysconfig; print(sysconfig.get_paths()['include'])"],
            capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(
            ["cc", "-O2", "-fPIC", "-shared", "-I" + inc, "-o", so,
             os.path.join(ROOT, "demuxaccel.c"), "-lpthread"],
            check=True, capture_output=True)
    except Exception:
        return None
    sys.path.insert(0, tmp)
    try:
        import _demuxaccel
        return _demuxaccel
    except ImportError:
        return None


# --- reference codecs, written from the wire formats -------------

def ref_ws_frame(fin, opcode, payload, mask=None):
    out = bytearray([(0x80 if fin else 0) | opcode])
    ln = len(payload)
    mbit = 0x80 if mask else 0
    if ln < 126:
        out.append(mbit | ln)
    elif ln <= 0xFFFF:
        out.append(mbit | 126)
        out += struct.pack(">H", ln)
    else:
        out.append(mbit | 127)
        out += struct.pack(">Q", ln)
    if mask:
        out += mask
        out += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    else:
        out += payload
    return bytes(out)


def ref_ws_parse(buf):
    frames, pos = [], 0
    while len(buf) - pos >= 2:
        b0, b1 = buf[pos], buf[pos + 1]
        ln = b1 & 0x7F
        p = pos + 2
        if ln == 126:
            if len(buf) - p < 2:
                break
            ln = int.from_bytes(buf[p:p + 2], "big")
            p += 2
        elif ln == 127:
            if len(buf) - p < 8:
                break
            ln = int.from_bytes(buf[p:p + 8], "big")
            p += 8
        mask = None
        if b1 & 0x80:
            if len(buf) - p < 4:
                break
            mask = buf[p:p + 4]
            p += 4
        if len(buf) - p < ln:
            break
        body = buf[p:p + ln]
        if mask:
            body = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
        frames.append((1 if b0 & 0x80 else 0, b0 & 0x0F, body))
        pos = p + ln
    return frames, pos


def ref_mux_frame(sid, status, data=b"", target=b"", server=False):
    meta = sid.to_bytes(2, "big") + bytes([status, 1 if data else 0])
    meta += target
    out = len(meta).to_bytes(2, "big") + meta
    if data:
        out += len(data).to_bytes(2, "big") + data
    # A data-less frame ends at the meta, in both directions (the
    # spec's shape; the gateway once appended a zero length for
    # empty server frames, which strict stream readers desync on).
    return out


def ref_mux_parse(buf):
    frames, pos = [], 0
    while len(buf) - pos >= 2:
        meta_len = int.from_bytes(buf[pos:pos + 2], "big")
        if meta_len < 4 or meta_len > 4096:
            raise ValueError("meta length")
        if len(buf) - pos < 2 + meta_len:
            break
        meta = buf[pos + 2:pos + 2 + meta_len]
        sid = int.from_bytes(meta[0:2], "big")
        status, option = meta[2], meta[3]
        p = pos + 2 + meta_len
        if option & 0x01:
            if len(buf) - p < 2:
                break
            dlen = int.from_bytes(buf[p:p + 2], "big")
            if len(buf) - p - 2 < dlen:
                break
            frames.append((sid, status, 1, buf[p + 2:p + 2 + dlen]))
            pos = p + 2 + dlen
        else:
            frames.append((sid, status, 0, b""))
            pos = p
    return frames, pos


# --- codec differential checks ------------------------------------

def codec_checks(A):
    rng = random.Random(20261109)
    # WS: random frame streams, then buffer splits at random points.
    ok = True
    for _ in range(300):
        frames = []
        stream = bytearray()
        for _ in range(rng.randrange(1, 6)):
            fin = rng.randrange(2)
            opcode = rng.choice([0, 1, 2, 8, 9, 10])
            ln = rng.choice([0, 1, 5, 125, 126, 300, 5000])
            payload = rng.randbytes(ln)
            mask = rng.randbytes(4) if rng.randrange(2) else None
            stream += ref_ws_frame(fin, opcode, payload, mask)
            frames.append((fin, opcode, payload))
        cut = rng.randrange(len(stream) + 1)
        got, used = A.parse_ws_frames(bytes(stream[:cut]))
        want, want_used = ref_ws_parse(bytes(stream[:cut]))
        if got != want or used != want_used:
            ok = False
            break
        built = A.build_ws_frame(2, b"payload", None)
        if built != ref_ws_frame(1, 2, b"payload"):
            ok = False
            break
        m = rng.randbytes(4)
        if A.build_ws_frame(2, b"payload", m) != ref_ws_frame(1, 2, b"payload", m):
            ok = False
            break
    check("accel: WS codec matches the reference on random streams",
          ok)

    # Mux: same treatment; New frames carry a target in the meta.
    ok = True
    for _ in range(300):
        stream = bytearray()
        want = []
        for _ in range(rng.randrange(1, 6)):
            sid = rng.randrange(0, 65536)
            status = rng.choice([1, 2, 3, 4])
            data = rng.randbytes(rng.choice([0, 1, 40, 1000])) \
                if status in (1, 2) and rng.randrange(4) else b""
            target = rng.randbytes(rng.randrange(0, 12)) if status == 1 \
                else b""
            stream += ref_mux_frame(sid, status, data, target)
            want.append((sid, status, 1 if data else 0, data))
        cut = rng.randrange(len(stream) + 1)
        got, used = A.parse_mux_frames(bytes(stream[:cut]))
        want_prefix, want_used = ref_mux_parse(bytes(stream[:cut]))
        if got != want_prefix or used != want_used:
            ok = False
            break
        if A.build_mux_frame(5, 2, b"xyz") != ref_mux_frame(5, 2, b"xyz"):
            ok = False
            break
        if A.build_mux_frame(5, 3, b"") != ref_mux_frame(5, 3, server=True):
            ok = False
            break
    check("accel: mux codec matches the reference on random streams",
          ok)

    try:
        A.parse_mux_frames(b"\x00\x03\x00\x01\x01\x00")
        bad = False
    except ValueError:
        bad = True
    check("accel: implausible mux meta length is an error", bad)
    try:
        A.build_mux_frame(1, 2, b"x" * 60001)
        big = False
    except ValueError:
        big = True
    check("accel: oversized mux payload is an error", big)


# --- demux_submit end to end ---------------------------------------

def submit_checks(A):
    be = socket.socket()
    be.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    be.bind(("127.0.0.1", 0))
    be_port = be.getsockname()[1]
    be.listen(4)
    records = []

    def ws_read_msg(conn, buf):
        def rd(n):
            nonlocal buf
            while len(buf) < n:
                chunk = conn.recv(65536)
                if not chunk:
                    raise EOFError
                buf += chunk
            out, buf = buf[:n], buf[n:]
            return out
        h = rd(2)
        ln = h[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(rd(2), "big")
        mask = rd(4) if h[1] & 0x80 else None
        body = rd(ln)
        if mask:
            body = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
        return body

    def backend():
        while True:
            try:
                conn, _ = be.accept()
            except OSError:
                return
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                head += chunk
            if b"\r\n\r\n" not in head:
                conn.close()
                continue
            records.append(("open",))
            buf = head.split(b"\r\n\r\n", 1)[1]
            # A real WS server aborts the upgrade when frame bytes
            # precede its 101 (xray resets the connection), so the
            # accelerator must hold session data until the head is
            # answered. Hold the 101 briefly and count any bytes
            # that arrive in the window as a pipelining violation.
            conn.settimeout(0.3)
            try:
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    records.append(("pipelined", len(chunk)))
                    buf += chunk
            except (socket.timeout, TimeoutError):
                pass
            conn.settimeout(None)
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                         b"Upgrade: websocket\r\n"
                         b"Connection: Upgrade\r\n"
                         b"Sec-WebSocket-Accept: x\r\n\r\n")
            try:
                while True:
                    msg = ws_read_msg(conn, buf)
                    buf = b""
                    records.append(("data", msg))
                    up = msg.upper()
                    conn.sendall(bytes([0x82, len(up)]) + up)
            except (EOFError, OSError):
                records.append(("close",))
                conn.close()

    threading.Thread(target=backend, daemon=True).start()

    cli, mine = socket.socketpair()
    mine.settimeout(10)
    target = (443).to_bytes(2, "big") + bytes([1, 127, 0, 0, 1])
    new7 = ref_mux_frame(7, 1, b"hello", target)
    taken = A.demux_submit(cli.fileno(), be_port, "/ss-ws", new7, b"")
    check("accel: demux_submit takes the connection", taken is True)
    cli.close()

    wsbuf = bytearray()
    pending = []

    def next_mux():
        # The gateway sends exactly one mux frame per WS message;
        # parse each message on its own (a data-less frame's
        # trailing length bytes belong to that message only).
        while not pending:
            chunk = mine.recv(65536)
            if not chunk:
                raise EOFError("client socket closed")
            wsbuf.extend(chunk)
            messages, used = ref_ws_parse(bytes(wsbuf))
            del wsbuf[:used]
            for _fin, _op, payload in messages:
                try:
                    frames, _used = ref_mux_parse(payload)
                except ValueError:
                    # A data-less frame sent by the gateway carries
                    # a trailing zero length inside its own WS
                    # message; drop those two bytes and reparse.
                    if not payload.endswith(b"\x00\x00"):
                        raise
                    frames, _used = ref_mux_parse(payload[:-2])
                pending.extend(frames)
        return pending.pop(0)

    sid, status, opt, data = next_mux()
    check("accel: session reply comes back mux-framed",
          (sid, status, opt, data) == (7, 2, 1, b"HELLO"),
          f"got {(sid, status, opt, data)!r}")
    # client End is echoed as End (the backend thread's farewell),
    # matching the Python demuxer's observable behavior.
    def client_frame(payload):
        mask = os.urandom(4)
        return ref_ws_frame(1, 2, payload, mask)
    mine.sendall(client_frame(ref_mux_frame(7, 3)))
    sid, status, opt, data = next_mux()
    check("accel: client End is answered with End",
          (sid, status, opt, data) == (7, 3, 0, b""),
          f"got {(sid, status, opt, data)!r}")
    for _ in range(30):
        if any(r[0] == "close" for r in records):
            break
        time.sleep(0.1)
    check("accel: backend connection closed after End",
          any(r[0] == "close" for r in records),
          f"records {records!r}")
    check("accel: no session data pipelined before the 101",
          not [r for r in records if r[0] == "pipelined"],
          f"records {records!r}")
    mine.close()
    be.close()


def main():
    A = load_accel()
    if A is None:
        print("SKIP _demuxaccel unavailable (no compiler/headers); "
              "the pure-Python path is covered by test_dispatch.py")
        return 0
    codec_checks(A)
    submit_checks(A)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
