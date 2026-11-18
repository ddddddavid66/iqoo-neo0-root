#!/usr/bin/env python3
"""Transparent adb proxy that decodes packets so a real client's AUTH
exchange can be compared with ours.

    python tools/adb_mitm.py 5556 127.0.0.1 5555
    adb connect 127.0.0.1:5556
"""
import socket
import struct
import sys
import threading

CMD = {
    0x4E584E43: "CNXN", 0x48545541: "AUTH", 0x4E45504F: "OPEN",
    0x59414B4F: "OKAY", 0x45545257: "WRTE", 0x45534C43: "CLSE",
    0x534C5453: "STLS", 0x4C4E4B53: "LNK?" ,
}

lock = threading.Lock()


def out(s):
    with lock:
        sys.stdout.buffer.write((s + "\n").encode("utf-8", "backslashreplace"))
        sys.stdout.flush()


def describe(who, buf):
    """buf is one complete packet (header + payload)."""
    cmd, a0, a1, dlen, chk, magic = struct.unpack("<6I", buf[:24])
    name = CMD.get(cmd, hex(cmd))
    body = buf[24:24 + dlen]
    ok = "magic-ok" if magic == (cmd ^ 0xFFFFFFFF) else "MAGIC-BAD"
    note = ""
    if name == "AUTH":
        role = {1: "TOKEN", 2: "SIGNATURE", 3: "RSAPUBLICKEY"}.get(a0, f"a0={a0}")
        note = f" role={role} bodylen={len(body)}"
        if a0 == 2:
            note += f" sig[0:8]={body[:8].hex()}"
            with open("tools/last_sig.bin", "wb") as f:
                f.write(body)
        elif a0 == 1:
            note += f" token={body.hex()}"
            with open("tools/last_token.bin", "wb") as f:
                f.write(body)
    elif name == "CNXN":
        note = f" banner={body[:120]!r}"
        if who.startswith("cli"):
            with open("tools/last_cnxn.bin", "wb") as f:
                f.write(body)
    elif name == "OPEN":
        note = f" service={body[:60]!r}"
    elif name == "WRTE":
        note = f" data={body[:60]!r}"
    out(f"[{who}] {name} a0={a0} a1={a1} len={dlen} chk={chk} {ok}{note}")


def pump(src, dst, tag, sink):
    buf = b""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            if sink is not None:
                buf += data
                while len(buf) >= 24:
                    dlen = struct.unpack("<I", buf[12:16])[0]
                    if len(buf) < 24 + dlen:
                        break
                    describe(tag, buf[:24 + dlen])
                    buf = buf[24 + dlen:]
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def main():
    lport = int(sys.argv[1]) if len(sys.argv) > 1 else 5556
    thost = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    tport = int(sys.argv[3]) if len(sys.argv) > 3 else 5555

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", lport))
    srv.listen(8)
    out(f"[*] proxy 127.0.0.1:{lport} -> {thost}:{tport}")

    n = 0
    while True:
        cli, _ = srv.accept()
        n += 1
        up = socket.create_connection((thost, tport))
        out(f"[*] connection {n} accepted")
        # client->adbd is where CNXN + AUTH live; adbd->client too (challenges)
        t1 = threading.Thread(target=pump, args=(cli, up, f"cli{n}->adbd", True), daemon=True)
        t2 = threading.Thread(target=pump, args=(up, cli, f"adbd->cli{n}", True), daemon=True)
        t1.start()
        t2.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
