#!/usr/bin/env python3
"""Minimal adb protocol client — proves that RSA auth + shell exec works
with the existing host adbkey. This is the reference implementation that
the Android-side Java client will be ported from.

Usage:
    python adb_probe.py <host:port> [command]
"""
import socket
import struct
import sys
import zlib
import os

CMD_CNXN = 0x4E584E43
CMD_AUTH = 0x48545541
CMD_OPEN = 0x4E45504F
CMD_OKAY = 0x59414B4F
CMD_WRTE = 0x45545257
CMD_CLSE = 0x45534C43
CMD_STLS = 0x534C5453

AUTH_TOKEN = 1
AUTH_SIGNATURE = 2
AUTH_RSAPUBLICKEY = 3

A_VERSION = 0x01000001
A_VERSION_MIN = 0x01000000
MAXDATA = 1024 * 1024

NAMES = {
    CMD_CNXN: "CNXN", CMD_AUTH: "AUTH", CMD_OPEN: "OPEN",
    CMD_OKAY: "OKAY", CMD_WRTE: "WRTE", CMD_CLSE: "CLSE", CMD_STLS: "STLS",
}


class Msg:
    __slots__ = ("cmd", "arg0", "arg1", "payload", "crc")

    def __init__(self, cmd, arg0, arg1, payload=b"", crc=None):
        self.cmd, self.arg0, self.arg1, self.payload, self.crc = cmd, arg0, arg1, payload, crc

    def __repr__(self):
        body = self.payload
        text = body.decode("ascii", "backslashreplace")
        if len(text) > 200:
            text = text[:200] + "..."
        return f"<{NAMES.get(self.cmd, hex(self.cmd))} a0={self.arg0} a1={self.arg1} len={len(body)} {text}>"


def checksum(data):
    """adbd validates with a plain byte sum (not crc32) and skips the check
    when the field is 0. Sending the real sum matches a stock client."""
    return sum(data) & 0xFFFFFFFF


def encode(cmd, arg0, arg1, payload=b""):
    magic = cmd ^ 0xFFFFFFFF
    return struct.pack("<6I", cmd, arg0, arg1, len(payload), checksum(payload), magic) + payload


# DigestInfo for SHA-1, used verbatim by adb's auth path.
_SHA1_DIGESTINFO = bytes.fromhex("3021300906052b0e03021a05000414")


def load_key(path):
    """Build adb's auth signer.

    adb does NOT run SHA1withRSA over the 20-byte token. It treats the token as
    an already-computed digest and signs ``DigestInfo(SHA-1) || token`` raw.
    Confirmed against a captured stock-client packet: the recovered block is
    ``00 01 ff*218 00 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || token``.
    A textbook SHA1withRSA signature is rejected by adbd.
    """
    from cryptography.hazmat.primitives import serialization

    with open(path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), None)
    nums = priv.private_numbers()
    n = nums.public_numbers.n
    d = nums.d
    k = (n.bit_length() + 7) // 8

    def sign(token):
        di = _SHA1_DIGESTINFO + token
        em = b"\x00\x01" + b"\xff" * (k - 3 - len(di)) + b"\x00" + di
        return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")

    return sign


def android_pubkey_b64(pubkey_pem_path):
    """Read the host adbkey.pub (already in Android RSAPublicKey format)."""
    with open(pubkey_pem_path, "r", encoding="utf-8") as f:
        return f.read().strip().split()[0]


class Conn:
    def __init__(self, host, port, timeout=8.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""

    def send(self, msg):
        self.s.sendall(encode(msg.cmd, msg.arg0, msg.arg1, msg.payload))

    def recv(self):
        while len(self.buf) < 24:
            chunk = self.s.recv(65536)
            if not chunk:
                return None
            self.buf += chunk
        cmd, arg0, arg1, dlen, crc, magic = struct.unpack("<6I", self.buf[:24])
        while len(self.buf) < 24 + dlen:
            chunk = self.s.recv(65536)
            if not chunk:
                return None
            self.buf += chunk
        payload = self.buf[24:24 + dlen]
        self.buf = self.buf[24 + dlen:]
        return Msg(cmd, arg0, arg1, payload, crc)

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    target = sys.argv[1] if len(sys.argv) > 1 else "10.206.33.5:5555"
    command = sys.argv[2] if len(sys.argv) > 2 else "id; getprop ro.build.type"
    host, port = target.rsplit(":", 1)
    port = int(port)

    home = os.path.expanduser("~")
    key = os.path.join(home, ".android", "adbkey")
    pub = os.path.join(home, ".android", "adbkey.pub")
    sign = load_key(key)

    c = Conn(host, port)
    print(f"[*] connected to {target}")

    banner = f"host::features=cmd,shell_v2\x00".encode()
    c.send(Msg(CMD_CNXN, A_VERSION, MAXDATA, banner))
    print("[*] sent CNXN")

    authed = False
    for attempt in range(6):
        m = c.recv()
        if m is None:
            print("[-] connection closed by adbd")
            return 1
        print(f"    <- {m}")
        if m.cmd == CMD_CNXN:
            print("[+] AUTH OK — device accepted our key")
            authed = True
            break
        if m.cmd == CMD_AUTH and m.arg0 == AUTH_TOKEN:
            sig = sign(m.payload)
            print(f"[*] signing {len(m.payload)}B token -> {len(sig)}B sig (attempt {attempt + 1})")
            c.send(Msg(CMD_AUTH, AUTH_SIGNATURE, 0, sig))
            continue
        if m.cmd == CMD_STLS:
            print("[-] adbd requested STLS (TLS). Not expected on localhost, aborting.")
            return 1
        print(f"[-] unexpected {m}")
        return 1

    if not authed:
        print("[-] auth failed after retries")
        return 1

    # open a shell stream
    local_id = 4391
    svc = f"shell,v2,TERM=dumb,raw:{command}\x00".encode()
    c.send(Msg(CMD_OPEN, local_id, 0, svc))
    print(f"[*] OPEN {svc!r}")

    remote_id = None
    out = bytearray()
    err = bytearray()
    exit_code = -1
    stdin_closed = False
    while True:
        m = c.recv()
        if m is None:
            print("[*] stream closed (EOF)")
            break
        if m.cmd == CMD_OKAY:
            remote_id = m.arg0
            if m.arg1 == local_id and not stdin_closed:
                print(f"[+] OKAY remote={remote_id}")
                # shell_v2: sid 4 closes stdin so nothing blocks waiting for it
                c.send(Msg(CMD_WRTE, local_id, remote_id, b"\x04\x00\x00\x00\x00"))
                stdin_closed = False
            continue
        if m.cmd == CMD_WRTE:
            # shell_v2 payload is a sequence of records, not a single header:
            #   [sid:1][len:4 little-endian][data:len]
            # sid: 0 stdin, 1 stdout, 2 stderr, 3 exit status, 4 close-stdin.
            # Treating the length word as data is what silently ate every
            # external command's output.
            p = m.payload
            i = 0
            while i + 5 <= len(p):
                sid = p[i]
                ln = int.from_bytes(p[i + 1:i + 5], "little")
                if i + 5 + ln > len(p):
                    break
                data = p[i + 5:i + 5 + ln]
                if sid == 1:
                    out += data
                elif sid == 2:
                    err += data
                elif sid == 3:
                    exit_code = data[0] if data else -1
                i += 5 + ln
            c.send(Msg(CMD_OKAY, local_id, m.arg0))
            continue
        if m.cmd == CMD_CLSE:
            print(f"[*] CLSE a0={m.arg0} a1={m.arg1}")
            break
        print(f"    <- {m}")

    c.close()
    print(f"[+] stdout={len(out)}B stderr={len(err)}B exit={exit_code}")
    if out:
        print("=== stdout ===")
        sys.stdout.buffer.write(bytes(out[:4096]))
        print("=== end ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
