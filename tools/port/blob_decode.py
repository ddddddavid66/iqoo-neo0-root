#!/usr/bin/env python3
"""Decode a GhostLock `profile.bin` blob back into key/value pairs.

Format (from the project README):

    u32 magic 0x0D000721 | u16 version=2 | u16 frontend | u16 backend | u16 route
    u16 releaseLen | u16 0 | release bytes | u16 sectionCount
      per section: u8 nameLen + name + u32 entryCount
        per entry: u8 keyLen + key + i64 value

    python tools/port/blob_decode.py build/profile.bin            # print
    python tools/port/blob_decode.py build/profile.bin --json out.json
"""
import argparse
import json
import struct
import sys

MAGIC = 0x0D000721


def decode(blob):
    p = 0
    magic, version, frontend, backend, route = struct.unpack_from('<IHHHH', blob, p)
    p += 12
    if magic != MAGIC:
        raise SystemExit(f'bad magic {magic:#x} (want {MAGIC:#x})')
    rel_len, _reserved = struct.unpack_from('<HH', blob, p)
    p += 4
    release = blob[p:p + rel_len].decode('utf-8')
    p += rel_len
    (count,) = struct.unpack_from('<H', blob, p)
    p += 2
    sections = {}
    for _ in range(count):
        (n,) = struct.unpack_from('<B', blob, p)
        p += 1
        name = blob[p:p + n].decode('utf-8')
        p += n
        (entries,) = struct.unpack_from('<I', blob, p)
        p += 4
        kv = {}
        for _ in range(entries):
            (kn,) = struct.unpack_from('<B', blob, p)
            p += 1
            key = blob[p:p + kn].decode('utf-8')
            p += kn
            (val,) = struct.unpack_from('<q', blob, p)
            p += 8
            kv[key] = val
        sections[name] = kv
    if p != len(blob):
        sections['__trailing_bytes__'] = {'n': len(blob) - p}
    return {'version': version, 'frontend': frontend, 'backend': backend,
            'route': route, 'release': release, 'sections': sections}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('blob')
    ap.add_argument('--json')
    args = ap.parse_args(argv)
    out = decode(open(args.blob, 'rb').read())
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2, sort_keys=True)
        print(json.dumps({'out': args.json, 'release': out['release'],
                          'route': out['route'],
                          'sections': sorted(out['sections'])}, ensure_ascii=False))
        return 0
    print(f'release={out["release"]} route={out["route"]} '
          f'frontend={out["frontend"]} backend={out["backend"]}')
    for name, kv in out['sections'].items():
        print(f'[{name}]')
        for k, v in kv.items():
            print(f'  {k} = {v}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
