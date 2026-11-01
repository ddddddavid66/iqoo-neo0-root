#!/usr/bin/env python3
"""Write a SHA256SUMS file for a directory tree.

    python tools/port/gen_checksums.py artifacts/5.15.137
    python tools/port/gen_checksums.py artifacts/5.15.137 --verify
"""
import argparse
import hashlib
import os
import sys


def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if name == 'SHA256SUMS':
                continue
            full = os.path.join(dirpath, name)
            yield full, os.path.relpath(full, root).replace(os.sep, '/')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('dir')
    ap.add_argument('--verify', action='store_true')
    args = ap.parse_args(argv)

    manifest = os.path.join(args.dir, 'SHA256SUMS')
    if args.verify:
        if not os.path.exists(manifest):
            raise SystemExit(f'{manifest} missing')
        bad = 0
        total = 0
        with open(manifest, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                digest, _, rel = line.partition('  ')
                total += 1
                path = os.path.join(args.dir, rel)
                if not os.path.exists(path):
                    print(f'MISSING {rel}')
                    bad += 1
                    continue
                got = sha256(path)
                if got != digest:
                    print(f'CHANGED {rel}\n  want {digest}\n  got  {got}')
                    bad += 1
        print(f'{"OK" if not bad else "FAIL"}: {total - bad}/{total} files verified')
        return 0 if not bad else 1

    entries = []
    for full, rel in walk(args.dir):
        entries.append((rel, sha256(full)))
    with open(manifest, 'w', encoding='utf-8', newline='\n') as f:
        for rel, digest in entries:
            f.write(f'{digest}  {rel}\n')
    print(f'wrote {manifest} ({len(entries)} files)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
