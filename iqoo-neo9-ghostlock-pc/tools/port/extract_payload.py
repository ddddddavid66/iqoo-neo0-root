#!/usr/bin/env python3
"""Extract partitions from an Android A/B OTA payload.bin.

The upstream `payload_dumper` 0.3.0 writes only the first destination extent of
each operation, which truncates images whose ops carry several extents (vivo
splits `boot` into three 32 MiB chunks). This tool assigns the decompressed
buffer across every extent in order and pre-truncates the output to the real
partition size.

    python tools/port/extract_payload.py payload.bin out/ boot xbl_config uefi
    python tools/port/extract_payload.py payload.bin --list
"""
import argparse
import bz2
import lzma
import os
import struct
import sys

try:
    import payload_dumper.update_metadata_pb2 as um
except ImportError:  # pragma: no cover
    sys.exit('missing dependency: pip install payload_dumper')

OP_REPLACE, OP_REPLACE_BZ, OP_ZERO, OP_REPLACE_XZ = 0, 1, 6, 8
OP_NAMES = {0: 'REPLACE', 1: 'REPLACE_BZ', 6: 'ZERO', 8: 'REPLACE_XZ'}
MAGIC = b'CrAU'


class Payload:
    def __init__(self, path):
        self.path = path
        self.fh = open(path, 'rb')
        magic = self.fh.read(4)
        if magic != MAGIC:
            raise SystemExit(f'{path}: not a payload (magic {magic!r})')
        self.version = struct.unpack('>Q', self.fh.read(8))[0]
        manifest_size = struct.unpack('>Q', self.fh.read(8))[0]
        sig_size = struct.unpack('>I', self.fh.read(4))[0] if self.version > 1 else 0
        manifest = self.fh.read(manifest_size)
        self.signature = self.fh.read(sig_size)
        self.data_offset = self.fh.tell()
        self.manifest = um.DeltaArchiveManifest()
        self.manifest.ParseFromString(manifest)
        self.block_size = self.manifest.block_size

    def partitions(self):
        return {p.partition_name: p for p in self.manifest.partitions}

    def size_of(self, part):
        blocks = sum(e.num_blocks for op in part.operations for e in op.dst_extents)
        return blocks * self.block_size

    def extract(self, name, out_path):
        parts = self.partitions()
        if name not in parts:
            raise SystemExit(f'no partition {name!r}; have: {sorted(parts)}')
        part = parts[name]
        size = self.size_of(part)
        with open(out_path, 'wb') as out:
            out.truncate(size)
            for op in part.operations:
                self.fh.seek(self.data_offset + op.data_offset)
                data = self.fh.read(op.data_length)
                if op.type == OP_REPLACE_XZ:
                    data = lzma.LZMADecompressor().decompress(data)
                elif op.type == OP_REPLACE_BZ:
                    data = bz2.BZ2Decompressor().decompress(data)
                elif op.type == OP_ZERO:
                    data = b''
                elif op.type != OP_REPLACE:
                    raise SystemExit(f'{name}: unsupported op type {op.type}')
                pos = 0
                for ext in op.dst_extents:
                    if pos >= len(data):
                        break
                    nbytes = ext.num_blocks * self.block_size
                    out.seek(ext.start_block * self.block_size)
                    if op.type == OP_ZERO:
                        out.write(b'\0' * nbytes)
                        continue
                    # vivo/aosp payloads may carry less data than the extent
                    # covers; the tail of the extent stays zero (pre-truncated).
                    chunk = data[pos:pos + nbytes]
                    out.write(chunk)
                    pos += len(chunk)
                if pos < len(data):
                    raise SystemExit(
                        f'{name}: trailing data ({len(data) - pos} B) does not fit '
                        f'the declared extents')
        return size


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('payload')
    ap.add_argument('outdir', nargs='?', default='.')
    ap.add_argument('partitions', nargs='*')
    ap.add_argument('--list', action='store_true', help='list partitions and exit')
    args = ap.parse_args(argv)

    p = Payload(args.payload)
    parts = p.partitions()
    if args.list or not args.partitions:
        print(f'payload: version={p.version} block={p.block_size} '
              f'partitions={len(parts)} data_offset={p.data_offset}')
        for name in sorted(parts):
            print(f'  {name:24s} {p.size_of(parts[name]):>12d} B')
        return 0

    os.makedirs(args.outdir, exist_ok=True)
    for name in args.partitions:
        out = os.path.join(args.outdir, name + '.img')
        size = p.extract(name, out)
        print(f'{name}: {size} bytes -> {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
