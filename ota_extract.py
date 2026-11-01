#!/usr/bin/env python3
"""Correct A/B payload.bin partition extractor (handles multi-extent ops)."""
import bz2, lzma, os, struct, sys
import payload_dumper.update_metadata_pb2 as um

OP_REPLACE, OP_REPLACE_BZ, OP_ZERO, OP_REPLACE_XZ = 0, 1, 6, 8


def load(path):
    f = open(path, 'rb')
    assert f.read(4) == b'CrAU'
    ver = struct.unpack('>Q', f.read(8))[0]
    msz = struct.unpack('>Q', f.read(8))[0]
    sigsz = struct.unpack('>I', f.read(4))[0] if ver > 1 else 0
    man = f.read(msz)
    f.read(sigsz)
    dam = um.DeltaArchiveManifest()
    dam.ParseFromString(man)
    return f, dam, f.tell()


def extract(payload, part, outpath):
    f, dam, data_off = load(payload)
    names = [p.partition_name for p in dam.partitions]
    if part not in names:
        raise SystemExit(f'no partition {part}; have {names}')
    p = dam.partitions[names.index(part)]
    total_blocks = sum(e.num_blocks for op in p.operations for e in op.dst_extents)
    size = total_blocks * dam.block_size
    with open(outpath, 'wb') as out:
        out.truncate(size)
        for op in p.operations:
            f.seek(data_off + op.data_offset)
            data = f.read(op.data_length)
            t = op.type
            if t == OP_REPLACE_XZ:
                data = lzma.LZMADecompressor().decompress(data)
            elif t == OP_REPLACE_BZ:
                data = bz2.BZ2Decompressor().decompress(data)
            elif t == OP_ZERO:
                data = b''
            elif t != OP_REPLACE:
                raise SystemExit(f'unsupported op type {t} in {part}')
            pos = 0
            for e in op.dst_extents:
                n = e.num_blocks * dam.block_size
                if t == OP_ZERO:
                    out.seek(e.start_block * dam.block_size)
                    out.write(b'\0' * n)
                else:
                    out.seek(e.start_block * dam.block_size)
                    out.write(data[pos:pos + n])
                    pos += n
    return size


if __name__ == '__main__':
    payload = sys.argv[1]
    for name in sys.argv[2:]:
        out = os.path.join(os.path.dirname(payload), name + '.img')
        n = extract(payload, name, out)
        print(f'{name}: {n} bytes -> {out}')
