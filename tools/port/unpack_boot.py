#!/usr/bin/env python3
"""Unpack a vivo Android boot partition into its kernel image.

Two quirks this handles that generic `unpack_bootimg` does not:

1. vivo stores the boot partition as a sequence of independent zstd frames, one
   per 32 MiB partition chunk, each followed by zero padding to the chunk
   boundary. The logical boot image is the concatenation of the decompressed
   chunks, so a single-frame decompress truncates it (that is why a plain
   `zstd -d boot.img` yields exactly 32 MiB and a kernel header claiming 49 MB).
2. The Android header is v4 with `ramdisk_size == 0` and the kernel starting at
   page 0 + 4096.

    python tools/port/unpack_boot.py boot.img -o out/            # -> out/kernel.bin
    python tools/port/unpack_boot.py boot.img --info
"""
import argparse
import json
import os
import re
import struct
import sys

ANDROID_MAGIC = b'ANDROID!'
ARM64_MAGIC = b'ARM\x64'
ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'
CHUNK = 32 * 1024 * 1024


def zstd_chunks(data):
    """Decompress every zstd frame, concatenating the chunk payloads."""
    import zstandard as zstd
    out = []
    pos = 0
    n = len(data)
    while pos < n:
        if data[pos:pos + 4] == ZSTD_MAGIC:
            dobj = zstd.ZstdDecompressor().decompressobj()
            out.append(dobj.decompress(data[pos:]))
            used = n - pos - len(dobj.unused_data)
            if used <= 0:
                raise SystemExit(f'zstd frame at {pos:#x} consumed nothing')
            pos += used
        else:
            # zero padding up to the next 32 MiB chunk boundary
            nxt = (pos // CHUNK + 1) * CHUNK
            while nxt < n and data[nxt:nxt + 4] != ZSTD_MAGIC:
                nxt += CHUNK
            if nxt >= n:
                break
            pos = nxt
    return b''.join(out)


def parse_boot_header(img):
    if img[:8] != ANDROID_MAGIC:
        raise SystemExit('not an Android boot image (no ANDROID! magic)')
    hdr = {
        'kernel_size': struct.unpack('<I', img[8:12])[0],
        'ramdisk_size': struct.unpack('<I', img[12:16])[0],
        'os_version': struct.unpack('<I', img[16:20])[0],
        'header_size': struct.unpack('<I', img[20:24])[0],
        'page_size': struct.unpack('<I', img[36:40])[0],
        'header_version': struct.unpack('<I', img[40:44])[0],
    }
    cmdline = img[44:44 + 512].split(b'\0', 1)[0].decode('utf-8', 'replace')
    hdr['cmdline'] = cmdline
    return hdr


def carve_kernel(img, hdr):
    hv = hdr['header_version']
    page = hdr['page_size'] or 4096
    if hv >= 3:
        off = 4096
    else:
        off = page
    size = hdr['kernel_size']
    kernel = img[off:off + size]
    if len(kernel) != size:
        raise SystemExit(f'logical image too small: want {size} kernel bytes '
                         f'at {off}, have {len(kernel)}')
    if kernel[56:60] != ARM64_MAGIC:
        raise SystemExit(f'kernel does not look like an arm64 Image '
                         f'(magic {kernel[56:60]!r} at +56)')
    return kernel, off


def image_info(kernel):
    return {
        'image_size': struct.unpack('<Q', kernel[16:24])[0],
        'text_offset': struct.unpack('<Q', kernel[8:16])[0],
        'flags': struct.unpack('<Q', kernel[24:32])[0],
    }


RELEASE_RE = re.compile(rb'Linux version (\d+\.\d+\.\d+[^\s()\x00]*)\s')


def kernel_release(kernel):
    """Return the UTX banner release string.

    The kernel also embeds the literal format string `Linux version %s (%s)`,
    so the first `Linux version ` hit is not necessarily the banner; only a
    token that starts with a numeric version is accepted.
    """
    for m in RELEASE_RE.finditer(kernel):
        return m.group(1).decode('utf-8', 'replace')
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('boot')
    ap.add_argument('-o', '--outdir', default='.')
    ap.add_argument('--info', action='store_true')
    args = ap.parse_args(argv)

    raw = open(args.boot, 'rb').read()
    if raw[:8] == ANDROID_MAGIC:
        img, chunks = raw, 0
    elif raw[:4] == ZSTD_MAGIC:
        img = zstd_chunks(raw)
        chunks = len(img) // CHUNK
    else:
        raise SystemExit(f'{args.boot}: unknown container '
                         f'(starts with {raw[:8].hex()})')

    hdr = parse_boot_header(img)
    kernel, off = carve_kernel(img, hdr)
    info = {'logical_image_size': len(img), 'chunks': chunks,
            'kernel_offset': off, **hdr, **image_info(kernel),
            'release': kernel_release(kernel)}

    if args.info:
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0

    os.makedirs(args.outdir, exist_ok=True)
    out = os.path.join(args.outdir, 'kernel.bin')
    with open(out, 'wb') as f:
        f.write(kernel)
    print(json.dumps({'out': out, 'size': len(kernel), 'release': info['release']},
                     ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
