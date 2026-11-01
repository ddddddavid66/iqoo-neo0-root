#!/usr/bin/env python3
"""Recover the kallsyms table of a stripped arm64 kernel Image into an ELF.

Thin wrapper on `vmlinux-to-elf` so the port pipeline has one reproducible call:

    python tools/port/kernel_syms.py artifacts/5.15.137/kernel.bin -o build/t1/
    # -> build/t1/vmlinux.elf, build/t1/symbols.json

`symbols.json` holds the base address plus the offsets (`sym - base`) the GhostLock
profile needs, because the profile stores everything relative to `_text`.
"""
import argparse
import json
import os
import sys

# Symbols the GhostLock profile encodes as `sym - _text`.
WANTED = [
    '_text', '_head',
    'init_task', 'init_cred', 'empty_zero_page', 'root_task_group',
    'selinux_enforcing', 'selinux_state', 'selinux_blob_sizes', 'security_hook_heads',
    'nfulnl_logger', 'loggers', 'boot_id', 'sysctl_bootid',
    '__tracepoint_sys_exit',
    'init_user_ns', 'init_ucounts', 'init_groups', 'root_user', 'ext_root_user',
    # route probes: which exploitation path this kernel supports
    'ip_mc_source', 'ip_mc_msfadd', 'core_sys_select', 'futex_wait',
    'tcp_zerocopy_receive',
]


def find_btf_offset(kernel):
    """Return the BTF blob offset/size inside a raw arm64 Image, or None."""
    import struct
    i = kernel.find(b'\x9f\xeb\x01\x00')
    while i != -1:
        if i + 24 <= len(kernel):
            magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = \
                struct.unpack('<HBBIIIII', kernel[i:i + 24])
            total = hdr_len + type_off + type_len + str_off + str_len
            strs = kernel[i + hdr_len + type_off + str_off:
                          i + hdr_len + type_off + str_off + 24]
            if magic == 0xeb9f and hdr_len == 24 and 0 < total < len(kernel) and \
                    type_len > 0 and str_len > 0 and strs.startswith(b'\x00'):
                return i, total
        i = kernel.find(b'\x9f\xeb\x01\x00', i + 1)
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('kernel')
    ap.add_argument('-o', '--outdir', default='.')
    ap.add_argument('--elf-only', action='store_true')
    args = ap.parse_args(argv)

    from vmlinux_to_elf.core.kallsyms import KallsymsFinder
    from vmlinux_to_elf.core.elf_symbolizer import ElfSymbolizer

    kernel = open(args.kernel, 'rb').read()
    os.makedirs(args.outdir, exist_ok=True)

    finder = KallsymsFinder(kernel)
    # `symbol_addresses` stays None until the table is parsed; the parsed
    # `symbols` list carries the decoded virtual addresses.
    pairs = [(s.name, s.virtual_address) for s in finder.symbols]
    names = [n for n, _ in pairs]
    addrs = [a for _, a in pairs]
    base = finder.kernel_text_candidate
    info = {
        'kernel': os.path.abspath(args.kernel),
        'size': len(kernel),
        'symbols': len(names),
        'base': base,
        'btf': None,
    }
    btf = find_btf_offset(kernel)
    if btf:
        info['btf'] = {'offset': btf[0], 'size': btf[1]}

    elf_path = os.path.join(args.outdir, 'vmlinux.elf')
    ElfSymbolizer(kernel, output_file=elf_path, base_address=base)
    info['elf'] = os.path.abspath(elf_path)

    if not args.elf_only:
        table = {}
        for n, a in zip(names, addrs):
            if n in WANTED and n not in table:
                table[n] = a
        wanted = {
            'base': base,
            'offsets': {n: a - base for n, a in table.items()},
            'addresses': table,
            'missing': [n for n in WANTED if n not in table],
        }
        js = os.path.join(args.outdir, 'symbols.json')
        with open(js, 'w', encoding='utf-8') as f:
            json.dump(wanted, f, indent=2, sort_keys=True)
        info['symbols_json'] = os.path.abspath(js)
        info['missing'] = wanted['missing']

    print(json.dumps(info, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
