#!/usr/bin/env python3
"""Locate and parse the BTF blob embedded in a raw arm64 kernel Image.

Gives the struct member offsets the GhostLock profile needs, without pahole:

    python tools/port/kernel_btf.py artifacts/5.15.137/kernel.bin -o build/t1/kernel.btf
    python tools/port/kernel_btf.py artifacts/5.15.137/kernel.bin --show task_struct cred
    python tools/port/kernel_btf.py artifacts/5.15.137/kernel.bin --json build/t1/structs.json
"""
import argparse
import json
import struct
import sys

K_STRUCT, K_UNION, K_ENUM, K_INT = 4, 5, 6, 1
K_ARRAY, K_ENUM64, K_DECL_TAG = 3, 19, 17


class BTF:
    def __init__(self, blob):
        magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = \
            struct.unpack('<HBBIIIII', blob[:24])
        if magic != 0xeb9f:
            raise ValueError(f'bad BTF magic {magic:#x}')
        self.hdr_len = hdr_len
        self.strs = blob[hdr_len + str_off: hdr_len + str_off + str_len]
        raw = blob[hdr_len + type_off: hdr_len + type_off + type_len]
        self.types = [None]
        p = 0
        while p + 12 <= len(raw):
            name_off, info, size = struct.unpack('<III', raw[p:p + 12])
            p += 12
            kind = (info >> 24) & 0x1f
            vlen = info & 0xffff
            kflag = (info >> 31) & 1
            rec = {'name': self.name(name_off), 'kind': kind, 'vlen': vlen,
                   'size': size, 'kflag': kflag, 'members': []}
            if kind in (K_STRUCT, K_UNION):
                for _ in range(vlen):
                    mo, mt, moff = struct.unpack('<III', raw[p:p + 12])
                    p += 12
                    if kflag:
                        bit_off, bit_sz = moff & 0xffffff, moff >> 24
                    else:
                        bit_off, bit_sz = moff, 0
                    rec['members'].append((self.name(mo), mt, bit_off, bit_sz))
            elif kind == K_INT:
                p += 4
            elif kind == K_ENUM:
                p += 8 * vlen
            elif kind == K_ENUM64:
                p += 12 * vlen
            elif kind == K_ARRAY:
                p += 12
            elif kind in (12, 13):  # FUNC / FUNC_PROTO
                p += 8 * vlen
            elif kind == 14:  # VAR
                p += 4
            elif kind == 15:  # DATASEC
                p += 12 * vlen
            elif kind == K_DECL_TAG:
                p += 4
            self.types.append(rec)

    def name(self, off):
        if not off:
            return ''
        end = self.strs.find(b'\0', off)
        return self.strs[off:end].decode('utf-8', 'replace')

    def struct(self, name):
        for t in self.types:
            if t and t['kind'] in (K_STRUCT, K_UNION) and t['name'] == name:
                return t
        return None

    def member_offsets(self, name):
        t = self.struct(name)
        if not t:
            return None
        return {m[0]: m[2] // 8 for m in t['members'] if m[0]}

    def size_of(self, name):
        t = self.struct(name)
        return t['size'] if t else None


def find_btf(kernel):
    i = kernel.find(b'\x9f\xeb\x01\x00')
    while i != -1:
        if i + 24 <= len(kernel):
            magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = \
                struct.unpack('<HBBIIIII', kernel[i:i + 24])
            total = hdr_len + type_off + type_len + str_off + str_len
            strs = kernel[i + hdr_len + type_off + str_off:
                          i + hdr_len + type_off + str_off + 16]
            if magic == 0xeb9f and hdr_len == 24 and type_len and str_len and \
                    0 < total <= len(kernel) - i and strs.startswith(b'\x00'):
                return i, total
        i = kernel.find(b'\x9f\xeb\x01\x00', i + 1)
    return None


# task_struct members the profile encodes, in blob order
TASK_KEYS = ['prio', 'normal_prio', 'sched_task_group', 'pi_lock', 'pi_waiters',
             'pi_top_task', 'pi_blocked_on', 'pid', 'tgid', 'atomic_flags',
             'real_cred', 'cred', 'comm', 'tasks', 'seccomp']
# cred members backing the credential template
CRED_REFS = ['user', 'user_ns', 'ucounts', 'group_info']
CRED_KEYS = ['usage', 'cap_permitted', 'cap_effective', 'cap_bset', 'cap_ambient']


def dump_structs(btf):
    out = {'task_struct': {}, 'cred': {}, 'rt_mutex_waiter': {}, 'sizes': {}}
    ts = btf.member_offsets('task_struct')
    cred = btf.member_offsets('cred')
    waiter = btf.member_offsets('rt_mutex_waiter')
    if not (ts and cred and waiter):
        raise SystemExit('BTF is missing task_struct/cred/rt_mutex_waiter')
    out['task_struct'] = {k: ts[k] for k in TASK_KEYS if k in ts}
    out['task_struct_missing'] = [k for k in TASK_KEYS if k not in ts]
    out['cred'] = {k: cred[k] for k in CRED_KEYS if k in cred}
    out['cred_refs'] = {k: cred[k] for k in CRED_REFS if k in cred}
    out['rt_mutex_waiter'] = {k: waiter[k] for k in
                              ('tree_entry', 'pi_tree_entry', 'task', 'lock',
                               'wake_state', 'ww_ctx') if k in waiter}
    for n in ('cred', 'rt_mutex_waiter', 'mm_struct', 'tracepoint',
              'tracepoint_func', 'selinux_state'):
        out['sizes'][n] = btf.size_of(n)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('kernel')
    ap.add_argument('-o', '--out', help='write the raw .btf blob here')
    ap.add_argument('--show', nargs='*', metavar='STRUCT')
    ap.add_argument('--json', help='write struct offsets here')
    args = ap.parse_args(argv)

    kernel = open(args.kernel, 'rb').read()
    found = find_btf(kernel)
    if not found:
        raise SystemExit('no embedded BTF found')
    off, size = found
    blob = kernel[off:off + size]
    btf = BTF(blob)

    if args.out:
        with open(args.out, 'wb') as f:
            f.write(blob)
    if args.show:
        for n in args.show:
            t = btf.struct(n)
            if not t:
                print(f'{n}: not found')
                continue
            print(f'struct {n} size={t["size"]} ({t["size"]:#x}) members={t["vlen"]}')
            for mname, mt, bo, bs in t['members']:
                print(f'  +{bo // 8:#6x} {mname}')
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump({'btf_offset': off, 'btf_size': size, **dump_structs(btf)},
                      f, indent=2, sort_keys=True)

    if not (args.out or args.show or args.json):
        print(json.dumps({'btf_offset': off, 'btf_size': size,
                          **dump_structs(btf)}, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
