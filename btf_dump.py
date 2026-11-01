#!/usr/bin/env python3
"""Minimal BTF parser: dump struct member bit offsets for named structs."""
import struct, sys

BTF_KIND_INT, BTF_KIND_PTR, BTF_KIND_ARRAY, BTF_KIND_STRUCT = 1, 2, 3, 4
BTF_KIND_UNION, BTF_KIND_ENUM, BTF_KIND_FWD, BTF_KIND_TYPEDEF = 5, 6, 7, 8
BTF_KIND_VOLATILE, BTF_KIND_CONST, BTF_KIND_RESTRICT = 9, 10, 11
BTF_KIND_FUNC, BTF_KIND_FUNC_PROTO, BTF_KIND_VAR, BTF_KIND_DATASEC = 12, 13, 14, 15
BTF_KIND_FLOAT, BTF_KIND_DECL_TAG, BTF_KIND_TYPE_TAG, BTF_KIND_ENUM64 = 16, 17, 18, 19


class BTF:
    def __init__(self, blob):
        magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack(
            '<HBBIIIII', blob[:24])
        assert magic == 0xeb9f, hex(magic)
        self.strs = blob[hdr_len + str_off: hdr_len + str_off + str_len]
        raw = blob[hdr_len + type_off: hdr_len + type_off + type_len]
        self.types = [None]  # index 0 = void
        p = 0
        while p < len(raw):
            name_off, info, size = struct.unpack('<III', raw[p:p + 12])
            p += 12
            kind = (info >> 24) & 0x1f
            vlen = info & 0xffff
            rec = {'name_off': name_off, 'kind': kind, 'vlen': vlen, 'size': size,
                   'kflag': (info >> 31) & 1, 'members': [], 'extra': None}
            if kind in (BTF_KIND_STRUCT, BTF_KIND_UNION):
                for _ in range(vlen):
                    mo, mt, moff = struct.unpack('<III', raw[p:p + 12])
                    p += 12
                    if rec['kflag']:
                        bit_off, bit_sz = moff & 0xffffff, moff >> 24
                    else:
                        bit_off, bit_sz = moff, 0
                    rec['members'].append((mo, mt, bit_off, bit_sz))
            elif kind == BTF_KIND_INT:
                rec['extra'] = struct.unpack('<I', raw[p:p + 4])[0]
                p += 4
            elif kind == BTF_KIND_ENUM:
                p += 8 * vlen
            elif kind == BTF_KIND_ENUM64:
                p += 12 * vlen
            elif kind == BTF_KIND_ARRAY:
                rec['extra'] = struct.unpack('<III', raw[p:p + 12])
                p += 12
            elif kind == BTF_KIND_FUNC_PROTO:
                rec['extra'] = [struct.unpack('<II', raw[p + 8 * i:p + 8 * i + 8]) for i in range(vlen)]
                p += 8 * vlen
            elif kind == BTF_KIND_VAR:
                rec['extra'] = struct.unpack('<I', raw[p:p + 4])[0]
                p += 4
            elif kind == BTF_KIND_DATASEC:
                p += 12 * vlen
            elif kind == BTF_KIND_DECL_TAG:
                p += 4
            self.types.append(rec)

    def name(self, off):
        if off == 0:
            return ''
        end = self.strs.find(b'\0', off)
        return self.strs[off:end].decode('utf-8', 'replace')

    def find(self, kind, name):
        return [i for i, t in enumerate(self.types)
                if t and t['kind'] == kind and self.name(t['name_off']) == name]

    def show_struct(self, name, verbose=True):
        ids = self.find(BTF_KIND_STRUCT, name)
        if not ids:
            print(f'!! struct {name} not found')
            return None
        for i in ids:
            t = self.types[i]
            print(f'== struct {name} id={i} size={t["size"]} ({hex(t["size"])}) members={t["vlen"]}')
            if verbose:
                for mo, mt, bo, bs in t['members']:
                    tn = self.types[mt]
                    tk = tn['kind'] if tn else 0
                    print(f'   +{bo//8:#5x} {self.name(mo):32s} type#{mt} kind={tk}')
            return t
        return None

    def size_of(self, name, kind=BTF_KIND_STRUCT):
        ids = self.find(kind, name)
        return self.types[ids[0]]['size'] if ids else None


def extract(blob, offset):
    return blob[offset:]


if __name__ == '__main__':
    path = sys.argv[1]
    blob = open(path, 'rb').read()
    if blob[:2] != b'\x9f\xeb':
        raise SystemExit('not a btf blob')
    btf = BTF(blob)
    for n in sys.argv[2:]:
        if n.startswith('size:'):
            nm = n.split(':', 1)[1]
            print(f'sizeof({nm}) =', btf.size_of(nm), btf.size_of(nm, BTF_KIND_UNION))
        else:
            btf.show_struct(n)
