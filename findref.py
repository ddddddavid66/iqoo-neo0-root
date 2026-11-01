#!/usr/bin/env python3
"""Locate aarch64 code referencing given strings and disassemble it."""
import struct, sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def load(path):
    f = open(path, 'rb')
    e = ELFFile(f)
    text = e.get_section_by_name('.text')
    ro = e.get_section_by_name('.rodata')
    return e, text, ro


def str_va(e, needle):
    for sec in e.iter_sections():
        if sec['sh_type'] not in ('SHT_PROGBITS',):
            continue
        data = sec.data()
        i = data.find(needle)
        while i != -1:
            yield sec, sec['sh_addr'] + i, i
            i = data.find(needle, i + 1)


def find_refs(text, target_va, code_va_base):
    """Find adrp+add or adrp+ldr pairs landing on target_va."""
    data = text.data()
    hits = []
    for off in range(0, len(data) - 8, 4):
        insn = struct.unpack('<I', data[off:off + 4])[0]
        # ADRP: 1xx10000 in top bits
        if (insn & 0x9f000000) != 0x90000000:
            continue
        rd = insn & 0x1f
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        pc = code_va_base + off
        page = (pc & ~0xfff) + (imm << 12)
        nxt = struct.unpack('<I', data[off + 4:off + 8])[0]
        # ADD (imm, 64-bit): 1001000100...
        if (nxt & 0x7f000000) == 0x11000000 or (nxt & 0x7f000000) == 0x11000000:
            pass
        if (nxt & 0xffc00000) == 0x91000000:
            rn = (nxt >> 5) & 0x1f
            imm12 = (nxt >> 10) & 0xfff
            sh = (nxt >> 22) & 1
            if rn == rd:
                addr = page + (imm12 << (12 if sh else 0))
                if addr == target_va:
                    hits.append((pc, off))
        # LDR (unsigned offset) from the page base
        if (nxt & 0xffc00000) == 0xf9400000:
            rn = (nxt >> 5) & 0x1f
            imm12 = (nxt >> 10) & 0xfff
            if rn == rd:
                addr = page + imm12 * 8
                if addr == target_va:
                    hits.append((pc, off))
    return hits


def disasm_range(text, start_va, n, md):
    data = text.data()
    start = start_va - text['sh_addr']
    code = data[max(0, start - 0x80): start + n]
    base = start_va - 0x80 if start >= 0x80 else text['sh_addr']
    out = []
    for i in md.disasm(code, base):
        out.append(f'{i.address:#x}: {i.mnemonic:8s} {i.op_str}')
    return out


if __name__ == '__main__':
    path = sys.argv[1]
    needles = sys.argv[2:]
    e, text, ro = load(path)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    for needle in needles:
        nb = needle.encode()
        print(f'##### searching {needle!r}')
        for sec, va, i in str_va(e, nb):
            print(f'  string at {sec.name}+{i:#x} va={va:#x}')
            for pc, off in find_refs(text, va, text['sh_addr']):
                print(f'  ref at {pc:#x} (text+{off:#x})')
                for line in disasm_range(text, pc, 0x60, md):
                    print('    ' + line)
