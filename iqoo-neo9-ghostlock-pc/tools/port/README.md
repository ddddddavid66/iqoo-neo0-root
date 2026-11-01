# tools/port — 把一台新固件接进 GhostLock

目标：给定一个 OTA 全量包（或 `boot.img` / 原始 arm64 `Image`），在 PC 上产出
一台设备可用的 GhostLock 内核 profile（`.conf`），并把每个字段的来源说清楚。
官方 `ghostlock-extract` 是 aarch64 Android 原生程序，只能在手机上跑；这里给出的
是纯 PC 的等价管线，并用它的输出做逐字段验收。

## 用法

```bash
# 1) OTA -> 分区镜像（payload_dumper 0.3.0 会在多 extent 上截断，必须用这个）
python tools/port/extract_payload.py payload.bin out/ boot xbl_config uefi
python tools/port/extract_payload.py payload.bin --list          # 只看清单

# 2) boot 分区 -> 内核 Image（vivo 把 boot 切成 N 段各 32 MiB 的独立 zstd frame）
python tools/port/unpack_boot.py out/boot.img -o out/           # -> out/kernel.bin
python tools/port/unpack_boot.py out/boot.img --info            # 头部/版本/大小

# 3) kallsyms + BTF
python tools/port/kernel_syms.py out/kernel.bin -o out/         # vmlinux.elf, symbols.json
python tools/port/kernel_btf.py out/kernel.bin -o out/kernel.btf --json out/structs.json

# 4) 组装 profile
python tools/port/derive_profile.py out/kernel.bin -o out/profile.conf \
    --workdir out --waiter-off 80

# 5) 验收：与官方提取器的黄金样本逐字段比对
python tools/port/derive_profile.py out/kernel.bin -o out/profile.conf --workdir out \
    --waiter-off 80 --diff golden/extractor-conf.conf \
    --skip vr_guard mcast offset.vr_sys_exit_tp

# 6) 编译成 native 吃的 blob，再解回来核对
ghostlock profile compile out/profile.conf -o out/profile.bin
python tools/port/blob_decode.py out/profile.bin

# 7) 资产校验
python tools/port/gen_checksums.py artifacts/<release>
python tools/port/gen_checksums.py artifacts/<release> --verify
```

## 字段来源总表

| profile 字段 | 来源 | 说明 |
|---|---|---|
| `release` | 内核镜像里的 UTX banner | 注意镜像里还有 `Linux version %s (%s)` 格式串，只认数字开头的 token |
| `kernel_major` | `release` 主版本 | 决定 `compact_waiter` 等分支 |
| `route` | 符号探测 | 5.x 有 `ip_mc_source` → `multicast_waiter`；否则 `core_sys_select`+`futex_wait` → `select_stack`；再否则 `tcp_zerocopy_receive` → `tcp_zerocopy` |
| `route.multicast_waiter.task_offset` / `lock_offset` | BTF `rt_mutex_waiter` | 本机 0x30 / 0x38 |
| `route.multicast_waiter.buffer_size` | 常量 264 | 伪造对象大小，与内核版本无关 |
| `route.multicast_waiter.waiter_off` | **不可离线推导** | 官方提取器用反汇编栈深度差算出（本机 `0x358-0x308=0x50`）；移植时用 `--waiter-off` 显式给值 |
| `kernelsnitch.collisions` | 常量 8 | 官方提取器对所有 5.15/6.x 都写 8 |
| `kernelsnitch.mm_struct_sz` | BTF `sizeof(mm_struct)` → slab 桶 | 992 → 1024 |
| `task_struct.*` | BTF | 15 个字段全部来自 `struct task_struct` |
| `cred.copy_size` | BTF `sizeof(cred)` | 176 |
| `cred.caps_offset` / `caps_count` / `caps_value` | BTF `cap_permitted` 起 3 段 | `caps_value = (1<<41)-1` |
| `cred.ref*_offset` | BTF `user`/`user_ns`/`ucounts`/`group_info` | 0x80/0x88/0x90/0x98 |
| `cred.ref*_image` | 符号地址的 i64 | `ext_root_user`（vivo 专有，缺失回退 `root_user`）/ `init_user_ns` / `init_ucounts` / `init_groups` |
| `offset.init_task` 等 | 符号 − `_text` | 包括 `empty_zero_page`、`root_task_group`、`selinux_blob_sizes`、`security_hook_heads` |
| `offset.selinux_enforcing` | 符号 `selinux_state` | 该内核没有单独的 `selinux_enforcing` 符号，取 `selinux_state` 地址（实测与官方输出一致） |
| `offset.slide_nfulnl_logger` | 符号 `nfulnl_logger` | — |
| `offset.slide_loggers_0_1` | 官方输出导入（`loggers`+8） | 数组在镜像里全 0（启动期才注册），下标不可读；`--from-extractor` 时按出处导入 |
| `offset.slide_boot_id` | 符号 `sysctl_bootid` | 未按 8 对齐（字符数组），官方输出也是这个值 |
| `offset.vr_sys_exit_tp` | 符号 `__tracepoint_sys_exit` | 已定：给 tracepoint 基址，`.funcs` 的 0x40 由 payload 自己加（真机日志证实） |
| `execution.*` / `mcast.*` / `vr_guard.*` | 同机型已实测配置 | 与内核版本无关；`--includes` 可改成 `include` 共享 preset |

## 已在 5.15.137 上验证的结论

- `extract_payload.py` 复现的分区与旧脚本逐字节一致；`unpack_boot.py` 复现的
  `kernel.bin` 与手工切出的完全相同（sha256 相等）。
- `kernel_btf.py` 取出的 BTF blob 与镜像内嵌段逐字节一致。
- `derive_profile.py` 产出的 **54 个内核相关字段与官方 `ghostlock-extract`
  的黄金样本全等**；另有 26 个只属于调优段的字段，与仓库内已实测的
  5.15.197 profile 全等（38/38）。
- `waiter_off` 仍不可离线推导（用 `--from-extractor` 带出处导入）；`vr_sys_exit_tp` 语义已由真机日志确认。
- 真机结果：`PD2338_A_14.0.17.6.W10.V000L1` 上 `su -c id` → `uid=0(root) context=u:r:ksu:s0`，`kernelsu`/`vrpatch` 均在 `/proc/modules`。
