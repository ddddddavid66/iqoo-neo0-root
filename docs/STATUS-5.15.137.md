# 状态：iQOO Neo9 5.15.137 移植 + 真机 root

时间：2026-11-01 02:5x

## 结论

- **移植完成**：`tools/port/` 纯 PC 管线可从 OTA 复现整条链路，54 个内核字段与官方
  `ghostlock-extract` 输出全等；干净目录重跑得到**逐字节相同**的 `kernel.bin`、
  `kernel.btf` 与**完全相同**的 profile.conf。
- **真机 root 达成**：`su -c id` → `uid=0(root) context=u:r:ksu:s0`，
  `/proc/modules` 里有 `kernelsu` 与 `vrpatch`。root 只在内存，硬重启即失效。

## Review 发现并修掉的问题

| # | 问题 | 证据 | 修复 |
|---|---|---|---|
| 1 | 官方 root 脚本找不到 ksud（SukiSU 伪装包把 `libksud.so` 改名成 `libdhxddxovny.so`），`[!] ksud missing`，late-load 不执行 | `ksu-*.log`：`[*] ksud=/data/adb/ksu/bin/ksud` → `[!] ksud missing` | `stage.Push` 用 `ksudForPackage`（含「最大 .so」回退）把真实 ksud 复制到 `/data/local/tmp/ksud`；`discoverKsud` 同样加回退 |
| 2 | 设备高负载时 `AliveFast` 单次 8s 探活失败 → 把「刚好成功」误判成 panic | 尝试 B/C 已拿到 root，工具却报 panic | `AliveFast` 改为 8s/15s/15s 三次重试 |
| 3 | 成功判据只认 ksu 日志里的 `KernelSU module loaded`；脚本被杀就没有该行 | 同 2 | `fire()` 在 handoff 后追加 `su -c id` 事实判定；`loop` 在连接掉线并回连后再探一次 `su` |
| 4 | `vr_sys_exit_tp` 语义未定，早期还留了 `funcs/iterator` 模式 | 日志 `image=ffffffc082f0c708`，低位 `0x2f0c708 = tp_off(0x2f0c6c8) + 0x40` | 语义定为「tracepoint 基址」，`.funcs` 偏移由 payload 自己加；删掉会写错 +0x80 的其它模式 |
| 5 | `slide_loggers_0_1` 用硬编码 slot=1 | 官方 conf 值为 `loggers+8` | 改为 `--from-extractor` 按出处导入，保留公式回退 |
| 6 | 文档说 `payload_dumper` 「多 extent 截断」，表述不准 | 实际是「不补齐分区尾部」+ boot 三帧 zstd | 已改写说明 |

## 复核过的、确认无误的部分

- `offset.*` 每个值都与**真机 `/proc/kallsyms`** 对齐（把 `kptr_restrict` 从 2 改成 0 后读过一次）：
  `init_task`、`init_cred`、`selinux_state`、`nfulnl_logger`、`loggers`、`sysctl_bootid`、
  `__tracepoint_sys_exit`、`ext_root_user`、`init_user_ns/init_ucounts/init_groups` 全部一致。
- `cred.ref0_image` 必须是 `ext_root_user`（vivo 专有），用 `root_user` 会偏 0x1320。
- `caps_value = 2199023255551`（`0x1ffffffffff`，41 位）：实测 `CapPrm/CapEff/CapBnd = 000001ffffffffff`，一致。
- BTF 结构偏移（task_struct 15 项、cred、rt_mutex_waiter、mm_struct 992→1024）与官方输出逐字段相等。
- blob 编码/解码 13 个 section，`waiter_off=80`、`execution.*` 非零、`vr_guard.tracepoint_funcs=64`。
- `go vet ./...`、`go test ./...` 全绿（含新增 `TestResolveNeo9_5137` 锁 30 个字段 + `Validate()` + `InvalidPaths` 为空）。

## 仍然存在的已知限制

1. `route.multicast_waiter.waiter_off` 不能从镜像推导（栈槽级差异），用 `--from-extractor` 带出处导入。
2. `pselect_waiter_shift` 在本机推导失败（`-248`），`select_stack` 路由不可用。
3. `kernel_phys_load/offset` 走运行时 SoC 回退（xbl_config/uefi 都没有 Kernel memory-map）。
4. 命中率是概率性的：本轮 9 次发射中命中 3 次，失败形态是内核 panic 自动重启。

## 修复后的干净验证（2026-11-01 03:2x）

命令：`ghostlock run --loop --rounds 6 --per-boot 2 --reboot-first --force-attack`

```
[*] 先重启，抢开机窗口…
第 1 轮 / 第 1 次（uptime=32s）→ === native exit=1      ← 干净未中
第 1 轮 / 第 2 次（uptime=43s）→ [+] 成功：root 已在（KernelSU late-load）
```

结果：`su -c id` → `uid=0(root) context=u:r:ksu:s0`，`/proc/modules` 有
`kernelsu` + `vrpatch`，`getenforce` → `Enforcing`（脚本收尾时恢复）。

这一次成功判定走的是 **ksu 日志里的 `KernelSU module loaded`** 路径，
说明修复后的判定链路正常；此前「打中了却报 panic」的情况也已有 `su -c id` 兜底。

同一轮里还修掉一个窗口 bug：`per-boot` 的第二次发射原先不重读 uptime，
在 uptime 200s+ 时仍会空放一枪；现在每次发射前重读，超出窗口就改为重启再打。

## 复现

```bash
# 离线重建（干净目录，逐字节可复现）
python tools/port/extract_payload.py ota/payload.bin build/t2 boot
python tools/port/unpack_boot.py build/t2/boot.img -o build/t2
python tools/port/kernel_syms.py build/t2/kernel.bin -o build/t2
python tools/port/kernel_btf.py build/t2/kernel.bin -o build/t2/kernel.btf --json build/t2/structs.json
python tools/port/derive_profile.py build/t2/kernel.bin -o build/t2/profile.conf --workdir build/t2 \
    --from-extractor artifacts/5.15.137/extractor-conf.conf \
    --diff artifacts/5.15.137/extractor-conf.conf --skip vr_guard mcast offset.vr_sys_exit_tp

# 真机（root 只在内存，重启后重跑）
ghostlock run --loop --rounds 6 --per-boot 2
```
