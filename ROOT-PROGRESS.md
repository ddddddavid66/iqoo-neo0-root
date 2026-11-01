# iQOO Neo9 (PD2338) GhostLock root — 进度与续跑说明

最后更新：2026-10-31 22:0x（会话中断点）
工作目录：`D:\David\temp\root`

## 目标

用 OTA 全量包为本机固件重建 GhostLock（CVE-2026-43499）内核 profile，编译
`ghostlock`（PC 侧 Go 工具），通过 adb 拿到临时 root（KernelSU late-load）。

## 设备/固件实测事实（本轮已确认）

| 项 | 值 |
|---|---|
| 机型 | PD2338 / V2338A（iQOO Neo9，SM8550） |
| serial | `10CE5P1A4G001PA`（现已断开，需重新插线并 `adb devices -l` 确认） |
| 内核 release | `5.15.137-g7cb3e06b062c-dirty` |
| 版本 | `PD2338_A_14.0.17.6.W10.V000L1`，Android 14，incremental `eng.compil.20241024.142910` |
| 安全补丁 | 2024-08-01 |
| verifiedboot / BL 锁 | green / `ro.boot.flash.locked=1` |
| OTA 包 | `C:\Users\123\Downloads\2024102417450012e95ba0ef486241d8f9248499af622d.zip`（7.26 GB，`post-version` 与设备完全一致） |

`/proc/kallsyms`、`/proc/iomem`、`/sys/kernel/btf/vmlinux` 对 shell 用户均 **Permission denied**，所以一切偏移都从 OTA 里的内核镜像离线提取。

## 已完成的产物

| 文件 | 说明 |
|---|---|
| `ota/payload.bin` | 从 zip 解出的 payload（7.25 GB，zip 内是 STORED，直接拷出） |
| `ota_extract.py` | 自写的 payload 分区提取器。**payload_dumper 0.3.0 有 bug：多 extent 只写第一个 extent，`boot.img` 会被截断**（当时只拿到 64 MB / 32 MiB 解压结果）。必须用本脚本：`python ota_extract.py ota/payload.bin boot init_boot vendor_boot system_dlkm vendor_dlkm xbl_config uefi` |
| `ota/boot.img` | 100663296 B。vivo 把 boot 分区拆成 **3 段各 32 MiB 的独立 zstd frame**（偏移 0 / 32 MiB / 64 MiB），逻辑镜像 = 三段解压后顺次拼接 |
| `ota/boot_r0..2.raw`, `ota/boot_full.raw` | 三段解压结果与拼接后的完整 96 MiB boot 镜像 |
| `ota/kernel.bin` | 原始 arm64 `Image`，49 789 440 B（`boot_full.raw[4096:]`，header v4，ramdisk_size=0）。内含 `Linux version 5.15.137-g7cb3e06b062c-dirty`，与设备一致 |
| `ota/vmlinux.elf` | 用 `vmlinux-to-elf` 恢复 kallsyms 后的 ELF（187 976 个符号），基址 `0xffffffc008000000`（`text_offset=0`） |
| `ota/kernel.btf` | 内嵌 BTF，从 `kernel.bin` 的 `0x24a1a5c` 处取出，9 341 850 B |
| `btf_dump.py` | 自写 BTF 解析器（`python btf_dump.py ota/kernel.btf task_struct cred rt_mutex_waiter`） |
| `findref.py` | aarch64 字符串引用定位 + capstone 反汇编小工具 |
| `ota/gl-profile-5.15.137.conf` | **重建出的 profile**，见下 |
| `iqoo-neo9-ghostlock-pc/` | 已 clone 的上游仓库（HEAD `5ed65f8`） |
| 设备侧 | `/data/local/tmp/{gl-extract, gl-kernel.img, gl-xbl_config.img, gl-uefi.img, gl-profile.conf}`（可随时重推） |

## profile 是怎么来的（关键结论）

上游 `ghostlock-extract`（在 `internal/assets/payload/`，是 **aarch64 Android 原生 Rust 程序**，可在设备上以 shell 身份直接跑）就是官方的偏移提取器。PC 上跑不了，所以推到手机跑：

```bash
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'   # 否则 /data/... 会被 MSYS 改写
adb push iqoo-neo9-ghostlock-pc/internal/assets/payload/ghostlock-extract /data/local/tmp/gl-extract
adb push ota/kernel.bin /data/local/tmp/gl-kernel.img
adb push ota/xbl_config.img /data/local/tmp/gl-xbl_config.img
adb push ota/uefi.img /data/local/tmp/gl-uefi.img
adb shell "chmod 755 /data/local/tmp/gl-extract; cd /data/local/tmp && ./gl-extract gl-kernel.img \
  --xbl-config gl-xbl_config.img --uefi gl-uefi.img --analysis --work-dir /data/local/tmp"
adb shell "cd /data/local/tmp && ./gl-extract gl-kernel.img --route multicast_waiter --format conf \
  --out /data/local/tmp/gl-profile.conf --work-dir /data/local/tmp"
```

`--analysis` 输出（已跑通）：

- kallsyms 恢复 187 976 符号（pre-6.4 布局）
- **primitive 存在**：`remove_waiter@0x1827508 still uses current` → 该固件未打补丁，可利用
- `rt_mutex_waiter`：`task=0x30 lock=0x38 tree=0x0 pi_tree=0x18 wake_state=0x40 ww_ctx=0x50 size=0x58`
- `mm_struct` size `0x3e0`
- 三条路都存在（ip_mc_source / core_sys_select / tcp_zerocopy_receive）
- **建议路由 `multicast_waiter`**（5.x 有 mcast 路径，pselect 在该布局上推导失败）
- `multicast waiter_off derived = 0x50`（setsockopt depth 0x358 − futex depth 0x308）→ `waiter_off=80`
- 注意：`5.15.137... is unverified; no family-derived geometry will be emitted`，`pselect_waiter_shift` 推导失败（`−248`），xbl_config/uefi 里也没有 Kernel memory map → `kernel_phys_load` 只能留 `null`（运行时按 SoC 公式回退）

**已交叉验证**（我用 BTF 独立核过，与 extractor 输出逐字段一致）：

- `task_struct`：prio 0x7c、normal_prio 0x84、sched_task_group 0x400、tasks 0x4d0、atomic_flags 0x598、pid 0x5d8、tgid 0x5dc、real_cred 0x790、cred 0x798、comm 0x7a8、seccomp 0x860、pi_lock 0x884、pi_waiters 0x898、pi_top_task 0x8a8、pi_blocked_on 0x8b0
- `struct cred` size 176，`cap_permitted` 0x30/0x38/0x40 → `caps_offset=48 caps_count=3`；refs 0x80(user)/0x88(user_ns)/0x90(ucounts)/0x98(group_info)
- `kallsyms`：init_task 0x2e72600、init_cred 0x2e2a5b8、empty_zero_page 0x2f80000、root_task_group 0x2f84b40、selinux_blob_sizes 0x22ecec8、security_hook_heads 0x22eaa70、nfulnl_logger 0x2ce20b0、loggers 0x2ce1fd8、`__tracepoint_sys_exit` 0x2f0c6c8

## 唯一未闭环的技术点：`offset.vr_sys_exit_tp`

- 上游 5.15.197（已验证可用的 Neo9 配置）里带 `vr_guard { enabled=1 tracepoint_funcs=64 }` 和 `offset.vr_sys_exit_tp = 50141424`（= `0x2fd18f0`，8 对齐）。
- `resolve.go` 注释说明：vivo 设备上不做这个中和，multicast 路由会被 `EADDRNOTAVAIL` 拒掉，所以不能简单设 `enabled=0`。
- extractor **不输出**这两个键（它的键表里没有 vr_*），所以只能手工补。
- 我已写入 `vr_sys_exit_tp = 49333960`（`__tracepoint_sys_exit - 0xffffffc008000000`）。**语义尚未最终确认**：候选是
  1. tracepoint 结构体地址（当前采用）
  2. 结构体内 `.funcs` 字段地址 = +0x40（本内核 BTF：`funcs` 在 `struct tracepoint+0x40`，`iterator` 在 +0x28）
- 判定手段（下一步做，不必逆向）：跑一次看 `native-*.log` 里的
  `vr guard: neutralizing __tracepoint_sys_exit.funcs image=... target=... width=...`
  —— `target` 应是 `0xffffffc0…` 形态的规范内核指针；若 image/target 明显不对或直接 panic，换成 +0x40 或 +0x28 重试。

## 剩余步骤（续跑清单）

1. **插回手机**，`adb devices -l` 确认 `10CE5P1A4G001PA` 在线；按 README 的「手机侧准备」：USB 调试已授权、关闭「停止限制子进程」、去掉锁屏、USB 配置=文件传输。
2. **放 KSU 管理器 APK**：仓库不附带。需要 SukiSU Ultra（或 KSU 的 spoofed 构建）APK，放到 `iqoo-neo9-ghostlock-pc/` 同目录或 `~/Downloads`（工具会自动找），`ghostlock manager install` 用。
3. **编译**：`cd iqoo-neo9-ghostlock-pc && make win` → `bin/ghostlock.exe`（本机 go 1.26.2 可用）。
4. **把 profile 接进去**：两种方式
   - 快：`./bin/ghostlock.exe run --loop --conf ..\ota\gl-profile-5.15.137.conf`
   - 稳：把 `ota/gl-profile-5.15.137.conf` 复制成
     `internal/assets/profiles/5.15.137-g7cb3e06b062c-dirty.conf`，在 `internal/assets/profiles/index.conf`
     的 `profiles = [...]` 里加一行
     `{ release = "5.15.137-g7cb3e06b062c-dirty", file = "5.15.137-g7cb3e06b062c-dirty.conf" }`，
     再 `make win`（这样 `doctor` 也能自动匹配 release）
5. **体检**：`./bin/ghostlock.exe doctor`（只读）。期望：内核匹配、profile 命中、无 `InvalidPaths`（若 `execution.*` 报缺失说明 conf 的 execution 段没被读到）。
6. **干跑**：`./bin/ghostlock.exe run --dry-run`，看推上去的命令与 profile.bin 是否合理。
7. **实跑**：`./bin/ghostlock.exe run --loop`（默认 10 轮；失败常伴随 panic 自动重启，不要手动重启；连续多轮不中再冷启动）。
   - 关注 `/data/local/tmp/ghostlock/native-*.log`：`multicast route status=… errno=…`（99=EADDRNOTAVAIL 就是 vr_guard 没生效）、`native exit=…`
8. **判定成功**：`adb shell su -c id` → `uid=0(root) context=u:r:ksu:s0`；或 `/proc/modules` 里有 `kernelsu`。
9. **收尾**：`./bin/ghostlock.exe run --loop --clean-after` 清 staging；root 只在内存，重启即掉，需重跑。

## 风险/注意

- 失败会让内核 panic 重启，属该漏洞正常失败形态；root 不落盘，系统分区保持 erofs + dm-verity green。
- 会临时 `SELinux=permissive` 并加载 `kernelsu` / `vrpatch` 两个模块。
- `vrpatch.ko` 的 vermagic 是 `5.15.202-…`，与本机 `5.15.137` 不一致；但 README 说明它走 ksud 的 late-load（手动重定位、绕过 vermagic 校验），所以仍应可用；若 `ksud.log` 报 insmod 失败就是这里的问题。
- `kernel_phys_load` 暂为 `null`（走 SoC 回退 0xA8000000/0x80000000，与 5.15.197 配置相同）；若 KernelSnitch 阶段一直失败，用 `--phys` 或改 conf 显式给 `kernel_phys_load = 2818572288`、`kernel_phys_offset = 2147483648` 再试。
