# Phase 0 侦查报告 — iQOO Neo9 (PD2338 / V2338A)

采集时间 2026-10-30 18:43–18:50 (Asia/Shanghai)。全部命令只读。

## 1. 设备与构建

| 项 | 值 |
|---|---|
| 型号 | PD2338 / V2338A（iQOO Neo9，kalama = Snapdragon 8 Gen 2） |
| ROM | OriginOS 14.1，`vivo/PD2338/PD2338:14/UP1A.231005.007/compiler05171902:user/release-keys` |
| Android | 14（SDK 34） |
| 内核 | `5.15.104-g3089a64cc8dc-dirty`，clang 14.0.7，SMP PREEMPT aarch64，构建于 2024-05-17 |
| 安全补丁 | 2024-03-01 |
| CPU / 内存 | `nproc` = 8，MemTotal 15.5 GB（16 GB 版） |
| 槽位 | `ro.boot.slot_suffix=_a`，A/B，`force_normal_boot=1` |

## 2. 启动链（闸门 B）

```
ro.boot.verifiedbootstate   green
ro.boot.flash.locked        1
ro.boot.vbmeta.device_state locked
ro.boot.vbmeta.avb_version  1.2
ro.boot.veritymode          enforcing
ro.vivo.dyn.veritystate     enforcing
ro.boot.secureboot_enable   1  (key=qcom_mobile, ver=6)
sys.oem_unlock_allowed      0
```

system / vendor / vendor_dlkm 均挂载为 erofs `ro`；`/data` f2fs `rw`。
结论：AVB + dm-verity + EROFS 全绿，OEM 明确关闭解锁开关。持久化路线（Magisk 写入 boot/init_boot）在软件层面被封锁。

## 3. 当前权限面

```
uid=2000(shell)  context=u:r:shell:s0  Selinux: Enforcing (policyvers 331)
CapInh/Prm/Eff = 0   CapBnd = 0x00000000000000c0
Seccomp: 0  Seccomp_filters: 0
ro.secure=1  ro.debuggable=0  ro.adb.secure=1
system/bin/su、/system/xbin/su 不存在
```

shell 域无任何 effective capability，且无 seccomp 过滤器 —— 系统调用面完整可用。

## 4. 内核攻击面与加固（离线可读、在线被拒的区分）

可读：
- `/proc/config.gz` 全量可读
- `CONFIG_SLUB=y`、`SLAB_FREELIST_RANDOM=y`、`SLAB_FREELIST_HARDENED=y`、`SLAB_MERGE_DEFAULT` 关闭
- `CONFIG_SLUB_MIRROR=y`（厂商额外硬化）
- `CONFIG_RANDOMIZE_BASE=y`（KASLR）
- `CONFIG_HARDENED_USERCOPY=y`
- `CONFIG_STATIC_USERMODEHELPER=y`，路径 `/system/bin/vivo_coredump`
- `CONFIG_KALLSYMS=y`、`KALLSYMS_ALL=y`、`KALLSYMS_BASE_RELATIVE=y`
- `CONFIG_DEBUG_INFO_BTF=y`、`DEBUG_INFO_BTF_MODULES=y`
- `CONFIG_USER_NS` **未开启**
- `perf_event_paranoid = -1`（最宽松）

被 SELinux 拒绝：
- `/proc/kallsyms`、`/proc/sys/kernel/kptr_restrict`、`/proc/sys/kernel/dmesg_restrict`
- `/sys/kernel/btf/vmlinux`、`/proc/timer_list`、`/proc/sys/vm/mmap_min_addr`
- `/proc/sys/kernel/unprivileged_bpf_disabled`、`/proc/sys/user/max_user_namespaces`
- 所有 `/dev/block/*` 块设备节点（`brw-------` root）

## 5. 三道闸门判定

| 闸门 | 判定 | 依据 |
|---|---|---|
| A 内核受影响 | **开** | 内核 5.15.104 / 构建 2024-05，SPL 2024-03；CVE-2026-64560 修复于 2026 年中，未回补 |
| B 启动链 | **关（持久化）** | verifiedboot green、vbmeta locked、verity enforcing、erofs ro、oem_unlock_allowed=0 |
| C 持久化 | **关** | vivo/iQOO 无官方 BL 解锁入口，OEM 开关已置 0 |

## 6. 可行性结论

能拿到：`shell`（uid 2000）→ 内核态任意读写 → 覆写自身 `cred` + `selinux_state.enforcing` → 一个 uid 0 进程。
拿不到：`/system` 可写、Magisk/KernelSU 持久安装、重启后保留（内存态 root 随重启消失）。

现成弹药：公开移植均针对 6.6 / 6.12 GKI 机型（OnePlus 15T / OnePlus 16 / realme RMX6699 / XRING O1），见
[plz110-6.12.69 port](https://github.com/feiguang-ai/plz110-6.12.69-cve-2026-64560-ksu)、
[OnePlus16-Jailbreak](https://github.com/Yunnijian/OnePlus16-Jailbreak)、
[rmx6699 port](https://github.com/totsiaw/cve-2026-64560-rmx6699)、
[PLC110 触发器分析](https://github.com/ADWMC/CVE-2026-98260-PLC110-6.6.66)、
[Analysis](https://github.com/villager1314/CVE-2026-64560-Analysis)。
5.15 + vivo 定制内核的移植需要自行完成，工作量集中在偏移重建与堆布局适配。

有利条件：
- shell 无 seccomp，`timer_create` / `clone` / `execve` 竞态原语可直接调用
- `perf_event_paranoid=-1` 提供潜在 KASLR/信息泄漏面
- `/proc/config.gz` + `KALLSYMS_ALL` + `BTF` 三项齐备，可从公开固件包离线重建符号与结构偏移（PD2338 固件在 [hello-firmware](https://hello-firmware.com/index.php?a=downloads&b=file&id=13969) / [gsmnex](https://gsmnex.com/index.php?a=downloads&b=file&id=8592) 有包）
- 8 核 16 GB，堆喷与竞态放大窗口充裕
- 全内存态利用，不写任何分区 → 变砖风险仅限内核 panic 后重启自愈

不利条件：
- vivo 非 GKI 5.15 树，KernelSU LKM 需要该机型 kernel 树或 Module.symvers 才可编译
- `SLUB_MIRROR` + `FREELIST_RANDOM` + `HARDENED` 使跨缓存与 freelist 攻击显著变难
- `USER_NS` 关闭，失去 userns 堆喷与 namespace 逃逸辅助
- `STATIC_USERMODEHELPER` 让 `core_pattern` / `modprobe_path` 类收尾技巧失效，提权后需要在内存里自建 su 通道

## 7. 下一步（Phase 2 入口）

1. 取 PD2338 `boot_a` 固件镜像，提取 `.BTF` 与内嵌 kallsyms，建立 `task_struct.cred`、`k_itimer`、`selinux_state`、`init_task` 偏移表
2. 审阅 ADWMC 的 PLC110 触发器分析，确认 5.15 分支 `posix-cpu-timers` + `de_thread()` 竞态窗口差异
3. 编写 aarch64 单文件触发器，先做"竞态是否命中"的可观测验证（不追求提权）
4. 命中后接堆喷 → 任意读写 → cred/SELinux 覆写 → 内存态 su
