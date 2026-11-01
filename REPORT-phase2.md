# Phase 2 进展报告 — iQOO Neo9 (PD2338) CVE-2026-64560

时间 2026-10-30 18:56–19:08 (Asia/Shanghai)。设备全程在线，未发生重启（boot_id 不变），未写入任何分区。

## 1. 闸门 A 复核：漏洞确认存在

官方修复表（[Analysis 仓库](https://github.com/villager1314/CVE-2026-64560-Analysis)）：

| 分支 | 受影响区间 | 修复版本 | Stable 提交 |
|---|---|---|---|
| 5.15 LTS | 5.7 ~ 5.15.212 | 5.15.213 | `d8bcb28abad8` |

本机内核 `5.15.104-g3089a64cc8dc-dirty`，构建于 2024-05-17，落在受影响区间内，且 vivo 未回补 `timer_lock_sighand()` 重试 helper。
漏洞引入提交 `55e8c8eb2c7b`（v5.7, 2020），mainline 修复 `920f893f735e`，CVSS 3.1 = 7.8（AV:L/AC:L/PR:L）。

## 2. 工具链与触发器实测

- 交叉编译：`zig 0.13.0` → `zig cc -target aarch64-linux-musl -O2 -static`
- 产物：`exploit\cve64560_arm64`，1.1 MB 静态 aarch64，无 PT_INTERP
- 部署：`/data/local/tmp/cve64560`，shell 域直接执行

实测记录：

| 轮次 | 参数 | 时长 | 结果 |
|---|---|---|---|
| 冒烟 | `--check` | 即时 | `[+] prerequisites OK`，`CLOCK_PROCESS_CPUTIME_ID` 可用，`/system/bin/true` 可执行 |
| 1 | `-t 4 -e 4` | 30 s | 无 panic，uptime 连续 |
| 2 | `-t 8 -e 8` | 240 s | 无 panic，boot_id 不变 |

270 秒双角色高频竞态未触发可观测崩溃属预期行为：原厂内核无 KASAN，命中表现为静默的 timerqueue 损坏，只有后续 timer 操作才会踩到悬空节点。命中概率需要在 exploit 阶段用真正的堆风水放大。

## 3. 现成利用框架的解剖结果

`totsiaw/cve-2026-64560-rmx6699` 是一套 profile 驱动的完整链（源自 OP13 PoC）：

```
stage0  竞态 + 堆回收           → 泄漏 KASLR slide
bridge  伪造 misc fops          → 打开 /dev/uhid 得到任意读写（bridge_read64/write64）
stage8  覆写 selinux_state      → permissive
cred    覆写自身 cred           → uid 0
temp-su 当前 boot 内 su broker  → 接受 shell uid 客户端
```

关键点：**整条链绑定精确内核镜像**。每台设备需要从 decoded Image 推导出：

- kallsyms 布局（`numSyms` / `names` / `markers` / `tokenTable` / `offsets` / `relativeBase`）
- 静态符号：`MISC_LIST`、`UHID_MISC`、`UHID_FOPS`、`SELINUX_STATE`、`INIT_TASK`、`INIT_CRED`、`KMALLOC_CACHES`、`SDATA`、`ANON_PIPE_BUF_OPS`、`MODULE_DIRECT_BASE`、`MODULE_PLT_BASE`、`KIMAGE_VOFFSET`、`MEMSTART_ADDR`、`SYSCTL_BOOTID`、`CYCLE_C`、`CYCLE_D`、`CONFIGFS_*`、`ASHMEM_*`
- BTF 结构偏移（`task_struct.comm/tasks/parent`、`cred` 等）
- 物理布局（`imagePhys` / `memstartAddr` / `physicalDelta`）、`randomTableDataOffset`、`twoNodeCycles`
- 设备侧事实：uhid 设备号、页大小、CPU 拓扑、boot_id 校验值

本机可提供的部分：页大小 4096、8 核、`/proc/config.gz` 全量配置、uhid 在 shell 的补充组内（group 3011）。

## 4. 唯一硬阻塞：精确 boot.img

目标版本 `PD2338_A_14.0.15.8.W10.V000L1`（fingerprint `compiler05171902`）。各来源现状：

| 来源 | 内容 | 状态 |
|---|---|---|
| [onfix.cn/rom/1055724](https://onfix.cn/rom/1055724) | 卡刷包 `PD2338_A_14.0.15.8.W10.V000L1-update-full.zip`，6882 MB | 精确匹配，需付费下单 |
| [hello-firmware id=11920](https://hello-firmware.com/index.php?a=downloads&b=file&id=11920) | `PD2338_A_14.0.17.6.W10` system_split | 版本接近（A14 更晚 OTA），需账号 |
| [solution-firmware 目录 96](https://solution-firmware.com/index.php?a=downloads&b=folder&id=96) | PD2338 系列，含 A15 版本 | 需账号 |
| [vivo 开源门户](https://opensource.vivo.com) | `android_15.0_kernel_SM8550` / `android_16.0_kernel_SM8550` 源码（含 iQOO Neo9） | 官方免费，但 API 需登录；A15/A16 树与 A14 构建不对应 |
| vivo 官网 | 无公开固件下载（404/302） | 不可用 |
| 设备本体 | `/sdcard` 无 OTA 包；`/cache/ota`、`/data/ota` 需 root | 不可读 |

## 5. 结论

A 闸门成立，工具链与触发器就绪，框架结构已完全掌握，缺的是目标 Image。拿到 `boot.img` 后 `tools/derive_profile.py` + `kallsyms_extract.py` + `btf_offsets.py` 能一次性产出全部 LINK_* 与结构偏移，随后进入堆风水与竞态参数标定。
