# iQOO Neo9 (PD2338 / V2338A) 提权研究计划

状态：仅计划，未执行。设备已通过 adb 连接（序列号 10CE5P1A4G001PA），adb 37.0.1。

## 目标

判定并（若可行）实施一条从 `adb shell`（uid 2000 / shell 域）到 root 的路径，
评估 CVE-2026-64560（posix-cpu-timers non-leader exec() UAF）在 PD2338 上的适用性。

## 漏洞背景

- CVE-2026-64560：`posix-cpu-timers` 中非 leader 线程 `exec()` 竞态导致的 UAF，内核提权类。
- 修复进入 mainline，公告时间约 2026-07-29。
- 公开 PoC 候选：GitHub `Feng1586/CVE-2026-64560-public`（"staged security research package"），需审阅。
- 关键未知量：受影响的 5.15 / 6.1 等 stable 区间、以及 vivo 定制内核是否回补。

## Phase 0 — 只读侦查（不改动设备状态）

目标：拿到内核与启动链事实，为可行性判定提供依据。

```bash
adb shell getprop ro.product.model
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.vivo.os.version
adb shell uname -a
adb shell cat /proc/version
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked
adb shell getprop ro.boot.vbmeta.device_state
adb shell getprop ro.boot.slot_suffix
adb shell getprop ro.secure
adb shell getprop ro.debuggable
adb shell getprop ro.adb.secure
adb shell getenforce
adb shell id
adb shell cat /proc/self/attr/current
adb shell cat /proc/self/status | grep -i cap
adb shell ls -l /dev/block/by-name
adb shell zcat /proc/config.gz
adb shell cat /proc/kallsyms | head -5
adb shell cat /proc/sys/kernel/kptr_restrict
adb shell cat /proc/sys/kernel/perf_event_paranoid
adb shell cat /proc/sys/kernel/unprivileged_bpf_disabled
```

同时离线核对：vivo 开源代码门户是否发布 PD2338 内核源码（决定是否有 vmlinux/BTF 可用于算结构偏移）。

## Phase 1 — 三道闸门

- 闸门 A 内核受影响：`/proc/version` 版本号与构建时间落在受影响区间，且未回补修复补丁。
- 闸门 B 启动链：`verifiedbootstate=green` + `flash.locked=1` 时，任何内核态写入都无法持久化，无法 remount `/system`。
- 闸门 C 持久化：BL 是否可解锁，决定能否走 Magisk 路线。

任一门关闭即改变路线，不必进入 Phase 2。

## Phase 2 — LPE 路线（研究型）

前提：A、B 通过。

1. 工具链：NDK clang，`aarch64-linux-android34-clang`，静态链接单文件 PoC。
2. 偏移获取：从 vivo 内核源码构建同版本 vmlinux，或用 BTF 提取 `task_struct`/`k_itimer`/`selinux_state` 偏移；配合 KASLR 泄漏。
3. 触发：`CLOCK_PROCESS_CPUTIME_ID` 定时器 + 非 leader 线程 `exec()` 竞态，制造悬挂 timer 引用。
4. 利用：堆喷回收 `k_itimer`，转换为任意读写，覆写 `cred` 与 `selinux_state.enforcing`。
5. 预期收益上限：`shell` 域内的 uid 0 进程。`/system` 只读（dm-verity/AVB），Magisk 无法安装，重启失效。

## Phase 3 — 现实路线：BL 解锁 + Magisk

vivo/iQOO 不提供官方解锁入口；PD2338 的 A/B + AVB 需要设备专属签名校验。
该路线依赖第三方工程工具或授权服务，风险为变砖、失保、数据丢失。

## 交付物

1. 侦查报告（版本、启动状态、SELinux、capability、可用内核面）。
2. 结论：该机型是否可被该 CVE 提权，收益是什么级别。
3. 路线选择：研究型临时 root vs BL 解锁持久 root。

## 风险与注意

- `adb reboot bootloader`、`fastboot` 相关命令会改变设备状态，只在执行阶段使用。
- vivo 定制加固（反调试、OEM 钩子）可能使通用 PoC 直接失效。
- 任何内核态写入失败都可能硬砖，需要可用的 fastboot/EDL 恢复手段。
