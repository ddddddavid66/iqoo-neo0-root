# Phase 2b — iQOO Neo9 生态盘点（免费路线）

## 1. 关键发现：这台机型已经有现成 root 方案

| 项目 | 内容 |
|---|---|
| GhostLock fork | [`linux-tools/Ghostlock-app-for-IQOO_Neo9`](https://github.com/linux-tools/Ghostlock-app-for-IQOO_Neo9)，PD2338 定向适配，含预构建 payload `ghostlock-vivo-neo9.so` |
| PC 一键版 | [`AuroraMythweaver/iqoo-neo9-ghostlock-pc`](https://github.com/AuroraMythweaver/iqoo-neo9-ghostlock-pc)，`reroot.sh` 连 adb 直接打 |
| 上游 | [`YuKongA/ghostlock-app`](https://github.com/YuKongA/ghostlock-app) |
| 漏洞 | **CVE-2026-43499**（futex PI waiter 竞态），不是 64560；5.15 走 `multicast_waiter` 路由 |
| 效果 | 内存态 uid 0 + `selinux_state.enforcing=0` + `insmod vrpatch.ko` 中和 vivo 自家的 `vr.ko` + KernelSU `ksud late-load` |
| 持久性 | 无。重启失效，重跑 `reroot.sh` |
| 变砖风险 | 无（不写分区）；失败表现为内核 panic 自动重启 |

## 2. 硬门槛：`uname -r` 精确匹配

两套方案都按 release 字符串严格绑定：

- fork 内置 profile：`5.15.197-g708015331567-dirty` → 对应 **OriginOS 6 / 16.2.13.2**
- PC 一键版 README 明写：vivo iQOO Neo9（PD2338）· OriginOS 6 16.2.13.2 · 内核 5.15.197

本机：OriginOS 14.1 / A14 / 内核 `5.15.104-g3089a64cc8dc-dirty` → **不匹配，脚本会直接拒绝**。

GhostLock 全部 5.15 内置 profile：5.15.41 / 5.15.119 / 5.15.167 / 5.15.189×2 / 5.15.197，没有 5.15.104。

## 3. 自建 profile 所需的全部输入

`tools/extract_rs`（Rust 提取器）从 `boot.img` / 全量 OTA zip / http(s) URL 推导：

```
route.multicast_waiter  waiter_off/buffer_size/task_offset/lock_offset
task_struct              prio/normal_prio/pi_lock/pi_waiters/pi_top_task/
                         pi_blocked_on/pid/tgid/atomic_flags/real_cred/cred/comm/tasks/seccomp
cred                     caps_offset/copy_size/usage_value/caps_count/caps_value/ref0..3
offset                   init_task/init_cred/empty_zero_page/root_task_group/
                         selinux_enforcing/selinux_blob_sizes/security_hook_heads/
                         slide_nfulnl_logger/slide_boot_id/slide_loggers_0_1
kernel_phys_load         / kernel_phys_offset
```

其中 `task_struct.*` 与 `cred.*` 在 5.15 同一 vivo 树上基本可复用 `5.15.197` 那份；真正必须从本机镜像重算的是 `offset.*` 十项和两个物理地址。

## 4. 免费镜像源排查结果

| 来源 | 结果 |
|---|---|
| vivo 官网 | 无公开固件下载 |
| [vivo 开源门户](https://opensource.vivo.com) | 只有 A15/A16 的 SM8550 源码，无 A14；`getPubSourceDownloadUrl` 需登录 |
| [needrom](https://www.needrom.com/download/vivo-iqoo-neo-9-5g-pd2338-16/) | 免费注册可下，但仅有 **Android 16** 版本 |
| [filewale](https://filewale.com/files/tag/PD2338) | 只有 PD2338F（Neo9 Pro，联发科）系列 |
| [onfix](https://onfix.cn/rom/1055724) | 有精确的 `PD2338_A_14.0.15.8.W10.V000L1-update-full.zip`（6882 MB），付费 |
| hello-firmware / solution-firmware | 有 A14/A15/A16，付费账号 |
| 设备本体 | `/sdcard` 无 OTA 包，`/cache/ota` 与 `/data/ota` 需 root |

结论：A14 那一版镜像在免费渠道里查不到。

## 5. 免费路线的两个选项

**A. 把手机升到 OriginOS 6 / 16.2.13.2，直接用现成一键工具**
- 成本：0
- 命中率：作者已实测调优（开机后 30–45 秒窗口，多轮重试）
- 代价：升级不可逆；OTA 只给最新版，若跳到比 16.2.13.2 更新的版本，`uname -r` 又会超出已覆盖范围
- 准备：USB 调试、关闭「停止限制子进程」、去掉锁屏密码、默认 USB 配置改文件传输

**B. 留在 A14，自建 profile**
- 成本：一份镜像（目前只有付费源）
- 代价：要在 Windows 上装 Rust 工具链并编译 `extract_rs`，然后做竞态参数标定

## 6. 建议

走 A。这台机器的 root 生态已经成熟到「一条命令」的程度，唯一障碍是固件版本对不上；升级是免费且可自动化的那一半，自建 profile 是要花时间和钱的另一半。
