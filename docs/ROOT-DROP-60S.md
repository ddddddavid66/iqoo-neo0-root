# 「root 拿到后 60 秒就没了」—— 定位与修复

日期：2026-11-16
设备：PD2338 / V2338A · kernel `5.15.137-g7cb3e06b062c-dirty` · Android 14
结论：**这是 loop 的一个误判 bug，不是 exploit 本身不稳定。**

## 现象

真机上有两种截然不同的结果，交替出现：

| 结果 | native 日志结尾 | 之后 |
|---|---|---|
| 稳住 500s+ | `KernelSU ready` → `=== native exit=0` | 心跳持续通过 |
| 60–65 秒后内核崩溃重启 | `[T+47900ms] heap spray done` 之后无输出，或整段变 NUL | bootId 变化，root 归零 |

两次「outstanding」记录：`01:11:05` 拿到 → `01:12:11` 掉（66s）；`01:28:22` 拿到 → `01:29:27` 掉（65s）。

## 证据

把设备上留存的 native log 与 fire log 按时间轴对齐后，两条曲线完全分开：

| 轮次 | 发射 uptime | 发射次数 | 结果 |
|---|---|---|---|
| 01:18:06 成功 | 34s | **1** | 稳 500s+ |
| 01:27:25 失败 | 41s → 66s | **2**（同一 boot） | 65s 后崩 |
| 01:30:28 失败 | 77s | 1 | 发射途中日志变 NUL |

关键在第二行：`uptime=41s` 与 `uptime=66s` 是**同一个 boot**（41→66 连续增长，没有归零）。第一次发射的 ksu log 完整：

```
[*] late-load exit=0
[+] KernelSU module loaded
[*] script done
```

也就是说**第一次就打中了**。第二次发射的 native log 停在：

```
[T+46474ms]   heap spray start
[T+47900ms]   heap spray done      ← 之后没有下文，内核已死
```

第二次发射时 `W2: cred` 的目标地址被重新写了一遍，而内核里已经有一个 late-load 的 KernelSU：内存布局和第一次不同，写下去就把内核打死了。约 60 秒后 panic。

## 为什么会发第二次

`fire()` 靠读设备上的 `ksu-<ts>.log` 判成功。hand-off 那几秒 adb 连接会断（root 脚本是从获胜线程 fork 出去的后台进程，native 退出瞬间 transport 也消失），于是：

1. `fire()` 读不到 log → 判 `Dropped`
2. `Dropped` 分支 `WaitShell` 成功（adb 几秒就回来）后**只查一次** `su -c id`
3. 那一刻模块还没进 `/proc/modules`（late-load 才刚开始）→ 判失败
4. 回到主循环，`uptime=66s` 仍在 90s 窗口内 → 再发一次
5. 第二次把内核打死

成功那次是 uptime 34s 一次打中、`fire()` 当场读到 `KernelSU module loaded` 直接返回，loop 结束，没有第二次。

## 修复

三处，缺一不可：

### 1. 一个 boot 只发一次（`internal/run/loop.go`）

```go
fired := ""                       // 本 loop 已发射过的 boot_id
...
if id := o.ADB.BootID(); id != "" && id == fired {
    lo.printf("[i] 这个 boot 已经打过一次，不再重复发射（二次发射会打死内核）—— 重启换 boot")
    o.ADB.Reboot()
    continue
}
...
if id := o.ADB.BootID(); id != "" { fired = id }   // 发射前记，发射把内核打死就没机会记了
```

`device.ADB.BootID()` 读 `/proc/sys/kernel/random/boot_id`，用来区分「重启了」和「还是同一个 boot」。

### 2. 掉线后轮询确认，而不是查一次（`confirmRoot`）

```go
func confirmRoot(a *device.ADB, budget time.Duration, say func(string, ...any)) bool
```

每 3 秒查一次 `/proc/modules` 里的 `kernelsu`（不 spawn `su`），模块进来说明 late-load 到底了，再用 `su -c id` 做事实核对。最多等 90 秒。

另外加了短路：`WaitShell` 回来后如果 boot_id 变了，说明是真重启，没有 hand-off 可等，立刻返回。

### 3. 窗口上沿从 90s 收到 50s（`autoroot/auto-reroot.ps1`）

`34s` 发射 → 稳；`66s`、`77s` 发射 → 崩。新增 `-MaxUptime`（默认 50），并把 `--window` 显式传给 ghostlock（此前没传，ghostlock 内部默认 90s，窗口外照样发射）。

`-PerBoot` 默认从 2 改成 1。

## 验证

```
01:56:12  已过窗口（uptime=820s > 50s），主动重启
01:56:56  进入窗口：uptime=32s，发射
01:57:33  成功：su 已可用
01:58:33  静置 90s 复查
02:00:08  root-ok（bootId 未变，uptimeAfter=223s）
```

fire log 确认只发了一次：

```
[i] 最多 4 轮 × 每轮 1 次；uptime 窗口 50s
================ 第 1/4 轮 ================
[i] uptime=40s
---- 第 1 轮 / 第 1 次（uptime=40s）----
[+] 成功：root 已在（KernelSU late-load）
```

发射时 uptime 31.73s。之后三次复查：

| 时刻 | uptime | kernelsu | su |
|---|---|---|---|
| 01:58:30 | 88s | 1 | `uid=0(root)` |
| 02:00:00 | 184s | 1 | `uid=0(root)` |
| 02:04:30 | 586s | 1 | `uid=0(root)` |

**零掉线 555 秒**（此前两次都是 65 秒就掉）。

## 遗留

- 第二次发射仍然可能发生：`Loop` 只有在 `fired` 记录到 boot_id 时才拦得住。如果 `BootID()` 读失败（adb 抖动），保护退化为 `PerBoot=1`，此时一轮只发一次，靠 `Rounds` 里「超窗就重启」兜底。
- `confirmRoot` 的 90s 预算在模块始终不出现时会白等。设备已重启的情况由 boot_id 短路挡掉了。
