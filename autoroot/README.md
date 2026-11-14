# autoroot/ — 开机自愈（PC 侧守护）

给锁 BL 的 iQOO Neo9（`5.15.137-g7cb3e06b062c-dirty`）用：设备每次重启后 root 就没了，
这个守护在**开机窗口（uptime 5–85s）**里自动重打一次，让 `su` 回到可用状态。

## 文件

| 文件 | 作用 |
|---|---|
| `go.ps1` | **上机入口**：找设备（USB 优先，失败转 Wi-Fi）→ 跑 `doctor` 体检 → 交棒 `watch-root.ps1` |
| `auto-reroot.ps1` | 状态机：等设备 → 幂等查 root → 等窗口 → 发射 → 用 `su -c id` 事实判定 → 静置复查 → 记事件/刹车 |
| `watch-root.ps1` | **常驻监督**：每 20s 用 `grep -c kernelsu /proc/modules` 判活（不 spawn `su`），掉则调 `auto-reroot.ps1`；心跳时额外做一次 `su` 核对，识别「模块在但 su 用不了」；失败指数退避 |
| `install-autostart.ps1` | 注册/卸载自启（默认写「启动」文件夹，指向 `watch-root.ps1` 并带 `-FallbackWireless`；`-Method Task` 才用计划任务） |
| `selftest.ps1` | **无真机自测**：七个场景跑在假 adb 上（命中 / 抢窗口 / 无设备 / 监督补打 / 崩溃恢复 / 上机入口 / 假健康） |
| `soak.ps1` | 反复掉线压测：交替模拟「设备在跑 root 消失」与「panic 重启」，看每次是否补回 |
| `device/` | **设备侧自启**（不依赖 PC）：Termux:Boot 钩子 + adb key 授权脚本，见 `device/README.md` |
| `state/auto-reroot-YYYYMM.log` | 人读日志 |
| `state/watch-YYYYMM.log` | 常驻监督器日志（含心跳） |
| `state/events.jsonl` | 机器读事件（`already-root` / `root-ok` / `root-fail` / `root-unstable` / `root-unusable` / `root-partial` / `window-missed` / `switch-transport` / `watch-*`） |
| `state/state.json` | 失败计数与冷却期 |
| `state/fire-*.log` | 每次发射时 `ghostlock run` 的完整输出 |
| `state/crash/` | 拿到 root 那一刻抓的 pstore/dmesg（本机 pstore 无 record 区，通常为空） |

## 用法

```powershell
# 一条命令上机（推荐）：体检 + 常驻自动 root
.\go.ps1
.\go.ps1 -Wireless                 # 走 Wi-Fi
.\go.ps1 -CheckOnly                # 只体检不发射

# 或者分开用
.\auto-reroot.ps1 -DryRun          # 先干跑看计划
.\auto-reroot.ps1                  # 手动跑一次（设备已 root 会直接退出）
.\auto-reroot.ps1 -RebootIfLate    # 开机太晚、已过窗口时主动重启去抢下一次

# 常驻监督（默认就会主动重启抢窗口；-NoReboot 关掉这个行为）
.\watch-root.ps1
.\watch-root.ps1 -Wireless          # 走 WiFi adb（10.206.33.5:5555）
.\watch-root.ps1 -MaxHours 8        # 跑 8 小时自动停
.\watch-root.ps1 -Once              # 只判活 + 必要的补打一次

# 注册自启 / 卸载
.\install-autostart.ps1
.\install-autostart.ps1 -Remove
```

常用参数：`-Window 90`（窗口上沿）、`-MaxRounds 4`（每次开机最多几轮，每轮由 ghostlock
自己等下一次 panic 重启）、`-PerBoot 2`、`-SettleSec 90`（成功后静置复查秒数）、
`-MaxConsecutiveFailures 5`、`-CooldownHours 24`、`-Exe <path>`。

`watch-root.ps1` 另有：`-PollSec 20`（判活间隔）、`-FailBackoffSec 300` /
`-MaxBackoffSec 3600`（失败退避）、`-HeartbeatEvery 15`（每 15 次判活打一条心跳）、
`-MaxHours 0`（0 = 不限时）、`-NoReboot`。

## 自测（不需要手机）

```powershell
cd tools\mockadb
go build -o mockadb.exe . ; go build -o mockghostlock.exe .
cd ..\..

powershell -File autoroot\selftest.ps1     # 七个场景，约 7 分钟
powershell -File autoroot\soak.ps1         # 反复掉线，约 3 分钟

cd iqoo-neo9-ghostlock-pc
go test ./internal/run/ -run TestLoop -v  # Go 侧发射与判胜
```

判据：`selftest` 全绿、`soak` 每轮都补回、`go test` 通过，才上真机。

## 实测时序（2026-11-01，6 次重启）

| 次 | 配置 | 结果 | 就绪时 uptime |
|---|---|---|---|
| 1 | rounds=2 | 成功 | 110s |
| 2 | rounds=2 | **失败**（2 发全 panic） | — |
| 3 | rounds=4 + manager 缓存 | 成功 | 92s |
| 4 | 同上 | 成功 | 68s |
| 5 | 同上 | 成功 | 68s |
| 6 | 同上 | 成功 | 92s |

结论：`rounds=4` 之后连续 4 次成功；root 就绪落在 **68–92s**，守护本身在
**脚本启动后 ~38s** 就进入窗口（受 adb 恢复时间限制）。

## 两个把时间压下来的改动

1. **manager 包名走设备侧缓存**：`findManager` 原来会遍历一串可能
   `pm list packages` 探测（每次 miss 睡 500ms），实测吃掉 ~20s；现在先读
   `/data/local/tmp/ghostlock/.gl_ksu_pkg` 并 `pm path` 验证，第一发从 uptime 58s
   提前到 39s。
2. **窗口内才发射**：脚本自己轮询 uptime，不在超窗时浪费弹药（ghostlock 内部也会在
   超窗后等重启）。

## 已知边界

- 需要电脑开机、USB 连着、adb 已授权；授权被撤销要人手点一次「允许」。
- 每次开机可能 panic 0–N 次（漏洞正常失败形态）；连续 5 次开机失败会自动冷却 24h。
- 锁屏不影响命中（实测锁屏状态也能打上）。
- 换内核（OTA）后要先跑 `tools/port/` 生成新 profile，否则守护会因 release 不匹配拒绝。
