# autoroot/ — 开机自愈（PC 侧守护）

给锁 BL 的 iQOO Neo9（`5.15.137-g7cb3e06b062c-dirty`）用：设备每次重启后 root 就没了，
这个守护在**开机窗口（uptime 5–85s）**里自动重打一次，让 `su` 回到可用状态。

## 文件

| 文件 | 作用 |
|---|---|
| `auto-reroot.ps1` | 状态机：等设备 → 幂等查 root → 等窗口 → 发射 → 用 `su -c id` 事实判定 → 记事件/刹车 |
| `install-autostart.ps1` | 注册/卸载自启（默认写「启动」文件夹，不需要管理员；`-Method Task` 才用计划任务） |
| `state/auto-reroot-YYYYMM.log` | 人读日志 |
| `state/events.jsonl` | 机器读事件（`already-root` / `root-ok` / `root-fail` / `unauthorized` / `window-missed`） |
| `state/state.json` | 失败计数与冷却期 |
| `state/fire-*.log` | 每次发射时 `ghostlock run` 的完整输出 |

## 用法

```powershell
# 先干跑看计划
.\auto-reroot.ps1 -DryRun

# 手动跑一次（设备已 root 会直接退出）
.\auto-reroot.ps1

# 开机太晚、已过窗口时主动重启去抢下一次
.\auto-reroot.ps1 -RebootIfLate

# 注册自启 / 卸载
.\install-autostart.ps1
.\install-autostart.ps1 -Remove
```

常用参数：`-Window 90`（窗口上沿）、`-MaxRounds 4`（每次开机最多几轮，每轮由 ghostlock
自己等下一次 panic 重启）、`-PerBoot 2`、`-MaxConsecutiveFailures 5`、
`-CooldownHours 24`、`-Exe <path>`。

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
