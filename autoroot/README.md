# autoroot/ — PC 侧发射器（手动）

手机自己就能在开机后拿回 root，见 `apk/` 与 [docs/PLAN-B-SHELL-BRIDGE.md](../docs/PLAN-B-SHELL-BRIDGE.md)。
这里保留的是**电脑在旁边时的工具**：首次部署、换机器、手机连试几次没中时人工兜底。

**没有注册任何自启动。**要用就手动跑。

## 文件

| 文件 | 作用 |
|---|---|
| `go.ps1` | 上机入口：找设备（USB 优先，失败转 Wi-Fi）→ `doctor` 体检 → 交棒 `watch-root.ps1` |
| `auto-reroot.ps1` | 一次性：等设备 → 幂等查 root → 等窗口 → 发射 → `su -c id` 事实判定 → 静置复查 → 记事件/刹车 |
| `watch-root.ps1` | 常驻监督：每 20s 用 `grep -c kernelsu /proc/modules` 判活（不 spawn `su`），掉则补打，失败指数退避 |
| `state/` | 运行状态：`auto-reroot-YYYYMM.log`、`watch-YYYYMM.log`、`events.jsonl`、`state.json`、`fire-*.log` |

## 用法

```powershell
# 一条命令上机：体检 + 常驻自动 root
.\go.ps1
.\go.ps1 -Wireless              # 走 Wi-Fi
.\go.ps1 -CheckOnly             # 只体检不发射

# 一次性
.\auto-reroot.ps1 -DryRun       # 干跑看计划
.\auto-reroot.ps1               # 设备已 root 会直接退出（幂等）
.\auto-reroot.ps1 -RebootIfLate # 已过窗口，主动重启抢下一次

# 常驻监督
.\watch-root.ps1                # 默认会主动重启抢窗口
.\watch-root.ps1 -Wireless
.\watch-root.ps1 -Once          # 只判活 + 必要时补打一次
.\watch-root.ps1 -MaxHours 8
```

常用参数：`-MinUptime 25` / `-MaxUptime 50`（发射窗口，**上沿不要放宽**）、
`-MaxRounds 4`、`-PerBoot 1`（每个 boot 只发一次，第二次会把内核打死）、
`-SettleSec 90`、`-MaxConsecutiveFailures 5`、`-CooldownHours 24`、`-Exe <path>`。

`watch-root.ps1` 另有：`-PollSec 20`、`-FailBackoffSec 300` / `-MaxBackoffSec 3600`、
`-HeartbeatEvery 15`、`-MaxHours 0`（不限时）、`-NoReboot`。

> 改这些 `.ps1` 时必须保留 **UTF-8 BOM**。PowerShell 5.1 会把无 BOM 的 UTF-8 按
> OEM 代码页（936）解码，中文注释变乱码后引号配对失败，整个脚本直接语法错误。
> 用编辑器改完确认头三字节是 `EF BB BF`。

## 实测时序（2026-11-01，6 次重启）

| 次 | 配置 | 结果 | 就绪时 uptime |
|---|---|---|---|
| 1 | rounds=2 | 成功 | 110s |
| 2 | rounds=2 | **失败**（2 发全 panic） | — |
| 3 | rounds=4 + manager 缓存 | 成功 | 92s |
| 4 | 同上 | 成功 | 68s |
| 5 | 同上 | 成功 | 68s |
| 6 | 同上 | 成功 | 92s |

`rounds=4` 之后连续 4 次成功；root 就绪落在 68–92s，守护本身在脚本启动后约 38s
进入窗口（受 adb 恢复时间限制）。

两个把时间压下来的改动：

1. **manager 包名走设备侧缓存**：`findManager` 原来会遍历 `pm list packages` 探测
   （每次 miss 睡 500ms），实测吃掉约 20s；现在先读 `/data/local/tmp/ghostlock/.gl_ksu_pkg`
   并 `pm path` 验证，第一发从 uptime 58s 提前到 39s。
2. **窗口内才发射**：脚本自己轮询 uptime，不在超窗时浪费弹药。

## 已知边界

- 需要电脑开机、USB 连着、adb 已授权；授权被撤销要人手点一次「允许」。
- 每次开机可能 panic 0–N 次（漏洞正常失败形态）；连续 5 次开机失败会自动冷却 24h。
- 锁屏不影响命中。
- 换内核（OTA）后要先跑 `tools/port/` 生成新 profile，否则会因 release 不匹配拒绝。
- 首次装机需要 root 才能 `pm install`（vivo ICP 弹窗拦 `adb install`），
  所以第一次必须走这里。
