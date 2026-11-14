# 真机测试手册（明天上机用）

目标：把「自动 root」跑成一条可复现的流程——插上手机（或连上 Wi-Fi）后不用人管，
两分钟内拿到 `uid=0`，并且设备每次重启后自动补回来。

设备：iQOO Neo9 / PD2338 / `5.15.137-g7cb3e06b062c-dirty` / `PD2338_A_14.0.17.6.W10.V000L1`
序列号：`10CE5P1A4G001PA`（USB）· `10.206.33.5:5555`（Wi-Fi adb）

---

## 0. 成功判据（三条全满足才算过）

1. `adb -s <serial> shell su -c id` → `uid=0(root) gid=0(root) ... context=u:r:ksu:s0`
2. 静置 90 秒后仍然 `su -c id` 可用（`auto-reroot.ps1 -SettleSec 90` 会自检，事件记为 `root-ok`）
3. `adb shell grep -c kernelsu /proc/modules` → `1`

## 1. 前置检查（约 30 秒）

```powershell
adb devices -l
# 期望：10CE5P1A4G001PA  device
#      （可选）10.206.33.5:5555  device

adb -s 10CE5P1A4G001PA shell "getprop ro.boot.verifiedbootstate; getprop persist.adb.tcp.port; cat /proc/uptime"
# 期望：green / 5555 / 任意 uptime

cd iqoo-neo9-ghostlock-pc
.\bin\ghostlock.exe doctor --serial 10CE5P1A4G001PA
# 期望：设备识别出 V2338A、kernel 5.15.137-...、profile 命中、KSU 管理器为 com.sukisu.ultra
```

任一项不对就先修这一项再往下走。

## 2. 启动自动 root

### 模式 A：PC 监督（默认，今天已验证过）

```powershell
cd autoroot
.\watch-root.ps1                       # USB
.\watch-root.ps1 -Wireless             # Wi-Fi（10.206.33.5:5555）
.\watch-root.ps1 -MaxHours 8           # 过夜跑 8 小时就停
```

行为：每 20s 判活（`grep -c kernelsu /proc/modules`，不 spawn `su`）；root 不在就调
`auto-reroot.ps1`：等/抢开机窗口（uptime 5–85s）→ 发射 → `su -c id` 事实判定 →
静置 90s 复查（`bootId` 未变且 `su` 仍在）→ 写事件。

失手会让内核 panic 自动重启，监督器会在下一次开机窗口再打；连续失败按 300s 起指数退避。

### 模式 B：设备侧自启（不依赖 PC，需要先做一次性配置）

见 [autoroot/device/README.md](../autoroot/device/README.md)：授权 Termux 的 adb key →
装 Termux:Boot（当前卡签名）→ 部署 `termux-boot-ghostlock.sh`。

两者可以同时开：PC 监督是主力，设备侧是 PC 不在时的兜底。

## 3. 观察（跑起来之后）

```powershell
Get-Content autoroot\state\watch-202611.log -Tail 20 -Wait      # 心跳 + 补打进度
Get-Content autoroot\state\events.jsonl -Tail 5                  # 结构化事件
Get-Content autoroot\state\fire-*.log -Tail 40                   # 最近一次发射的完整输出
```

正常一轮的样子（2026-11-01 实测）：

```
20:11:43 已过窗口（uptime=6073s），主动重启抢下一次
20:12:27 进入窗口：uptime=31s，发射
20:14:33 成功：su 已可用
20:17:03 root-ok  settleSec=90  uptimeAfter=236s
```

发射阶段 `fire-*.log` 里应看到 `native exit=1`（干净失手）或连接掉线（panic），
然后要么命中、要么进下一轮。命中标记是 ksu 日志里的 `[+] KernelSU module loaded`。

## 4. 故障处置

| 现象 | 原因 | 动作 |
|---|---|---|
| `more than one device/emulator` | USB 与 Wi-Fi 两个 transport 同时在线，且命令没带 `-s` | 所有 adb 命令都显式加 `-s <serial>`；脚本已内置 |
| `no bundled profile for kernel ""` | 探测到的是未唤醒的 transport，内核版本为空 | 同上；或先 `adb -s <serial> shell uname -r` 确认 |
| `adb: device unauthorized` | 重连后授权丢失 | 亮屏点「允许」（勾选「一律允许」） |
| 一直是 `window-missed` | 设备开机太久，uptime 早过窗口 | `-RebootIfLate`（`watch-root.ps1` 默认已开） |
| 连续 `root-fail` 但 `fire-*.log` 里没有 `native exit` | 载荷没推上去 / ksud 缺失 | 看 `fire-*.log` 头部；必要时 `ghostlock stage` 重推 |
| 拿到 root 后 1~2 分钟又没了 | SELinux 被改成 permissive 导致 `init` SIGABRT（历史主因） | 确认没有加 `--permissive`；默认 `ENFORCE=1` |
| `INSTALL_FAILED_ABORTED: User rejected permissions` | vivo 拦截 `adb install` | 亮屏时安装，或直接在手机上点安装包 |

## 5. 收尾

```powershell
# 停监督器
Get-Process powershell | Where-Object { $_.CommandLine -like "*watch-root*" } | Stop-Process
# 或直接关掉那个窗口；锁文件 autoroot/state/watch.lock 会自动清理

# 卸载开机自启
.\autoroot\install-autostart.ps1 -Remove
```

清理设备侧痕迹（可选）：

```powershell
cd iqoo-neo9-ghostlock-pc
.\bin\ghostlock.exe clean --serial 10CE5P1A4G001PA
```

## 6. 已知边界

- root 只在内存里，**重启必丢**；BL 锁定（`flash.locked=1` / `verifiedbootstate=green`）写不了 boot。
- 命中窗口 uptime 30–70s，窗口外发射必失手并触发 panic 重启——这是设计内的重试成本。
- 本机 pstore 没有 ramoops record 区（`/sys/fs/pstore` 恒空），内核崩溃现场拿不到；
  定位崩溃只能靠 root 存活期间的 dmesg。
- 每次失手都真的会重启手机，`MaxConsecutiveFailures` + 冷却期是刹车，别关掉。
