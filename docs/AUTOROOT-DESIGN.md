# 自动 root 的设计

问题不是「怎么打进去」——那已经通了。问题是：**root 只在内存里，重启就没，而且命中窗口只有开机后 30–70 秒**。
所以「自动 root」本质是一个**三层时序系统**，每一层都必须存在，缺一层就退化成手动。

## 三层

```
第 1 层  触发层：在 uptime 30–70s 内发出 exploit
            ↑ 人手做不到（要卡秒），必须由程序计时
第 2 层  监督层：root 不在了就重新触发（含跨重启）
            ↑ 没有它就只是「一次性成功」
第 3 层  时序层：失手会让内核 panic 重启，必须容忍并等下一次开机窗口
            ↑ 没有它就会在错误时机连打，把设备打进重启循环
```

### 第 1 层：触发

| 要素 | 取值 | 依据 |
|---|---|---|
| 窗口下沿 | uptime ≥ 25s（`-MinUptime 25`） | 实测命中集中在 31–71s；早于 25s 发出去基本白送一次 panic 重启 |
| 窗口上沿 | uptime ≤ 85s（`--window 90`） | 超出后竞争窗口关闭，必失手 |
| 每次开机连发次数 | 2（`--per-boot 2`） | 干净失手只需 ~20s，窗口内还能补一发 |
| 轮数 | 4（`--rounds 4`） | 每轮之间靠 panic 重启自然拉开 |

发射器是 `ghostlock run --loop`，它自己在轮间等设备回来。

> 这条下沿是真被自测抓出来的：假 adb 场景 B 里设备刚重启，守护原先在 uptime 5s 就发射，
> 而真实命中区间在 30s 以后。加了 `-MinUptime` 之后同样的场景改在 26s 发射。
> 复现：`autoroot/selftest.ps1` 的 B-reboot-late 会断言「发射 uptime ≥ 25s」。

### 第 2 层：监督

两种拓扑，可同时开：

- **PC 侧**（`watch-root.ps1`）：每 20s 判活 → 掉则调 `auto-reroot.ps1`（等/抢窗口 → 发射 →
  `su -c id` 事实判定 → 静置 90s 复查）。
- **设备侧**（`device/termux-boot-ghostlock.sh`）：Termux:Boot 在开机时执行，
  用 Termux 内的 adb 连 `127.0.0.1:5555` 拿到 shell 上下文后发射。

判活为什么用 `grep -c kernelsu /proc/modules` 而不是 `su -c id`：
late-load 之后内核会把自己列进 `/proc/modules`，shell 权限就能读；而高频 spawn `su`
与设备上出现 `SYSTEM_RESTART` 在时间上高度相关（13:41–14:46 五次），能避开就避开。

### 第 3 层：时序容错

- 失手 = 内核 panic 自动重启（cmdline 里有 `kernel.panic_on_rcu_stall=1`），**这是设计内的失败路径**，
  不要每轮再手动 `adb reboot`（手动重启后 adb 回来得快，会在 uptime 11–13s 就发射，几乎必失手）。
- 窗口外不发射：`watch-root` 默认 `-RebootIfLate`，主动重启把设备推回窗口，
  而不是干等（设备不会自己回到窗口内）。
- 连续失败指数退避（300s 起，上限 1h），避免「发射→panic→重启→发射」把设备打瘫。

## 为什么不能更「持久」

`ro.boot.flash.locked=1`、`verifiedbootstate=green`：boot 分区写不了，AVB 会拒。
KernelSU 只能 late-load 到内存，**任何重启都清零**。想要一次搞定永久 root，只有解锁 BL 一条路，
而那会清数据且本机型官方不提供。

在这个前提下，「自动 root」的天花板就是：**只要有一层监督在跑，root 掉线后平均 1–3 分钟自动回来**。

## 失败模式与对应设计

| 失败模式 | 设计上的应对 |
|---|---|
| 开机窗口错过 | 监督器主动重启（`-RebootIfLate`） |
| 发射后内核 panic | 等设备自己回来，回到窗口再打 |
| 命中但内核随后崩（SELinux permissive 是历史主因） | 默认 `ENFORCE=1`；成功后再静置 90s 复查 |
| 判活把设备搞崩 | 判活不 spawn `su`，只读 `/proc/modules` |
| USB 与 Wi-Fi 两个 transport 打架 | 所有 adb 调用显式 `-s <serial>` |
| 无人值守过夜 | `-MaxHours` 到点自停；心跳日志每 15 次判活一条 |
| PC 不在 | 设备侧 Termux:Boot 钩子（需一次性配置） |

## 判定「成功」的定义

三条同时成立才算数，缺一条都不认：

1. `adb shell su -c id` 返回 `uid=0(...) context=u:r:ksu:s0`
2. 90 秒后仍然可用（排除「刚拿到就崩」的假阳性）
3. `grep -c kernelsu /proc/modules` = 1

日志证据：`autoroot/state/events.jsonl` 里的 `root-ok`（带 `bootId`、`settleSec`、`uptimeAfter`）。
