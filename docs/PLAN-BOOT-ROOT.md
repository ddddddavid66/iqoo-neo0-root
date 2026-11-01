# 计划：开机自动拿到 root（持久化方案）

设备：iQOO Neo9 / PD2338 / `5.15.137-g7cb3e06b062c-dirty` / `PD2338_A_14.0.17.6.W10.V000L1`
现状：root 已在（KernelSU late-load），**内存态，硬重启即失效**；`ro.boot.flash.locked=1`，
`verifiedbootstate=green`，系统分区 erofs + dm-verity。

---

## 0. 先把「开机就有 root」拆成三档，避免自欺

| 档 | 含义 | 本机可行性 |
|---|---|---|
| **L1 开机自愈** | 每次开机后 ~40s 内自动跑一次漏洞，root 自动就绪，人手不介入 | **可做**（本计划主体） |
| **L2 无感自愈** | 不插电脑也能自愈（设备自己触发） | 可做但要赌时序与 App 存活，成功率待实测 |
| **L3 永久 root** | 重启后 root 直接还在，不依赖再次利用漏洞 | **不可达**（见第 4 节） |

关键约束来自实测：漏洞只在 **uptime ≈ 30–70s** 命中（命中样本 31/34/43/53/58s；
`--window 90`；uptime ≥ 200s 的发射全部空放）。所以「开机就有 root」的本质是
**在每次开机的 30–90s 窗口内自动完成一次利用**。

其它已确认的事实（决定了方案形状）：

- 触发只需要 **shell（uid 2000 / `u:r:shell:s0`）**，PC 的 `adb shell` 与设备侧的
  shell 通道等价；
- `/data/local/tmp` 内容**跨重启保留**（`glrun.sh`、`profile.bin`、日志都在）；
- **adb 授权跨重启保留**（本轮 9+ 次重启都自动回来且仍是 `device`）；
- `ghostlock run --loop --reboot-first` 实测在 reboot 后 **uptime≈31–36s** 就能开火 →
  说明 adb 通道在 30s 左右可用，窗口剩余约 60s，够 2–3 发；
- 设备上**已装 Termux 与 Shizuku**（`com.termux`、`moe.shizuku.privileged.api`），
  无线调试当前关闭（`adb_wifi_enabled=0`），未装 Termux:Boot；
- **锁屏不挡命中**：本轮验证那一次（`attempt-I`，uptime=43s）就是在重启后锁屏状态下打成的，
  「去锁屏」只影响命中率与观察便利性，不构成前置条件。

---

## 1. 方案 A：PC 侧看门狗（先做这个，时序最稳）

**形态**：Windows 计划任务（登录触发 + 开机触发各一条）→ 一个 PowerShell 脚本。
仓库里 `run/auto-reroot.ps1`、`run/install-autostart.ps1` 是 10/30 的旧版，需要按当前
profile 与修复后的二进制重写。

**状态机**（每一步都有 5–10s 的短超时，绝不阻塞）：

1. **互斥**：`%TEMP%\ghostlock-reroot.lock`，拿不到就退出（避免计划任务与手动运行打架）。
2. **等设备**：`adb wait-for-device`（上限 180s）；`adb devices` 里出现 `unauthorized`
   → 记一条 WARN 并停（这一步必须人手点「允许」，脚本不猜）。
3. **判断是否已 root**：`adb shell su -c id` 命中 `uid=0` → 记 OK，退出（幂等）。
4. **等窗口**：轮询 `cat /proc/uptime`，每 2s；当 `5 ≤ uptime ≤ 85` 时进入发射；
   若 uptime 已 >85 → 不空放，直接等下一次开机（或按策略 `adb reboot` 再抢，需配置开关）。
5. **发射**：`ghostlock run --loop --rounds 2 --per-boot 2`（**不带** `--reboot-first`，
   已经在窗口里了；`--force-attack` 由第 3 步的结果决定）。
6. **判定**：脚本自己再跑一次 `su -c id` 作为事实判定（不依赖工具输出）。
7. **收尾**：成功 → 写一行 JSON 到 `run/logs/auto-reroot.jsonl`（时间、uptime、轮次、
   是否 panic）；失败 → 记失败并等待下一次开机事件，**不在同一次开机里反复重打**
   （窗口过了重打只会白耗 panic 次数）。

**额外要做的工程细节**

- **panic 计数与刹车**：连续 N 次（默认 5）开机都没成功 → 暂停自动尝试 24h 并告警，
  避免无限 panic 重启磨损存储。
- **日志滚动**：保留最近 30 天。
- **可观测**：托盘气泡/控制台标题显示「未就绪 / 已 root / 需授权」。
- **开机自启两条**：`ONLOGON`（有人登录时）+ `ONSTART`（无人登录也跑，需 `/RL HIGHEST`）。
- **卸载路径**：`install-autostart.ps1 -Remove` 一键删计划任务。

**验收标准（按实测修订）**：守护在**脚本启动后 ~38s** 进入窗口（受 adb 恢复限制），
root 就绪落在 **68–92s**（都是 uptime），连续 3 次重启 3 次成功。

**已实测（2026-11-01，6 次重启）**

| 次 | 配置 | 结果 | 就绪 uptime |
|---|---|---|---|
| 1 | rounds=2 | 成功 | 110s |
| 2 | rounds=2 | 失败（2 发全 panic） | — |
| 3 | rounds=4 + manager 缓存 | 成功 | 92s |
| 4 | 同上 | 成功 | 68s |
| 5 | 同上 | 成功 | 68s |
| 6 | 同上 | 成功 | 92s |

两个提速改动：`findManager` 先读设备侧 `.gl_ksu_pkg` 缓存（省掉 ~20s 的包名探测，
第一发从 uptime 58s 提前到 39s）；守护自己轮询窗口，超窗不空放。
刹车也验过：`state.json` 里 `failures=5` + `pausedUntil` 生效时脚本直接退出并打印冷却时间。

**稳定性抽样**：04:20:26 拿到 root 后不再触碰设备，每 20s 采一次，**18/18 次采样全部
`uid=0`**，一直在线到 uptime≈459s（≈7.6 分钟），零掉线。期间观察到一次「成功后约 2 分钟自发重启」的
个例（04:14:58 成功 → 04:16:2x 重启，`ro.boot.bootreason=reboot`，cmdline 里
`kernel.panic_on_rcu_stall=1`），需要后续用多次采样定性，暂列为已知风险。

---

## 2. 方案 B：设备侧自愈（不插电脑）

目标：不依赖 PC，开机后由设备自己把漏洞打一遍。两条子路线，**都建立在同一件事实上**——
我们需要一个「shell 级」的本地执行通道。

### B1 Shizuku（已装，优先）

1. 开发者选项 → 打开**无线调试**（`adb_wifi_enabled=1`），与 Shizuku 完成一次配对；
2. Shizuku 设置里开启「开机自启动」（它靠无线调试自连，配对信息在 `/data/misc/adb` 持久化）；
3. 在 `/data/local/tmp/ghostlock/` 放一个 `boot.sh`：等 `shizuku` 就绪 → 用 rish/shell
   通道执行 `./ghostlock --load-prebuilt-profile ./profile.bin --force-attack`；
4. 校验：`su -c id`。

**风险（必须先量）**：Shizuku 在 vivo 上的自启时机通常在 30–60s，可能刚好压在窗口边缘；
后台管控（`vivo 自启动/后台高耗电`）会杀它。→ 用一个「开机时间线打点脚本」先测量
「Shizuku 就绪时刻」的分布，再决定是否把它当主路径。

### B2 Termux + Termux:Boot（备选）

Termux:Boot 收到 `BOOT_COMPLETED` 后跑 `~/.termux/boot/*.sh`（Termux 用户身份，非 shell）。
脚本里再用 `adb connect 127.0.0.1:<无线调试端口>`（或 `rish`）拿到 shell 通道 → 打漏洞。
端口每次开机会变，需要用 `adb mdns services` 发现，或在脚本里遍历 30000–50000 常见端口。

**结论**：B 只在 A 稳定后再投入；B 的验收标准是「连续 5 次开机，≥4 次在 90s 内自愈」，
达不到就退回 A。

---

## 3. 方案 A+B 的组合（推荐终态）

- **主**：PC 看门狗（快、可观测、可回滚）。
- **备**：Shizuku 自愈（PC 不在时兜底）。
- 两者共用同一份 `/data/local/tmp/ghostlock` 与同一个 profile，互斥靠设备侧锁文件
  （`/data/local/tmp/ghostlock/.lock`，谁先拿到谁打）。

---

## 4. 方案 C：真·永久 root —— 为什么在本机不可达

要做到「重启后 root 还在」，只有三条路，本机全部堵死：

1. **刷 patched boot.img（Magisk/KSU LKM）**：需要 `fastboot flashing unlock`。
   本机 `ro.boot.flash.locked=1`、`verifiedbootstate=green`；vivo CN 的 Neo9 没有官方
   解锁通道，`fastboot oem unlock` 直接拒绝。
2. **关 AVB / 关 dm-verity 再改系统分区**：`fastboot --disable-verification flash vbmeta`
   同样要 BL 解锁；否则改 `boot`/`vbmeta` 必然 AVB 红字 + 起不来。
3. **在 boot 链里塞持久化（init.rc / init.d / vendor hook）**：这些都在 verified 分区里，
   没有第 1、2 条就写不进去；`/data` 里的东西不会被 init 执行。

因此「真正的 root」在当前 BL 状态下只能是 **L1/L2：每次开机自动重打**。
它的用户体感取决于第 1–3 节做得多快：PC 看门狗通常 20–40s 就绪，Shizuku 兜底 40–70s。

> 如果哪天愿意走「付费解锁 / 第三方解锁漏洞」这条路，那就是另一份计划：
> 解锁 → 提取本机 boot.img（我们已有 OTA 全量包和 `unpack_boot.py`）→ 打 KSU LKM/GKI
> → 刷入 → 之后才是真正的持久 root。风险：保修、变砖、OTA 覆盖、支付与合规问题。

---

## 5. 阶段与验收

| 阶段 | 内容 | 验收 |
|---|---|---|
| **P-B1** | 重写 PC 看门狗（`autoroot/`，启动文件夹自启 + 一键卸载），接当前 profile 与修复后的二进制 | ✅ 连续 4 次重启全部拿到 root（68–92s） |
| **P-B2** | 刹车/告警/日志滚动/unauthorized 检测 | ✅ 冷却期与 unauthorized 分支已验证（滚动日志同为月度文件） |
| **P-B3** | 开机时间线打点（uptime、adb 就绪、进窗、命中） | ⏳ PC 侧已打点（events.jsonl 带 adbReadySec/windowDelaySec/totalSec）；Shizuku 就绪时刻待测 |
| **P-B4** | 按 P-B3 数据决定是否上 Shizuku 自愈（B1） | 5 次开机 ≥4 次 90s 内自愈 |
| **P-B5** | 文档 + 回滚（停用计划任务、清设备端文件、恢复原状） | 一键卸载可复现 |

## 6. 风险与代价（必须提前接受）

- 每次开机窗口内失败会让内核 **panic 重启**（这是该漏洞的正常失败形态），
  L1/L2 会把「每次开机」变成「每次开机 panic 0–N 次」；P-B2 的刹车就是为此。
- 自动重打会占用开机阶段 CPU、抬温，可能影响首屏体验。
- `adb` 授权若被撤销/换线，方案 A 立刻失效，需要人手点「允许」。
- 无线调试常开 + Shizuku 常驻会扩大攻击面（本机已是可被本地提权的状态）。
- 系统更新（OTA）会换内核 release，profile 需重新按 `tools/port/` 生成——这条路径已经打通。
