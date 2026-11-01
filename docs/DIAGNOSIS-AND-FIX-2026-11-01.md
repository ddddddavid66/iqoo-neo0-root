# iQOO Neo9 (PD2338) GhostLock 移植：现状诊断与修复计划

日期：2026-11-01 19:20
内核：`5.15.137-g7cb3e06b062c-dirty` / `PD2338_A_14.0.17.6.W10.V000L1` / Android 14
设备：`10CE5P1A4G001PA`（USB）+ `10.206.33.5:5555`（WiFi adb）
BL：`ro.boot.flash.locked=1`、`ro.boot.verifiedbootstate=green`

---

## 1. 已经做完的事（可复现，不是"感觉能打"）

| # | 成果 | 证据 |
|---|---|---|
| 1 | 离线从 OTA 还原内核与符号 | `artifacts/5.15.137/`：`boot.img` → 3×32MiB zstd 帧 → arm64 `Image` → kallsyms + BTF；`SHA256SUMS` 12 文件校验通过 |
| 2 | 自写 toolchain（上游 dump 工具都会截断/漏帧） | `tools/port/extract_payload.py`、`unpack_boot.py`、`kernel_syms.py`、`kernel_btf.py`、`derive_profile.py`、`blob_decode.py`、`gen_checksums.py` |
| 3 | 为 5.15.137 生成并接入 profile | `internal/assets/profiles/5.15.137-g7cb3e06b062c-dirty.conf` + `index.conf` 注册 + `TestResolveNeo9_5137`（30 字段 + `Validate()`） |
| 4 | 真机打通：一次成功击穿 → KernelSU late-load | `ksu-*.log` 里 `policyload before=0 after=2` → `vrpatch exit=0` → `late-load exit=0` → `[+] KernelSU module loaded` |
| 5 | `su` 可用性已由设备侧事实判定（不再靠日志猜） | 多轮 `adb shell su -c id` → `uid=0` |
| 6 | 无人值守看门狗（USB / WiFi 双模） | `autoroot/auto-reroot.ps1`：等开机窗口 → 发射 → 事实判定 → 写 `events.jsonl` |
| 7 | 无线 adb 常驻 | `persist.adb.tcp.port=5555`，重启后 `[::]:5555` 自动 LISTEN，PC 侧复用已有 key 免配对 |
| 8 | 复现实验台 | `build/t2/`（clean-room 重放）、`build/variants/{vr0,vr-funcs,vr-iterator,phys}.conf` 对照 |

当前状态：**没有 root**。设备 uptime 2409s（≈18:30 那次开机到现在），`su: inaccessible or not found`。

---

## 2. 为什么现在没有 root —— 时间线证据

```
18:27:20  看门狗启动，uptime=32s
18:27:25  第1轮 第1次  exit=1（干净失败）
18:27:34  第1轮 第2次  exit=1（干净失败）
18:28:0x  主动重启 → 第2轮
18:28:40  第2轮 第1次  exit=1
18:28:5x  第2轮 第2次  adb 掉线（panic）
18:29:31  ghostlock 打印「设备回来后 su 已可用」→ 看门狗记 root-ok，exit 0
18:30:28  设备又重启了一次（SYSTEM_BOOT 18:31:59 对应本次开机）
19:10     设备已开机 40 分钟，su 不在
```

三件事同时成立，root 才会消失：

1. **late-load 只活在内存里**。BL 锁定（`flash.locked=1` / `verifiedbootstate=green`），无法写 boot 分区，KernelSU 只能 late-load，任何一次重启都清零。
2. **设备在 root 成功后几分钟内会自己重启**（见下节数据）。这一次是 18:30:28。
3. **看门狗在成功那一刻就退出了**（`auto-reroot.ps1` 成功分支 `exit 0`）。重启之后没有任何东西在等下一个开机窗口。

第 3 条是这次"没 root"的直接原因：root 拿到过，但只活了 ~54 秒，然后没人补打。

---

## 3. 为什么"一直有 root"做不到 —— 分层归因

### 3.1 root 存活时长数据（来自 `events.jsonl` + dropbox `SYSTEM_BOOT`）

| 拿到 root | 下一次开机 | 存活 |
|---|---|---|
| 04:20:26 | 17:31（我手动重启） | **13 小时（稳定）** |
| 17:33:56 | 17:36:15 | ~2.3 分钟 |
| 17:44:27 | 17:49:54 | ~5.5 分钟 |
| 18:03:09 | 18:05:26 | ~2.3 分钟 |
| 18:12:47 | 18:15:46 | ~3 分钟 |
| 18:29:34 | 18:30:28 | ~0.9 分钟 |

同一条内核、同一份 profile：早上那次 13 小时纹丝不动，下午这几次 2–6 分钟就崩。**"能不能一直有 root"的第一杀手是 root 之后的稳定性，不是命中率。**

当前引导原因证据：`vivoboot.bootreason=HARD_RESET/PS_HOLD/NONE+NONE`，同时 `logcat -b crash` 里有 `Fatal signal 6 (SIGABRT) in tid (init)`。这是 SoC 级硬复位（内核崩 → crashdump → PMIC 复位）的形态，区别于 Android 正常 `reboot`。

候选根因（按嫌疑排序，每条都给了判定方法）：

| # | 假设 | 支持证据 | 反证 | 判定方法 |
|---|---|---|---|---|
| H1 | profile 里 `kernel_phys_load` 用了 SoC 兜底值，写错了物理页 → 命中能用，但污染了别的页，几分钟后踩到 | 该字段没有从本机推导出来，是 SoC 兜底；命中后延时崩 | 早上 13h 用的也是同一个值 | 用带 `--dump-kernel-log` 的 variant 跑，看崩溃点是不是落在我们写过的物理区间 |
| H2 | SELinux 被改成 permissive（`echo 0 > /sys/fs/selinux/enforce`）+ reload policy，vivo 自家守护进程越权后崩 | 崩溃 boot 上 `init` 收到 SIGABRT；脚本无条件 permissive | permissive 每次都做，13h 那次也做了 | 把 `KSU_ENFORCE` 改成 1（不动 SELinux）连做 3 次 |
| H3 | 同一 boot 内多次失败 spray 累积泄漏（每次 `heap spray` 都漏 `mm_struct`），加上 `kernel.panic_on_rcu_stall=1` 把 RCU stall 变成 panic | cmdline 有 `kernel.panic_on_rcu_stall=1`；18:28 那个 boot 里成功前有 3 次 native、共 7 次 spray | 单次 native 成功时也是 5 次 spray，早上那次同样 5 次 | 每次开机只允许 1 发，失败就重启，成功前 spray 数压到 5 |
| H4 | 高频 `su -c id` 轮询本身就是压垮源（13:41–14:46 有 5 次 `SYSTEM_RESTART`，正好在我每 20s 轮询那段时间） | 时间高度重合 | 没有对照组 | 改用 `/proc/modules` 判活，完全不起 `su`，静置 30 分钟 |

### 3.2 其余四层障碍（结构性，短期绕不开）

| 层 | 障碍 | 现状 |
|---|---|---|
| 物理 | BL 锁定，`avb` green，boot 分区改不了 | 无解；root 只能是"每次开机重打" |
| 时序 | 命中窗口 uptime ≈ 30–70s，靠人手必错过 | 已由看门狗解决（机器计时） |
| 监督 | 成功即退出，重启后无人补打；PC 侧自启只在 Windows 登录时跑一次 | 待修（P0） |
| 触发 | 设备侧开机自启需要 Termux:Boot，签名与设备上的 Termux `0.118.0 DEBUGGABLE`（`db86cf3c`）不匹配：`INSTALL_FAILED_SHARED_USER_INCOMPATIBLE`；vivo 对 `adb install` 还有弹窗拦截（灭屏时 `User rejected permissions`） | 卡住，需人工装同签名 boot 插件或换 F-Droid 版 Termux |

---

## 4. 代码 review：确认的 bug

### 4.1 高危（直接导致误判 / 白跑）

| # | 位置 | 问题 | 后果 | 修法 |
|---|---|---|---|---|
| B1 | `internal/stage/scripts.go:62` + `internal/run/run.go:208-219` | loop 模式走 `runScript`，enforce 值来自 `cat $H/ksu_target`，而**全工程没有任何地方写 `ksu_target`** → 恒为 `0`；`buildCommand()` 里 `--temp-root`→`ENFORCE=9` 的逻辑只在非 loop 路径生效 | `run --loop --temp-root` 静默失效，仍然做完整 late-load + permissive。**我之前的"temp-root vs late-load"对照实验是无效的** | `Push()` 写入 `ksu_target`；或 `runScript` 接受 `GL_ENFORCE` 参数并由 `fire()` 传入 |
| B2 | `internal/run/loop.go:338-347` | `fire()` 每次循环**先** `AliveFast()`（最多 3 次重试、8+15+15s），失败就直接 `Dropped=true` 返回；此时根本没读 ksu log | handoff 期间设备 load 30+，探测失败 → 把**已经成功**的一次记成掉线；成功后仍然要等重启回来才判成功（就是 18:29 那条路径），中间白白给了内核崩溃的时间窗 | 先读 ksu log 再判活；判活失败时再补读一次 log；用 `boot_id` 区分"adb 掉了"和"内核死了" |
| B3 | `internal/run/loop.go:263-273` | `res.Won`（ksu log 里出现 `KernelSU module loaded`）直接 return，**没有** `su -c id` 事实核对，也没有稳定性观察 | 日志说成功 ≠ 能用；且成功即退出，无人监督 | 成功前必须过 `su -c id`；再等 60–90s 复查一次 |
| B4 | `internal/run/loop.go:282-289` | 掉线后用 `WaitShell(180s)` 等回来，但 `WaitShell` 在**同一条将死的 transport** 上也可能立刻返回 true，且没有比对 `boot_id` | 会把"重启前那一瞬"的 su 当成功（18:29 就是这样记的） | 记录开机前的 `boot_id`，必须等 `boot_id` 变化后才判 |
| B5 | `internal/run/loop.go:239-245` | 超出窗口的分支打印"等设备重启"，实际只调用 `WaitShell(180s)`（设备本来就活着 → 立即返回）然后 `continue` | 窗口错过时把 4 轮瞬间烧完，一次重启都不做（`events.jsonl` 里 `04:18:00 window-missed` 就是这个） | 该分支直接 `o.ADB.Reboot()` |
| B6 | `internal/device/probe.go:119-125` | `IsRoot()` 用 `su -c id -u` 然后 `strings.Contains(out,"0")` | `1000`/`10234` 都含 `0` → 假阳性；`Loop` 开头据此直接返回"已经是 root"，整轮跳过 | `strings.TrimSpace(out) == "0"`，并统一用 `su -c id` 判 `uid=0` |

### 4.2 中低危（健壮性 / 卫生）

| # | 位置 | 问题 | 修法 |
|---|---|---|---|
| B7 | `internal/device/adb.go:19` | 所有 adb 调用共用 25s 上限；`push` 484KB 二进制 + 249KB ko 走 WiFi 时很容易超时 | `Push`/`Pull` 用单独的超时（120s） |
| B8 | `internal/device/adb.go:103-128` | `Stream(..., idle time.Duration)` 的 `idle` 参数完全没用 | 删掉或实现 idle 超时 |
| B9 | `internal/run/loop.go:96-109` | `RebootFirst` 里先 `IsRoot()` 再 reboot，`lo.RebootFirst=false` 后又在下一次进 `if lo.RebootFirst` 的分支里重复 reboot | 状态机收敛成一个 `needReboot` 布尔 |
| B10 | 设备侧 `.ghostlock_root.sh`（内嵌 payload） | 无条件 `echo 0 > /sys/fs/selinux/enforce`；`FIXUP_RC != 0` 时还打印"SELinux left permissive"（其实没改） | 默认 enforcing；permissive 只在显式要求时开；修掉错误文案 |
| B11 | 设备侧 `.ghostlock_root.sh` | 后台 `while :; do ... sleep 0.3; done` 常驻 root 调试终端 | 默认关闭，需显式开启 |
| B12 | `autoroot/auto-reroot.ps1:286-292` | 成功即 `exit 0`；判活用 `su -c id`（可能本身就是扰动源） | 改成常驻监督：`/proc/modules` 判活 → 消失即等下次开机重打 |
| B13 | `autoroot/auto-reroot.ps1` | 无 `boot_id`/重启计数，`events.jsonl` 里 `uptimeAfter` 只是运气 | 事件里加 `bootId`、`rootedSec`、`diedAfterSec` |

---

## 5. 修复计划

原则：**先让它"打上就待得住"，再让它"掉了自己回来"**。顺序有依赖，B1 不修后面两个实验都做不了。

### P0 — 让 root 待得住（先定性崩溃）

| 步骤 | 动作 | 验收 |
|---|---|---|
| P0-1 | 修 B1（`ksu_target` 落盘 / `GL_ENFORCE` 透传） | `run --loop --temp-root` 的 ksu log 出现 `temp root only: vrpatch loaded, KSU skipped` |
| P0-2 | 打开崩溃取证：`--dump-kernel-log DIR` + 后台 `dmesg -w` 持续落盘；成功后第一件事 `cat /sys/fs/pstore/*` 落盘 | 下一次崩后能拿到 `pstore`/dmesg 尾部，定位 panic 点 |
| P0-3 | H2 对照：`ENFORCE=1`（不动 SELinux）连做 3 次 | 3 次都活过 10 分钟 → SELinux 是元凶，默认改 enforcing |
| P0-4 | H1 对照：`phys` variant 与当前兜底值各 3 次 | 谁的存活中位数高就定谁；若都崩 → 排除 H1 |
| P0-5 | H3：每次开机只打 1 发（`--per-boot 1`），失败即重启 | 成功前的 spray 数稳定在 5，存活中位数 ≥ 10 分钟 |

### P1 — 让看门狗常驻（这次"没 root"的直接病根）

| 步骤 | 动作 | 验收 |
|---|---|---|
| P1-1 | `auto-reroot.ps1` 加 `-Watch` 常驻模式：循环 `{ 等开机 → 窗口内发射 → 成功后每 10s 用 /proc/modules 判活 → 消失则重新等开机 }` | 连续 8 小时无人工干预，root 在线率 ≥ 95% |
| P1-2 | 判活换成 `grep -c kernelsu /proc/modules`（B12），彻底不 spawn `su` | `SYSTEM_RESTART` 数量归零，且 H4 得到验证/否定 |
| P1-3 | 成功判定加 `boot_id` + 90s 稳定复查（B3/B4） | 不再出现"记了成功但下一分钟就掉" |

### P2 — 让代码不再自欺（B2–B6, B7–B11）

| 步骤 | 动作 | 验收 |
|---|---|---|
| P2-1 | 修 B2/B5/B6 + `boot_id` 工具函数 | `go test ./...` 通过；新增 `TestFireReadsLogBeforeLiveness`、`TestWindowMissReboots`、`TestIsRootExact` |
| P2-2 | 设备侧脚本卫生（B10/B11） | 默认 enforcing；调试终端默认关闭 |
| P2-3 | 跑一次干净的 `run --loop --rounds 4 --per-boot 2` 回归 | 4 轮内成功，`events.jsonl` 里 `uptimeAfter - uptime` 记录合理 |

### P3 — 开机自启（设备侧，仍卡在外部）

| 步骤 | 前置 | 验收 |
|---|---|---|
| P3-1 | 装与现有 Termux 同签名的 `com.termux.boot`，或把 Termux 换成 F-Droid 版（会清数据） | `adb install` 成功，`~/.termux/boot/ghostlock.sh` 开机执行 |
| P3-2 | `ghostlock.sh`：等 `sys.boot_completed=1` → `adb connect 127.0.0.1:5555` → 走无线模式发射 | 5 次开机验收全部自动拿到 root |

P3 需要你在手机上点一次（签名/安装确认），其余全自动。

---

## 6. 立刻要做的三件事

1. 修 B1（否则 P0-3/P0-4 的实验结论都是假的）。
2. 给下一次发射加崩溃取证（P0-2），抓到真正 panic 点。
3. 看门狗改常驻 + 无 `su` 判活（P1），把"打上就没人管"这个洞补掉。

---

## 7. 本轮已落地（2026-11-01 19:30）

| 项 | 内容 | 验证 |
|---|---|---|
| B1 修复 | `stage.Options.KsuEnforce` 新增；`runScript(remote, force, enforce)` 把 enforce 真正烘进 `export GHOSTLOCK_KSU_ENFORCE=` 并写 `$H/ksu_target`；`run.ksuEnforce()` 成为唯一决策点，`buildCommand` 与 loop 共用 | `TestRunScriptBakesEnforce`、`TestKsuEnforceSharedByLoopAndDirect` 通过 |
| B2 修复 | `fire()` 先读 ksu log 再判活；掉线前再补读一次；handoff 分支不再 `continue` 跳过判活 | `go test ./internal/...` 全绿 |
| B5 修复 | 超出窗口不再空转 `WaitShell`，直接 `Reboot()` | 代码审查 |
| B6 修复 | `IsRoot()` 改成 `su -c id` + 精确匹配 `0` / `uid=0(` 前缀 | 代码审查 |
| P0-2 崩溃取证 | `ramoops` + `pstore` 模块与 `ramoops_region` 已确认存在；`auto-reroot.ps1` 成功瞬间调 `Save-CrashDump`：`su -c 'cat /sys/fs/pstore/*'` + `su -c dmesg` 落盘到 `autoroot/state/crash/` | 函数就位，等下一次成功触发 |
| P1-1 常驻监督 | 新脚本 `autoroot/watch-root.ps1`：每 20s 判活 → 不在就调 `auto-reroot.ps1` → 失败指数退避（300s 起，上限 1h）→ 单实例锁 | 语法检查通过，`-Once` 可用 |
| P1-2 无 su 判活 | 判活改 `grep -c kernelsu /proc/modules`（实测返回 `0`/`1`，不 spawn su、不需要 root） | 设备实测 |
| P1-3 稳定性判定 | `auto-reroot.ps1` 成功后 `-SettleSec 90` 静置复查：`bootId` 未变且 `su` 仍在才算 `root-ok`；否则记 `root-unstable` 并 exit 6，交给外层重打 | `-DryRun` 冒烟通过 |
| 自启切换 | `install-autostart.ps1` 改指向 `watch-root.ps1`；启动项 `GhostLock-WatchRoot.cmd` 已安装，旧的 `GhostLock-AutoRoot.cmd` 已删除 | 启动目录已核对 |

下一步就一条命令触发实弹验证（会重启手机）：

```
powershell -ExecutionPolicy Bypass -File autoroot\watch-root.ps1 -RebootIfLate
```

跑完看三处：`autoroot/state/watch-202611.log`、`events.jsonl` 里新增的 `bootId`/`settleSec`/`root-unstable`、以及 `autoroot/state/crash/` 里第一次拿到的 pstore dmesg。

