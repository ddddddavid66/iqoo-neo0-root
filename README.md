# iQOO Neo9 (PD2338) 内存 root 工程

在 **vivo iQOO Neo9 / PD2338 / V2338A**（Android 14，内核 `5.15.137-g7cb3e06b062c-dirty`，BL 锁定 `flash.locked=1` / `verifiedbootstate=green`）上，用 [GhostLock](https://github.com/AuroraMythweaver/iqoo-neo9-ghostlock-pc)（CVE-2026-43499，futex-PI 竞争）击穿内核，late-load KernelSU 拿到 `uid=0`。

Bootloader 锁死，boot 分区改不了，所以 root **只存在于内存**：每次重启归零，靠开机窗口内自动重打来维持。这个仓库就是那套东西：离线派生内核 profile、移植 payload、无人值守看门狗、常驻监督，以及踩过的所有坑。

上游基线：`AuroraMythweaver/iqoo-neo9-ghostlock-pc` @ `5ed65f8`，本仓库的 `iqoo-neo9-ghostlock-pc/` 是在它基础上的移植与修复（改动清单见 [docs/PORT-NOTES.md](docs/PORT-NOTES.md)）。

---

## 1. 现状

| 能力 | 状态 |
|---|---|
| 从官方 OTA 离线还原内核、符号、BTF | 完成，校验和可复现 |
| 为 `5.15.137-g7cb3e06b062c-dirty` 生成 profile 并接入 | 完成，30 字段 + `Validate()` + 单测 |
| 真机击穿 → KernelSU late-load → `su` 可用 | 完成，单 boot 内实测持续 **1479s+ 无抖动** |
| 无人值守：开机窗口内自动发射 | 完成，`autoroot/auto-reroot.ps1` |
| 常驻监督：root 掉了自动补打 | 完成，`autoroot/watch-root.ps1` |
| 设备侧开机自启（不依赖 PC） | **未完成**，卡 Termux:Boot 签名不兼容 |
| 永久 root（写 boot 镜像） | 不可能，BL 锁定 |

实测存活记录（同一内核、同一 profile，唯一变量是 SELinux 处理方式）：

| 拿到 root | 下一次开机 | 存活 |
|---|---|---|
| 04:20:26 | 17:31（手动重启） | 13 小时 |
| 17:33:56 | 17:36:15 | 2.3 分钟 |
| 18:03:09 | 18:05:26 | 2.3 分钟 |
| 18:29:34 | 18:30:28 | 54 秒 |
| **20:14:33（enforce=1）** | — | **> 25 分钟无抖动，采样到 1479s 仍在** |

分水岭是 `GHOSTLOCK_KSU_ENFORCE`：先前默认 `0`（把 SELinux 改成 permissive）的那几次，设备在几分钟内以 `HARD_RESET/PS_HOLD` 硬复位，`logcat -b crash` 里能看到 `Fatal signal 6 (SIGABRT) in tid (init)`；改成 `1`（保持 enforcing）后同样的 late-load 一直活着。**permissive 是本机不稳定主因。**

---

## 2. 关键发现

### 2.1 命中窗口只有 30–70 秒

`--window 90`，实测成功集中在 uptime 31–71s。窗口外发射必失手，而失手的表现是**内核 panic 自动重启**（cmdline 里有 `kernel.panic_on_rcu_stall=1`），所以不能靠人手，必须机器计时。

### 2.2 profile 必须按本机内核离线派生

偏移不能从别的机型借用。`tools/port/` 是为此写的整条链路（上游 dump 工具会在多 extent 的 payload 上截断、在 boot.img 的多个 zstd 帧上前功尽弃）：

```
payload.bin → boot.img（3×32MiB 独立 zstd 帧）→ arm64 Image
           → kallsyms（_text=0xffffffc008000000）+ 内嵌 BTF
           → profile.conf → profile.bin
```

派生规则：`offset.* = 符号地址 - _text`；`task_struct` / `cred` 结构偏移取自内嵌 BTF。

### 2.3 `vr_sys_exit_tp` 存的是 tracepoint 基址

profile 里写 `__tracepoint_sys_exit + 0x0`，payload 自己加 `.funcs` 的 `+0x40`（日志里 `image=ffffffc082f0c708` = tp_off `0x2f0c6c8` + `0x40`）。这一条搞错了会得到 `setsockopt: EADDRNOTAVAIL`。

### 2.4 SukiSU 会重命名 `libksud.so`

`internal/stage/scripts.go` 的上游逻辑 `find /data/... -name libksud.so` 在伪装构建上找不到（实际叫 `libdhxddxovny.so`），还会把 wrapper 覆盖掉。修法：按包名取「lib 目录里最大的 aarch64 .so」，并把可执行副本落到固定的 `/data/local/tmp/ksud`。这一条是 KernelSU 迟迟不接管 root 的真凶。

### 2.5 判活不要 spawn `su`

每 20s 一次 `su -c id` 与 `13:41–14:46` 的五次 `SYSTEM_RESTART` 在时间上高度重合。late-load 之后内核会把自己列进 `/proc/modules`，`grep -c kernelsu /proc/modules` 用 shell 权限就能读，判活全程走它。

### 2.6 pstore 这条路是死的

`ramoops` 模块加载了，但 DT 的 `ramoops_region` 只有 `size=0x200000` 和 `pmsg-size=0x200000`，**没有 `record-size`**，因此不注册任何 dump 记录区，`/sys/fs/pstore/` 恒空。内核崩溃现场拿不到，只能靠 dmesg 侧证（`init` SIGABRT、反复打向 ghostlock 线程的 `sig 9`、857MB 级 slab 占用、vivo 自家 `do_futex uaddr2 value wrong` 审计）。

### 2.7 无线 adb 让「手机自己补打」成为可能

`setprop persist.adb.tcp.port 5555` 之后，每次开机 adbd 都监听 TCP，PC 侧复用已有 key 免配对直连。设备侧脚本连 `127.0.0.1:5555` 即可拿到等价 shell——这是 P3（设备侧自启）唯一还差的一环的前提。

---

## 3. 目录结构

```
.
├── NOTICE.md                   # 上游来源与许可说明（必读）
├── iqoo-neo9-ghostlock-pc/     # GhostLock 移植（Go）
│   ├── cmd/ghostlock/          # CLI
│   ├── internal/
│   │   ├── assets/profiles/    # 派生出的 5.15.137 profile（本仓库新增）
│   │   ├── device/             # adb 封装、探测、判活
│   │   ├── profile/            # conf 解析 / 二进制编码 / 校验
│   │   ├── run/                # 单次执行与 --loop 重试机
│   │   └── stage/              # 推送 payload、生成设备侧脚本
│   └── tools/port/             # OTA → 内核 → profile 的离线工具链
├── autoroot/
│   ├── auto-reroot.ps1         # 一次性：等窗口 → 发射 → 事实判定 → 静置复查
│   ├── watch-root.ps1          # 常驻：判活 → 掉则补打 → 指数退避
│   ├── install-autostart.ps1   # 注册 Windows 登录自启
│   └── README.md
└── docs/
    ├── DIAGNOSIS-AND-FIX-2026-11-01.md   # 归因、13 条代码 bug、P0–P3 计划
    ├── FIX-RUN-2026-11-01.md             # 修复实弹记录
    ├── PORT-NOTES.md                     # 字段逐个溯源与实测对照
    ├── STATUS-5.15.137.md
    ├── PLAN-BOOT-ROOT.md                 # 开机持久化设计
    └── PERSISTENCE-STATUS.md
```

工作区已收敛到最小可用集（120MB）：`artifacts/5.15.137/` 只留 `kernel.bin` + `kernel.btf` + 推导记录文本，`boot.img` / `vmlinux.elf` / `boot_full.raw` 等中间件已删（可用 `tools/port` 从 `Downloads` 里的 OTA 全量包重新生成）。`ota/`、`build/`、`_research/`、`intel/`、`gpu-root/`、`run/`、`ksu/`、`publish/`、`exploit/`、会话转写等探索期产物已清空。

`iqoo-neo9-ghostlock-pc/` 是快照目录：上游仓库的 `.git` 已移到 `_src/ghostlock-upstream-dotgit`，需要和上游对比时 `git --git-dir=_src/ghostlock-upstream-dotgit --work-tree=iqoo-neo9-ghostlock-pc diff` 即可。

上游来源、许可与再分发限制见 [NOTICE.md](NOTICE.md)。

---

## 4. 用法

### 4.1 一次性重打（PC 侧）

```powershell
# 设备已在窗口内
.\autoroot\auto-reroot.ps1

# 设备已开机很久，先主动重启抢窗口
.\autoroot\auto-reroot.ps1 -RebootIfLate

# 走 WiFi，不用 USB
.\autoroot\auto-reroot.ps1 -Wireless
```

关键参数：`-Window`（uptime 窗口上沿，默认 90）、`-MaxRounds`、`-PerBoot`、`-SettleSec`（成功后静置复查秒数，默认 90；`bootId` 未变且 `su` 仍在才算成功）。

### 4.2 常驻监督

```powershell
.\autoroot\watch-root.ps1 -RebootIfLate      # 前台常驻
.\autoroot\install-autostart.ps1             # 注册 Windows 登录自启
.\autoroot\install-autostart.ps1 -Remove     # 卸载
```

每 20s 跑一次 `grep -c kernelsu /proc/modules`；消失就调 `auto-reroot.ps1`，失败按 300s 起指数退避（上限 1h），避免把设备打进无限 panic 重启。

### 4.3 手动发射与调试

```powershell
cd iqoo-neo9-ghostlock-pc
go build -o bin\ghostlock.exe .\cmd\ghostlock

# 单次（不带循环，最省事）
.\bin\ghostlock.exe run --serial 10CE5P1A4G001PA

# 无人值守循环
.\bin\ghostlock.exe run --loop --rounds 4 --per-boot 2 --serial 10CE5P1A4G001PA

# 只拿临时 root（只加载 vrpatch，不做 late-load）
.\bin\ghostlock.exe run --loop --temp-root

# 保持 SELinux enforcing（默认），要复现旧行为才加 --permissive
.\bin\ghostlock.exe run --loop --permissive
```

同时挂着 USB 与 WiFi 两个 transport 时**必须显式 `--serial`**，否则 adb 会报 `more than one device/emulator`，payload 探测出空内核版本直接拒跑。

### 4.4 为另一台机器重新派生 profile

```bash
python tools/port/extract_payload.py  payload.bin -o out/
python tools/port/unpack_boot.py      out/boot.img -o out/
python tools/port/kernel_syms.py      out/kernel.bin -o out/
python tools/port/kernel_btf.py       out/kernel.bin -o out/
python tools/port/derive_profile.py   --kernel out/kernel.bin --btf out/kernel.btf \
                                      --release "$(cat out/release.txt)" -o my.conf
python tools/port/gen_checksums.py    out/
```

生成的 `.conf` 放进 `internal/assets/profiles/`，在 `index.conf` 里注册一行，跑 `go test ./internal/profile/`。

---

## 5. 代码修复清单

移植过程中查出并修掉的 13 条，带位置的完整版在 [docs/DIAGNOSIS-AND-FIX-2026-11-01.md](docs/DIAGNOSIS-AND-FIX-2026-11-01.md)：

| # | 位置 | 问题 |
|---|---|---|
| B1 | `stage/scripts.go`, `run/loop.go` | loop 路径的 enforce 恒为 0，`--temp-root` 被静默吞掉（之前的对照实验因此全部无效） |
| B2 | `run/loop.go` `fire()` | 先判活再读日志，handoff 期间把已经成功的一次记成掉线 |
| B3 | `run/loop.go` | ksu log 说成功就返回，没有 `su` 事实核对 |
| B4 | `run/loop.go` | 掉线后用 `WaitShell` 判「回来」，可能判在将死的 transport 上，且不比对 `bootId` |
| B5 | `run/loop.go` | 超出窗口的分支只 `WaitShell`（设备本来就活着），4 轮瞬间烧完，一次重启都不做 |
| B6 | `device/probe.go` | `IsRoot()` 用 `Contains(out,"0")`，`1000`/`10234` 都算 root |
| B7 | `device/adb.go` | `Push` 共用 25s 超时，730KB 走 WiFi 会失败 |
| B8 | `device/adb.go` | `Stream` 的 `idle` 参数没实现，内核卡死时挂住整轮 |
| B9 | `run/loop.go` | `RebootFirst` 状态散在三处，可能连重启两次 |
| B10 | 设备侧 root script | 无条件 `echo 0 > /sys/fs/selinux/enforce` |
| B11 | 设备侧 root script | 常驻 root 调试终端默认开启 |
| B12 | `auto-reroot.ps1` | 成功即 `exit 0`，重启后无人补打；判活用 `su` |
| B13 | `auto-reroot.ps1` | 事件里没有 `bootId`，无法区分「掉了」和「重启了」 |

B1–B8、B10 已在代码里修掉并有单测；B9/B11 记录在案；B12/B13 由 `watch-root.ps1` + `-SettleSec`/`bootId` 解决。

---

## 6. 已知限制

1. **root 不持久**。BL 锁定、AVB green，写不了 boot。一切「持久」都靠重启后自动重打。
2. **设备侧自启未打通**。设备上的 Termux 是 `0.118.0 DEBUGGABLE`（签名 `db86cf3c`），F-Droid 的 `com.termux.boot` 与它共享 `com.termux` 用户但签名不同，装不上：`INSTALL_FAILED_SHARED_USER_INCOMPATIBLE`；vivo 对 `adb install` 还有弹窗拦截（灭屏时 `User rejected permissions`）。解法是把 Termux 换成 F-Droid 版（会清数据）或改用 Shizuku 配对。
3. **崩溃现场不可取证**。见 §2.6，pstore 无记录区。要定位内核崩溃只能靠 root 存活期间的 `dmesg -w` 落盘。
4. **部分 profile 字段只能导入**。`waiter_off`、`slide_loggers_0_1` 来自上游实测提取器的输出（`--from-extractor`），`pselect_waiter_shift` 无法推导（`select_stack` 不可用），`kernel_phys_load` 用 SoC 兜底值。这三处是「命中但不稳」的头号嫌疑。
5. **每次失手都是一次 panic 重启**。循环重试会真的把手机反复重启，`MaxConsecutiveFailures` + 冷却期是刹车。

---

## 7. 环境

- 主机：Windows，PowerShell 5.1，Go 1.22+，Python 3.10+，`adb`（platform-tools）
- 设备：iQOO Neo9 PD2338 (V2338A)，Android 14，`PD2338_A_14.0.17.6.W10.V000L1`
- 传输：USB（序列号）或 WiFi adb（`persist.adb.tcp.port=5555`，`10.206.33.5:5555`）
- 上游 payload：`ghostlock` native 二进制 + `vrpatch.ko`（内嵌于 `internal/assets/payload/`）

---

## 8. 适用范围

仅用于本机（本人持有设备）的内核漏洞验证与移植研究。所有实测数据均来自这台 PD2338。
