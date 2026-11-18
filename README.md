# iQOO Neo9 (PD2338) 内存 root 工程

**手机自己开机就能拿回 root，电脑不用参与。**

Bootloader 锁定、AVB green、boot 分区写不了，所以 root 只存在于内存，每次重启归零。
本工程做的事：在每次开机的 30–48 秒窗口内，让手机自己把
[CVE-2026-43499](https://github.com/AuroraMythweaver/iqoo-neo9-ghostlock-pc)（futex-PI 竞争）
再打一遍，把 KernelSU late-load 回内核。

2026-11-17 实测，PC 侧看门狗停用、Windows 启动项改名、`adb` 只旁观：

| # | 发射 uptime | 结果 |
|---|---|---|
| 1 | 30.0s | **成功**，21 秒后 `su` 可用 |
| 2 | 30.0s | 失败，竞争没打中 |
| 3 | 30.0s | **成功**，15 秒后 `su` 可用 |
| 4 | 30.0s | **成功**，uptime 59s 时已 `uid=0` |

3/4。第 4 次那份 root 连续存活 **40 小时** 无抖动（采样到 uptime 144230s 仍在）。

上游基线：`AuroraMythweaver/iqoo-neo9-ghostlock-pc` @ `5ed65f8`，本仓库的
`iqoo-neo9-ghostlock-pc/` 是它在本机的移植与修复（改动清单见 [docs/PORT-NOTES.md](docs/PORT-NOTES.md)）。

---

## 1. 现状

| 能力 | 状态 |
|---|---|
| 从官方 OTA 离线还原内核、符号、BTF | 完成，校验和可复现 |
| 为 `5.15.137-g7cb3e06b062c-dirty` 生成 profile 并接入 | 完成，30 字段 + `Validate()` + 单测 |
| 真机击穿 → KernelSU late-load → `su` 可用 | 完成 |
| **设备侧开机自启（不依赖 PC）** | **完成**：APK 在 uptime 30s 经本机 adbd 桥接在 shell 域发射，4 次冷启动 3 次成功 |
| PC 侧看门狗（部署工具 + 应急兜底） | 完成，`autoroot/` |
| 永久 root（写 boot 镜像） | 不可能，BL 锁定 |

---

## 2. 两种用法

### 2.1 手机自足（日常就用这个）

**开机，等一分钟，什么都不用做。**

```
23s   无障碍服务连上，App 开始等窗口
30s   TCP 127.0.0.1:5555 → adbd 认证 → shell 域跑 exploit
60-70s  su 可用
```

判断成没成：`su -c id` 返回 `uid=0(root)`，或者直接打开 KernelSU 管理器。

暗屏、锁屏都不影响（实测过）。**失败了就再重启一次** —— 手机自己没 root 时连
`reboot` 权限都没有，不会自动重试，这一次 boot 就结束了。

三条别破坏的前提：

1. 别卸载 `com.ghostlock.boot`
2. 别关它的**无障碍服务**（唯一能在 22s 内触发的通道）
3. 别清 `/data/local/tmp/ghostlock/`（payload、profile、启动脚本在这里，跨重启保留）

### 2.2 PC 兜底（首次部署、应急、换机器）

```powershell
cd autoroot
.\go.ps1                  # 找设备（USB 优先，失败转 Wi-Fi）→ 体检 → 常驻自动 root
.\go.ps1 -Wireless        # 强制走 Wi-Fi
.\go.ps1 -CheckOnly       # 只体检，不发射

.\auto-reroot.ps1 -RebootIfLate    # 一次性：设备已开机很久，先重启抢窗口
```

**这里不注册任何开机自启。**要跑就手动开。

关键参数：`-Window`（窗口上沿，默认 90）、`-MinUptime`（下沿，默认 25）、
`-MaxRounds`、`-PerBoot`（每 boot 发射次数，默认 1）、`-SettleSec`（成功后静置复查，默认 90）。

常驻监督每 20s 跑一次 `grep -c kernelsu /proc/modules`（不 spawn `su`，见 §6.5）；
消失就补打，失败按 300s 起指数退避。

APK 构建与装机：

```bash
python apk/build.py --fetch-ksud     # 首次需要从设备拉 libksud.so
adb push apk/build/ghostlock-boot.apk /data/local/tmp/gl.apk
adb shell 'su -c "pm install -r -d /data/local/tmp/gl.apk"'   # 普通 adb install 会被 vivo ICP 弹窗拦
adb shell 'su -c "settings put secure accessibility_enabled 1"'
```

---

## 3. 原理

### 3.1 root 不持久

BL 锁定 + AVB green ⇒ 改 `boot`/`vboot` 必然红字起不来，`/data` 里的东西 init 不执行。
所以所有「持久化」都只能是「每次开机重打一次」。

### 3.2 exploit 必须在 shell 域跑 —— adbd 桥接

App 进程是 `u:r:untrusted_app_27`，`Seccomp=2`，连 `/sys/fs/selinux/enforce` 都读不到：

```
[+] startup context pid=7267 uid=10293 attr=u:r:untrusted_app_27:s0 enforce=unreadable
[+] startup limits  pid=7267 NoNewPrivs=0 Seccomp=2 Seccomp_filters=1
[-] prepare_kernel_page retry 4/4 +9089ms -> heap spray failed
```

而 `adbd` 每台机器都在跑，`persist.adb.tcp.port=5555` 让它监听 `0.0.0.0`，
fork 出来的服务是 `u:r:shell:s0` / `Seccomp=0` / enforce 可读 —— 正是 exploit 需要的环境：

```
[+] startup context pid=8873 uid=2000 attr=u:r:shell:s0 enforce=1
[+] startup limits  pid=8873 NoNewPrivs=0 Seccomp=0 Seccomp_filters=0
```

所以 App 只需说一句话：

```
TCP 127.0.0.1:5555 → CNXN → AUTH SIGNATURE
                   → OPEN "shell,v2,TERM=dumb,raw:sh /data/local/tmp/ghostlock/glrun.sh"
```

约 400 行 Java，零外部依赖（`apk/src/com/ghostlock/boot/AdbBridge.java`）。
协议细节与四个坑见 [docs/PLAN-B-SHELL-BRIDGE.md](docs/PLAN-B-SHELL-BRIDGE.md)。

**一次性前提**：PC 的 adb 公钥要在 `/data/misc/adb/adb_keys` 里。本机第一行本来就是它，
APK 内置的 `assets/adbkey.der` 直接可用。换机器时用主页「复制 adb 公钥」按钮，
在有 root 的会话里追加到该文件即可。

### 3.3 时序

| 时刻（uptime） | 事件 | 依据 |
|---|---|---|
| 22–26s | 无障碍服务连接 | 实测 22.1 / 22.6 / 23.0 / 24.6 / 26.3s |
| 23.1s | adbd 认证即通（22.6s 时端口通但不回包） | 实测 |
| **30s** | 发射 | 命中区间 31–71s；23s 在必死区 |
| 30–40s | exploit 跑完（3.4–9.8s） | `prepare_kernel_page` + PI route |
| 45–70s | `su` 可用（late-load 异步） | 成功后 15–21s |

---

## 4. 目录结构

```
.
├── NOTICE.md                    # 上游来源与许可（必读）
├── apk/                         # 设备侧自足 root（Android 工程，无 Gradle）
│   ├── AndroidManifest.xml      #   targetSdk 28 / extractNativeLibs / directBootAware
│   ├── build.py                 #   aapt2 + javac + d8 + zipalign + apksigner
│   ├── src/com/ghostlock/boot/
│   │   ├── Launcher.java        #   窗口判定 / 单次发射守卫 / 环境变量 / exec
│   │   ├── AdbBridge.java       #   本机 adbd 客户端：RSA 认证 + shell_v2 执行
│   │   ├── RootAccessibilityService.java  # 22s 触发的唯一可靠通道
│   │   ├── BootReceiver.java / BootJobService.java / RootService.java
│   │   └── MainActivity.java    #   状态页 + 测试通道 + 复制公钥
│   ├── assets/                  #   profile.bin / vrpatch.ko / adbkey.der
│   └── lib/arm64-v8a/           #   libghostlock.so（可执行 payload）/ libksud.so
├── iqoo-neo9-ghostlock-pc/      # GhostLock 移植（Go）
│   ├── cmd/ghostlock/           #   CLI
│   └── internal/                #   assets/profiles · device · profile · run · stage
├── autoroot/                    # PC 侧发射器（手动，无常驻自启）
│   ├── go.ps1                   #   上机入口：找设备 → 体检 → 交棒常驻
│   ├── auto-reroot.ps1          #   一次性：等窗口 → 发射 → 事实判定 → 静置复查
│   └── watch-root.ps1           #   常驻：判活 → 掉则补打 → 指数退避
├── tools/
│   ├── port/                    # OTA → 内核 → profile 工具链
│   ├── adb_probe.py             # adb 协议参考实现（定位桥接 bug 全靠它）
│   └── adb_mitm.py              # adb 抓包代理（逐字节对比真实客户端）
├── artifacts/5.15.137/          # kernel.bin + kernel.btf + 推导记录
└── docs/
    ├── PLAN-B-SHELL-BRIDGE.md   # ★ adbd 桥接设计 + 10 个坑 + 验收数据
    ├── ROOT-DROP-60S.md         # 「root 拿到 60 秒就没了」的定位与修复
    ├── RUNBOOK-REAL-DEVICE.md   # 上机手册（判据 / 检查 / 故障处置）
    └── PORT-NOTES.md            # 字段逐个溯源与实测对照
```

`iqoo-neo9-ghostlock-pc/` 是快照目录：上游 `.git` 在 `_src/ghostlock-upstream-dotgit`，
需要对比时 `git --git-dir=_src/... --work-tree=iqoo-neo9-ghostlock-pc diff`。

---

## 5. 为另一台机器重新派生 profile

偏移不能从别的机型借用。整条链路在 `tools/port/`：

```bash
python tools/port/extract_payload.py  payload.bin -o out/
python tools/port/unpack_boot.py      out/boot.img -o out/
python tools/port/kernel_syms.py      out/kernel.bin -o out/
python tools/port/kernel_btf.py       out/kernel.bin -o out/
python tools/port/derive_profile.py   --kernel out/kernel.bin --btf out/kernel.btf \
                                      --release "$(cat out/release.txt)" -o my.conf
python tools/port/gen_checksums.py    out/
```

生成的 `.conf` 放进 `internal/assets/profiles/`，在 `index.conf` 注册一行，
跑 `go test ./internal/profile/`。设备侧还要同步 `/data/local/tmp/ghostlock/profile.bin`。

---

## 6. 关键发现

### 6.1 命中窗口只有 30–70 秒

实测成功集中在 uptime 31–71s。窗口外发射必失手，失手的表现是**内核 panic 自动重启**
（cmdline 有 `kernel.panic_on_rcu_stall=1`）。所以不能靠人手，必须机器计时。

**23s 以前是必死区**：2026-11-17 00:30 那次在 23.0s 发射，桥接 probe 明明已经拿到
shell 域，exploit 一跑内核就死、设备从 USB 消失。

### 6.2 profile 必须按本机内核离线派生

派生规则：`offset.* = 符号地址 - _text`；`task_struct` / `cred` 结构偏移取自内嵌 BTF。
上游 dump 工具会在多 extent 的 payload 上截断、在 boot.img 的多个 zstd 帧上前功尽弃，
`tools/port/` 是为绕开这两点重写的。

### 6.3 `vr_sys_exit_tp` 存的是 tracepoint 基址

profile 里写 `__tracepoint_sys_exit + 0x0`，payload 自己加 `.funcs` 的 `+0x40`。
这一条搞错会得到 `setsockopt: EADDRNOTAVAIL`。

### 6.4 SukiSU 会重命名 `libksud.so`

上游的 `find /data/... -name libksud.so` 在伪装构建上找不到（实际叫 `libdhxddxovny.so`），
还会把 wrapper 覆盖掉。修法：按包名取「lib 目录里最大的 aarch64 .so」，
并把可执行副本落到固定的 `/data/local/tmp/ksud`。

### 6.5 判活不要 spawn `su`

每 20s 一次 `su -c id` 与 `SYSTEM_RESTART` 在时间上高度重合。late-load 之后内核会把
自己列进 `/proc/modules`，`grep -c kernelsu /proc/modules` 用 shell 权限就能读。

**例外**：App 侧发射后的判定**必须**问 `su` —— 因为要知道的是「用户能不能用 root」，
而 `late-load` 完成到 `su` 发布之间隔了 15–21 秒（见 §6.7）。

### 6.6 SELinux 保持 enforcing

默认 `GHOSTLOCK_KSU_ENFORCE=1`。早先默认 `0`（改成 permissive）的那几次，设备在几分钟内
以 `HARD_RESET/PS_HOLD` 硬复位，`logcat -b crash` 里有 `Fatal signal 6 (SIGABRT) in tid (init)`。
改回 enforcing 后同样 late-load 一直活着。**permissive 是本机不稳定主因。**

### 6.7 late-load 是异步的，判定要轮询

2026-11-17 00:52 那次，两发都在 payload 刚结束时判「su 不可用」，
而 `su` 在 26 秒后才活过来 —— **那发其实是成功的**。判定改成「发射一次，然后每 3s 查一次
`su`，给满 60s」。uptime 只约束发射，不该约束等待。

### 6.8 pstore 这条路是死的

`ramoops` 加载了，但 DT 的 `ramoops_region` 只有 `size`/`pmsg-size`，**没有 `record-size`**，
`/sys/fs/pstore/` 恒空。崩溃只能靠 `dmesg` 侧证（`init` SIGABRT、反复打向 ghostlock 线程的
`sig 9`、857MB 级 slab 占用、vivo 自家 `do_futex uaddr2 value wrong` 审计）。

---

## 7. 代码修复清单

### 7.1 移植期修掉的 13 条（PC 侧）

| # | 位置 | 问题 |
|---|---|---|
| B1 | `stage/scripts.go`, `run/loop.go` | loop 路径 enforce 恒为 0，`--temp-root` 被静默吞掉 |
| B2 | `run/loop.go` `fire()` | 先判活再读日志，handoff 期间把成功记成掉线 |
| B3 | `run/loop.go` | ksu log 说成功就返回，没有 `su` 事实核对 |
| B4 | `run/loop.go` | 掉线后用 `WaitShell` 判「回来」，可能判在将死的 transport 上 |
| B5 | `run/loop.go` | 超窗分支只 `WaitShell`，4 轮瞬间烧完 |
| B6 | `device/probe.go` | `IsRoot()` 用 `Contains(out,"0")`，`1000` 也算 root |
| B7 | `device/adb.go` | `Push` 共用 25s 超时，730KB 走 Wi-Fi 会失败 |
| B8 | `device/adb.go` | `Stream` 的 `idle` 参数没实现，内核卡死时挂住整轮 |
| B9 | `run/loop.go` | `RebootFirst` 状态散在三处，可能连重启两次 |
| B10 | 设备侧 root script | 无条件 `echo 0 > /sys/fs/selinux/enforce` |
| B11 | 设备侧 root script | 常驻 root 调试终端默认开启 |
| B12 | `auto-reroot.ps1` | 成功即 `exit 0`，重启后无人补打；判活用 `su` |
| B13 | `auto-reroot.ps1` | 事件里没有 `bootId`，分不清「掉了」和「重启了」 |

### 7.2 APK 侧修的 10 条（设备侧自足）

每一个的表现都只是「没反应」，全靠抓真实 adb 会话逐字节对比才定位。
完整过程见 [docs/PLAN-B-SHELL-BRIDGE.md](docs/PLAN-B-SHELL-BRIDGE.md) 第 10 节。

| # | 问题 | 真正的成因 |
|---|---|---|
| A1 | 认证一直失败 | adbd 签的是 `DigestInfo(SHA-1) ‖ token` 裸串；标准 `SHA1withRSA` 被静默拒绝，看起来像「公钥没登记」 |
| A2 | `bad payload length 335544320` | `readInt` 已按小端解析，又翻了一次字节序 |
| A3 | 外部命令无输出 | `shell:` 分配 pty，第一个外部命令之后整条流就死 |
| A4 | 同上 | shell_v2 是 `[sid:1][len:4][data]` 记录序列，长度字被当正文 |
| A5 | 流一个 chunk 就断 | 客户端 OKAY 要发 `(local, remote)`，发反了 |
| A6 | 第二条连接认证即断 | CLSE 没应答，adbd 留着悬空流，伪装成「adbd 未就绪」 |
| A7 | 整 boot 一次没发射 | 守卫写在等窗口**之前**，一次 20.5s 的触发把时间戳写死，后续触发被自己拦掉 |
| A8 | 同上 | 时间戳没绑 `boot_id`，两个 boot 都在 21–23s，裸毫秒值互相冒充「刚打过」 |
| A9 | 每次冷启动内核 panic | `WIN_LOW=23` 落在必死区 |
| A10 | 成功被当成失败 | 按 payload 退出码判定，而 late-load 是异步的 |

---

## 8. 已知限制

1. **root 不持久**。BL 锁定、AVB green，写不了 boot。一切「持久」都靠重启后自动重打。
2. **单发命中率约六成**。本机实测 3/4（75%）。失败是 futex-PI 竞争没抢到窗口，
   内核状态干净（payload 自报 `clean=1/1`），重启重试即可。连续两次不中的概率约 25%，
   三次都空约 6%——真碰上就该怀疑内核被 OTA 换了导致 profile 过期。
3. **失败不会自动重试**。没 root 时手机连 `reboot` 权限都没有，需要手动重启。
   这也是好事：同一 boot 反复打会把内核拖死。
4. **崩溃现场不可取证**。见 §6.8。
5. **部分 profile 字段只能导入**。`waiter_off`、`slide_loggers_0_1` 来自上游实测提取器，
   `pselect_waiter_shift` 无法推导（`select_stack` 不可用），`kernel_phys_load` 用 SoC 兜底值。
   这三处是「命中但不稳」的头号嫌疑。
6. **vivo ICP 弹窗拦 `adb install`**。必须 `su -c pm install`，且 `su` 得先存在。

---

## 9. 环境

- 主机（仅兜底与构建时需要）：Windows，PowerShell 5.1，Go 1.22+，Python 3.10+，`adb`
- 设备：iQOO Neo9 PD2338 (V2338A)，Android 14，`PD2338_A_14.0.17.6.W10.V000L1`，
  内核 `5.15.137-g7cb3e06b062c-dirty`，serial `10CE5P1A4G001PA`
- 传输：USB 或 Wi-Fi adb（`persist.adb.tcp.port=5555`）
- 上游 payload：`ghostlock` native 二进制 + `vrpatch.ko`（内嵌于 `internal/assets/payload/`）

同时挂 USB 与 Wi-Fi 两个 transport 时**必须显式指定 serial**，否则 adb 报
`more than one device/emulator`。

---

## 10. 适用范围

仅用于本机（本人持有设备）的内核漏洞验证与移植研究。所有实测数据均来自这台 PD2338。
上游来源、许可与再分发限制见 [NOTICE.md](NOTICE.md)。
