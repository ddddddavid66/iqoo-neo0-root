# GhostLock Boot —— 手机自己开机自动 root

目标：手机重启后自己完成 root，**PC 不参与**。

现状：**已跑通**。2026-11-17 凌晨 4 次冷启动（PC 侧看门狗停用、启动项临时改名），
3 次由手机自己在 uptime 30s 发射并拿到 root，第 4 次是 futex-PI 竞争没打中。
App 域连本机 adbd 57–236ms，exploit 在 `u:r:shell:s0` / `Seccomp=0` 环境里执行。

`libksud.so` 需要从设备拉一次（插上 USB 后跑 `python build.py --fetch-ksud`）。

桥接的原理与四个实测坑见 `docs/PLAN-B-SHELL-BRIDGE.md`。

---

## 为什么必须是 APK

Android 上「开机自动执行任意程序」只有一条合法路径：一个装了 `BOOT_COMPLETED`
接收器的 App。没有 root 时，App 是权限最低的载体，所以整个方案要绕开两条硬限制：

| 限制 | 绕法 |
|---|---|
| Android 10+ 禁止 App 执行自己数据目录里的文件（`app_data_file` 无 `execute`） | payload 放进 `lib/arm64-v8a/`，那是 `apk_data_file`，允许 exec |
| App 完全碰不到 `/data/local/tmp`（`shell_data_file` 域隔离） | 所有文件走 `filesDir`，ksud 用软链指向 `nativeLibraryDir` |

`lib/arm64-v8a/` 里的 `.so` 不是库，是可执行的 PIE 二进制。安装时
`extractNativeLibs=true` 会把它们解压到 `nativeLibraryDir`，那里可以直接 `exec`。
Shizuku 用的是同一个手法。

## 工程结构

```
apk/
  AndroidManifest.xml          targetSdk 28（保住 untrusted_app_27 域）
  res/values/strings.xml
  src/com/ghostlock/boot/
    Launcher.java              窗口判定 / 单次发射 / 环境变量 / exec
    AdbBridge.java             本机 adbd 客户端：RSA 认证 + shell_v2 执行
    BootReceiver.java          BOOT_COMPLETED 入口
    RootService.java           前台服务 + WakeLock，承载 payload
    MainActivity.java          手动控制台
  assets/
    profile.bin                由 ghostlock profile compile 生成
    vrpatch.ko                 内核模块
    adbkey.der                 PC 的 adb 私钥（不入库），用于通过 adbd 认证
  lib/arm64-v8a/
    libghostlock.so            GhostLock native payload
    libksud.so                 从设备拉，SukiSU 的 lib（混淆名 libdhxddxovny.so）
  build.py                     构建脚本，不需要 Gradle
```

## 构建

需要（都已在本机 `D:\David\study2222\tool`）：

- `android-sdk/build-tools/37.0.0`（aapt2 / d8 / zipalign / apksigner）
- `android-sdk/platforms/android-36/android.jar`
- `jdk/jdk-21.0.12.1+1`

```powershell
cd D:\David\temp\root\apk
python build.py --fetch-ksud      # 第一次要把 libksud.so 从手机拉下来
```

`--fetch-ksud` 只是只读操作：找到设备上最大的 aarch64 `.so`，`adb pull` 下来。
不改设备任何状态。

产物：`build/ghostlock-boot.apk`（约 6.5 MB，主要体积是 ksud）。

> **换机器或重新 clone 时注意签名。** `keystore.jks` 与 `assets/adbkey.der` 都不入库。
> `build.py` 发现 keystore 缺失会自己生成一把，但新签名与设备上已装的 APK 冲突，
> `pm install` 会报 `INSTALL_FAILED_UPDATE_INCOMPATIBLE`。此时先
> `pm uninstall com.ghostlock.boot` —— 代价是旧密钥随之失效，重装后要在有 root 的
> 会话里把新公钥追加到 `/data/misc/adb/adb_keys`（App 主页「复制 adb 公钥」）。
> 两个文件都留着就不用管这条。

## 安装与放行

```powershell
adb install -r build\ghostlock-boot.apk
```

装完必须在手机上手动做两件事，否则 `BOOT_COMPLETED` 收不到：

1. **i管家 → 应用管理 → 自启动**：把 `GhostLock Boot` 加白名单（OriginOS 默认杀第三方自启）
2. **设置 → 电池 → 后台高耗电**：允许后台

Android 14 上 `targetSdk 28` 的 APK 安装时会提示「专为旧版 Android 打造」，点继续。

## 实测流程

1. 打开 App，确认状态页五行都是 `ok`：
   ```
   payload     : ok
   ksud        : ok
   profile.bin : ok
   vrpatch.ko  : ok
   ```
2. 重启手机，锁屏放着就行
3. 开机后 `adb shell su -c id` → 期望 `uid=0(root) ... context=u:r:ksu:s0`
4. 没成的话打开 App 看日志，`adb logcat -s GhostLockBoot` 同时抓一份

App 里的两个按钮：

- **立即发射（忽略窗口）**：跳过 uptime 窗口直接打。用在「开机广播来晚了、窗口已过」
  的情况，风险是可能把内核打死重启
- **重置本 boot 标记**：清掉「这个 boot 已经打过」的记录，才能手动重打

## adbd 桥接：为什么 exploit 不在 App 里跑

App 进程是 `u:r:untrusted_app_27`，`Seccomp=2`，连 `/sys/fs/selinux/enforce` 都读不到。
exploit 在里面能启动、能进 `prepare_kernel_page`，然后连续 4 次 `heap spray failed`：

```
[+] startup context pid=7267 uid=10293 attr=u:r:untrusted_app_27:s0:c37,c257,c512,c768 enforce=unreadable
[+] startup limits  pid=7267 NoNewPrivs=0 Seccomp=2 Seccomp_filters=1
[-] prepare_kernel_page retry 4/4 +9089ms -> heap spray failed
```

而 adbd 每台机器上都已经在跑，`persist.adb.tcp.port=5555` 让它监听 0.0.0.0，
并且它 fork 出来的服务是 `u:r:shell:s0`、`Seccomp=0`、enforce 可读 —— 正是 exploit
需要的环境。所以 App 只需要说一句话：

```
TCP 127.0.0.1:5555  →  CNXN  →  AUTH SIGNATURE  →  OPEN "shell,v2,TERM=dumb,raw:sh /data/local/tmp/ghostlock/glrun.sh"
```

约 400 行 Java，没有外部依赖。四个实测坑（签名算法、pty、记录格式、OKAY 顺序）
记在 `docs/PLAN-B-SHELL-BRIDGE.md` 第 10 节。

**一次性前提**：PC 的 adb 公钥要在 `/data/misc/adb/adb_keys` 里。实测这台机器第一行
本来就是它，所以连这一步都省了 —— APK 里带的 `assets/adbkey.der` 直接可用。
换机器时用主页的「复制 adb 公钥」按钮把公钥交给有 root 的会话追加进去即可。

## 代码里定死的规则（都有实测依据）

| 规则 | 依据 |
|---|---|
| 一个 boot 只发射一次 | 同一 boot 第二次发射会让内核在约 60s 后 panic，连第一次拿到的 root 一起赔掉。见 `docs/ROOT-DROP-60S.md` |
| 窗口 30–48s | 命中集中在 uptime 31–71s；66s、77s 两次把内核打死。下沿从 23 抬到 30：2026-11-17 00:30 那次在 23.0s 发射，probe 明明已经拿到 shell 域，exploit 一跑内核就死、设备从 USB 消失 |
| `GHOSTLOCK_KSU_ENFORCE=1` | W1（写 `selinux_enforcing`）在本机直接崩内核，只能跳过，SELinux 保持 Enforcing |
| `targetSdk 28` | 保住 `untrusted_app_27` 域；targetSdk 29+ 会进 `untrusted_app`，seccomp 更严 |
| 守卫写在「等窗口」之后 | 2026-11-17 00:15 那次：20.5s 的触发先写了时间戳再去 sleep 等 23s，21.4s 无障碍到达时看到秒新的时间戳，以「fired 0s ago」把自己拦了，之后每个触发同样被拦，整个 boot 一次都没发射 |
| 时间戳必须带 boot_id | `elapsedRealtime` 每次开机归零。裸毫秒值在两个 boot 的相同时刻会互相冒充「刚打过」—— 而开机触发点每次都落在 21–23s，必然撞车 |
| 桥接前先轮询 adbd 就绪 | uptime 22s 时 adbd 的 TCP 端口能连上但一个字节都不发就关掉，直接读作「桥不可用」而降级到注定失败的本地路径。截止到 uptime 36s，留 12s 给 exploit |
| 判定要轮询，不能看 payload 退出码 | late-load 是异步的：2026-11-17 00:52 两发都在 payload 刚结束时判「su 不可用」，而 su 在 26s 后才活过来。发射一次后每 3s 查一次 `su`，给满 60s |
| 窗口内可补第二发 | 单发命中率约六成。payload 自己判定 `clean=1/1`，说明没打中时内核状态干净，同一窗口再打一次安全（00:52 那次就是第二发中的） |

## 已知风险（明天实测要重点看）

1. **`exec` 能不能成**。App 域执行 `nativeLibraryDir` 的二进制是主流做法（Shizuku、
   Termux 都这么干），但本机没验证过。
2. **insmod 会不会被 SELinux 拦**。exploit 拿到 uid0 后，进程域仍是
   `untrusted_app_27`；`init_module` 需要 `kernel:system module_request`，这个域可能没有。
   PC 端是 `u:r:shell:s0`，能 insmod。
   → 如果失败，日志里会看到 `Loaded kernel module` 缺失，或 ksu.log 停在 `vrpatch` 那一步。
3. **seccomp**。App 默认带 seccomp filter，PC 端 shell 域是 `Seccomp=0`。
   futex/mmap/clone 都在白名单里，但 exploit 若用到 `perf_event_open` 之类的会被 SIGSYS。
4. **BOOT_COMPLETED 的时机**。OriginOS 可能把广播压到 uptime 60s 之后，那样会
   `skip: uptime past window`。看日志里第一行 broadcast 的时间戳就知道。
