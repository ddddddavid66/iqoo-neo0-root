# 设备侧开机自启（不依赖 PC）

目标：手机重启后自己把 root 打回来。做法是让设备内部的 adb（Termux 里装的）
连 `127.0.0.1:5555` 拿到 shell 上下文，再由 Termux:Boot 在开机时执行发射脚本。

## 前置条件（两条，缺一不可）

1. `persist.adb.tcp.port=5555` 已设置 —— 已在本机做过，可用
   `adb shell getprop persist.adb.tcp.port` 确认；返回 `5555` 就说明每次开机
   adbd 都会监听 TCP。
2. Termux 的 adb key 被设备接受，否则连 127.0.0.1 会要求授权弹窗。

## 步骤

### 1. 授权 Termux 的 adb key（复用 PC 已授权的 key）

PC 的 key 早就在 `/data/misc/adb/adb_keys` 里，所以直接把同一对 key 放进 Termux：

```powershell
.\autoroot\device\authorize-termux-adb.ps1          # 推 key 到 /sdcard/Download/
```

然后在手机上的 Termux 里执行（一次性）：

```sh
mkdir -p ~/.android
cp /sdcard/Download/adbkey     ~/.android/adbkey
cp /sdcard/Download/adbkey.pub ~/.android/adbkey.pub
chmod 600 ~/.android/adbkey
pkg install -y android-tools
```

验证：`adb connect 127.0.0.1:5555 && adb shell id` 应返回 `uid=2000(shell)`，
且**不弹授权框**。

### 2. 装 Termux:Boot（当前卡点）

设备上的 Termux 是第三方 `0.118.0 DEBUGGABLE`（签名 `db86cf3c`），F-Droid 的
`com.termux.boot` 与它共享 `com.termux` 用户但签名不同，装不上：

```
INSTALL_FAILED_SHARED_USER_INCOMPATIBLE:
  Package com.termux.boot has no signatures that match those in shared user com.termux
```

两条可行路线，选一条：

- **A（推荐，最稳）**：卸载现有 Termux，改装 F-Droid 版 `com.termux` +
  `com.termux.boot`（两者同源同签名）。代价是 Termux 里已有数据会清空。
- **B**：从当初安装这个 Termux 的同一来源找配套的 Termux:Boot（同签名）。
  找不到就只能走 A。

注意 vivo 对 `adb install` 有弹窗拦截（灭屏时直接 `User rejected permissions`），
所以 Termux:Boot 建议**直接在手机上用文件管理器点安装**，或保持亮屏时用
`adb install` 并立刻点允许。

### 3. 部署钩子

```sh
mkdir -p ~/.termux/boot
cp termux-boot-ghostlock.sh ~/.termux/boot/ghostlock.sh
chmod +x ~/.termux/boot/ghostlock.sh
```

（该文件在本仓库 `autoroot/device/` 下；也可以用 PC 侧 `adb push` 到
`/sdcard/Download/` 再在 Termux 里 cp。）

### 4. 验证

重启手机，等 2~3 分钟，然后：

```sh
cat ~/ghostlock-boot.log        # 在 Termux 里看钩子日志
```

期望看到：`boot_completed` → `uptime=2Xs` → `fire run_id=...` → `after fire: kernelsu=1`。

## 已知限制

- **payload 必须先由 PC 部署一次**。`/data/local/tmp/ghostlock/` 里需要有
  `ghostlock`、`profile.bin`、`vrpatch.ko`、`glrun.sh`、`ksud`；Termux（普通 app）
  写不进去，所以这一层仍然是「PC 首次部署 + 之后设备自愈」。
- **失手会 panic 重启**，钩子在下次开机再跑。连续多次没中会陷入
  「开机→发射→panic→开机」的循环，日志里能看到每轮 uptime 都只有几十秒。
- 设备侧路径没有「静置复查」和「崩溃取证」，这两件事仍依赖 PC 侧的
  `auto-reroot.ps1` / `watch-root.ps1`。
