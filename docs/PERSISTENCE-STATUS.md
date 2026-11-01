# P-B4（设备侧自愈）进展与阻塞点

时间：2026-11-01 18:0x

## 已打通：设备侧需要的「shell 通道」可以做到无 USB

用 root 设了一次：

```
setprop persist.adb.tcp.port 5555
```

之后**每次开机 adbd 都监听 TCP**（实测重启后 `netstat -ltn` 有 `[::]:5555 LISTEN`），
PC 侧 `adb connect <手机IP>:5555` 直接可用，复用已授权的 adb key：

```
$ adb connect 10.206.33.5:5555
connected to 10.206.33.5:5555
$ adb -s 10.206.33.5:5555 shell cat /proc/uptime
49.80 119.09
```

这条通道是「设备自己连自己」的前提：手机上的 Termux/任意 shell 客户端连
`127.0.0.1:5555` 就能拿到 `u:r:shell:s0`（uid 2000），与 USB adb 等价。

## 看门狗已支持无线

`autoroot/auto-reroot.ps1 -Wireless 10.206.33.5:5555`：

- 启动时 `adb connect`，`Wait-Device` 里每 5s 重试（开机后 Wi-Fi 关联要 20–30s，
  adbd 的 5555 在那之前连不上）；
- 发射时把 `--serial <IP>:5555` 显式传给 ghostlock，避免 USB 与 TCP 同时在线时选错设备。

实测：18:01 无线模式下窗口内发射成功（日志 `成功：su 已可用`）。
注意本机 adb over Wi-Fi 会偶发 `offline`/连接超时，脚本已按「重试 + 显式 serial」处理。

## 阻塞点 1：Termux:Boot 装不上（签名不匹配）

- 设备上的 Termux 是 `0.118.0`，`pkgFlags=[DEBUGGABLE …]`，签名 `db86cf3c`
  （GitHub/第三方构建，不是 F-Droid 签名）。
- F-Droid 的 `com.termux.boot_1000.apk` 与它共享 `com.termux` 用户但签名不同：

```
Failure [INSTALL_FAILED_SHARED_USER_INCOMPATIBLE:
  Reconcile failed: Package com.termux.boot has no signatures that match those
  in shared user com.termux; ignoring!]
```

可选解法：装与当前 Termux 同签名的 boot 插件；或把 Termux 换成 F-Droid 版（会清数据）。
两条都需要人手。

## 阻塞点 2：adb install 需要屏幕上点「允许」

vivo 对 `adb install` 弹窗确认，屏幕灭/锁屏时直接 `INSTALL_FAILED_ABORTED: User rejected permissions`。
`settings put global verifier_verify_adb_installs 0`（root 下）后仍会被 vivo 的安装器拦。
==> 任何「临时装一个 APK」的方案都需要用户在场点一次。

## 阻塞点 3（更严重）：root 拿到后可能 1–2 分钟内被重启

多次观察到：`成功：su 已可用` 之后 60–120s，设备自己重启，root 丢失
（`ro.boot.bootreason` 有的是 `reboot`（我 adb reboot 的），有的是内核 panic）。

对照实验结论（2026-11-01 18:1x）：

| 场景 | 结果 |
|---|---|
| 带 vrpatch 打成功后，**13 小时不碰** | root 全程在线（uptime 47394s）→ 不是「必崩」 |
| 带 vrpatch 打成功后，每 20s 轮询 `su -c id` | 1–8 分钟内掉（多次） |
| **`--no-vrpatch`** 打成功后每 20s 轮询 | 18:13:16 拿到 root，18:13:36 掉线，18:14:49 已重启（≈30s 内） |
| 14:20 那次打成功后 `18/18` 次采样（20s 间隔） | 到 uptime 459s 全程在线 |

结论：**不是 vrpatch 单独引起的**；「频繁用 `su -c id` 轮询」与「掉 root」在时间上高度相关，
嫌疑落在 late-load 之后的 su/ksud 路径或 `kernel.panic_on_rcu_stall=1`。静置不碰的样本
（13h、7.6min）都活着。

下一步对照：打成功后**完全不碰设备** 5 分钟再采一次；以及 `--temp-root`（不 late-load）
同样的静置/轮询对比。

## 下一步（按依赖顺序）

1. 定性「成功后自发重启」：`--no-vrpatch` / `--temp-root` 两组对照，各跑 3 次。
2. 若 `--temp-root` 稳定：说明 KSU late-load 是代价，考虑只在需要时才 late-load
   （平日 temp root 足够用）。
3. 设备侧自愈：解决 Termux:Boot 签名（找人手一次）后，脚本已可写：
   `/data/data/com.termux/files/home/.termux/boot/ghostlock.sh` → `adb connect 127.0.0.1:5555`
   → `adb -s 127.0.0.1:5555 shell /data/local/tmp/ghostlock/glrun.sh`。
4. 备选：用户手动开无线调试 + Shizuku 配对一次，用 Shizuku 的「开机自启动」。


## 18:2x 补充：看门狗的一个真 bug（已修）

`auto-reroot.ps1` 在 **无线模式下** 调用 ghostlock 时，`--serial` 只在地址形如 `IP:port`
时才加；但该脚本里 `$Serial` 被换成 `10.206.33.5:5555` 之后，
`$Serial -match ":\d+$"` 这层判断在 USB 模式里不会生效，于是 USB 和 TCP 同时在线时
ghostlock 可能选到未醒的 transport，探测出空内核：

```
错误: no bundled profile for kernel "" — pass --conf with your own profile
```

18:17 与 18:23 两次「失败」都是这个原因，不是漏洞没打中。

修复：
- 永远显式传 `--serial $Serial`；
- 发射前加 `Wait-Probe`（`adb shell uname -r` 非空，最多等 20s），探测不到就记
  `probe-failed` 并放弃本次，不浪费窗口；
- 无线模式下发射前再 `adb connect` 一次。

修完后 18:29 恢复成功（第 3 轮命中，`成功：su 已可用`）。
