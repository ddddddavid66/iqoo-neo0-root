# 方案 B：设备侧自足 root —— adbd 本地回环桥

设备：iQOO Neo9 / PD2338 / `5.15.137-g7cb3e06b062c-dirty` / Android 14 / BL 锁定
前提：App 侧触发链已打通（无障碍服务 uptime ≈22s 连接，窗口 23–48s 内发射）
本文解决：**exploit 在 App 域跑不动**的问题，让设备自己完成整条利用链。

---

## 0. 结论

方案 B 可行，卡点只剩一处：**adbd 需要一把它认可的 RSA 公钥**。这把公钥写入
`/data/misc/adb/adb_keys` 后永久有效，之后每次开机 App 都能通过本地回环连上 adbd，
由 adbd fork 出 **shell 域**进程执行 exploit —— 环境与 PC 侧成功时逐项一致。

不再需要：PC、Shizuku、Termux、无线调试配对、外部 adb 二进制。
新增只需要：App 内一个约 400 行的 Java adb 协议客户端。

---

## 1. 已实测的证据链

| # | 验证项 | 结果 |
|---|---|---|
| 1 | adbd 监听端口 | `/proc/net/tcp6` 两条 `:15B3`(5555)：`0000...0000:15B3`（全接口）+ `FFFF00000521CE0A:15B3`（10.206.33.5） |
| 2 | 端口属性持久化 | `persist.adb.tcp.port = 5555`，重启后保留 |
| 3 | shell 域本地回环 | `nc 127.0.0.1 5555` 建连成功 |
| 4 | 协议握手 | 发 24B `CNXN` 包 → 收到 `AUTH a0=1 len=20` + 20 字节挑战 |
| 5 | PC 现成密钥 | 用 `~/.android/adbkey` 做 `SHA1withRSA` 签名 → adbd 回新 token（协议与签名格式均正确，公钥不在白名单） |
| 6 | payload 驻留 | `/data/local/tmp/ghostlock/` 下 `ghostlock`(484840B)、`profile.bin`(2027B)、`glrun.sh`、`vrpatch.ko`、`ksud.bin` 全部在，跨重启保留 |

第 4 项的原始回包（证明 adbd 真的在跟我们对协议）：

```
41 55 54 48 | 01 00 00 00 | 00 00 00 00 | 14 00 00 00 | 00 00 00 00 | be aa ab b7
"  AUTH   "   arg0=TOKEN      arg1=0      len=20        check=0       magic
ed af e5 88 6f 51 22 b9 a9 4f da 24 1c 7a 86 2d 08 90 81 e4   ← 20B token
```

---

## 2. 架构

```
┌─────────────────────────────┐
│ MainActivity / 无障碍服务    │  22s 进入窗口，单次发射守卫
│ u:r:untrusted_app_27:s0     │  Seccomp=2，读不到 selinux enforce
└──────────────┬──────────────┘
               │ TCP 127.0.0.1:5555  (CNXN → AUTH SIGNATURE → OPEN "shell:")
               ▼
┌─────────────────────────────┐
│ adbd  (u:r:adbd:s0, system) │  每次认证重读 /data/misc/adb/adb_keys
└──────────────┬──────────────┘
               │ fork + setsid + setuid(2000)
               ▼
┌─────────────────────────────┐
│ sh -c 'sh /data/local/tmp/  │  u:r:shell:s0
│        ghostlock/glrun.sh'  │  Seccomp=0，enforce=1  ← PC 侧成功时的同款环境
└──────────────┬──────────────┘
               ▼
        ghostlock --force-attack → su 可用
```

**这条路的本质**：App 只负责「发起一次 TCP 连接 + 一次 RSA 签名」，exploit 本身在
adbd 的 shell 子进程里跑。App 域的三条限制（`enforce=unreadable`、`Seccomp=2`、
`untrusted_app_27`）对 exploit 不再生效。

---

## 3. 一次性部署（需要一次 root）

### 3.1 App 侧

首次启动时生成 RSA 2048 密钥对，私钥存 device-protected storage
（`/data/user_de/0/com.ghostlock.boot/files/gl/adbkey.pk8`），主页显示公钥串并提供
「复制公钥」按钮。公钥按 Android `RSAPublicKey` 结构编码：

```
struct RSAPublicKey {
    uint32_t modulus_size_words;   // 2048/32 = 64
    uint32_t n0inv;                // -1/N[0] mod 2^32
    uint8_t  modulus[256];         // 小端
    uint8_t  rr[256];              // R^2 mod N = 2^4096 mod N，小端
};
base64(结构) + " ghostlock@iqoo"
```

### 3.2 root 侧（一次）

```bash
# App 把公钥写到 /data/local/tmp/gl_pub.txt 后：
su -c 'cp /data/misc/adb/adb_keys /data/local/tmp/adb_keys.bak 2>/dev/null'
su -c 'cat /data/local/tmp/gl_pub.txt >> /data/misc/adb/adb_keys'
su -c 'chown system:shell /data/misc/adb/adb_keys'
su -c 'chmod 0640 /data/misc/adb/adb_keys'
```

`adbd` 在每次 `adb_auth_verify` 时重新读该文件，**不需要重启 adbd**。

App 侧对应的自动化入口：`MainActivity` 的「登记 adb 公钥」按钮，在检测到 `su` 可用时
自动执行上面四条（用 `su -c` 拼成一条 shell 命令）。

---

## 4. Java 客户端规格

### 4.1 报文

```java
static final int CMD_CNXN = 0x4e584e43;  // "CNXN"
static final int CMD_AUTH = 0x48545541;  // "AUTH"
static final int CMD_OPEN = 0x4e45504f;  // "OPEN"
static final int CMD_OKAY = 0x59414b4f;  // "OKAY"
static final int CMD_WRTE = 0x45545257;  // "WRTE"
static final int CMD_CLSE = 0x45534c43;  // "CLSE"

// 24 字节头，小端
void writeHeader(cmd, arg0, arg1, dataLen) {
    magic = cmd ^ 0xffffffff;
    // check 恒发 0 → adbd 侧 `if (check == 0) return true`，跨版本安全
}
```

### 4.2 认证

```
1. 发 CNXN(0x01000001, 256*1024, "host::features=cmd,shell_v2\0")
2. 收 AUTH(arg0=1, 20B token)
3. sig = Signature("SHA1withRSA").sign(token)     // 256B
4. 发 AUTH(arg0=2, sig)
5. 收 CNXN → 通过；收 AUTH(arg0=1) → 失败，最多重试 6 次
```

`SHA1withRSA` 与 adbd 侧 `RSA_verify(NID_sha1, token, 20, sig, 256, key)` 等价。

### 4.3 执行

```
OPEN(localId=1, 0, "shell:sh /data/local/tmp/ghostlock/glrun.sh\0")
  ← OKAY(remoteId, 1)
  ← WRTE(remoteId, 1, chunk) ...  每包回 OKAY(remoteId, 1)
  ← CLSE(remoteId, 1)
```

用老式 `shell:` 服务名即可，输出是裸字节流，省掉 `shell_v2` 的包 ID 解析。
需要拿退出码时改用 `shell,v2,raw:`，首字节是 stream id（0=stdin 1=stdout 2=stderr 3=exit）。

### 4.4 失败降级

| 现象 | 含义 | 处理 |
|---|---|---|
| `connect` 被拒/超时 | adbd 未起或 SELinux 拦 | 记 `bridge: connect failed`，退回到 native payload 直跑 |
| 收到 AUTH token 但循环 6 次不过 | 公钥未登记 | 记 `bridge: auth rejected`，主页高亮「需要登记 adb 公钥」 |
| OPEN 后无 OKAY | 服务名不支持 | 降级 `shell,v2,raw:` |
| 一切正常但 `su` 仍不可用 | exploit 本身失败 | 记 native.log 尾部 |

---

## 5. 时序预算

| 阶段 | 时刻（uptime） | 依据 |
|---|---|---|
| adbd 就绪 | ≈5–15s | init `core` 类服务，比 App 早得多 |
| 无障碍服务连接 | **22.2s** | 实测 |
| TCP 建连 + 认证 | +50ms | 本地回环 |
| `glrun.sh` 启动 | +100ms | |
| `prepare_kernel_page` 重试（最坏 4 次） | +9.1s | 实测日志 |
| exploit 完成 | ≈32s | |
| **窗口上限** | **48s** | 实测硬边界 |

余量约 16s，够一次重试。发射点固定在无障碍服务回调，不做额外等待。

---

## 6. 风险与对策

| 风险 | 概率 | 对策 |
|---|---|---|
| SELinux 拦 `untrusted_app` 连 5555 | 中 | **首要验证项**，见 §7。若拦，改用 `A_AUTH` 前先 `bind` 到 `wlan0` 出口 |
| `adb_keys` 被 OTA / 恢复出厂清空 | 低 | 清空时功能降级为「手动登记」，主页提示 |
| OTA 换内核导致 profile 失效 | 中 | 已有 `tools/port/` 重新生成流程 |
| 认证成功但 adbd 因 `ro.adb.secure=1` 限制本地回环 | 低 | 实测已证 adbd 对 loopback 与远端一视同仁 |
| 窗口内 adbd 尚未 ready | 低 | 22s 时 adbd 已跑 7s 以上；仍失败则记录 `adbd not ready` 供次日分析 |
| 同 boot 二次发射 | — | 沿用现有 `fireOnce` 单次守卫，一条路径成功即锁存 |

---

## 7. 首要验证项 —— 已通过

**App 域能否连上 `127.0.0.1:5555`。** 判据：收到 `AUTH` 挑战包。

已实测通过，`untrusted_app_27` 连 loopback adbd 不受限制：

```
11-16 23:32:11 bridge exec: ran via adbd, rc=0, 286B out (52ms) cmd=id; getenforce
11-16 23:32:11 bridge stdout: uid=2000(shell) ... context=u:r:shell:s0 Enforcing
11-16 23:32:11 bridge probe: bridge OK, shell domain reachable, selinux=Enforcing (52ms)
```


---

## 8. 实施阶段与验收

| 阶段 | 内容 | 验收 |
|---|---|---|
| **B-1** | `AdbBridge.java`：协议 + 认证 + exec，`MainActivity` 加「测试 adbd 通道」按钮 | 点击后 logcat 出现 `AUTH received` 或 `auth rejected`（两者都算连通性通过） |
| **B-2** | 公钥生成与登记：App 生成密钥对、显示公钥；`su` 可用时一键写 `adb_keys` | 登记后「测试通道」返回 `CNXN OK` |
| **B-3** | 接入 `fireOnce`：窗口内先走桥（`adb shell glrun.sh`），桥不可用时退回 native 直跑 | 手动点「立即发射」能在 shell 域跑起 glrun.sh，native.log 出现 `startup context ... u:r:shell:s0` |
| **B-4** | 冷启动实测：重启后不插电脑，观察是否自动拿到 root | 连续 5 次重启，≥4 次在 uptime 60s 内 `su -c id` 返回 uid=0 |
| **B-5** | 文档与回滚：`adb_keys` 备份、按钮级回滚、README 补齐 | 回滚后设备行为与改动前一致 |

---

## 9. 与既有方案的关系

- **PC 侧看门狗**继续保留，作为 B 失败时的兜底与「一次 root 换取 adb_keys 登记」的工具。
- 两条路共用 `/data/local/tmp/ghostlock/` 与同一份 `profile.bin`，互斥用设备侧锁文件。
- B 跑通后，PC 侧从「每次开机必需」降级为「部署工具 + 应急」。

---

## 10. 实测记录（2026-11-16）

四个坑，全部靠「抓一次真实 adb 的会话再逐字节对比」定位。任何一个没修好，
表现都只是「没反应」，极易误判成 SELinux 拦截或密钥未登记。

### 10.1 认证签名：adbd 不做 SHA1withRSA

教科书 `SHA1withRSA(token)` 会被静默拒绝，adbd 只回一个新 token，看起来
与「公钥没登记」一模一样。把 `adb_keys` 里明明存在的公钥当成「没写进去」，
排查方向就全错了。

用 PC 的 adb 密钥解出真实签名块才看清结构：

```
00 01 ff*218 00 | 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 | <20B token>
                 └────────────── DigestInfo(SHA-1) ─────────────┘   └ 直接是 token ┘
```

也就是说 **token 被当成已经算好的摘要**，`DigestInfo || token` 裸签。
按这个算式重算，与抓到的签名逐字节相同（`23c5b264c9cb7eb2...`）。

### 10.2 shell 服务：`shell:` 的 pty 会杀死流

`echo a; echo b` 正常，`echo a; id; echo b` 只回 `a`。第一个外部命令之后
整个流就结束了。换成 `shell,v2,TERM=dumb,raw:` 解决。

### 10.3 shell_v2 的记录格式：不是「1 字节 id + 数据」

真实的是**记录序列** `[sid:1][len:4 小端][data:len]`，一个 WRTE 里可能串了
多条（`A2\n` 和退出码 0 就在同一个包里）。把长度字当成正文，就会得到
「内建命令正常、外部命令输出全丢」这种诡异现象。

### 10.4 OKAY 的 id 顺序：客户端发 `(local, remote)`

adbd 发的是 `OKAY a0=remote a1=local`，客户端要回 `OKAY a0=local a1=remote`。
发反了，adbd 收一个 chunk 就 CLSE，表现是「只拿到第一行输出」。

### 10.5 最终状态

| 项 | 结果 |
|---|---|
| App 域连 loopback adbd | ✔ 25–52ms |
| RSA 认证 | ✔ 一次通过 |
| shell 域执行 | ✔ `uid=2000` / `u:r:shell:s0` |
| 退出码与 stdout/stderr 分离 | ✔ `rc=0`，286B |
| `su` 在桥接 shell 里 | ✔ `uid=0(root)` / `u:r:ksu:s0` |
| adb 公钥登记 | ✔ `/data/misc/adb/adb_keys` 2 行（PC 那把本就在第一行） |

注意最后一行：**PC 的公钥一直都在 `adb_keys` 第一行**。之前「认证失败」
纯粹是签名算法错，与登记无关。这也意味着**登记这一步其实可以完全跳过**——
直接用 PC 的密钥（已经打进 `assets/adbkey.der`）就能工作。

### 10.6 CLSE 必须应答（2026-11-17 00:20 那次冷启动）

守卫和桥接都对了，probe 在 uptime 23.1s 拿到 shell 域，exploit 真的发射出去，然后：

```
00:20:42 bridge exec: stream died mid-run: adbd closed after 0/24 bytes
00:20:42 bridge ran the exploit (1445ms)
00:20:42 payload exited rc=-1 -> shell domain returned nothing
```

`0/24 bytes` 是认证阶段就读不到包头，看上去像「adbd 挂了」。真实原因是**上一条流
没回 `CLSE`**：adbd 按 transport 维护流状态，一条悬空的流会让下一次连接在认证时
被判为异常。补上

```java
ch.send(CMD_CLSE, localId, m.arg0, null);
```

即恢复。这个坑的误导性在于它伪装成「adbd 还没就绪」，很容易让人去调时序而不是查协议。

### 10.7 adbd 的就绪时刻

实测 uptime **22.6s** 时 TCP 端口能连上但一个字节都不回，**23.1s** 时认证即通。
无障碍服务在 22.5s 连接，`fireOnce` 等到 23.0s 才发射 —— 这三条时间线刚好咬合，
但余量只有约 0.5s。所以桥接前的轮询不是保险丝，是必需品。

### 10.8 发射时刻：23s 是必死区，必须 30s

2026-11-17 00:30 那次冷启动，桥接本身完全正常：

```
00:30:22 accessibility connected, uptime=22.114s
00:30:23 firing (accessibility) uptime=23.0s
00:30:23 bridge ready at uptime=23.2s (shell domain reachable, selinux=Enforcing)
00:30:24 bridge exec: stream died mid-run: adbd closed after 0/24 bytes
```

探针单独复现 `sh glrun.sh` 时更直接：adbd 连接以裸 `closed` 结束，设备随即从 USB 消失。
内核被打了。

这不是协议问题。早先记录过命中区间是 **uptime 31–71s**，早于 25s 发射等于拿一次
内核 panic 换零收益。而 `WIN_LOW` 当时是 23 —— 正好落在必死区，于是每一次冷启动
都在「一切正常」的表象下把内核打死一次。

改成 30。PC 侧一直用 `-MinUptime 25`、实际落在 30s 左右，这正是它成功而 App 失败的原因。

顺带说明桥接为什么值得保留这个轮询：adbd 在 22.6s 时端口通但不回包，23.1s 才认证通过。
把发射点挪到 30s 之后，probe 一次就过，轮询退化成纯保险。

### 10.9 单发命中率不够，窗口内要重试

2026-11-17 00:42 那次，桥接和窗口都对了，exploit 在 shell 域完整跑完 3.5 秒：

```
[+] startup context pid=8873 uid=2000 euid=2000 gid=2000 boot_ms=30256 attr=u:r:shell:s0 enforce=1
[+] startup limits  pid=8873 NoNewPrivs=0 Seccomp=0 Seccomp_filters=0
[+] prepare_kernel_page ok attempt=1 +1189ms
[route] CMP_REQUEUE_PI ret=-1 errno=35; waiting route_done
[-]   PI route did not produce a verified write
[-] W1: SELinux attempt 1 route failed; backing off
[-] Write 1 failed
=== native exit=1
```

这三行 startup 与 PC 侧成功时逐字相同 —— 环境问题已经解决，剩下的纯粹是 futex-PI
竞争没打中。payload 自己判定 `clean=1/1`，说明内核状态干净，同一窗口再打一次是安全的。

于是 `fire` 改成窗口内最多 3 次、间隔 1.5s，用 `su -c id` 做事实判定，
超过 uptime 46s 就停（剩余窗口不够跑一次 4 秒的 exploit）。PC 侧看门狗本来也要
1–2 轮才成功，单发命中率约六成。

### 10.10 六个坑的排查顺序（下次直接照这个走）

1. TCP 能不能连上 5555 → `nc 127.0.0.1 5555`
2. 有没有收到 `AUTH` 挑战包 → 收不到是 SELinux 或 adbd 未起
3. 签名对不对 → 解出签名块看是不是 `DigestInfo || token`
4. 流活着吗 → 外部命令之后还有输出吗（`echo a; id; echo b`）
5. OKAY/CLSE 的 id 顺序对不对 → 一条流只能用一次，第二次连接认证即断
6. 发射时刻在不在 30–48s → 23s 会把内核打死

### 10.11 判定时机：late-load 是异步的

2026-11-17 00:52 那次，两发都在 `su` 上判"失败"：

```
00:52:33 bridge exec: rc=0, 1829B out (9252ms)   ← 第 1 发，uptime 30→39s
00:52:33 su -c id -> /system/bin/sh: su: inaccessible or not found
00:52:39 bridge exec: rc=0, 1885B out (4362ms)   ← 第 2 发，uptime 39→45s
00:52:39 su -c id -> /system/bin/sh: su: inaccessible or not found
```

但外部脚本在 **uptime 71s** 拿到了 `uid=0`。**第 2 发其实是成功的** —— exploit
只负责把内核模块载进去，KernelSU 的 daemon 还要过几秒才把 `su` 发布出来。

于是判定改成：**发射一次，然后每 3s 查一次 `su`，最多 60s**。
uptime 只约束「发射」这件事，不该约束「等待」。

这也解释了为什么早先版本看起来"完全没反应"：每发之后立刻判负，然后降级，
真正成功的那一发从来没有机会被认出来。

---

## 11. 验收结果（2026-11-17 凌晨）

条件：PC 侧看门狗已停用、启动项临时改名，`adb` 只用来观察，不发送任何命令。

| 时刻 | 发射 uptime | 结果 | 备注 |
|---|---|---|---|
| 01:00:21 | 30.0s | **成功** | 21s 后 `su` 可用 |
| 01:04:18 | 30.0s | 失败 | 单发未中，内核 `clean=1/1` |
| 01:09:07 | 30.0s | **成功** | 15s 后 `su` 可用 |
| 01:13:05 | 30.0s | **成功** | uptime 59s 时 `uid=0` |

3/4。失败那次可以确认是 futex-PI 竞争没打中，环境与成功的三次完全相同。

成功那次的完整日志：

```
01:09:07 firing (accessibility) uptime=30.0s boot=3f5d6264-...
01:09:07 bridge ready at uptime=30.1s (bridge OK, shell domain reachable, selinux=Enforcing (75ms))
01:09:22 bridge: attempt 1 missed (uptime=44s), no room for another shot
01:09:37 bridge: root confirmed late, 15s after the last shot
```

注意 `attempt 1 missed` 后面紧接 `root confirmed late` —— 同一次发射，只是 `su` 晚到了
15 秒。这正是第 10.11 节那个坑的实例：如果按 payload 退出码判定，这一发会被判失败。

至此「手机自己开机自动 root」闭环成立：触发、桥接、发射、判定全部在设备侧完成。
