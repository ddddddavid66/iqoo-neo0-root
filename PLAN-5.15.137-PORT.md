# 移植计划：GhostLock PC 工具支持 iQOO Neo9 `5.15.137-g7cb3e06b062c-dirty`

范围：先把「这台机器的固件」变成仓库里一等公民（可重跑、可测试、语义可解释），
真机 root 作为第二阶段单独执行。全部 P0–P4 都不需要手机在线。

前置事实（已实测，见 `ROOT-PROGRESS.md`）：
设备 `PD2338_A_14.0.17.6.W10.V000L1` / 内核 `5.15.137-g7cb3e06b062c-dirty`；
OTA 里 `remove_waiter@0x1827508` 未打补丁；建议路由 `multicast_waiter`，`waiter_off=80`。

---

## P0 资产固化（DoD：目录 + 校验和清单）

1. `artifacts/5.15.137/` 存放：`kernel.bin`（49 789 440 B）、`kernel.btf`、`vmlinux.elf`、
   `boot_full.raw`、`xbl_config.img`、`uefi.img`、`extractor-analysis.txt`、`extractor-conf.conf`。
2. `artifacts/SHA256SUMS` 记录每个文件哈希 + OTA 包 `FILE_HASH`（`payload_properties.txt` 里的 base64 → hex）。
3. 说明 OTA 来源与解包命令，保证任何人能从 zip 复现到 `kernel.bin`。

## P1 PC 侧重建管线（DoD：一条命令产出 conf，且与原生 extractor 输出逐字段一致）

新建 `tools/port/`，把上一轮的一次性脚本产品化：

| 文件 | 职责 |
|---|---|
| `extract_payload.py` | payload.bin 解析（含多 extent 正确分配、XZ/BZ/ZERO），替代有 bug 的 `payload_dumper` |
| `unpack_boot.py` | vivo 的「boot 分区 = N×32 MiB 独立 zstd frame」拆解 + Android boot header v4 解析 + 切出 arm64 `Image` |
| `kernel_syms.py` | 调 `vmlinux-to-elf` 恢复 kallsyms，导出符号表 JSON（基址 `0xffffffc008000000`） |
| `kernel_btf.py` | 从 `Image` 定位内嵌 BTF（magic `0xeb9f` + 头部自洽校验），解析 `task_struct` / `cred` / `rt_mutex_waiter` / `mm_struct` / `tracepoint` |
| `derive_profile.py` | 组装 conf：route 判定（`ip_mc_source`/`core_sys_select`/`tcp_zerocopy_receive` 是否存在）、`waiter_off`、`offset.*`（符号 − `_text`）、cred 模板、`ref*_image`、`vr_sys_exit_tp` |
| `blob_decode.py` | 按 README 的 blob 格式解码 `profile.bin`，用于验收 P3 的编码结果 |

验收：`python tools/port/derive_profile.py artifacts/5.15.137/kernel.bin -o out.conf` 的输出，
与 `artifacts/5.15.137/extractor-conf.conf`（设备上 `gl-extract --format conf` 的黄金样本）
做结构化 diff：`task_struct.*`、`cred.*`、`offset.*`、`route.multicast_waiter.*` 必须全等。

## P2 语义闭环（DoD：`docs/PORT-NOTES.md` 里每个非显然字段都有出处）

需要在这阶段讲清并写进文档的字段：

1. `offset.vr_sys_exit_tp` —— 现在填的是 `__tracepoint_sys_exit − _text = 49333960`。候选还有
   `+0x40`（`.funcs` 字段，本内核 BTF 实测）与 `+0x28`（`iterator`）。
   手段：capstone 定位 payload 里消费该 offset 的函数（日志串 `.rodata+0x1541d`），
   看它是 `target = image + slide` 还是 `image + slide + const`，即可定语义。
2. `route.multicast_waiter.waiter_off` —— 验证「setsockopt 路径栈深度 − futex 路径栈深度」
   这一解释：用我们内核 `Image` 反汇编 `ip_mc_source` / `futex_wait` 的栈帧偏移，
   复算 0x358 − 0x308 = 0x50，确认与原生 extractor 一致。
3. `cred.ref0..3_image` —— 判定它编码的全局对象（`root_user` / `init_user_ns` /
   `init_ucounts` / `init_groups`）。我们的符号表里有这四个，可直接验证公式形状
   （绝对值 → 符号地址与偏移的映射）。
4. `cred.caps_*` / `ref*_offset` 来自 BTF 的哪些字段（`cap_permitted` 起 3 段、`user`/`user_ns`/`ucounts`/`group_info`）。
5. `kernel_phys_load` / `kernel_phys_offset` 在 `null` 时原生的回退规则（SoC 公式），
   以及与本机 xbl_config/uefi 解析失败的关系（两者都没带 Kernel memory-map）。
6. `recommend_shizuku`、`mcast.attempts/arm_*`、`execution.*` 这些「非提取项」的取值来源
   （沿用 5.15.197 的实测值，标注为「同族继承」）。

## P3 集成进仓库（DoD：`go test ./...` 全绿，`profile show` 能列出新 release）

1. 新增 `internal/assets/profiles/5.15.137-g7cb3e06b062c-dirty.conf`（由 P1 产出 + P2 补齐的 vr 段）。
2. `internal/assets/profiles/index.conf` 增加 `{ release = "5.15.137-…", file = "5.15.137-….conf" }`。
3. `internal/profile/profile_test.go` 增加 `TestResolveNeo9_5137`：锁住 `waiter_off`、
   `task_struct.cred`、`cred.copy_size`、`offset.init_task`、`meta.vr_guard`、
   `route.multicast_waiter.waiter_off`，并断言 `Resolve` 的 `InvalidPaths` 为空
   （`execution.*` 全部命中，说明 conf 自洽）。
4. `internal/stage/stage.go` 的 release 匹配路径加一条 fallback：`-dirty` 后缀 / 前缀匹配
   命中时打印明确提示（现在不匹配就直接报「no bundled profile」）。
5. README：把「只支持 5.15.197 一种」改为支持列表 + 「同族 profile 生成流程」一节，
   指向 `tools/port/`。

## P4 离线验收（DoD：产物与日志留档，不接触设备）

1. `go vet ./...`、`go test ./...`。
2. `bin/ghostlock.exe profile show 5.15.137-g7cb3e06b062c-dirty` —— 字段全打印、无 0 值异常项。
3. `bin/ghostlock.exe profile compile internal/assets/profiles/5.15.137-….conf -o build/profile-5137.bin`，
   再用 `tools/port/blob_decode.py` 解码，与 conf 逐键比对；确认 `meta.vr_guard=1`、
   `route.multicast_waiter.waiter_off=80`、`kernel.compact_waiter=1`、
   `offset.vr_sys_exit_tp` 落在可打印范围。
4. `make win` / `make arm64` 两个目标都能产出单文件二进制。
5. 交叉校验：把 `tools/port` 的产出与 `gl-extract --format json` 的 `struct_fields` 全字段比对
   （`waiter_task/lock/tree/pi_tree/wake_state/ww_ctx`、`task_cred`、`cred_caps`、`mm_struct` size）。

## P5 真机 root（第二阶段，单独一轮执行）

1. 手机侧准备：USB 调试已授权、关闭「停止限制子进程」、去锁屏、USB=文件传输。
2. KSU 管理器 APK 就位（SukiSU Ultra / KSU spoofed 构建），`manager install`。
3. `doctor` → `run --dry-run` → `run --loop`。
4. 日志 triage 矩阵：
   - `multicast route status=… errno=99` → vr_guard 未生效，切 `vr_sys_exit_tp` 候选（`+0x40` / `+0x28`）。
   - KernelSnitch 阶段反复失败 → 显式给 `kernel_phys_load=2818572288` / `kernel_phys_offset=2147483648`。
   - mcast 几何报错 → 回退 `--route select_stack`（当前 `waiter_shift` 推导失败，需先补 P2 的推导）。
   - `ksud.log` insmod 失败 → 换 APK 版本（`vrpatch.ko` vermagic 是 5.15.202，走 late-load 绕过）。
5. 成功判据：`adb shell su -c id` → `uid=0(root)`，或 `/proc/modules` 出现 `kernelsu`。
6. 收尾：`run --loop --clean-after` 清 staging；记录本轮成功参数到 `ROOT-PROGRESS.md`。

## P6 回滚与记录

系统分区全程不写（erofs + dm-verity 保持 green）；全量包在手可直接重刷复原。
每次真机尝试记录：时间、参数、`native-*.log` 关键行、是否 panic/重启。

---

## 执行顺序与门禁

| 阶段 | 门禁 |
|---|---|
| P0 | 哈希清单可复现 |
| P1 | 与黄金样本逐字段 diff 为空 |
| P2 | `PORT-NOTES.md` 中 6 项全部有出处；`vr_sys_exit_tp` 语义唯一确定 |
| P3 | `go test` 全绿 + `profile show` 正常 |
| P4 | blob 解码一致 + 双平台构建通过 |
| P5 | 拿到 `uid=0` 或明确失败原因 |

P1/P2 是本次的重点：把「一次性凑出来的 conf」变成「可解释、可重跑、可测试的移植」。
