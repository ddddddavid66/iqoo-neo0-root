# PORT-NOTES — `5.15.137-g7cb3e06b062c-dirty` 移植笔记

设备：iQOO Neo9（PD2338 / V2338A，SM8550）· `PD2338_A_14.0.17.6.W10.V000L1` · Android 14
内核：`5.15.137-g7cb3e06b062c-dirty`（`#1 SMP PREEMPT Mon Oct 21 08:59:09 UTC 2024`）
OTA：`2024102417450012e95ba0ef486241d8f9248499af622d.zip`（`post-version` 与设备一致）

本文回答「每个非显然字段为什么是这个值」，并把两个**无法离线推导**的字段单独列出。

---

## 1. 从镜像里能直接算出来的（可复算）

### 1.1 kallsyms 与基址

镜像内嵌 kallsyms（压缩名字表），`vmlinux-to-elf` 恢复出 **187 976** 个符号。
`text_offset = 0`，因此内核虚拟基址 `_text = 0xffffffc008000000`（与官方提取器
`kimage_text_base` 字段一致）。profile 的 `offset.*` 全部是 **符号地址 − `_text`**。

实测（十进制 / 十六进制）：

| 符号 | 偏移 |
|---|---|
| `init_task` | 48702976 / `0x2e72600` |
| `init_cred` | 48407992 / `0x2e2a5b8` |
| `empty_zero_page` | 49807360 / `0x2f80000` |
| `root_task_group` | 49826624 / `0x2f84b40` |
| `security_hook_heads` | 36612720 / `0x22eaa70` |
| `selinux_blob_sizes` | 36622024 / `0x22ecec8` |
| `nfulnl_logger` | 47063216 / `0x2ce20b0` |
| `loggers` | 47063000 / `0x2ce1fd8` |
| `sysctl_bootid` | 51191369 / `0x30d1e49` |
| `selinux_state` | 51076992 / `0x30b5f80` |
| `__tracepoint_sys_exit` | 49333960 / `0x2f0c6c8` |

两个容易踩的坑：

- **`selinux_enforcing` 在本内核没有独立符号。** 它是 `struct selinux_state` 的
  第一个成员，直接取 `selinux_state` 的地址即为官方输出值（51076992，实测相等）。
- **`slide_boot_id` 不是 8 对齐值**（`0x30d1e49`）。它对应 `sysctl_bootid`（字符数组），
  官方输出同样不对齐，不要「修正」它。

### 1.2 `slide_loggers_0_1`

`loggers[]`（`net/netfilter/nf_log.c`，5 项指针）在镜像里**全是 0** —— 各 netfilter
logger 在启动期才注册，所以下标无法从镜像读出。已验证的关系：

- `nfulnl_logger` 恰好位于 `loggers + 0x50`（= 数组末尾之后的独立变量）；
- 官方 profile 的 `slide_loggers_0_1 = 47063008 = loggers + 8`，即 **第 2 项**。

因此规则定为 `loggers + 8 * 1`，与已实测 profile 保持同一约定；`loggers` 若整体移动，
该值随之移动。这个字段运行时只需要一个「可读、且与 `nfulnl_logger` 构成两锚点」的地址。

### 1.3 `task_struct` / `cred`（来自内嵌 BTF）

镜像带 `.BTF`（偏移 `0x24a1a5c`，9 341 850 字节，`type_len=3443632`、`str_len=2454562`），
`pahole` 不需要，用 `tools/port/kernel_btf.py` 直接解析。实测与官方输出逐字段相等：

```
task_struct: prio 0x7c  normal_prio 0x84  sched_task_group 0x400  tasks 0x4d0
             atomic_flags 0x598  pid 0x5d8  tgid 0x5dc  real_cred 0x790  cred 0x798
             comm 0x7a8  seccomp 0x860  pi_lock 0x884  pi_waiters 0x898
             pi_top_task 0x8a8  pi_blocked_on 0x8b0
cred        : size 0xb0(176)  cap_permitted 0x30 → 3 段caps (0x30/0x38/0x40)
              user 0x80  user_ns 0x88  ucounts 0x90  group_info 0x98
rt_mutex_waiter: tree_entry 0x0  pi_tree_entry 0x18  task 0x30  lock 0x38
                 wake_state 0x40  ww_ctx 0x50  size 0x58
mm_struct   : 0x3e0(992) → 416 字节以上最近的 kmalloc 桶 = 1024
```

`cred.ref*_image` 是**全局对象地址的 i64 有符号值**，对应顺序与 `ref*_offset` 一致：

| 槽 | 字段 | 符号 | 本机值 |
|---|---|---|---|
| ref0 | cred->user | **`ext_root_user`**（vivo 专有；缺失回退 `root_user`） | -274696488624 / `0xffffffc00ad03950` |
| ref1 | cred->user_ns | `init_user_ns` | -274694422352 / `0xffffffc00aefc0b0` |
| ref2 | cred->ucounts | `init_ucounts` | -274696487232 / `0xffffffc00ad03ec0` |
| ref3 | cred->group_info | `init_groups` | -274696488456 / `0xffffffc00ad039f8` |

> 注意 ref0 指向的是 **`ext_root_user`**，不是 `root_user`（两者相距 0x1320）。
> 这是本轮反推出来的关键点：用 `root_user` 会让 ref0_image 偏移 0x1320，
> 官方提取器的输出证明必须是 `ext_root_user`。

---

## 2. 不能从镜像导出、必须显式给的

### 2.1 `route.multicast_waiter.waiter_off`（本机 = 80）

官方提取器的说法是「setsockopt 栈深度 `0x358` − futex 栈深度 `0x308` = `0x50`」。
本轮尝试用本机内核复算，结论是**该数值不是单个函数的帧大小**：

```
__sys_setsockopt   frame 0x80     __arm64_sys_futex   frame 0xa0
sock_setsockopt    frame 0xa0     do_futex            frame 0xd0
ip_mc_msfilter     frame 0xa0     futex_wait          frame 0x160
ip_mc_source       frame 0xb0     futex_wait_queue_me frame 0x2c0
                                  futex_lock_pi       frame 0x1a0
```

两条链的帧大小之和分别约 `0x1d0` 与 `0x2d0`，既凑不出 `0x358/0x308`，差值也不等于
`0x50`（且符号相反）。说明它度量的是「同一内核栈上两个局部量之间的距离」，取决于
编译器的栈槽分配（hoisting/slot reuse），需要逐指令的栈槽追踪才能复现；而这正是
官方提取器 `--no-disasm` 关掉的那部分逻辑。

工程处理：`tools/port/derive_profile.py --from-extractor <官方 conf>` 把它作为
**带出处的导入值**写入（生成行末带 `# from extractor`），并保留 `--waiter-off` 手工覆盖。
旁证可信度：同族 5.15.189 为 96，5.15.197 与本机均为 80，差异 16 字节符合「栈槽分配
差异」而非随机错误。

### 2.2 `offset.vr_sys_exit_tp`（已定：`__tracepoint_sys_exit` 基址 = 49333960）

真机日志把这个问题解掉了。profile 里写 `49333960`（`0x2f0c6c8`）时，payload 打印：

```
vr guard: neutralizing __tracepoint_sys_exit.funcs
          image=ffffffc082f0c708  target=ffffff802af0c708  width=8
[+] vr guard: sys_exit probe disabled (attempt 1)
```

`image` 的低位是 `0x2f0c708`，正好是 `0x2f0c6c8 + 0x40` —— **`.funcs` 字段偏移由
payload 自己加上**。所以 profile 必须给 tracepoint 基址；如果写成 `tp+0x40`
（早期我预留的 `funcs` 模式），payload 会写到 `tp+0x80`，属于错位脏写。

`derive_profile.py` 因此只保留 `--vr-sys-exit-mode tp`，其余取值直接报错，
并在源码注释里写明这个证据。`width=8` 来自 `vr_guard.tracepoint_funcs = 64`（位宽）。

同时确认：`vr_guard { enabled = 1 }` 与 `enabled = 0` **两条路都能打通**
（`enabled=0` 时 multicast 路由仍 `status=0 … success=1`，说明本固件不靠这一步也能
拿到 `child is root`）。保留 `enabled = 1` 是更接近已验证配置的选择；
`vr0.conf` 留在 `build/variants/` 作为回退。

## 3. 与官方提取器的验收对账

| 项目 | 结果 |
|---|---|
| `kernel.bin` 复现 | sha256 与手工切出的完全一致（`tools/port/unpack_boot.py`） |
| `kernel.btf` 复现 | sha256 与镜像内嵌段一致 |
| 内核相关字段 | **54/54 全等**（`--diff artifacts/5.15.137/extractor-conf.conf`，跳过 `vr_guard`/`mcast`/`offset.vr_sys_exit_tp`） |
| 调优相关字段 | **38/38 全等**（对照仓库内 5.15.197 已实测 profile，`--only execution vr_guard mcast kernelsnitch route`） |
| blob 编码 | `ghostlock profile compile` → `tools/port/blob_decode.py` 还原 13 个 section，`waiter_off=80`、`vr_guard.tracepoint_funcs=64`、`execution.*` 非零 |
| Go 测试 | `TestResolveNeo9_5137` 锁住 30 个关键字段 + `Validate()` + `InvalidPaths` 为空 |

复现命令见 `tools/port/README.md`。

---

## 4. 遗留与后续

1. `waiter_off` 的机制级复现（需要栈槽级追踪；当前用导入值，已标注出处）。
2. `vr_sys_exit_tp` 语义的运行时判定（上面的三步实验）。
3. `pselect_waiter_shift`：官方提取器在本机推导失败（`-248`），因此 `select_stack`
   路由暂时不可用；只有 multicast 失败且原因是几何而非 vr_guard 时才需要补。
4. `kernel_phys_load` / `kernel_phys_offset`：本机 `xbl_config` 与 `uefi` 都不含
   Kernel memory-map，提取器给 `null`（运行时按 SoC 公式回退）。若 KernelSnitch
   阶段反复失败，再显式写 `0xA8000000` / `0x80000000` 试。
