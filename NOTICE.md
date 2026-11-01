# NOTICE · 来源与许可

本仓库是一个**移植分支**，主体代码来自他人的公开项目，本次只做 PC 侧适配、
profile 重建与真机问题修复。原始作品的权利归各自作者所有。

## 上游

| 组件 | 来源 | 说明 |
|---|---|---|
| GhostLock PC 驱动（`cmd/`、`internal/` 除 `tools/port` 外） | [AuroraMythweaver/iqoo-neo9-ghostlock-pc](https://github.com/AuroraMythweaver/iqoo-neo9-ghostlock-pc) | 本仓库在其 `5ed65f8` 基础上打补丁；上游未附 LICENSE 文件，版权归上游作者 |
| exploit payload（`internal/assets/payload/ghostlock`、`ghostlock-extract`、`ghostlock.i64`、`vrpatch.ko`） | GhostLock（CVE-2026-43499）作者发布的 APK（经上游项目转存） | 仅随工具内嵌分发，未做修改 |
| KernelSU 内核模块与 `ksud` | [SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) 上游 | 由用户自行安装的管理器 APK 提供，本仓库**不附带 APK** |
| 5.15.137 内核 profile、`tools/port/`、`docs/` | 本仓库新增 | 由 OTA 全量包离线推导，见 `docs/PORT-NOTES.md` |

## 没有 LICENSE 这件事

上游仓库未声明许可证，因此**本仓库不额外授予任何许可**：代码按原样提供，供设备所有者
在自己的机器上研究使用。如果你要把它用于分发或商业用途，请先取得上游作者与 payload
作者的许可。

## 不包含的内容

- 未包含 OTA 全量包、内核镜像、`vmlinux.elf`、`kernel.btf` 等大文件（见
  `artifacts/5.15.137/README.md` 里的重建命令）；
- 未包含任何 KernelSU 管理器 APK；
- 未包含设备提取物、账号、密钥等个人信息。

## 用途声明

该工具会对设备内核做内存写入并可能触发 panic 重启。仅用于**你自己的设备**，
风险自负。
