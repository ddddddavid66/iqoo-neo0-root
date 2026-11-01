# artifacts/5.15.137 — 冻结资产（iQOO Neo9 PD2338）

设备：`PD2338_A_14.0.17.6.W10.V000L1`，Android 14，内核 `5.15.137-g7cb3e06b062c-dirty`，
`ro.boot.flash.locked=1`，verifiedboot=green，安全补丁 2024-08-01。

## 来源

OTA 全量包：`C:\Users\123\Downloads\2024102417450012e95ba0ef486241d8f9248499af622d.zip`

`payload_properties.txt`（包内）：

```
FILE_HASH=eS2tNFfMpti5Rba208dGbGQtZoHZWUnNNPxj9JAMkvE=
FILE_SIZE=7251077017
METADATA_HASH=H6PHMw5zPNgmnuf6WtDWrJXCiaN91ZBucf/Zt4I+UAU=
METADATA_SIZE=22960
```

`META-INF/com/android/metadata` 关键项：`post-build=vivo/PD2338/PD2338:14/UP1A.231005.007/compiler10241429:user/release-keys`、
`post-build-incremental=eng.compil.20241024.142910`、`post-version=PD2338_A_14.0.17.6.W10.V000L1`、
`post-timestamp=1729751350`、`pre-device=PD2338`、`ota-type=AB`、`package-type=full`、`vfs-type=erofs`。

## 复现命令

```bash
# 1) 取出 payload.bin（zip 内是 STORED，直接解压即可）
python -c "import zipfile,shutil;z=zipfile.ZipFile(r'...zip');open('payload.bin','wb').write(z.read('payload.bin'))"

# 2) 解分区（必须用本仓库脚本；payload_dumper 0.3.0 多 extent 会截断）
python tools/port/extract_payload.py payload.bin out/ boot xbl_config uefi

# 3) 拆 boot：vivo 把 boot 分区切成 N 段各 32 MiB 的独立 zstd frame
python tools/port/unpack_boot.py out/boot.img -o out/

# 4) 恢复 kallsyms + 取 BTF
python tools/port/kernel_syms.py out/kernel.bin -o out/
python tools/port/kernel_btf.py out/kernel.bin -o out/kernel.btf

# 5) 生成 profile（与设备端原生 gl-extract 的输出做 diff）
python tools/port/derive_profile.py out/kernel.bin -o out/profile.conf
```

设备端原生提取器（黄金样本生成器，aarch64 Android，需推到手机以 shell 跑）：

```bash
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
adb push iqoo-neo9-ghostlock-pc/internal/assets/payload/ghostlock-extract /data/local/tmp/gl-extract
adb push out/kernel.bin /data/local/tmp/gl-kernel.img
adb shell "chmod 755 /data/local/tmp/gl-extract; cd /data/local/tmp && \
  ./gl-extract gl-kernel.img --route multicast_waiter --format conf --out /data/local/tmp/gl-profile.conf"
adb pull /data/local/tmp/gl-profile.conf .
```

## 文件

| 文件 | 说明 |
|---|---|
| `boot.img` | payload 里 `boot` 分区原始内容（96 MiB，3×32 MiB zstd frame + 零填充） |
| `boot_full.raw` | 三段 frame 解压后拼接的 96 MiB 逻辑 boot 镜像（`ANDROID!` header v4，`kernel_size=49789440`，`ramdisk_size=0`） |
| `kernel.bin` | 切出的 arm64 `Image`，49789440 B，`text_offset=0`，`image_size=51445760`，含 `Linux version 5.15.137-g7cb3e06b062c-dirty` |
| `vmlinux.elf` | `vmlinux-to-elf` 恢复 kallsyms 后的 ELF，187976 符号，基址 `0xffffffc008000000` |
| `kernel.btf` | 内嵌 BTF（`kernel.bin` 偏移 `0x24a1a5c`），9341850 B，`type_len=3443632`，`str_len=2454562` |
| `xbl_config.img` / `uefi.img` | 用来推导 `kernel_phys_load` 的两个候选来源（本机两者都不含 Kernel memory-map） |
| `extractor-analysis.txt` | `gl-extract --analysis` 原始输出 |
| `extractor-conf.conf` | `gl-extract --format conf` 原始输出（黄金样本，**未经手工修改**） |
| `extractor.json` | `gl-extract --format json` 原始输出 |
| `profile-draft.conf` | 在黄金样本基础上手工补 `vr_guard` / `vr_sys_exit_tp` / `execution` 的草稿 |

## 校验

`SHA256SUMS` 由 `tools/port/gen_checksums.py` 生成，覆盖本目录全部文件。
