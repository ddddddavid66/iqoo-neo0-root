#!/data/data/com.termux/files/usr/bin/sh
# GhostLock 设备侧开机自愈钩子
#
# 安装位置：~/.termux/boot/ghostlock.sh（Termux:Boot 会在开机后执行该目录下所有脚本）
# 依赖：pkg install android-tools（提供 adb）
#
# 设计要点：
#   1. 手机自己连自己：adbd 在 persist.adb.tcp.port=5555 下每次开机都监听，
#      Termux 里的 adb 连 127.0.0.1:5555 就能拿到 shell(uid 2000) 上下文，
#      与 PC 侧 adb 等价 —— 这是不需要 PC 也能发射的关键。
#   2. 发射时机：命中窗口是 uptime 30~70s，所以先等 boot_completed，
#      再等到 uptime≥25s 才发。
#   3. 失手会让内核 panic 自动重启，钩子下次开机会再跑一遍，天然重试。

GH=/data/local/tmp/ghostlock
LOG=$HOME/ghostlock-boot.log
PORT=5555
exec >>"$LOG" 2>&1

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "=== boot hook start ==="

# 1. 等系统起完
for i in $(seq 1 300); do
  [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] && break
  sleep 1
done
log "sys.boot_completed"

# 2. 已经有 root 就不动（late-load 还在内存里）
if command -v su >/dev/null 2>&1 && su -c id 2>/dev/null | grep -q "uid=0"; then
  log "already root, skip"
  exit 0
fi

# 3. 等 uptime 进入窗口下沿
for i in $(seq 1 180); do
  up=$(cut -d' ' -f1 /proc/uptime 2>/dev/null | cut -d'.' -f1)
  [ -n "$up" ] && [ "$up" -ge 25 ] && break
  sleep 1
done
up=$(cut -d' ' -f1 /proc/uptime 2>/dev/null | cut -d'.' -f1)
log "uptime=${up}s"

# 4. 连本机 adb
if ! command -v adb >/dev/null 2>&1; then
  log "adb 不存在：在 Termux 里执行 pkg install android-tools"
  exit 1
fi
adb connect 127.0.0.1:$PORT >/dev/null 2>&1
adb devices

if ! adb -s 127.0.0.1:$PORT shell true >/dev/null 2>&1; then
  log "adb 连不上 127.0.0.1:$PORT（key 未授权 / tcp.port 未开）"
  log "修复：见 autoroot/device/README.md 的『授权 Termux 的 adb key』"
  exit 2
fi

# 5. payload 必须先由 PC 部署过一次（Termux 无法写 /data/local/tmp）
if ! adb -s 127.0.0.1:$PORT shell "[ -x $GH/glrun.sh ]" >/dev/null 2>&1; then
  log "设备上没有 $GH/glrun.sh，跳过本轮回（先用 PC 跑一次 ghostlock run 部署）"
  exit 3
fi

# 6. 发射
TS=$(date +%s)
log "fire run_id=$TS"
adb -s 127.0.0.1:$PORT shell "cd $GH && GL_RUN_ID=$TS setsid sh glrun.sh </dev/null >/dev/null 2>&1 &"

# 7. 90s 后判活（不 spawn su，避免扰动）
sleep 90
k=$(adb -s 127.0.0.1:$PORT shell "grep -c kernelsu /proc/modules 2>/dev/null" 2>/dev/null | tr -d '\r')
log "after fire: kernelsu=$k"
if [ "$k" = "1" ]; then
  log "=== root ok ==="
else
  log "本轮没中；若内核 panic 会自动重启，钩子下次开机继续"
fi
exit 0
