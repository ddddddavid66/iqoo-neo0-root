<#
.SYNOPSIS
  GhostLock 开机自愈守护：设备重启后自动在开机窗口内重打一次 root。

.DESCRIPTION
  状态机（每步都有短超时，不阻塞）：
    1. 互斥锁（防计划任务与手动运行打架）
    2. 等设备；adb=unauthorized 直接退出（需要人手点“允许”）
    3. 已经是 root 就直接退出（幂等）
    4. 轮询 /proc/uptime，落在 [5, Window-5] 才发射；超出窗口按 -RebootIfLate 决定
    5. 发射 ghostlock run --loop（不带 --reboot-first，因为已经在窗口里）
    6. 自己用 su -c id 做事实判定，成功/失败都写 JSONL
    7. 连续失败达到阈值 → 暂停 CooldownHours 小时（刹车，避免无限 panic 重启）

.EXAMPLE
  .\auto-reroot.ps1 -DryRun
  .\auto-reroot.ps1
  .\auto-reroot.ps1 -RebootIfLate -Window 90
#>
[CmdletBinding()]
param(
    [string]$Serial = "10CE5P1A4G001PA",
    [string]$WirelessAddr = "",
    [switch]$Wireless,
    [string]$Exe,
    [string]$Adb = "adb",
    [int]$Window = 90,
    [int]$MaxRounds = 4,
    [int]$PerBoot = 2,
    [switch]$RebootIfLate,
    [switch]$DryRun,
    [int]$MaxConsecutiveFailures = 5,
    [int]$CooldownHours = 24,
    [int]$SettleSec = 90,
    [string]$StateDir
)

$ErrorActionPreference = "Continue"
# -Wireless [IP:5555]：不用 USB，改走 adb over TCP。前提是设备上
# `setprop persist.adb.tcp.port 5555` 已设过（重启后 adbd 会监听 5555），
# 且本机 adb key 已在设备的 /data/misc/adb/adb_keys 里。
if ($Wireless -and -not $WirelessAddr) { $WirelessAddr = "10.206.33.5:5555" }
if ($WirelessAddr) { $Serial = $WirelessAddr }
# ghostlock 输出是 UTF-8；不显式设定的话 PowerShell 会按控制台代码页(936)解码，
# 落盘日志会变成乱码。
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $StateDir) { $StateDir = Join-Path $here "state" }

if (-not $Exe) {
    $candidates = @(
        (Join-Path (Split-Path -Parent $here) "iqoo-neo9-ghostlock-pc\bin\ghostlock.exe"),
        (Join-Path $here "ghostlock.exe")
    )
    foreach ($c in $candidates) { if (Test-Path $c) { $Exe = $c; break } }
}
if (-not $Exe -or -not (Test-Path $Exe)) {
    Write-Host "找不到 ghostlock.exe，请用 -Exe 指定（例如 ..\iqoo-neo9-ghostlock-pc\bin\ghostlock.exe）"
    exit 10
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$scriptStart = Get-Date
$tAdb = $null; $tWindow = $null; $tRoot = $null
function Sec-Since($t) { if ($null -eq $t) { return $null } else { return [math]::Round(((Get-Date) - $t).TotalSeconds, 1) } }
$logFile   = Join-Path $StateDir ("auto-reroot-" + (Get-Date -Format "yyyyMM") + ".log")
$eventFile = Join-Path $StateDir "events.jsonl"
$stateFile = Join-Path $StateDir "state.json"
$lockFile  = Join-Path $StateDir "run.lock"

function Write-Log([string]$msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format "MM-dd HH:mm:ss"), $msg
    Write-Host $line
    Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8
}

function Write-Event([hashtable]$kv) {
    $kv["ts"] = (Get-Date).ToString("o")
    $kv["serial"] = $Serial
    ($kv | ConvertTo-Json -Compress) | Add-Content -LiteralPath $eventFile -Encoding UTF8
}

function Read-State {
    if (-not (Test-Path $stateFile)) { return @{ failures = 0; pausedUntil = $null } }
    try {
        $o = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        return @{ failures = [int]$o.failures; pausedUntil = $o.pausedUntil }
    } catch {
        return @{ failures = 0; pausedUntil = $null }
    }
}

function Save-State([hashtable]$s) {
    $s | ConvertTo-Json -Compress | Set-Content -LiteralPath $stateFile -Encoding UTF8
}

function Invoke-Adb([string[]]$argv, [int]$timeoutSec = 30) {
    # Start-Job has ~0.5s startup cost and we poll every 2s, so drive adb
    # directly and enforce the timeout ourselves.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Adb
    $quoted = @("-s", $Serial) + $argv | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }
    $psi.Arguments = ($quoted -join " ")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    } catch {
        return $null
    }
    if (-not $proc.WaitForExit([int]($timeoutSec * 1000))) {
        try { $proc.Kill() } catch { }
        return $null
    }
    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    return ($out + $err)
}

function Connect-Wireless {
    if (-not $WirelessAddr) { return }
    $r = & $Adb connect $WirelessAddr 2>&1 | Out-String
    if ($r -match "connected") { Write-Log ("wireless adb connected: {0}" -f $WirelessAddr) }
    else { Write-Log ("wireless adb connect failed: {0}" -f ($r.Trim())) }
}

function Get-DeviceState {
    $out = (& $Adb devices 2>&1 | Out-String)
    foreach ($line in ($out -split "`r?`n")) {
        if ($line -match "^(\S+)\s+(\S+)") {
            if ($matches[1] -eq $Serial) { return $matches[2] }   # device / unauthorized / offline
        }
    }
    return "absent"
}

function Get-Uptime {
    $raw = Invoke-Adb @("shell", "cat /proc/uptime") 12
    if (-not $raw) { return $null }
    $f = ($raw.Trim() -split "\s+")[0]
    $v = 0.0
    if ([double]::TryParse($f, [ref]$v)) { return $v }
    return $null
}

function Test-Root {
    $out = Invoke-Adb @("shell", "su -c id") 15
    if ($null -eq $out) { return $false }
    return ($out -match "uid=0")
}

function Get-BootId {
    $b = Invoke-Adb @("shell", "cat /proc/sys/kernel/random/boot_id") 8
    if ($null -eq $b) { return $null }
    return $b.Trim()
}

function Test-KsuAlive {
    # 判活绝不能 spawn su：每 20s 一次 `su -c id` 与 SYSTEM_RESTART 在时间上
    # 高度重合，而 KSU late-load 会把自己列进 /proc/modules，shell 直接就能读。
    $out = Invoke-Adb @("shell", "grep -c kernelsu /proc/modules 2>/dev/null") 8
    if ($null -eq $out) { return $false }
    return ($out.Trim() -match '^[1-9]')
}

function Save-CrashDump {
    # ramoops_region 已确认存在，pstore 里存着上一次内核崩溃的 dmesg；只有 root
    # 能读，所以必须在拿到 root 的这一刻立刻抓走，否则又一次重启就没了。
    $dir = Join-Path $StateDir "crash"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $list = Invoke-Adb @("shell", "su -c 'ls -1 /sys/fs/pstore 2>/dev/null'") 25
    if ($list) {
        foreach ($n in (($list -split "`r?`n") | Where-Object { $_ -and $_.Trim() -ne "" })) {
            $name = $n.Trim()
            $body = Invoke-Adb @("shell", ("su -c 'cat /sys/fs/pstore/" + $name + " 2>/dev/null'")) 60
            if ($body) {
                $p = Join-Path $dir ("{0}-{1}" -f $stamp, $name)
                Set-Content -LiteralPath $p -Value $body -Encoding UTF8
                Write-Log ("崩溃取证已保存: {0} ({1} 字节)" -f $p, $body.Length)
            }
        }
    }
    $dm = Invoke-Adb @("shell", "su -c 'dmesg 2>/dev/null'") 60
    if ($dm) {
        Set-Content -LiteralPath (Join-Path $dir ("{0}-dmesg-boot.txt" -f $stamp)) -Value $dm -Encoding UTF8
    }
    return $stamp
}

function Wait-Probe([int]$timeoutSec = 20) {
    # ghostlock 自己在预检时会再探测一次；探测为空多半是 transport 还没醒。
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $k = Invoke-Adb @("shell", "uname -r") 10
        if ($k -and $k.Trim().Length -gt 0) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Wait-Device([int]$timeoutSec = 180) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $st = Get-DeviceState
        if ($st -eq "device") { return $true }
        if ($st -eq "unauthorized") { Write-Log "adb 未授权（需要在手机上点“允许 USB 调试”）"; return $false }
        Start-Sleep -Seconds 2
    }
    return $false
}

# ---------------------------------------------------------------- 主流程
$lock = $null
try {
    Connect-Wireless
    if (Test-Path $lockFile) {
        $age = (Get-Date) - (Get-Item $lockFile).LastWriteTime
        if ($age.TotalHours -lt 2) {
            Write-Log "已有实例在跑（锁 $lockFile，$([int]$age.TotalMinutes) 分钟前），本次退出"
            exit 0
        }
        Write-Log "清理过期锁（$([int]$age.TotalHours) 小时前）"
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
    }
    $lock = New-Item -ItemType File -Path $lockFile -Force -ErrorAction Stop

    Write-Log "=== 启动：exe=$Exe window=$Window rounds=$MaxRounds perBoot=$PerBoot dryRun=$DryRun"
    $state = Read-State
    if ($state.pausedUntil) {
        $until = [datetime]::Parse($state.pausedUntil)
        if ((Get-Date) -lt $until) {
            Write-Log "处于冷却期（连续失败 $($state.failures) 次），到 $($until.ToString('MM-dd HH:mm')) 再说"
            exit 0
        }
        Write-Log "冷却期结束，重置失败计数"
        $state = @{ failures = 0; pausedUntil = $null }
        Save-State $state
    }

    $dev = Get-DeviceState
    Write-Log "设备状态：$dev"
    if ($dev -eq "unauthorized") {
        Write-Event @{ event = "unauthorized" }
        exit 2
    }
    if ($dev -ne "device") {
        if (-not (Wait-Device 180)) { Write-Event @{ event = "device-missing" }; exit 2 }
    }

    if (Test-Root) {
        Write-Log "已经是 root（su 可用），无需重打"
        $state = @{ failures = 0; pausedUntil = $null }; Save-State $state
        Write-Event @{ event = "already-root"; uptime = (Get-Uptime) }
        exit 0
    }

    if ($DryRun) {
        Write-Log "DRY-RUN：将轮询 uptime 到 [5,$($Window - 5)] 区间后执行："
        Write-Log "  $Exe run --loop --rounds $MaxRounds --per-boot $PerBoot"
        exit 0
    }

    # 等窗口
    $up = $null
    $deadline = (Get-Date).AddMinutes(15)
    while ((Get-Date) -lt $deadline) {
        $up = Get-Uptime
        if ($null -eq $up) {
            Write-Log "读不到 uptime（可能在重启），等设备回来"
            if (-not (Wait-Device 180)) { Write-Event @{ event = "device-missing"; stage = "window" }; exit 2 }
            continue
        }
        if ($up -ge 5 -and $up -le ($Window - 5)) { break }
        if ($up -gt ($Window - 5)) {
            if ($RebootIfLate) {
                Write-Log ("已过窗口（uptime={0:N0}s），主动重启抢下一次" -f $up)
                Invoke-Adb @("reboot") 20 | Out-Null
                Start-Sleep -Seconds 5
                Wait-Device 180 | Out-Null
                continue
            }
            Write-Log ("已过窗口（uptime={0:N0}s），等下一次开机" -f $up)
            Write-Event @{ event = "window-missed"; uptime = $up }
            exit 3
        }
        Start-Sleep -Seconds 2
    }
    if ($null -eq $up -or $up -gt ($Window - 5)) {
        Write-Log "15 分钟内没等到窗口"
        Write-Event @{ event = "window-timeout" }
        exit 3
    }

    $tWindow = Get-Date
    Write-Log ("进入窗口：uptime={0:N0}s（脚本启动后 {1}s），发射" -f $up, (Sec-Since $scriptStart))
    $runLog = Join-Path $StateDir ("fire-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
    # 无线模式下必须把 transport 显式交给 ghostlock，否则它会自己按默认序列号
    # 必须把 transport 显式交给 ghostlock：USB 与 TCP 同时在线时它自己会选错设备，
    # 选到未连上的 transport 会探测出空内核版本并直接拒绝。
    $serialArg = @("--serial", $Serial)
    if ($WirelessAddr) { & $Adb connect $Serial 2>&1 | Out-Null }
    if (-not (Wait-Probe)) {
        Write-Log "ghostlock 探测不到设备（$Serial），放弃本次发射"
        $state.failures = [int]$state.failures + 1
        Save-State $state
        Write-Event @{ event = "probe-failed"; uptime = $up; failures = $state.failures }
        exit 5
    }
    $out = & $Exe run --loop --rounds $MaxRounds --per-boot $PerBoot @serialArg 2>&1 | Out-String
    $out | Set-Content -LiteralPath $runLog -Encoding UTF8
    Write-Log ("ghostlock 输出已写入 {0}" -f $runLog)

    # 掉线后可能仍在 handoff，等设备回来再判定
    Wait-Device 180 | Out-Null
    Start-Sleep -Seconds 3
    $ok = Test-Root
    $upAfter = Get-Uptime
    $bootId = Get-BootId
    if ($ok) {
        Write-Log "成功：su 已可用"
        # 崩溃取证要在这一刻做：pstore 只有 root 能读，下一次重启就覆盖。
        $dump = Save-CrashDump
        # 90s 静置复查。日志说成功不等于待得住：18:29 那次拿到 root 后 54 秒
        # 内核就崩了（PS_HOLD 硬复位），看门狗当时已经 exit 0，之后 40 分钟无人补打。
        $stable = $true
        if ($SettleSec -gt 0) {
            Write-Log ("静置 {0}s 复查 root 是否还在…" -f $SettleSec)
            Start-Sleep -Seconds $SettleSec
            $bootId2 = Get-BootId
            $stillRoot = Test-Root
            $stable = ($bootId2 -eq $bootId) -and $stillRoot
            if (-not $stillRoot) { Write-Log "复查：su 已不可用" }
            elseif ($bootId2 -ne $bootId) { Write-Log "复查：设备已重启（bootId 变了），root 归零" }
        }
        if (-not $stable) {
            $state.failures = [int]$state.failures + 1
            Save-State $state
            Write-Log ("root 拿到后又掉了（连续 unstable {0} 次），交给外层重新补打" -f $state.failures)
            Write-Event @{ event = "root-unstable"; uptime = $up; uptimeAfter = (Get-Uptime);
                          bootId = $bootId; settleSec = $SettleSec; dump = $dump;
                          failures = $state.failures; log = $runLog }
            exit 6
        }
        $state = @{ failures = 0; pausedUntil = $null }; Save-State $state
        Write-Event @{ event = "root-ok"; uptime = $up; uptimeAfter = (Get-Uptime);
                      bootId = $bootId; settleSec = $SettleSec; dump = $dump;
                      adbReadySec = (Sec-Since $tAdb); windowDelaySec = (Sec-Since $tWindow);
                      totalSec = (Sec-Since $scriptStart); log = $runLog }
        exit 0
    }

    $state.failures = [int]$state.failures + 1
    if ($state.failures -ge $MaxConsecutiveFailures) {
        $until = (Get-Date).AddHours($CooldownHours)
        $state.pausedUntil = $until.ToString("o")
        Write-Log ("连续失败 {0} 次，进入 {1} 小时冷却（到 {2}）" -f $state.failures, $CooldownHours, $until.ToString("MM-dd HH:mm"))
    }
    Save-State $state
    Write-Log ("失败：su 仍不可用（连续 {0} 次）" -f $state.failures)
    Write-Event @{ event = "root-fail"; uptime = $up; uptimeAfter = $upAfter;
                  adbReadySec = (Sec-Since $tAdb); windowDelaySec = (Sec-Since $tWindow);
                  totalSec = (Sec-Since $scriptStart); failures = $state.failures; log = $runLog }
    exit 4
}
finally {
    if ($lock) { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue }
}
