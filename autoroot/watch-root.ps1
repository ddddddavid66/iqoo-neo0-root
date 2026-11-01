<#
.SYNOPSIS
  GhostLock 常驻监督：root 掉了就补打，一直在。

.DESCRIPTION
  一次性的 auto-reroot.ps1 有个致命缺口：成功即 exit 0，之后设备一重启就再也
  没人补打（18:29 那次就是这么丢了 40 分钟 root）。这个脚本补上监督这一层。

  每 PollSec 秒做一次**不 spawn su** 的判活：
      adb shell "grep -c kernelsu /proc/modules"
  late-load 成功后 kernel 会把自己列进 /proc/modules，shell 就能读；因此判活
  本身不会扰动设备（每 20s 一次 `su -c id` 与 13:41–14:46 的五次 SYSTEM_RESTART
  在时间上高度重合，嫌疑太大，已经全面停用）。

  root 不在 → 调 auto-reroot.ps1（它负责等开机窗口、发射、事实判定、静置复查、
  pstore 崩溃取证）。失败按指数退避，避免把设备打进无限 panic 重启。

.EXAMPLE
  .\watch-root.ps1 -Once            # 只跑一遍判活 + 必要的补打
  .\watch-root.ps1                  # 常驻
  .\watch-root.ps1 -Wireless        # 走 WiFi adb（10.206.33.5:5555）
#>
[CmdletBinding()]
param(
    [string]$Serial = "10CE5P1A4G001PA",
    [switch]$Wireless,
    [string]$WirelessAddr = "",
    [int]$PollSec = 20,
    [int]$FailBackoffSec = 300,
    [int]$MaxBackoffSec = 3600,
    [switch]$RebootIfLate,
    [switch]$Once,
    [string]$Exe,
    [string]$Adb = "adb",
    [string]$StateDir
)

$ErrorActionPreference = "Continue"
if ($Wireless -and -not $WirelessAddr) { $WirelessAddr = "10.206.33.5:5555" }
if ($WirelessAddr) { $Serial = $WirelessAddr }
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $StateDir) { $StateDir = Join-Path $here "state" }
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$logFile    = Join-Path $StateDir ("watch-" + (Get-Date -Format "yyyyMM") + ".log")
$eventFile  = Join-Path $StateDir "events.jsonl"
$lockFile   = Join-Path $StateDir "watch.lock"
$reroot     = Join-Path $here "auto-reroot.ps1"

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

function Invoke-Adb([string[]]$argv, [int]$timeoutSec = 15) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Adb
    $quoted = @("-s", $Serial) + $argv | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }
    $psi.Arguments = ($quoted -join " ")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    try { $proc = [System.Diagnostics.Process]::Start($psi) } catch { return $null }
    if (-not $proc.WaitForExit([int]($timeoutSec * 1000))) {
        try { $proc.Kill() } catch { }
        return $null
    }
    return ($proc.StandardOutput.ReadToEnd() + $proc.StandardError.ReadToEnd())
}

function Test-KsuAlive {
    $out = Invoke-Adb @("shell", "grep -c kernelsu /proc/modules 2>/dev/null") 10
    if ($null -eq $out) { return $false }
    return ($out.Trim() -match '^[1-9]')
}

# ------------------------------------------------------------------ 单实例锁
if (Test-Path $lockFile) {
    $old = (Get-Content -LiteralPath $lockFile -Raw -ErrorAction SilentlyContinue)
    $alive = $false
    if ($old) {
        try { $alive = [bool](Get-Process -Id ([int]$old.Trim()) -ErrorAction Stop) } catch { $alive = $false }
    }
    if ($alive) { Write-Host "watch-root 已在运行（pid $old），退出"; exit 0 }
}
$PID | Set-Content -LiteralPath $lockFile -Encoding UTF8

$backoff = $FailBackoffSec
$rerooted = 0
Write-Log ("=== watch 启动：serial={0} poll={1}s once={2}" -f $Serial, $PollSec, [bool]$Once)
if ($WirelessAddr) { & $Adb connect $WirelessAddr 2>&1 | Out-Null }

try {
    while ($true) {
        # 必须带 -s：USB 与 WiFi 两个 transport 同时在线时，不带序列号的
        # `adb get-state` 直接报 "more than one device/emulator"。
        $state = (Invoke-Adb @("get-state") 10)
        if ($null -eq $state) { $state = "" }
        $state = $state.Trim()
        if ($state -ne "device") {
            if ($WirelessAddr) { & $Adb connect $WirelessAddr 2>&1 | Out-Null }
            Write-Log ("设备不可用（{0}），等 {1}s" -f $state, $PollSec)
            if ($Once) { exit 3 }
            Start-Sleep -Seconds $PollSec
            continue
        }

        if (Test-KsuAlive) {
            $backoff = $FailBackoffSec
            if ($Once) { Write-Log "root 在线"; exit 0 }
            Start-Sleep -Seconds $PollSec
            continue
        }

        Write-Log "root 不在，触发补打"
        Write-Event @{ event = "watch-reroot-start"; rerooted = $rerooted }
        $t = Get-Date
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $reroot)
        if ($Exe) { $argList += @("-Exe", $Exe) }
        if ($WirelessAddr) { $argList += @("-WirelessAddr", $WirelessAddr) }
        if ($RebootIfLate) { $argList += "-RebootIfLate" }
        if ($StateDir) { $argList += @("-StateDir", $StateDir) }
        & powershell.exe @argList | Out-Host
        $code = $LASTEXITCODE
        $rerooted++
        $secs = [math]::Round(((Get-Date) - $t).TotalSeconds, 1)
        Write-Log ("补打结束：exit={0} 用时 {1}s" -f $code, $secs)
        Write-Event @{ event = "watch-reroot-done"; exitCode = $code; secs = $secs; rerooted = $rerooted }

        if ($Once) { exit $(if ($code -eq 0) { 0 } else { 4 }) }

        if ($code -eq 0) {
            $backoff = $FailBackoffSec
            Start-Sleep -Seconds $PollSec
        } else {
            # 设备多半在 panic 重启，退避一下再上，别把它打进无限重启。
            Write-Log ("补打没成功，退避 {0}s" -f $backoff)
            Start-Sleep -Seconds $backoff
            $backoff = [math]::Min($backoff * 2, $MaxBackoffSec)
        }
    }
}
finally {
    Remove-Item -LiteralPath $lockFile -Force -ErrorAction SilentlyContinue
}
