<#
.SYNOPSIS
  把 PC 已授权的 adb key 推到设备，供 Termux 内的 adb 复用（设备侧自启的前置）。

.DESCRIPTION
  /data/misc/adb/adb_keys 里保存的是 PC 的公钥。把这同一对 key 放进 Termux 的
  ~/.android/ 之后，Termux 里的 adb 连 127.0.0.1:5555 会被直接接受，不弹授权框。
  这样开机钩子才能在没有人的情况下拿到 shell 上下文。

  本脚本只负责把文件推到 /sdcard/Download/，剩下两步要在 Termux 里执行（脚本会打印）。

.EXAMPLE
  .\authorize-termux-adb.ps1
  .\authorize-termux-adb.ps1 -Serial 10.206.33.5:5555
#>
[CmdletBinding()]
param(
    [string]$Serial = "10CE5P1A4G001PA",
    [string]$Adb = "adb",
    [string]$KeyDir = (Join-Path $env:USERPROFILE ".android"),
    [string]$RemoteDir = "/sdcard/Download"
)

$ErrorActionPreference = "Continue"
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

function Invoke-Adb([string[]]$argv, [int]$timeoutSec = 30) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Adb
    $psi.Arguments = ((@("-s", $Serial) + $argv) -join " ")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($timeoutSec * 1000)) { try { $p.Kill() } catch { }; return $null }
    return ($p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd())
}

$priv = Join-Path $KeyDir "adbkey"
$pub  = Join-Path $KeyDir "adbkey.pub"
if (-not (Test-Path $priv)) { Write-Host "找不到 $priv（这台机器还没生成过 adb key）"; exit 10 }
if (-not (Test-Path $pub))  { Write-Host "找不到 $pub"; exit 10 }

$state = (Invoke-Adb @("get-state") 10)
if (-not $state -or $state.Trim() -ne "device") {
    Write-Host ("设备不在 device 状态：" + ($state | Out-String).Trim())
    exit 11
}

foreach ($f in @($priv, $pub)) {
    $r = Invoke-Adb @("push", $f, $RemoteDir) 60
    Write-Host ("push " + (Split-Path -Leaf $f) + " -> " + $RemoteDir)
    if ($r -match "error|failed|cannot") { Write-Host ($r.Trim()); exit 12 }
}

# 顺便确认 TCP adb 端口是不是持久化的，这是设备侧自启的另一个前提
$port = (Invoke-Adb @("shell", "getprop persist.adb.tcp.port") 10)
Write-Host ("persist.adb.tcp.port = " + ($port | Out-String).Trim())
if (($port | Out-String).Trim() -ne "5555") {
    Write-Host "注意：该属性不是 5555，重启后 adbd 不会监听 TCP，设备侧自启会失效。"
    Write-Host "      有 root 时执行：adb shell su -c 'setprop persist.adb.tcp.port 5555'"
}

Write-Host ""
Write-Host "接下来在手机上的 Termux 里执行（一次性）："
Write-Host "  mkdir -p ~/.android"
Write-Host ("  cp " + $RemoteDir + "/adbkey     ~/.android/adbkey")
Write-Host ("  cp " + $RemoteDir + "/adbkey.pub ~/.android/adbkey.pub")
Write-Host "  chmod 600 ~/.android/adbkey"
Write-Host "  pkg install -y android-tools"
Write-Host "  adb connect 127.0.0.1:5555 && adb shell id    # 期望 uid=2000(shell)，不弹授权"
