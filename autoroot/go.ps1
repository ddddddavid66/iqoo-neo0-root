<#
.SYNOPSIS
  一条命令上机：检查 → 体检 → 常驻自动 root。

.DESCRIPTION
  明天上真机时只需要跑这个。它会：
    1. 找设备：先 USB，找不到再试 Wi-Fi（10.206.33.5:5555）
    2. 跑 ghostlock doctor 做体检（内核 / profile / SELinux / KSU 管理器）
    3. 体检通过就交给 watch-root.ps1 常驻（默认主动重启抢窗口）

  任何一步不满足都会直接说清楚缺什么，不会带病跑到发射阶段浪费五分钟。

.EXAMPLE
  .\go.ps1                 # 自动找设备，USB 优先
  .\go.ps1 -Wireless       # 强制走 Wi-Fi
  .\go.ps1 -MaxHours 8     # 跑 8 小时自停
  .\go.ps1 -CheckOnly      # 只做 1、2 步
#>
[CmdletBinding()]
param(
    [string]$Serial = "10CE5P1A4G001PA",
    [string]$WirelessAddr = "10.206.33.5:5555",
    [switch]$Wireless,
    [int]$MaxHours = 0,
    # 设备刚重启时 adb 里会有一段时间什么都没有；这里等它出现，而不是立刻放弃。
    [int]$WaitDeviceSec = 120,
    [switch]$CheckOnly,
    [string]$Adb = "adb"
)

$ErrorActionPreference = "Continue"
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$exe = Join-Path (Split-Path -Parent $here) "iqoo-neo9-ghostlock-pc\bin\ghostlock.exe"
$watch = Join-Path $here "watch-root.ps1"

function Say([string]$m) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m) }

if (-not (Test-Path $exe)) {
    Say "缺 ghostlock.exe：先在 iqoo-neo9-ghostlock-pc 里 go build -o bin\ghostlock.exe .\cmd\ghostlock"
    exit 10
}

# ---------------------------------------------------------------- 1. 找设备
$devices = (& $Adb devices 2>&1 | Out-String)
Say "adb devices:`n$($devices.Trim())"

$use = ""
if (-not $Wireless) {
    foreach ($line in ($devices -split "`r?`n")) {
        if ($line -match "^(\S+)\s+device") {
            if ($matches[1] -eq $Serial -or $matches[1] -notmatch ":") { $use = $matches[1]; break }
        }
    }
}
if (-not $use) {
    Say "试 Wi-Fi：$WirelessAddr"
    & $Adb connect $WirelessAddr 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    if ((& $Adb devices 2>&1 | Out-String) -match [regex]::Escape($WirelessAddr) + "\s+device") { $use = $WirelessAddr }
}
if (-not $use) {
    # 刚重启 / 刚插线时都会短暂看不到设备，先等一会儿再下结论。
    $deadline = (Get-Date).AddSeconds($WaitDeviceSec)
    Say ("暂时没看到设备，等它出现（最多 {0}s）…" -f $WaitDeviceSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $devices = (& $Adb devices 2>&1 | Out-String)
        foreach ($line in ($devices -split "`r?`n")) {
            if ($line -match "^(\S+)\s+device") {
                if ($matches[1] -eq $Serial -or $matches[1] -notmatch ":") { $use = $matches[1]; break }
            }
        }
        if ($use) { break }
        if (-not $Wireless) { & $Adb connect $WirelessAddr 2>&1 | Out-Null }
    }
}
if (-not $use) {
    Say "没找到可用设备。检查：USB 线 / 开发者选项里的 USB 调试 / Wi-Fi 是否同网段。"
    Say "亮屏时若是 unauthorized，需要在手机上点『允许』。"
    exit 11
}
Say "使用设备：$use"

# ---------------------------------------------------------------- 2. 体检
Say "ghostlock doctor …"
# -Adb 非默认时必须传给 doctor，否则它会去 PATH 找真 adb（自测用假 adb 就跑偏）。
$doctorArgs = @("doctor", "--serial", $use)
if ($Adb -and $Adb -ne "adb") { $doctorArgs += @("--adb", $Adb) }
$doc = (& $exe @doctorArgs 2>&1 | Out-String)
Write-Host $doc.Trim()

if ($doc -match "no bundled profile|不可用|not found|uname") {
    Say "体检没过：先解决上面的报错（多半是 profile 不匹配或设备没真正就绪）"
    exit 12
}

if ($CheckOnly) { Say "仅体检，退出"; exit 0 }

# ---------------------------------------------------------------- 3. 常驻
Say "交给 watch-root 常驻（root 掉了会自动补打）"
$argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $watch, "-Serial", $use)
if ($use -match ":") { $argList += @("-WirelessAddr", $use) }
if ($MaxHours -gt 0) { $argList += @("-MaxHours", $MaxHours) }
& powershell.exe @argList
exit $LASTEXITCODE
