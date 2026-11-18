<#
.SYNOPSIS
  把 root 自愈守护注册成登录自启项（默认）或计划任务，并提供一键卸载。

.DESCRIPTION
  装的是 watch-root.ps1（常驻监督），不是一次性的 auto-reroot.ps1：一次性脚本
  成功就退出，设备重启后没人补打，root 就那样丢着。

  默认用「启动文件夹」，不需要管理员，用户登录后立即运行（等价 ONLOGON）。
  需要「开机即跑、无需登录」时用 -Method Task（管理员终端）。

  安装前先检查三样是否就位：watch-root.ps1、ghostlock.exe、adb。
  adb 会解析成绝对路径写进自启命令 —— 登录时继承的 PATH 里不一定有
  platform-tools，只写 "adb" 会让守护在第一步就空转。

.EXAMPLE
  .\install-autostart.ps1
  .\install-autostart.ps1 -Verify    # 装完立刻跑一次 -Once，确认链路通
  .\install-autostart.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [ValidateSet("Startup", "Task")]
    [string]$Method = "Startup",
    [string]$TaskName = "GhostLock-WatchRoot",
    [string]$Adb = "",
    [string]$Serial = "10CE5P1A4G001PA",
    # 发射窗口必须和 auto-reroot 的默认值一致：上沿放宽到 60s 以上实测会把内核打死。
    [int]$MaxUptime = 50,
    [int]$MinUptime = 25,
    [string]$FallbackWireless = "10.206.33.5:5555",
    [switch]$NoReboot,
    [switch]$Verify
)

$ErrorActionPreference = "Continue"
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$watch = Join-Path $here "watch-root.ps1"
$exe = Join-Path (Split-Path -Parent $here) "iqoo-neo9-ghostlock-pc\bin\ghostlock.exe"
$startupDir = [Environment]::GetFolderPath("Startup")
$cmdPath = Join-Path $startupDir "GhostLock-WatchRoot.cmd"

# 卸载放在所有检查之前：exe 或 adb 已经不在时也要能卸干净。
if ($Remove) {
    if (Test-Path $cmdPath) { Remove-Item $cmdPath -Force; Write-Host "removed: $cmdPath" }
    $q = schtasks /Delete /TN $TaskName /F 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Host "removed task: $TaskName" }
    exit 0
}

# ------------------------------------------------------------------ 依赖检查
$problems = @()
if (-not (Test-Path $watch)) { $problems += "缺 watch-root.ps1：$watch" }
if (-not (Test-Path $exe)) {
    $problems += "缺 ghostlock.exe：$exe"
    $problems += "  先在 iqoo-neo9-ghostlock-pc 里 go build -o bin\ghostlock.exe .\cmd\ghostlock"
}
if (-not $Adb) {
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($cmd) { $Adb = $cmd.Source }
}
if (-not $Adb -or -not (Test-Path $Adb)) {
    $problems += "找不到 adb.exe，用 -Adb 指定，例如 -Adb D:\tools\platform-tools\adb.exe"
}
if ($problems.Count) {
    Write-Host "自启装不了，先把这些补上："
    $problems | ForEach-Object { Write-Host ("  ! " + $_) }
    exit 10
}
Write-Host ("adb      : " + $Adb)
Write-Host ("ghostlock: " + $exe)
Write-Host ("watch    : " + $watch)

# ------------------------------------------------------------------ 生成命令
# -RebootIfLate 不再传：watch-root 用的是自己的 $drive（默认开启 = 主动重启抢窗口），
# 那个开关参数从来没被读过。NoReboot 才是真正能关掉驱动的开关。
$argList = @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
    "-File", ('"' + $watch + '"'),
    "-Adb", ('"' + $Adb + '"'),
    "-Serial", $Serial,
    "-MaxUptime", "$MaxUptime",
    "-MinUptime", "$MinUptime"
)
if ($FallbackWireless) { $argList += @("-FallbackWireless", $FallbackWireless) }
if ($NoReboot) { $argList += "-NoReboot" }
$psLine = "powershell.exe " + ($argList -join " ")

$content = "@echo off`r`nrem GhostLock root supervisor (watch-root.ps1) on logon`r`nstart `"`" /min $psLine`r`n"
Set-Content -LiteralPath $cmdPath -Value $content -Encoding ASCII
Write-Host ("startup item written: " + $cmdPath)

$taskCreated = $false
if ($Method -eq "Task") {
    # /TR 指向 .cmd 而不是直接拼 powershell 命令：schtasks 对引号和长度的处理
    # 会让长命令行被拆坏，包一层 .cmd 就绕开了。
    $r = schtasks /Create /TN $TaskName /TR ('"' + $cmdPath + '"') /SC ONLOGON /RL HIGHEST /F 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        Write-Host ("task created: " + $TaskName)
        $taskCreated = $true
    } else {
        Write-Host ("task failed: " + $r.Trim())
        Write-Host "（Task 模式需要管理员终端；当前用户没权限时用默认的 -Method Startup）"
        exit 1
    }
}

Write-Host ("command: " + $psLine)
Write-Host ("uninstall: .\install-autostart.ps1 -Remove")

# ------------------------------------------------------------------ 立即验证
# 装好不等于能跑：这一步真的用自启命令里的参数跑一次 -Once，
# 让「开机后才发现少个 exe / adb 路径不对」提前到现在暴露。
if ($Verify) {
    Write-Host ""
    Write-Host "验证：用自启参数跑一次 watch-root -Once …"
    $verifyArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $watch,
        "-Adb", $Adb, "-Serial", $Serial,
        "-MaxUptime", "$MaxUptime", "-MinUptime", "$MinUptime", "-Once"
    )
    & powershell.exe @verifyArgs
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host "验证通过：root 在线（exit 0）"
    } else {
        Write-Host ("验证失败：watch-root -Once 退出码 {0}（3=设备不可用 4=补打没成功）" -f $code)
        exit $code
    }
}

if ($taskCreated) { Write-Host "注意：Task 模式是 ONLOGON，仍需登录才触发；要真开机即跑需要改成 ONSTARTUP 并配服务账户。" }
