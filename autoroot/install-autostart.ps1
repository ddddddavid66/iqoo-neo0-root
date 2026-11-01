<#
.SYNOPSIS
  把开机自愈守护注册成自启项，并提供一键卸载。
.DESCRIPTION
  默认用「启动文件夹」：不需要管理员，登录后自动运行（等价于 ONLOGON）。
  需要真正「开机即跑、无需登录」时用 -Method Task（需要管理员权限的终端）。
.EXAMPLE
  .\install-autostart.ps1
  .\install-autostart.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [ValidateSet("Startup", "Task")]
    [string]$Method = "Startup",
    [switch]$RebootIfLate,
    [string]$TaskName = "GhostLock-WatchRoot"
)

$ErrorActionPreference = "Continue"
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# 自启项指向常驻监督，而不是一次性的 auto-reroot：一次性脚本成功即退出，
# 设备重启后没人补打，root 就那样丢了 40 分钟。
$script = Join-Path $here "watch-root.ps1"
$startupDir = [Environment]::GetFolderPath("Startup")
$cmdPath = Join-Path $startupDir "GhostLock-WatchRoot.cmd"

if (-not (Test-Path $script)) { Write-Host "no watch-root.ps1"; exit 10 }

$extra = if ($RebootIfLate) { " -RebootIfLate" } else { "" }
$psLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$script""$extra"

if ($Remove) {
    if (Test-Path $cmdPath) { Remove-Item $cmdPath -Force; Write-Host "removed: $cmdPath" }
    $q = schtasks /Delete /TN $TaskName /F 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Host "removed task: $TaskName" }
    exit 0
}

if ($Method -eq "Task") {
    $r = schtasks /Create /TN $TaskName /TR $psLine /SC ONLOGON /RL HIGHEST /F 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Host "task created: $TaskName" } else { Write-Host ("task failed: " + $r.Trim()); exit 1 }
    exit 0
}

$content = "@echo off`r`nrem GhostLock root supervisor (watch-root.ps1) on logon`r`nstart `"`" /min $psLine`r`n"
Set-Content -LiteralPath $cmdPath -Value $content -Encoding ASCII
Write-Host ("startup item written: " + $cmdPath)
Write-Host ("command: " + $psLine)
Write-Host "uninstall: .\install-autostart.ps1 -Remove"
