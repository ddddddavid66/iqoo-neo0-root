<#
.SYNOPSIS
  假 adb 上的持续监督测试（soak）：反复把 root 打掉，看监督器能不能每次都补回来。

.DESCRIPTION
  selftest.ps1 证明的是「单次掉线能补回」，这个脚本证明的是「反复掉线也一直能补回」，
  并且交替模拟两种掉线形态：
    奇数次：设备还在跑，只是 root 没了（uptime 正常）
    偶数次：内核崩了重启（uptime 归零，必须先等到窗口下沿才允许发射）

  跑法：
    cd tools/mockadb ; go build -o mockadb.exe . ; go build -o mockghostlock.exe .
    powershell -File autoroot/soak.ps1 -Cycles 4
#>
[CmdletBinding()]
param(
    [int]$Cycles = 3,
    [int]$PerCycleTimeoutSec = 120,
    # 静置复查调小到 10s：soak 要跑多轮，90s 的静置会把单轮拖到 2 分钟。
    [int]$SettleSec = 10,
    [string]$StateDir = ""
)

$ErrorActionPreference = "Continue"
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$hereDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $StateDir) { $StateDir = Join-Path $hereDir "state\soak" }
$mockDir = Join-Path (Split-Path -Parent $hereDir) "tools\mockadb"
$mockAdb = Join-Path $mockDir "mockadb.exe"
$mockExe = Join-Path $mockDir "mockghostlock.exe"
$stateFile = Join-Path $mockDir "mock-state.txt"
$watch = Join-Path $hereDir "watch-root.ps1"

foreach ($p in @($mockAdb, $mockExe, $watch)) {
    if (-not (Test-Path $p)) { Write-Host "缺文件: $p"; exit 10 }
}
Remove-Item -Recurse -Force $StateDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

function Set-MockState([bool]$rooted, [int]$ageSec) {
    $boot = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $ageSec
    $r = if ($rooted) { 1 } else { 0 }
    "present=1 root=$r boot_unix=$boot" | Set-Content -LiteralPath $stateFile -Encoding ASCII
}

function Get-MockRooted {
    if (-not (Test-Path $stateFile)) { return $false }
    return ((Get-Content -LiteralPath $stateFile -Raw) -match "root=1")
}

# 起始：root 在线
Set-MockState $true 40
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "powershell.exe"
$psi.Arguments = (@(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $watch,
    "-Serial", "MOCKSERIAL", "-Adb", $mockAdb, "-Exe", $mockExe,
    "-StateDir", $StateDir, "-PollSec", "2", "-FailBackoffSec", "5",
    "-MaxBackoffSec", "20", "-HeartbeatEvery", "5", "-NoReboot",
    "-SettleSec", "$SettleSec"
) | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join " "
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$outTask = $proc.StandardOutput.ReadToEndAsync()

Start-Sleep -Seconds 5
Write-Host ("监督器已启动，初始 root={0}" -f (Get-MockRooted))

$rows = @()
$allOk = $true
for ($i = 1; $i -le $Cycles; $i++) {
    $rebootStyle = ($i % 2 -eq 0)
    if ($rebootStyle) {
        Write-Host ("--- 第 {0} 次掉线：模拟 panic 重启（uptime 归零）" -f $i)
        Set-MockState $false 0
    } else {
        Write-Host ("--- 第 {0} 次掉线：设备在跑，root 消失" -f $i)
        Set-MockState $false 45
    }

    $t0 = Get-Date
    $recovered = $false
    while (((Get-Date) - $t0).TotalSeconds -lt $PerCycleTimeoutSec) {
        if (Get-MockRooted) { $recovered = $true; break }
        Start-Sleep -Milliseconds 500
    }
    $secs = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    if (-not $recovered) { $allOk = $false }
    $rows += [pscustomobject]@{
        Cycle = $i
        Style = if ($rebootStyle) { "panic重启" } else { "root消失" }
        Recovered = $recovered
        Seconds = $secs
    }
    Write-Host ("    恢复={0} 用时 {1}s" -f $recovered, $secs)
    if (-not $recovered) { break }

    # 恢复之后要等这一轮「补打」真正收尾（auto-reroot 可能在静置复查里），
    # 否则下一次掉线会撞在静置窗口上，测到的就不是监督器的反应速度了。
    $ev = Join-Path $StateDir "events.jsonl"
    $waitDone = (Get-Date).AddSeconds(180)
    while ((Get-Date) -lt $waitDone) {
        $n = 0
        if (Test-Path $ev) { $n = ([regex]::Matches((Get-Content -LiteralPath $ev -Raw), "watch-reroot-done")).Count }
        if ($n -ge $i) { break }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Seconds 2
}

try { $proc.Kill() } catch { }
Start-Sleep -Milliseconds 500
$log = $outTask.Result
Set-Content -LiteralPath (Join-Path $StateDir "watch-stdout.txt") -Value $log -Encoding UTF8

Write-Host ""
$rows | Format-Table -AutoSize | Out-String | Write-Host
Set-MockState $true 40
if (-not $allOk) { Write-Host "soak 失败：至少一次没补回来"; exit 1 }
Write-Host ("soak 通过：{0} 次掉线全部补回" -f $Cycles)
exit 0
