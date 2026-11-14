<#
.SYNOPSIS
  无真机自测：用假 adb 驱动 auto-reroot.ps1 的状态机。

.DESCRIPTION
  真机没插上时，唯一能验证守护逻辑的办法是把它挂到假的 adb 上：
    tools/mockadb/mockadb.exe       假 adb（devices/get-state/shell/reboot/connect）
    tools/mockadb/mockghostlock.exe 假载荷（被 fire 就把 root 标成可用）

  场景：
    A 正常命中     窗口内、未 root           → 发射 → 事实判定 → root-ok
    B 窗口外抢跑   uptime 已 100 分钟 + -RebootIfLate → 先重启再发射 → root-ok
    C 没有设备     不发射，只在等            → 超时被掐断，且无 root-ok

  跑法：
    cd tools/mockadb ; go build -o mockadb.exe . ; go build -o mockghostlock.exe .
    powershell -File autoroot/selftest.ps1
#>
[CmdletBinding()]
param(
    [string]$StateDir = "",
    [int]$SettleSec = 2
)

# $PSScriptRoot 在 param 默认值里不一定可用（-File 调用时为空），这里统一在脚本体里算。
$hereDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $StateDir) { $StateDir = Join-Path $hereDir "state\selftest" }

$ErrorActionPreference = "Continue"
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$mockDir = Join-Path (Split-Path -Parent $hereDir) "tools\mockadb"
$mockAdb = Join-Path $mockDir "mockadb.exe"
$mockExe = Join-Path $mockDir "mockghostlock.exe"
$reroot  = Join-Path $hereDir "auto-reroot.ps1"

foreach ($p in @($mockAdb, $mockExe, $reroot)) {
    if (-not (Test-Path $p)) { Write-Host "缺文件: $p"; exit 10 }
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$results = @()

function Set-Mock {
    param([bool]$present, [bool]$rooted, [int]$ageSec)
    $boot = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $ageSec
    $p = if ($present) { 1 } else { 0 }
    $r = if ($rooted) { 1 } else { 0 }
    "present=$p root=$r boot_unix=$boot" |
        Set-Content -LiteralPath (Join-Path $mockDir "mock-state.txt") -Encoding ASCII
}

function Invoke-Case {
    param(
        [string]$name,
        [scriptblock]$setup,
        [string[]]$extra,
        [int]$expectExit,        # -1 表示「不应该在超时前退出」
        [string]$expectEvent,    # 空 = 不应该出现任何 root-ok
        [int]$minFireUptime = 0, # >0 时要求「进入窗口」那一行的 uptime 不低于它
        [int]$timeoutSec = 180
    )
    Write-Host ""
    Write-Host ("===== 场景 {0} =====" -f $name)
    & $setup

    $caseDir = Join-Path $StateDir $name
    Remove-Item -Recurse -Force $caseDir -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $caseDir | Out-Null

    $argList = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $reroot,
        "-Serial", "MOCKSERIAL", "-Adb", $mockAdb, "-Exe", $mockExe,
        "-StateDir", $caseDir, "-SettleSec", "$SettleSec",
        "-MaxRounds", "1", "-PerBoot", "1"
    ) + $extra

    # Start-Process -PassThru 在重定向时 ExitCode 会是 $null，直接驱动 Process 更可靠。
    $outFile = Join-Path $caseDir "stdout.txt"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = (($argList | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join " ")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $exited = $proc.WaitForExit($timeoutSec * 1000)
    if (-not $exited) { try { $proc.Kill() } catch { } }
    $log = $outTask.Result
    $errText = $errTask.Result
    $code = if ($exited) { $proc.ExitCode } else { -1 }
    Set-Content -LiteralPath $outFile -Value $log -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $caseDir "stderr.txt") -Value $errText -Encoding UTF8
    Write-Host ("   [debug] exited={0} code={1}" -f $exited, $code)

    $log = ""
    if (Test-Path $outFile) { $log = Get-Content -LiteralPath $outFile -Raw -Encoding UTF8 }
    Write-Host (($log -split "`r?`n" | Select-Object -Last 12) -join "`n")

    $events = Join-Path $caseDir "events.jsonl"
    $evText = if (Test-Path $events) { Get-Content -LiteralPath $events -Raw } else { "" }

    $exitOk  = if ($expectExit -eq -1) { -not $exited } else { $exited -and ($code -eq $expectExit) }
    $eventOk = if ($expectEvent -eq "") { $evText -notmatch "root-ok" } else { $evText -match [regex]::Escape($expectEvent) }

    # 发射时机必须落在窗口里：早于下沿的发射等于白送一次 panic 重启。
    $upOk = $true
    $fireUp = ""
    if ($minFireUptime -gt 0) {
        if ($log -match "进入窗口：uptime=(\d+)s") {
            $fireUp = [int]$matches[1]
            $upOk = $fireUp -ge $minFireUptime
        } else {
            $upOk = $false
        }
        Write-Host ("   [debug] 发射 uptime={0}s（要求 ≥{1}s）" -f $fireUp, $minFireUptime)
    }

    $pass = $exitOk -and $eventOk -and $upOk
    $results += [pscustomobject]@{
        Case = $name
        Exit = $code
        WantExit = if ($expectExit -eq -1) { "不退出" } else { $expectExit }
        Event = if ($expectEvent -eq "") { "无 root-ok" } else { $expectEvent }
        FireUptime = $fireUp
        Pass = $pass
    }
    Write-Host ("-> {0}" -f $(if ($pass) { "PASS" } else { "FAIL" }))
}

Invoke-Case "A-hit" { Set-Mock $true $false 30 } @() 0 "root-ok" -minFireUptime 25
Invoke-Case "B-reboot-late" { Set-Mock $true $false 6000 } @("-RebootIfLate") 0 "root-ok" -minFireUptime 25
Invoke-Case "C-absent" { Set-Mock $false $false 0 } @() -1 "" -timeoutSec 30

function Start-WatchProbe {
    param([string]$dir)
    $watch = Join-Path $hereDir "watch-root.ps1"
    $a = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $watch,
        "-Serial", "MOCKSERIAL", "-Adb", $mockAdb, "-Exe", $mockExe,
        "-StateDir", $dir, "-PollSec", "2", "-FailBackoffSec", "5",
        "-MaxBackoffSec", "10", "-HeartbeatEvery", "2", "-NoReboot"
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = (($a | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join " ")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    return @{ Proc = $p; Out = $p.StandardOutput.ReadToEndAsync() }
}

# ---------------------------------------------------------------- D：监督 + 掉线补打
# 这是「自动 root」的核心行为：root 在线时不动，掉线后自己补回来。
Write-Host ""
Write-Host "===== 场景 D-supervise ====="
Set-Mock $true $true 30
$dDir = Join-Path $StateDir "D-supervise"
Remove-Item -Recurse -Force $dDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $dDir | Out-Null

$watch = Join-Path $hereDir "watch-root.ps1"
$wArgList = @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $watch,
    "-Serial", "MOCKSERIAL", "-Adb", $mockAdb, "-Exe", $mockExe,
    "-StateDir", $dDir, "-PollSec", "2", "-FailBackoffSec", "5",
    "-MaxBackoffSec", "10", "-HeartbeatEvery", "2", "-NoReboot"
)
$wPsi = New-Object System.Diagnostics.ProcessStartInfo
$wPsi.FileName = "powershell.exe"
$wPsi.Arguments = (($wArgList | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join " ")
$wPsi.RedirectStandardOutput = $true
$wPsi.RedirectStandardError = $true
$wPsi.UseShellExecute = $false
$wPsi.CreateNoWindow = $true
$wProc = [System.Diagnostics.Process]::Start($wPsi)
$wOut = $wProc.StandardOutput.ReadToEndAsync()

Start-Sleep -Seconds 7
$before = @(Get-Content -LiteralPath (Join-Path $dDir "events.jsonl") -ErrorAction SilentlyContinue)
Write-Host ("   启动后事件数={0}（此时 root 在线，不该补打）" -f $before.Count)

Write-Host "   把 root 掉线…"
Set-Mock $true $false 30
Start-Sleep -Seconds 25

try { $wProc.Kill() } catch { }
Start-Sleep -Milliseconds 500
$wLog = $wOut.Result
Set-Content -LiteralPath (Join-Path $dDir "watch-stdout.txt") -Value $wLog -Encoding UTF8
Write-Host (($wLog -split "`r?`n" | Where-Object { $_ } | Select-Object -Last 8) -join "`n")

$dEvents = ""
$dEventsPath = Join-Path $dDir "events.jsonl"
if (Test-Path $dEventsPath) { $dEvents = Get-Content -LiteralPath $dEventsPath -Raw }
$after = Get-Content -LiteralPath (Join-Path $mockDir "mock-state.txt") -Raw

$dOk1 = $dEvents -match "watch-reroot-start"
$dOk2 = $dEvents -match "root-ok"
$dOk3 = $after -match "root=1"
$dPass = $dOk1 -and $dOk2 -and $dOk3
$results += [pscustomobject]@{
    Case = "D-supervise"
    Exit = "-"
    WantExit = "-"
    Event = "watch-reroot-start + root-ok"
    FireUptime = ""
    Pass = $dPass
}
Write-Host ("   触发补打={0} 补打成功={1} root 恢复={2}" -f $dOk1, $dOk2, $dOk3)
Write-Host ("-> {0}" -f $(if ($dPass) { "PASS" } else { "FAIL" }))

# ---------------------------------------------------------------- E：命中后内核崩（panic 重启）
# 11-01 18:29 的真实失败模式：root 拿到 ~1 分钟后内核崩、设备重启、root 归零。
# 这里把它做成：root 在线 → 突然 root=0 且 uptime 归零（模拟 panic 重启）→ 必须自己补回来。
Write-Host ""
Write-Host "===== 场景 E-panic-after-root ====="
Set-Mock $true $true 30
$eDir = Join-Path $StateDir "E-panic-after-root"
Remove-Item -Recurse -Force $eDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $eDir | Out-Null

$w = Start-WatchProbe $eDir
Start-Sleep -Seconds 6
Write-Host "   模拟「命中后内核崩」：root 归零 + 重启进行中（uptime 归 0）"
Set-Mock $true $false 0
Start-Sleep -Seconds 70

try { $w.Proc.Kill() } catch { }
Start-Sleep -Milliseconds 500
$wLog = $w.Out.Result
Set-Content -LiteralPath (Join-Path $eDir "watch-stdout.txt") -Value $wLog -Encoding UTF8
Write-Host (($wLog -split "`r?`n" | Where-Object { $_ } | Select-Object -Last 10) -join "`n")

$eEventsPath = Join-Path $eDir "events.jsonl"
$eEv = if (Test-Path $eEventsPath) { Get-Content -LiteralPath $eEventsPath -Raw } else { "" }
$eAfter = Get-Content -LiteralPath (Join-Path $mockDir "mock-state.txt") -Raw

$firedUp = -1
if ($wLog -match "进入窗口：uptime=(\d+)s") { $firedUp = [int]$matches[1] }

$eOk1 = $eEv -match "root-ok"          # 崩完之后仍然补回来了
$eOk2 = $eAfter -match "root=1"        # mock 侧确认 root 在位
$eOk3 = $firedUp -ge 25                # 重启后没有抢早，等到了窗口下沿
$ePass = $eOk1 -and $eOk2 -and $eOk3

$results += [pscustomobject]@{
    Case = "E-panic-after-root"
    Exit = "-"
    WantExit = "-"
    Event = "重启后 root-ok"
    FireUptime = $firedUp
    Pass = $ePass
}
Write-Host ("   重启后补回={0} root 在位={1} 发射 uptime={2}s（≥25）" -f $eOk1, $eOk2, $firedUp)
Write-Host ("-> {0}" -f $(if ($ePass) { "PASS" } else { "FAIL" }))

Write-Host ""
Write-Host "===== 汇总 ====="
$results | Format-Table -AutoSize | Out-String | Write-Host
Set-Mock $true $false 30 | Out-Null

$failed = @($results | Where-Object { -not $_.Pass }).Count
if ($failed -gt 0) { Write-Host ("有 {0} 个场景没过" -f $failed); exit 1 }
Write-Host "全部通过"
exit 0
