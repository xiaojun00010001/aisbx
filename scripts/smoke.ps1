#requires -Version 5.1
<#
.SYNOPSIS
  aisbx Windows 冒烟验证:默认隔离 / token 授权闭环 / 资源限制 / 网络拒绝。
.USAGE
  # 管理员 PowerShell(回环例外写入需要管理员;非管理员时 T4 回环断言自动降级为 WARN)
  .\scripts\smoke.ps1
  .\scripts\smoke.ps1 -SkipNetwork          # CI 无外网/无监听场景
.NOTES
  适用于:Windows 10 1809+ / Windows 11 / Server 2019+(最低 Win8,见 docs/03 §6)
  也适用于 GitHub Actions windows-latest runner(该环境是管理员,全程无需人工交互)
#>
param([switch]$SkipNetwork)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Write-Host "[$(Get-Date -Format HH:mm:ss)] == 0. 构建 =="
cargo build --release --bins --example burn 2>&1 | Select-Object -Last 2
$bin  = Join-Path $repo "target\release\aisbx.exe"
$burn = Join-Path $repo "target\release\examples\burn.exe"
if (-not (Test-Path $bin))  { throw "aisbx.exe 未生成" }
if (-not (Test-Path $burn)) { throw "burn.exe 未生成" }

$script:fail = 0
$script:rows = @()
function Assert($name, $cond) {
  if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green; $script:rows += "| $name | PASS |" }
  else       { Write-Host "  FAIL  $name (exit=$LASTEXITCODE)" -ForegroundColor Red; $script:rows += "| $name | **FAIL** (exit=$LASTEXITCODE) |"; $script:fail++ }
}
function Warn($name) { Write-Host "  WARN  $name" -ForegroundColor Yellow }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ── 任务环境:policy escalation=deny,确保授权只走 token 闭环 ──────────
$root = Join-Path $env:TEMP "aisbx-smoke-$PID"
$ws   = Join-Path $root "ws"
$out  = Join-Path $root "outside"
New-Item -ItemType Directory -Force -Path $ws, $out | Out-Null
Copy-Item $bin $ws; Copy-Item $burn $ws
$audit = Join-Path $root "audit.jsonl"
$p1    = Join-Path $root "p1.json"

@{
  task       = "smoke-$PID"
  filesystem = @{
    write           = @($ws)
    read            = @()
    deny_escalation = @("$env:ProgramData\ssh")
    allow_escalation= @()
    escalation      = "deny"
  }
  network    = @{ loopback = $true; internet = $false }
  resources  = @{ memory_mb_per_process = 64; memory_mb_total = 256; active_processes = 10 }
  broker     = @{ audit_log = $audit }
} | ConvertTo-Json -Depth 5 | Set-Content $p1 -Encoding UTF8

try {
  # ── T0 策略合法性 ────────────────────────────────────────────────
  Write-Host "[$(Get-Date -Format HH:mm:ss)] == T0 策略 =="
  & $bin policy-check -p $p1
  Assert "T0 策略解析与校验" ($LASTEXITCODE -eq 0)

  # ── T1 文件默认隔离 ──────────────────────────────────────────────
  Write-Host "[$(Get-Date -Format HH:mm:ss)] == T1 文件默认隔离 =="
  & $bin run -p $p1 -- "$ws\burn.exe" write "$out\f1.txt"
  Assert "T1a 白名单外写入被拒(退出码非 0)" ($LASTEXITCODE -ne 0)
  Assert "T1b 白名单外文件未落盘" (-not (Test-Path "$out\f1.txt"))
  & $bin run -p $p1 -- "$ws\burn.exe" write "$ws\f1.txt"
  Assert "T1c 白名单内写入成功" (($LASTEXITCODE -eq 0) -and (Test-Path "$ws\f1.txt"))

  # ── T2 token 授权闭环 ────────────────────────────────────────────
  # broker 生命周期 = 一次 run,故 token 必须在 run 存活期间由宿主签发。
  Write-Host "[$(Get-Date -Format HH:mm:ss)] == T2 token 授权闭环 =="
  # T2a: deny 模式下无 token 提权必须失败
  & $bin run -p $p1 -- "$ws\aisbx.exe" escalate -p $p1 --path "$out\f2.txt" --access write
  Assert "T2a 无 token 提权被拒(deny 模式)" ($LASTEXITCODE -ne 0)

  # T2b~T2e: Start-Process 后台保活 broker -> 宿主 authorize -> 沙箱内消费/写入/重放
  # 注:不用 Start-Job/Wait-Job(在 CI 中曾无界阻塞),改用进程句柄 WaitForExit(超时)
  $tokFile = Join-Path $ws "token.txt"
  Remove-Item $tokFile -ErrorAction SilentlyContinue
  $flowOut = Join-Path $ws "flow.out"; $flowErr = Join-Path $ws "flow.err"
  $proc = Start-Process -FilePath $bin -NoNewWindow -PassThru `
    -RedirectStandardOutput $flowOut -RedirectStandardError $flowErr `
    -ArgumentList @('run', '-p', $p1, '--', "$ws\burn.exe", 'flow', $p1, $tokFile, "$out\f2.txt", 'grant')
  Start-Sleep -Seconds 3
  $auth = (& $bin authorize -p $p1 --path $out --access write --ttl-seconds 120) | Out-String | ConvertFrom-Json
  Assert "T2b authorize 在 run 存活期签发 token" ($LASTEXITCODE -eq 0 -and $null -ne $auth.token -and $auth.token.Length -ge 32)

  Set-Content -Path $tokFile -Value $auth.token -Encoding ascii
  if (-not $proc.WaitForExit(90000)) { $proc.Kill(); Write-Host "flow run 90s 未退出,已强杀" }
  $r1 = @(Get-Content $flowOut, $flowErr -ErrorAction SilentlyContinue) -join "`n"
  $r1 = $r1 | Out-String
  Write-Host ($r1.Trim())
  Assert "T2c 沙箱内消费 token 成功" ($r1 -match "escalate=0")
  Assert "T2d 授权后真实写入放行" (Test-Path "$out\f2.txt")
  Assert "T2e token 不可重放" ($r1 -match "replay=(?!0)\d+")

  # T2f: 黑名单前置,token 也救不回 deny_escalation
  $tokFile2 = Join-Path $ws "token2.txt"
  Remove-Item $tokFile2 -ErrorAction SilentlyContinue
  $flowOut2 = Join-Path $ws "flow2.out"; $flowErr2 = Join-Path $ws "flow2.err"
  $proc2 = Start-Process -FilePath $bin -NoNewWindow -PassThru `
    -RedirectStandardOutput $flowOut2 -RedirectStandardError $flowErr2 `
    -ArgumentList @('run', '-p', $p1, '--', "$ws\burn.exe", 'flow', $p1, $tokFile2, "$env:ProgramData\ssh", 'deny')
  Start-Sleep -Seconds 3
  $auth2 = (& $bin authorize -p $p1 --path "$env:ProgramData\ssh" --access write --ttl-seconds 60) | Out-String | ConvertFrom-Json
  Set-Content -Path $tokFile2 -Value $auth2.token -Encoding ascii
  if (-not $proc2.WaitForExit(90000)) { $proc2.Kill(); Write-Host "flow2 run 90s 未退出,已强杀" }
  $r2 = @(Get-Content $flowOut2, $flowErr2 -ErrorAction SilentlyContinue) -join "`n"
  $r2 = $r2 | Out-String
  Write-Host ($r2.Trim())
  Assert "T2f deny_escalation 优先于 token" ($r2 -match "escalate=(?!0)\d+")

  # ── T3 资源限制 ──────────────────────────────────────────────────
  Write-Host "[$(Get-Date -Format HH:mm:ss)] == T3 资源限制(单进程 64MB / 全任务 256MB / 进程数 10) =="
  & $bin run -p $p1 -- "$ws\burn.exe" mem 32
  Assert "T3a 配额内分配成功" ($LASTEXITCODE -eq 0)
  & $bin run -p $p1 -- "$ws\burn.exe" mem 512
  Assert "T3b 单进程内存超限被发现(退出码非 0)" ($LASTEXITCODE -ne 0)
  & $bin run -p $p1 -- "$ws\burn.exe" fork 40
  Assert "T3c fork 超过 active_processes=10 被掐" ($LASTEXITCODE -eq 2)

  # ── T4 网络 ──────────────────────────────────────────────────────
  if (-not $SkipNetwork) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T4 网络(loopback=true / internet=false) =="
    $port = 47000 + (Get-Random -Maximum 2000)
    $job = Start-Job -ScriptBlock {
      param($p)
      $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
      $l.Start(); $c = $l.AcceptTcpClient(); $c.Close(); $l.Stop()
    } -ArgumentList $port
    Start-Sleep -Milliseconds 800
    & $bin run -p $p1 -- "$ws\burn.exe" conn 127.0.0.1 $port
    Assert "T4a 回环放行" ($LASTEXITCODE -eq 0)
    & $bin run -p $p1 -- "$ws\burn.exe" conn 1.1.1.1 53
    Assert "T4b 外网无 capability 被内核拒绝" ($LASTEXITCODE -ne 0)
    Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    if (-not $isAdmin) { Warn "非管理员:CheckNetIsolation 回环例外可能写入失败,T4a 结果仅供参考(GitHub Actions runner 为管理员)" }
  }

  # ── T5 审计断言 ──────────────────────────────────────────────────
  Write-Host "[$(Get-Date -Format HH:mm:ss)] == T5 审计 =="
  $events = Get-Content $audit | ForEach-Object { ($_ | ConvertFrom-Json).event }
  Assert "T5a token.issued 已落审计" ($events -contains "token.issued")
  Assert "T5b token.redeemed 已落审计" ($events -contains "token.redeemed")
  Assert "T5c escalation.deny 已落审计" ($events -contains "escalation.deny")

  # ── T6 网络代理(P0):精确目标自动采集 / 运行中授权 ─────────────────
  # burn proxy 只是遵守 HTTPS_PROXY 发一次 CONNECT,不主动上报、不解析命令。
  if (-not $isAdmin) {
    Warn "T6 非管理员:CheckNetIsolation 回环例外可能不可用,跳过网络代理断言"
  } else {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T6 网络代理(P0) =="
    $p6 = Join-Path $root "p6.json"
    $a6 = Join-Path $root "p6.audit.jsonl"
    @{
      task       = "smoke6-$PID"
      filesystem = @{
        write           = @($ws)
        read            = @()
        deny_escalation = @()
        allow_escalation= @()
        escalation      = "deny"
      }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{ memory_mb_per_process = 64; memory_mb_total = 256; active_processes = 10 }
      broker     = @{ audit_log = $a6 }
    } | ConvertTo-Json -Depth 5 | Set-Content $p6 -Encoding UTF8

    $t6out = Join-Path $ws "t6.out"; $t6err = Join-Path $ws "t6.err"
    $proc6 = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -RedirectStandardOutput $t6out -RedirectStandardError $t6err `
      -ArgumentList @('run', '-p', $p6, '--', "$ws\burn.exe", 'proxy', 'example.com', '443')
    for ($i = 0; $i -lt 100; $i++) {
      if ((Test-Path $a6) -and (Select-String -Path $a6 -Pattern '"event":"violation"' -Quiet)) { break }
      Start-Sleep -Milliseconds 200
    }
    $hasTarget = (Test-Path $a6) `
      -and (Select-String -Path $a6 -Pattern '"host":"example.com"' -Quiet) `
      -and (Select-String -Path $a6 -Pattern '"port":443' -Quiet)
    Assert "T6a 代理自动拿到精确 host:port(零解析/零改造)" $hasTarget

    $auth6 = (& $bin authorize -p $p6 --host example.com --port 443) | Out-String
    Assert "T6b authorize --host 放行" ($LASTEXITCODE -eq 0 -and $auth6 -match '"granted":\s*true')
    if (-not $proc6.WaitForExit(60000)) { $proc6.Kill(); Write-Host "T6 run 60s 未退出,已强杀" }
    $r6 = @(Get-Content $t6out, $t6err -ErrorAction SilentlyContinue) -join "`n"
    Write-Host ($r6.Trim())
    Assert "T6c 授权后运行中放行(proxy_status=200)" ($r6 -match "proxy_status=200")
    Assert "T6d net.grant 已落审计" ((Test-Path $a6) -and (Select-String -Path $a6 -Pattern '"event":"net.grant"' -Quiet))

    # ── T8 SOCKS5:同一端口按首字节分流 ───────────────────────────────
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T8 SOCKS5 =="
    $p8 = Join-Path $root "p8.json"
    $a8 = Join-Path $root "p8.audit.jsonl"
    @{
      task       = "smoke8-$PID"
      filesystem = @{
        write           = @($ws)
        read            = @()
        deny_escalation = @()
        allow_escalation= @()
        escalation      = "deny"
      }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{ memory_mb_per_process = 64; memory_mb_total = 256; active_processes = 10 }
      broker     = @{ audit_log = $a8 }
    } | ConvertTo-Json -Depth 5 | Set-Content $p8 -Encoding UTF8

    $t8out = Join-Path $ws "t8.out"; $t8err = Join-Path $ws "t8.err"
    $proc8 = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -RedirectStandardOutput $t8out -RedirectStandardError $t8err `
      -ArgumentList @('run', '-p', $p8, '--', "$ws\burn.exe", 'socks', 'example.com', '443')
    for ($i = 0; $i -lt 100; $i++) {
      if ((Test-Path $a8) -and (Select-String -Path $a8 -Pattern '"event":"violation"' -Quiet)) { break }
      Start-Sleep -Milliseconds 200
    }
    $has8 = (Test-Path $a8) `
      -and (Select-String -Path $a8 -Pattern '"host":"example.com"' -Quiet) `
      -and (Select-String -Path $a8 -Pattern '"port":443' -Quiet)
    Assert "T8a SOCKS5 自动拿到精确 host:port(零解析/零改造)" $has8
    $auth8 = (& $bin authorize -p $p8 --host example.com --port 443) | Out-String
    Assert "T8b authorize --host 放行" ($LASTEXITCODE -eq 0 -and $auth8 -match '"granted":\s*true')
    if (-not $proc8.WaitForExit(60000)) { $proc8.Kill(); Write-Host "T8 run 60s 未退出,已强杀" }
    $r8 = @(Get-Content $t8out, $t8err -ErrorAction SilentlyContinue) -join "`n"
    Write-Host ($r8.Trim())
    Assert "T8c SOCKS5 授权后运行中放行(socks_status=0)" ($r8 -match "socks_status=0")
    Assert "T8d net.grant 已落审计" ((Test-Path $a8) -and (Select-String -Path $a8 -Pattern '"event":"net.grant"' -Quiet))

    # ── T9 契约边界与安全断言 ────────────────────────────────────────
    # 单独兜底:任何 PowerShell 异常都要落到断言计数,不能让脚本静默中断
    # (否则 CI 只会看到 exit 1,日志里连 SMOKE_DONE 都没有)。
    try {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T9 契约边界与安全断言 =="
    $p9 = Join-Path $root "p9.json"; $a9 = Join-Path $root "p9.audit.jsonl"
    @{
      task       = "smoke9-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{ memory_mb_per_process = 64; memory_mb_total = 256; active_processes = 10 }
      broker     = @{ audit_log = $a9 }
    } | ConvertTo-Json -Depth 5 | Set-Content $p9 -Encoding UTF8

    # T9a --require-full 必须按能力报告判定,不能硬编码平台结论
    $capRaw = (& $bin capabilities 2>&1) | Out-String
    $capAll = $capRaw | ConvertFrom-Json
    $white = @('auto_violation_capture','cpu','memory_total','landlock','bubblewrap',
               'seatbelt','seccomp','launcher_retry')
    $fatal = @($capAll.capabilities.PSObject.Properties | Where-Object {
                 $_.Value -eq 'unavailable' -and $white -notcontains $_.Name })
    $expect = if ($fatal.Count -gt 0) { 'deny' } else { 'allow' }
    & $bin run --require-full -p $p9 -- "$ws\burn.exe" write "$ws\full.txt" 2>&1 | Out-Null
    $fullRc = $LASTEXITCODE
    $okFull = (($expect -eq 'deny' -and $fullRc -ne 0) -or ($expect -eq 'allow' -and $fullRc -eq 0))
    Assert "T9a --require-full 按能力报告判定($expect)" $okFull

    # T9b 没发生过真实越界时,宿主不能凭空签发网络授权(fail-closed)
    $procB = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -RedirectStandardOutput "$ws\t9b.run" -RedirectStandardError "$ws\t9b.err" `
      -ArgumentList @('run','-p',$p9,'--',"$ws\burn.exe",'spin','4')
    Start-Sleep -Seconds 1
    $authB = (& $bin authorize -p $p9 --host never-observed.invalid --port 443 2>&1) | Out-String
    $authRc = $LASTEXITCODE
    if (-not $procB.WaitForExit(20000)) { $procB.Kill() }
    Write-Host ($authB.Trim())
    Assert "T9b 无真实越界时拒绝签发网络授权(fail-closed)" ($authRc -ne 0)

    # T9c 两个并发任务的审计不得串台
    $p9a = Join-Path $root "p9a.json"; $a9a = Join-Path $root "p9a.audit.jsonl"
    $p9b = Join-Path $root "p9b.json"; $a9b = Join-Path $root "p9b.audit.jsonl"
    @{
      task       = "smoke9a-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{ memory_mb_per_process = 64; memory_mb_total = 256; active_processes = 10 }
      broker     = @{ audit_log = $a9a }
    } | ConvertTo-Json -Depth 5 | Set-Content $p9a -Encoding UTF8
    @{
      task       = "smoke9b-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{ memory_mb_per_process = 64; memory_mb_total = 256; active_processes = 10 }
      broker     = @{ audit_log = $a9b }
    } | ConvertTo-Json -Depth 5 | Set-Content $p9b -Encoding UTF8
    # Windows 的 --json 事件只 println、不写审计(spawned 不在 audit 里),
    # 因此用 --json 输出流做串台判定;Unix 侧两者都落审计,见 docs/07。
    $procA = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -RedirectStandardOutput "$ws\a9.out" -RedirectStandardError "$ws\a9.err" `
      -ArgumentList @('run','--json','-p',$p9a,'--',"$ws\burn.exe",'write',"$ws\a9.txt")
    $procC = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -RedirectStandardOutput "$ws\b9.out" -RedirectStandardError "$ws\b9.err" `
      -ArgumentList @('run','--json','-p',$p9b,'--',"$ws\burn.exe",'write',"$ws\b9.txt")
    $null = $procA.WaitForExit(30000); $null = $procC.WaitForExit(30000)
    $okC = (Test-Path "$ws\a9.out") -and (Test-Path "$ws\b9.out") `
      -and (Select-String -Path "$ws\a9.out" -Pattern 'a9.txt' -Quiet -ErrorAction SilentlyContinue) `
      -and (-not (Select-String -Path "$ws\a9.out" -Pattern 'b9.txt' -Quiet -ErrorAction SilentlyContinue)) `
      -and (Select-String -Path "$ws\b9.out" -Pattern 'b9.txt' -Quiet -ErrorAction SilentlyContinue) `
      -and (-not (Select-String -Path "$ws\b9.out" -Pattern 'a9.txt' -Quiet -ErrorAction SilentlyContinue))
    Assert "T9c 并发任务事件流不串台" $okC

    # T9d 代理拒绝 loopback 目标(防 SSRF)
    & $bin run -p $p9 -- "$ws\burn.exe" proxy 127.0.0.1 443 2>&1 | Out-Null
    Assert "T9d 代理拒绝 loopback 目标(SSRF fail-closed)" ($LASTEXITCODE -eq 3)

    # T9e 能力报告关键字段完整(避免静默降级)
    Assert "T9e 能力报告含采集能力与代理协议字段" `
      ($capRaw -match '"net_proxy"' -and $capRaw -match '"auto_violation_capture"')
    } catch {
      Warn "T9 段异常: $_"
      $script:rows += "| T9 段异常(未跑完) | **FAIL** |"
      $script:fail++
    }
  }
}
finally {
  Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "SMOKE_DONE fail=$script:fail"
if ($script:fail -eq 0) { Write-Host "冒烟验证全部通过" -ForegroundColor Green }
else                    { Write-Host "冒烟验证失败 $script:fail 项" -ForegroundColor Red }

if ($env:GITHUB_STEP_SUMMARY) {
  $md = @("### aisbx Windows 冒烟结果", "", "| 断言 | 结果 |", "|---|---|") + $script:rows
  $md | Add-Content -Path $env:GITHUB_STEP_SUMMARY -Encoding UTF8
}
exit $script:fail
