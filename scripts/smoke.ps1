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

# 段级进度回写:每进入一个 T 段就把「开始哪一段」推进仓库。
#
# 为什么要它:Windows 冒烟整轮要十几分钟,而 CI 日志我读不到(未认证 API
# 配额有限、job 日志需鉴权)—— 一旦某段卡死(无界等待),job 会被 cancel,
# 连 always 的回写都不执行,结果就是「Windows 这条链完全是盲的」。
# 有了它,卡住时仓库里最后一条进度就是卡住的那一段。
function Push-Progress($stage) {
  try {
    $dir = Join-Path $repo "ci/runs"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $f = Join-Path $dir "windows-progress.md"
    Add-Content -Path $f -Value ("- {0} @ {1}" -f $stage, (Get-Date -Format HH:mm:ss)) -Encoding UTF8
    $env:GIT_EDITOR = "true"
    $env:GIT_TERMINAL_PROMPT = "0"
    git config --global core.editor true 2>&1 | Out-Null
    git config user.name "github-actions[bot]"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
    git add ci/runs/windows-progress.md
    git commit -q -m "ci: windows smoke progress $stage [skip ci]"
    if ($LASTEXITCODE -ne 0) { return }
    # 进度走独立分支:15 次 push 不与任何结果回写抢同一分支
    $br = "ci-results/progress"
    git push origin "HEAD:$br" 2>&1 | Out-Null
  } catch {
    # 进度回写是尽力而为,失败不能影响冒烟本身
  }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ── 任务环境:policy escalation=deny,确保授权只走 token 闭环 ──────────
$rootTmp = Join-Path $env:TEMP "aisbx-smoke-$PID"
New-Item -ItemType Directory -Force -Path $rootTmp | Out-Null
# 取**长路径**:CI 的 $env:TEMP 是 8.3 短路径(RUNNER~1),而 canonicalize
# 之后的路径是长路径——两者形态不一致时,路径类断言无法比对。
$root = (Get-Item $rootTmp).FullName
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
  Push-Progress "T0"
  Write-Host "[$(Get-Date -Format HH:mm:ss)] == T0 策略 =="
  & $bin policy-check -p $p1
  Assert "T0 策略解析与校验" ($LASTEXITCODE -eq 0)

  # ── T1 文件默认隔离 ──────────────────────────────────────────────
  Push-Progress "T1"
  Write-Host "[$(Get-Date -Format HH:mm:ss)] == T1 文件默认隔离 =="
  & $bin run -p $p1 -- "$ws\burn.exe" write "$out\f1.txt"
  Assert "T1a 白名单外写入被拒(退出码非 0)" ($LASTEXITCODE -ne 0)
  Assert "T1b 白名单外文件未落盘" (-not (Test-Path "$out\f1.txt"))
  & $bin run -p $p1 -- "$ws\burn.exe" write "$ws\f1.txt"
  Assert "T1c 白名单内写入成功" (($LASTEXITCODE -eq 0) -and (Test-Path "$ws\f1.txt"))

  # ── T2 token 授权闭环 ────────────────────────────────────────────
  # broker 生命周期 = 一次 run,故 token 必须在 run 存活期间由宿主签发。
  Push-Progress "T2"
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
  Push-Progress "T3"
  Write-Host "[$(Get-Date -Format HH:mm:ss)] == T3 资源限制(单进程 64MB / 全任务 256MB / 进程数 10) =="
  & $bin run -p $p1 -- "$ws\burn.exe" mem 32
  Assert "T3a 配额内分配成功" ($LASTEXITCODE -eq 0)
  & $bin run -p $p1 -- "$ws\burn.exe" mem 512
  Assert "T3b 单进程内存超限被发现(退出码非 0)" ($LASTEXITCODE -ne 0)
  & $bin run -p $p1 -- "$ws\burn.exe" fork 40
  Assert "T3c fork 超过 active_processes=10 被掐" ($LASTEXITCODE -eq 2)

  # ── T4 网络 ──────────────────────────────────────────────────────
  if (-not $SkipNetwork) {
    Push-Progress "T4"
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
  Push-Progress "T5"
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
    Push-Progress "T6"
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
    Push-Progress "T8"
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
    Push-Progress "T9"
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

    # ── T10 能力契约组(C07/C19/C20/C22) ─────────────────────────────
    try {
    Push-Progress "T10"
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T10 能力契约组 =="
    $p10 = Join-Path $root "p10.json"; $a10 = Join-Path $root "p10.audit.jsonl"
    @{
      task       = "smoke10-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @($out); escalation = "auto" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{ memory_mb_per_process = 64; memory_mb_total = 256; active_processes = 10 }
      broker     = @{ audit_log = $a10 }
    } | ConvertTo-Json -Depth 5 | Set-Content $p10 -Encoding UTF8

    # T10a C07:auto 模式命中 allow_escalation 前缀(deny 模式已由 T2a 覆盖)
    & $bin run -p $p10 -- "$ws\aisbx.exe" escalate -p $p10 --path "$out\t10a.txt" --access write 2>&1 |
      Out-File "$ws\t10a.out" -Encoding utf8
    Assert "T10a C07 auto 模式按 allow_escalation 授权" `
      (Select-String -Path "$ws\t10a.out" -Pattern '"granted":true' -Quiet -ErrorAction SilentlyContinue)

    # T10b C22:--json 事件流含 spawned / exit
    & $bin run -p $p10 --json -- "$ws\burn.exe" write "$ws\t10b.txt" 2>&1 |
      Out-File "$ws\t10b.out" -Encoding utf8
    Assert "T10b C22 --json 事件流含 spawned/exit" `
      ((Select-String -Path "$ws\t10b.out" -Pattern '"event":"spawned"' -Quiet -ErrorAction SilentlyContinue) `
       -and (Select-String -Path "$ws\t10b.out" -Pattern '"event":"exit"' -Quiet -ErrorAction SilentlyContinue))

    # T10c C19:宿主被杀时 Job 应带走整棵进程树(KILL_ON_JOB_CLOSE)
    $capRaw10 = (& $bin capabilities 2>&1) | Out-String
    $cap10 = $capRaw10 | ConvertFrom-Json
    $ptk = $cap10.capabilities.process_tree_kill
    if ($ptk -eq 'full') {
      $procKill = Start-Process -FilePath $bin -NoNewWindow -PassThru `
        -RedirectStandardOutput "$ws\t10c.out" -RedirectStandardError "$ws\t10c.err" `
        -ArgumentList @('run','-p',$p10,'--',"$ws\burn.exe",'spin','20')
      Start-Sleep -Seconds 2
      try { $procKill.Kill() } catch { }
      Start-Sleep -Seconds 2
      $left = @(Get-CimInstance Win32_Process -Filter "Name='burn.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -like "*$ws*" })
      Assert "T10c C19 宿主被杀后无残留沙箱进程" ($left.Count -eq 0)
    } else {
      Warn "T10c C19 该平台标 $ptk,未验证"
    }

    # T10d C20:任务结束后提权新落的 ACE 必须被撤销(修复前会残留 package SID)
    $aclText = (& icacls "$out" 2>&1) | Out-String
    Assert "T10d C20 任务结束无提权 ACL 残余" ($aclText -notmatch 'S-1-15-2-')

    # T10e 能力报告每个能力都有明确状态值
    # (路径精度两个字段是枚举值 exact/reported/none,不是 full/partial/unavailable)
    $skip = @('net_proxy','violation_log_probe',
              'violation_file_path_precision','violation_net_path_precision')
    $bad = @($cap10.capabilities.PSObject.Properties | Where-Object {
               $skip -notcontains $_.Name -and $_.Value -notin @('full','partial','unavailable') })
    Assert "T10e 能力报告逐项状态明确" ($bad.Count -eq 0)
    } catch {
      Warn "T10 段异常: $_"
      $script:rows += "| T10 段异常(未跑完) | **FAIL** |"
      $script:fail++
    }

    # ── T11 L1:程序自报路径(stderr)───────────────────────────────
    # Windows 的 ERROR_ACCESS_DENIED 本身**不含路径**,而 .NET / PowerShell
    # 会把路径拼进异常消息("Access to the path 'X' is denied.")。
    # L1 补上「该放行谁」,让 in-place 放行精确到单个路径,而不是整条命令豁免。
    try {
    Push-Progress "T11"
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T11 L1:程序自报路径(stderr) =="
    $p11 = Join-Path $root "p11.json"; $a11 = Join-Path $root "p11.audit.jsonl"
    @{
      task       = "smoke11-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{}
      broker     = @{ audit_log = $a11; violation_capture = $true }
    } | ConvertTo-Json -Depth 5 | Set-Content $p11 -Encoding UTF8

    $t11target = Join-Path $out "t11.txt"
    & $bin run -p $p11 -- "$ws\burn.exe" stderrdeny $t11target 2>&1 |
      Out-File "$ws\t11.out" -Encoding utf8
    $t11audit = if (Test-Path $a11) { Get-Content $a11 -Raw } else { "" }
    # 把审计内容落进日志:路径断言失败时能直接看到实际采到的路径形态
    Write-Host "----- T11 审计 -----"
    Write-Host $t11audit
    Assert "T11a stderr 自报路径被采集" ($t11audit -match '"source":"stderr-selfreport"')
    Assert "T11b 路径精度标注为 reported" ($t11audit -match '"precision":"reported"')
    Assert "T11c 归属确定(attributed=true)" ($t11audit -match '"attributed":true')
    # JSON 里反斜杠被转义成双反斜杠,匹配前先做同样的转义
    # 采集到的路径可能是「程序自报的原样路径」,也可能是「规范化后的长路径」
    # (Windows 的 canonicalize 会补长路径)——两种形态都算对。
    # 只匹配**路径尾部**(目录名 + 文件名),不比整条路径:
    #   - 程序自报的是原样路径(CI 上是 8.3 短路径 RUNNER~1);
    #   - 规范化后的是长路径(C:\Users\runneradmin\...);
    #   - JSON 里反斜杠还要再转义一层。
    # 三种形态同时存在,只有尾部是稳定判据。
    $t11dir  = (Split-Path $t11target -Parent | Split-Path -Leaf)
    $t11leaf = Split-Path $t11target -Leaf
    $t11tail = [regex]::Escape($t11dir) + "\\+" + [regex]::Escape($t11leaf)
    Assert "T11d 采集到的路径正确" ($t11audit -match $t11tail)
    } catch {
      Warn "T11 段异常: $_"
      $script:rows += "| T11 段异常(未跑完) | **FAIL** |"
      $script:fail++
    }

    # ── T12 B 契约:授权后重跑(launcher retry)─────────────────────
    # 沙箱内程序写白名单外的路径 → 被拒(错误消息含路径)→ L1 采集 → 置 needs-approval
    # → launcher 等宿主授权 → 把该路径并入策略快照(落 ACL)→ 重跑 → 成功。
    # 与 Unix 侧 B 契约闭环一致:**重跑是主线**,in-place 只是 legacy 加速路径。
    try {
    Push-Progress "T12"
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T12 B 契约:授权后重跑 =="
    $p12 = Join-Path $root "p12.json"; $a12 = Join-Path $root "p12.audit.jsonl"
    @{
      task       = "smoke12-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{}
      broker     = @{ audit_log = $a12; violation_capture = $true }
    } | ConvertTo-Json -Depth 5 | Set-Content $p12 -Encoding UTF8

    $t12target = Join-Path $out "t12.txt"
    # 不做 stdout/stderr 重定向:CI 上 `-RedirectStandardOutput` 指向
    # `$ws\t12.out` 会报 "The filename, directory name, or volume label
    # syntax is incorrect."。本段断言只用退出码、文件落盘与审计。
    $proc12 = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -ArgumentList @('run','-p',$p12,'--',"$ws\burn.exe",'stderrdeny',$t12target)
    for ($i = 0; $i -lt 100; $i++) {
      if ((Test-Path $a12) -and (Select-String -Path $a12 -Pattern 'needs-approval' -Quiet)) { break }
      Start-Sleep -Milliseconds 200
    }
    & $bin authorize -p $p12 --path $t12target --access write 2>&1 | Out-Null
    if (-not $proc12.WaitForExit(60000)) { $proc12.Kill() }
    $rc12 = $proc12.ExitCode
    Assert "T12a 授权后重跑成功" ($rc12 -eq 0)
    Assert "T12b 文件真实落盘" (Test-Path $t12target)
    Assert "T12c retry 事件已落审计" `
      ((Test-Path $a12) -and (Select-String -Path $a12 -Pattern '"event":"retry"' -Quiet))
    } catch {
      Warn "T12 段异常: $_"
      $script:rows += "| T12 段异常(未跑完) | **FAIL** |"
      $script:fail++
    }

    # ── T13 授权粒度:不外溢 ──────────────────────────────────────
    # 用户在审批框里同意的是「创建 newfile」这一个文件;若实现对父目录授 Modify,
    # 实际授权范围就扩大到「改/删该目录下所有文件」→ 这是真实的越权面
    # (Unix 侧不存在:bwrap 只 --bind 目标路径本身)。
    # probe2 在一次 run 内先试 new(被拒→L1 采集→授权→重跑)、再试 existing:
    # 授权后 new 应创建成功,而 existing 必须仍写不动、内容不变。
    try {
    Push-Progress "T13"
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T13 授权粒度不外溢 =="
    $p13 = Join-Path $root "p13.json"; $a13 = Join-Path $root "p13.audit.jsonl"
    @{
      task       = "smoke13-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{}
      broker     = @{ audit_log = $a13; violation_capture = $true }
    } | ConvertTo-Json -Depth 5 | Set-Content $p13 -Encoding UTF8

    $t13new = Join-Path $out "t13new.txt"
    $t13old = Join-Path $out "t13old.txt"
    Set-Content -Path $t13old -Value "orig" -Encoding UTF8
    # 标记走 AISBX_REPORT 报告文件(沙箱内进程写白名单目录内的文件),
    # 宿主直接读:不依赖 stdout 捕获,也不依赖重定向能否成功。
    $rpt13 = Join-Path $ws "report13.txt"
    Remove-Item $rpt13 -ErrorAction SilentlyContinue
    $env:AISBX_REPORT = $rpt13
    $proc13 = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -ArgumentList @('run','-p',$p13,'--',"$ws\burn.exe",'probe2',$t13new,$t13old)
    for ($i = 0; $i -lt 100; $i++) {
      if ((Test-Path $a13) -and (Select-String -Path $a13 -Pattern 'needs-approval' -Quiet)) { break }
      Start-Sleep -Milliseconds 200
    }
    & $bin authorize -p $p13 --path $t13new --access write 2>&1 | Out-Null
    if (-not $proc13.WaitForExit(60000)) { $proc13.Kill() }
    $r13 = if (Test-Path $rpt13) { Get-Content $rpt13 -Raw } else { "" }
    Remove-Item Env:AISBX_REPORT -ErrorAction SilentlyContinue
    Assert "T13a 授权后新文件创建成功" ($r13 -match "NEW_CREATED")
    Assert "T13b 授权粒度不外溢(同目录既有文件仍不可写)" `
      (($r13 -match "EXISTING_DENIED") -and ($r13 -notmatch "EXISTING_WRITEABLE"))
    Assert "T13c 既有文件内容未被改动" ((Get-Content $t13old -Raw) -match "orig")
    } catch {
      Warn "T13 段异常: $_"
      $script:rows += "| T13 段异常(未跑完) | **FAIL** |"
      $script:fail++
    }

    # ── T14 status:agent 查询待授权信息 ──────────────────────────────
    # agent 是靠 `aisbx status` 拿「要放行哪个路径」的 → 这条交互必须
    # 三平台都有,且给出的信息形态一致(Unix 侧 T14a/b/c 同款)。
    try {
    Push-Progress "T14"
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T14 status 交互 =="
    $p14 = Join-Path $root "p14.json"; $a14 = Join-Path $root "p14.audit.jsonl"
    @{
      task       = "smoke14-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{}
      broker     = @{ audit_log = $a14; violation_capture = $true }
    } | ConvertTo-Json -Depth 5 | Set-Content $p14 -Encoding UTF8

    $t14target = Join-Path $out "t14.txt"
    $proc14 = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -ArgumentList @('run','-p',$p14,'--',"$ws\burn.exe",'stderrdeny',$t14target)
    for ($i = 0; $i -lt 150; $i++) {
      if ((Test-Path $a14) -and (Select-String -Path $a14 -Pattern 'needs-approval' -Quiet)) { break }
      Start-Sleep -Milliseconds 200
    }
    $st14 = (& $bin status -p $p14 | Out-String)
    # 只比尾部:短/长路径形态在 Windows 上并存(8.3 短路径 vs canonicalize 后的长路径)
    $t14leaf = Split-Path $t14target -Leaf
    Assert "T14a status 给出待授权的具体路径" ($st14 -match [regex]::Escape($t14leaf))
    Assert "T14b status 标注路径精度与归属" ($st14 -match 'reported|exact')
    Assert "T14c status 报告 needs_approval 标志" ($st14 -match 'needs[-_]approval')
    if (-not $proc14.WaitForExit(20000)) { $proc14.Kill() }
    } catch {
      Warn "T14 段异常: $_"
      $script:rows += "| T14 段异常(未跑完) | **FAIL** |"
      $script:fail++
    }

    # ── T15 对抗:程序自称路径 ≠ 它真正要的路径 ───────────────────────
    # spoof 先真的写 actual(被内核拒绝),再向 stderr 打印一个自称的 claimed。
    # 要验的是:授权**自称**路径后,**真实**路径仍写不动 → 伪造换不来越权。
    try {
    Push-Progress "T15"
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == T15 对抗:自称路径 vs 真实路径 =="
    $p15 = Join-Path $root "p15.json"; $a15 = Join-Path $root "p15.audit.jsonl"
    @{
      task       = "smoke15-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{}
      broker     = @{ audit_log = $a15; violation_capture = $true }
    } | ConvertTo-Json -Depth 5 | Set-Content $p15 -Encoding UTF8

    $t15claimed = Join-Path $out "t15claimed.txt"
    $t15actual  = Join-Path $out "t15actual.txt"
    $proc15 = Start-Process -FilePath $bin -NoNewWindow -PassThru `
      -ArgumentList @('run','-p',$p15,'--',"$ws\burn.exe",'spoof',$t15claimed,$t15actual)
    for ($i = 0; $i -lt 150; $i++) {
      if ((Test-Path $a15) -and (Select-String -Path $a15 -Pattern 't15claimed' -Quiet)) { break }
      Start-Sleep -Milliseconds 200
    }
    $a15txt = if (Test-Path $a15) { Get-Content $a15 -Raw } else { "" }
    # 审计打进日志:T15a 失败时能直接看到实际采到了什么(路径形态/来源/精度)
    Write-Host "----- T15 审计 -----"
    Write-Host $a15txt
    Assert "T15a 采到自称路径且精度为 reported" `
      (($a15txt -match 't15claimed') -and ($a15txt -match '"precision":"reported"'))
    # ⚠️ 只排除**内核通道**采到的条目:策略感知(source=explicit)也会记下
    # 这个路径,那是正常行为,不是「采到了真实路径」。
    Assert "T15b 未采到从未被拒的真实路径" `
      (-not ($a15txt -match 't15actual' -and $a15txt -match '"source":"sandbox-log"'))
    # 只授权【自称】路径 → 重跑 → 真实路径仍必须写不动
    & $bin authorize -p $p15 --path $t15claimed --access write 2>&1 | Out-Null
    if (-not $proc15.WaitForExit(60000)) { $proc15.Kill() }
    Assert "T15c 授权自称路径后真实路径仍被拒(伪造不构成越权)" `
      (-not (Test-Path $t15actual))
    } catch {
      Warn "T15 段异常: $_"
      $script:rows += "| T15 段异常(未跑完) | **FAIL** |"
      $script:fail++
    }

    # ── 跨平台契约检查(与 Unix **共用同一份** contract_check.py 与基线)──
    # 目的是保证「三个环境的表现形式与交互一样」:能力报告的键集合、
    # --json 事件流的事件名、审计事件类型、退出码语义,三平台必须一致。
    Push-Progress "contract"
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == 跨平台契约检查 =="
    $cp = Join-Path $root "contract"
    New-Item -ItemType Directory -Force -Path $cp | Out-Null
    # 用 WriteAllText 而不是 Out-File:PS 5.1 的 utf8 会带 BOM,JSON 解析会失败
    Push-Progress "contract/caps"
    [System.IO.File]::WriteAllText("$cp\caps.json", ((& $bin capabilities) | Out-String))
    $cpp = Join-Path $cp "policy.json"
    $cpa = Join-Path $cp "audit.jsonl"
    @{
      task       = "contract-$PID"
      filesystem = @{ write = @($ws); read = @(); deny_escalation = @()
                      allow_escalation = @(); escalation = "deny" }
      network    = @{ loopback = $true; internet = $false }
      resources  = @{}
      broker     = @{ audit_log = $cpa; violation_capture = $true }
    } | ConvertTo-Json -Depth 5 | Set-Content $cpp -Encoding UTF8
    # ⚠️ 这三步都**必须有界**:契约检查是纯文件处理(秒级),一旦卡住就是
    # 出了问题(实测 Windows 冒烟 15 段 2 分跑完后卡在这里,60 分钟
    # timeout 都救不回来 —— 因为卡住的步骤把整个 job 拖死了)。
    # 全部改成 Start-Process + WaitForExit(超时) → 卡住时被杀,冒烟继续。
    Push-Progress "contract/run"
    $cpe = Join-Path $cp "events.jsonl"
    # ⚠️ 不用 `Start-Process -RedirectStandardOutput`:那条路在 CI 的短路径
    # (RUNNER~1)下会报 "The filename, directory name, or volume label syntax
    # is incorrect."(实测踩过)。改用 cmd 的重定向(cmd 自己解析路径)。
    $cmdline = '"{0}" run -p "{1}" -- "{2}" stderrdeny "{3}" > "{4}" 2> "{5}"' -f `
      $bin, $cpp, "$wsurn.exe", (Join-Path $out "contract.txt"), $cpe, (Join-Path $cp "run.err")
    $pRun = Start-Process -FilePath "cmd.exe" -NoNewWindow -PassThru `
      -ArgumentList @('/c', $cmdline)
    if (-not $pRun.WaitForExit(60000)) { $pRun.Kill(); Write-Host "::notice::契约用的 run 超时,已终止" }
    $cpRc = $pRun.ExitCode

    Push-Progress "contract/check"
    # 平台名取自能力报告的 backend(不写死):契约基线按平台给期望值,
    # 写死会在平台间张冠李戴(实测 macOS 被 Linux 的期望判失败)。
    $cpPlatform = (Get-Content "$cp\caps.json" -Raw | ConvertFrom-Json).backend
    $cArgs = @('scripts/contract_check.py',
      '--caps', "$cp\caps.json",
      '--baseline', 'scripts/contract-baseline.json',
      '--platform', $cpPlatform,
      '--events', $cpe,
      '--audit', $cpa,
      '--exit-code', "$cpRc")
    # 输出继承控制台(不重定向)→ 避开上面那条路径坑;只看退出码
    # 报告落进回写目录:契约检查的输出继承控制台,而 Issue 只带 smoke.log →
    # 失败详情会丢;落盘才能随结果一起被读到。
    New-Item -ItemType Directory -Force -Path "ci/runs" | Out-Null
    $env:CONTRACT_REPORT_OUT = "ci/runs/contract-$cpPlatform.md"
    $pChk = Start-Process -FilePath "python" -NoNewWindow -PassThru -ArgumentList $cArgs
    if (-not $pChk.WaitForExit(30000)) {
      $pChk.Kill()
      Write-Host "::notice::契约检查超时,已终止"
      Assert "契约检查:能力/事件/审计/退出码 三平台同一份契约" $false
    } else {
      Assert "契约检查:能力/事件/审计/退出码 三平台同一份契约" ($pChk.ExitCode -eq 0)
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
