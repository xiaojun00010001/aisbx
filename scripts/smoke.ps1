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

Write-Host "== 0. 构建 =="
cargo build --release --bins --example burn 2>&1 | Select-Object -Last 2
$bin  = Join-Path $repo "target\release\aisbx.exe"
$burn = Join-Path $repo "target\release\examples\burn.exe"
if (-not (Test-Path $bin))  { throw "aisbx.exe 未生成" }
if (-not (Test-Path $burn)) { throw "burn.exe 未生成" }

$script:fail = 0
function Assert($name, $cond) {
  if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
  else       { Write-Host "  FAIL  $name" -ForegroundColor Red; $script:fail++ }
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
  Write-Host "== T0 策略 =="
  & $bin policy-check -p $p1
  Assert "T0 策略解析与校验" ($LASTEXITCODE -eq 0)

  # ── T1 文件默认隔离 ──────────────────────────────────────────────
  Write-Host "== T1 文件默认隔离 =="
  & $bin run -p $p1 -- cmd /c "echo x > `"$out\f1.txt`"" 2>$null
  Assert "T1a 白名单外写入被拒(退出码非 0)" ($LASTEXITCODE -ne 0)
  Assert "T1b 白名单外文件未落盘" (-not (Test-Path "$out\f1.txt"))
  & $bin run -p $p1 -- cmd /c "echo x > f1.txt"
  Assert "T1c 白名单内写入成功" (($LASTEXITCODE -eq 0) -and (Test-Path "$ws\f1.txt"))

  # ── T2 token 授权闭环 ────────────────────────────────────────────
  Write-Host "== T2 token 授权闭环 =="
  # deny 模式下无 token 提权必须失败
  & $bin run -p $p1 -- "$ws\aisbx.exe" escalate -p $p1 --path "$out\f2.txt" --access write 2>$null
  Assert "T2a 无 token 提权被拒(deny 模式)" ($LASTEXITCODE -ne 0)

  # 宿主侧签发(用户同意动作的代理点)
  $auth = (& $bin authorize -p $p1 --path $out --access write --ttl-seconds 120) | Out-String | ConvertFrom-Json
  Assert "T2b authorize 签发 token" ($null -ne $auth.token -and $auth.token.Length -ge 32)

  # 沙箱内消费 → ACL 落地 → 真实写入放行
  & $bin run -p $p1 -- "$ws\aisbx.exe" escalate -p $p1 --path "$out\f2.txt" --access write --token $auth.token 2>$null
  Assert "T2c token 消费成功" ($LASTEXITCODE -eq 0)
  & $bin run -p $p1 -- cmd /c "echo x > `"$out\f2.txt`""
  Assert "T2d 授权后真实写入放行" (($LASTEXITCODE -eq 0) -and (Test-Path "$out\f2.txt"))

  # 一次性:同 token 再消费必须失败
  & $bin run -p $p1 -- "$ws\aisbx.exe" escalate -p $p1 --path "$out\f3.txt" --access write --token $auth.token 2>$null
  Assert "T2e token 不可重放" ($LASTEXITCODE -ne 0)

  # 黑名单前置:token 也救不回 deny_escalation
  $auth2 = (& $bin authorize -p $p1 --path "$env:ProgramData\ssh" --access write) | Out-String | ConvertFrom-Json
  & $bin run -p $p1 -- "$ws\aisbx.exe" escalate -p $p1 --path "$env:ProgramData\ssh" --access write --token $auth2.token 2>$null
  Assert "T2f deny_escalation 优先于 token" ($LASTEXITCODE -ne 0)

  # ── T3 资源限制 ──────────────────────────────────────────────────
  Write-Host "== T3 资源限制(单进程 64MB / 全任务 256MB / 进程数 10) =="
  & $bin run -p $p1 -- "$ws\burn.exe" mem 32
  Assert "T3a 配额内分配成功" ($LASTEXITCODE -eq 0)
  & $bin run -p $p1 -- "$ws\burn.exe" mem 512 2>$null
  Assert "T3b 单进程内存超限被发现(退出码非 0)" ($LASTEXITCODE -ne 0)
  & $bin run -p $p1 -- "$ws\burn.exe" fork 40 2>$null
  Assert "T3c fork 超过 active_processes=10 被掐" ($LASTEXITCODE -eq 2)

  # ── T4 网络 ──────────────────────────────────────────────────────
  if (-not $SkipNetwork) {
    Write-Host "== T4 网络(loopback=true / internet=false) =="
    $port = 47000 + (Get-Random -Maximum 2000)
    $job = Start-Job -ScriptBlock {
      param($p)
      $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
      $l.Start(); $c = $l.AcceptTcpClient(); $c.Close(); $l.Stop()
    } -ArgumentList $port
    Start-Sleep -Milliseconds 800
    & $bin run -p $p1 -- "$ws\burn.exe" conn 127.0.0.1 $port
    Assert "T4a 回环放行" ($LASTEXITCODE -eq 0)
    & $bin run -p $p1 -- "$ws\burn.exe" conn 1.1.1.1 53 2>$null
    Assert "T4b 外网无 capability 被内核拒绝" ($LASTEXITCODE -ne 0)
    Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    if (-not $isAdmin) { Warn "非管理员:CheckNetIsolation 回环例外可能写入失败,T4a 结果仅供参考(GitHub Actions runner 为管理员)" }
  }

  # ── T5 审计断言 ──────────────────────────────────────────────────
  Write-Host "== T5 审计 =="
  $events = Get-Content $audit | ForEach-Object { ($_ | ConvertFrom-Json).event }
  Assert "T5a token.issued 已落审计" ($events -contains "token.issued")
  Assert "T5b token.redeemed 已落审计" ($events -contains "token.redeemed")
  Assert "T5c escalation.deny 已落审计" ($events -contains "escalation.deny")
}
finally {
  Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:fail -eq 0) { Write-Host "冒烟验证全部通过" -ForegroundColor Green }
else                    { Write-Host "冒烟验证失败 $script:fail 项" -ForegroundColor Red }
exit $script:fail
