#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回写改走独立分支 ci-results + 全程非交互(避免 git 在冲突时进入交互等待)。"""
import io

def patch(path, old, new, tag):
    s = io.open(path, encoding='utf-8').read()
    if old not in s:
        print('!! 未匹配:', tag); raise SystemExit(1)
    io.open(path, 'w', encoding='utf-8').write(s.replace(old, new, 1))
    print('patched', tag)

# ── 1) 通用非交互 git 前置 + 回写目标分支 ───────────────────────────────
NONINTERACTIVE = '''          # ⚠️ 全程非交互:git 一旦进入交互等待(冲突时问「怎么解决」),
          # 在 CI 里就是**永久卡死** —— 实测 Windows 冒烟 60 分钟 timeout
          # 都跑不完,卡的就是这一步(rebase 冲突 → 等输入)。
          export GIT_EDITOR=true
          export GIT_TERMINAL_PROMPT=0
          git config --global core.editor true || true
'''

# cross-platform.yml
patch('.github/workflows/cross-platform.yml',
'''          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add ci
          git commit -q -m "ci: record run ${{ github.run_id }} ${{ matrix.os }} [skip ci]" || exit 0
          # actions/checkout 可能是 detached HEAD → 先确保在 main 分支上,
          # 否则 push 推不动(实测后完成的 job 回写全部丢失)。
          git checkout main || git switch main || true
          # 三个 job 并发回写会互相冲突 → 先 rebase 再推
          git pull --rebase origin main || true
          git push origin HEAD:main || echo "::notice::结果回写失败(分支可能受保护),请看 run 日志与 Issue"''',
NONINTERACTIVE + '''          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add ci
          git commit -q -m "ci: record run ${{ github.run_id }} ${{ matrix.os }} [skip ci]" || exit 0
          # 回写走**独立分支** ci-results:不污染 main 的历史,也避免多个 job
          # 抢同一个分支导致冲突。读取:git fetch origin ci-results
          git checkout -B ci-results || git switch ci-results || git checkout main || true
          git pull --rebase origin ci-results || { git rebase --abort || true; }
          git push origin HEAD:ci-results || echo "::notice::结果回写失败,请看 run 日志与 Issue"''',
'cross-platform 回写→ci-results')

# windows-smoke.yml
patch('.github/workflows/windows-smoke.yml',
'''          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add ci
          git commit -q -m "ci: record run $env:GITHUB_RUN_ID windows [skip ci]"
          if ($LASTEXITCODE -ne 0) { Write-Host "::notice::commit 失败,回写跳过"; exit 0 }
          # actions/checkout 可能是 detached HEAD → 先确保在 main 分支上
          git checkout main 2>&1 | Out-Null
          if ($LASTEXITCODE -ne 0) { git switch main 2>&1 | Out-Null }
          # 多个 job 并发回写会互相冲突 → 先 rebase 再推
          git pull --rebase origin main
          if ($LASTEXITCODE -ne 0) { Write-Host "::notice::rebase 失败,回写跳过"; exit 0 }
          git push origin HEAD:main
          if ($LASTEXITCODE -ne 0) { Write-Host "::notice::结果回写失败(分支可能受保护),请看 run 日志与 Issue" }''',
'''          # ⚠️ 全程非交互:git 一旦进入交互等待(冲突时问「怎么解决」),
          # 在 CI 里就是**永久卡死** —— 实测 Windows 冒烟 60 分钟 timeout
          # 都跑不完,卡的就是这一步。
          $env:GIT_EDITOR = "true"
          $env:GIT_TERMINAL_PROMPT = "0"
          git config --global core.editor true 2>&1 | Out-Null
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add ci
          git commit -q -m "ci: record run $env:GITHUB_RUN_ID windows [skip ci]"
          if ($LASTEXITCODE -ne 0) { Write-Host "::notice::commit 失败,回写跳过"; exit 0 }
          # 回写走**独立分支** ci-results:不污染 main 的历史,也避免多个 job
          # 抢同一个分支导致冲突。读取:git fetch origin ci-results
          git checkout -B ci-results 2>&1 | Out-Null
          if ($LASTEXITCODE -ne 0) { git switch ci-results 2>&1 | Out-Null }
          git pull --rebase origin ci-results 2>&1 | Out-Null
          if ($LASTEXITCODE -ne 0) { git rebase --abort 2>&1 | Out-Null }
          git push origin HEAD:ci-results
          if ($LASTEXITCODE -ne 0) { Write-Host "::notice::结果回写失败,请看 run 日志与 Issue" }''',
'windows-smoke 回写→ci-results')

# ── 2) smoke.ps1 的 Push-Progress 同样非交互 + 独立分支 ─────────────────
patch('scripts/smoke.ps1',
'''    git config user.name "github-actions[bot]"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
    git add ci/runs/windows-progress.md
    git commit -q -m "ci: windows smoke progress $stage [skip ci]"
    if ($LASTEXITCODE -ne 0) { return }
    git checkout main 2>&1 | Out-Null
    git pull --rebase origin main 2>&1 | Out-Null
    git push origin HEAD:main 2>&1 | Out-Null''',
'''    # ⚠️ 全程非交互:git 冲突时进入交互等待 = CI 里永久卡死。
    $env:GIT_EDITOR = "true"
    $env:GIT_TERMINAL_PROMPT = "0"
    git config --global core.editor true 2>&1 | Out-Null
    git config user.name "github-actions[bot]"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
    git add ci/runs/windows-progress.md
    git commit -q -m "ci: windows smoke progress $stage [skip ci]"
    if ($LASTEXITCODE -ne 0) { return }
    # 进度也走独立分支 ci-results(与最终结果同一处,读取更方便)
    git checkout -B ci-results 2>&1 | Out-Null
    git pull --rebase origin ci-results 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { git rebase --abort 2>&1 | Out-Null }
    git push origin HEAD:ci-results 2>&1 | Out-Null''',
'smoke.ps1 Push-Progress 非交互')

# ── 3) 契约检查段也加进度标记(它是最后一步,之前卡住时看不出来)─────────
patch('scripts/smoke.ps1',
'''    Write-Host "[$(Get-Date -Format HH:mm:ss)] == 跨平台契约检查 =="''',
'''    Push-Progress "contract"
    Write-Host "[$(Get-Date -Format HH:mm:ss)] == 跨平台契约检查 =="''',
'smoke.ps1 契约检查进度标记')
print('ALL PATCHED')
