#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""修 workflow:补回被甩到末尾的 run 行;并加 step 结构校验与单测日志留存。"""
import io, sys, yaml

# ── 1) cross-platform.yml:修 Capability report 缺 run ───────────────────
p = '.github/workflows/cross-platform.yml'
s = io.open(p, encoding='utf-8').read()

bad = '''      - name: Capability report

      - name: Publish run result to repo'''
good = '''      - name: Capability report
        run: cargo run --quiet --bin aisbx -- capabilities

      - name: Publish run result to repo'''
assert bad in s, '未找到缺 run 的 Capability report'
s = s.replace(bad, good, 1)

# 末尾那行落单的 run 去掉
stray = '''          git push || echo "::notice::结果回写失败(分支可能受保护),请看 run 日志"
        run: cargo run --quiet --bin aisbx -- capabilities
'''
assert stray in s, '未找到落单的 run 行'
s = s.replace(stray, '''          git push || echo "::notice::结果回写失败(分支可能受保护),请看 run 日志"
''', 1)

# 2) 单测输出也落盘,并纳入回写内容(Windows 首次跑 cargo test 就红了,需要能看到原因)
old = '''      - name: Unit tests (all crates)
        run: cargo test --workspace'''
new = '''      - name: Unit tests (all crates)
        run: |
          set -o pipefail
          cargo test --workspace 2>&1 | tee test.log'''
assert old in s
s = s.replace(old, new, 1)

old = '''            cat smoke.log clippy.log 2>/dev/null | tail -n 400 || true'''
new = '''            cat smoke.log clippy.log test.log 2>/dev/null | tail -n 400 || true'''
assert old in s
s = s.replace(old, new, 1)

old = '''            cat clippy.log 2>/dev/null | tail -n 200 || true'''
new = '''            cat clippy.log test.log 2>/dev/null | tail -n 200 || true'''
assert old in s
s = s.replace(old, new, 1)

io.open(p, 'w', encoding='utf-8').write(s)
print('cross-platform.yml 已修')

# ── 3) windows-smoke.yml:单测日志也留存 + 回写容错 ─────────────────────
p = '.github/workflows/windows-smoke.yml'
s = io.open(p, encoding='utf-8').read()
old = '''      - name: Unit tests (all crates)
        run: cargo test --workspace'''
new = '''      - name: Unit tests (all crates)
        shell: pwsh
        run: |
          cargo test --workspace 2>&1 | Tee-Object -FilePath test.log
          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }'''
assert old in s
s = s.replace(old, new, 1)

old = '''          foreach ($f in @("smoke.log")) {'''
new = '''          foreach ($f in @("smoke.log", "test.log")) {'''
assert old in s
s = s.replace(old, new, 1)

old = '''          git add ci
          git commit -q -m "ci: record run $env:GITHUB_RUN_ID windows [skip ci]"
          git push
          if ($LASTEXITCODE -ne 0) { Write-Host "::notice::结果回写失败(分支可能受保护),请看 run 日志" }'''
new = '''          git add ci
          git commit -q -m "ci: record run $env:GITHUB_RUN_ID windows [skip ci]"
          if ($LASTEXITCODE -ne 0) { Write-Host "::notice::commit 失败,回写跳过"; exit 0 }
          git push
          if ($LASTEXITCODE -ne 0) { Write-Host "::notice::结果回写失败(分支可能受保护),请看 run 日志" }'''
assert old in s
s = s.replace(old, new, 1)
io.open(p, 'w', encoding='utf-8').write(s)
print('windows-smoke.yml 已修')

# ── 4) 结构校验:每个 step 必须有 run 或 uses;每个 job 必须有 steps ──────
bad = 0
for f in ['.github/workflows/cross-platform.yml', '.github/workflows/windows-smoke.yml']:
    d = yaml.safe_load(io.open(f, encoding='utf-8'))
    for jn, jv in d['jobs'].items():
        for st in jv.get('steps', []):
            if 'run' not in st and 'uses' not in st:
                print('  !! %s / %s: step「%s」既无 run 也无 uses' % (f, jn, st.get('name')))
                bad += 1
    print('  %s 结构校验: %s' % (f, 'OK' if bad == 0 else 'FAIL'))
print('step 结构校验:', '全部通过' if bad == 0 else ('%d 处问题' % bad))
sys.exit(1 if bad else 0)
