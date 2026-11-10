#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""行级:在所有 `s.widen(&path);` 之后插入 ensure_placeholder。"""
import io

p = 'crates/aisbx/src/unix/broker.rs'
lines = io.open(p, encoding='utf-8').read().split('\n')
out = []
hits = 0
for ln in lines:
    out.append(ln)
    st = ln.strip()
    if st == 's.widen(&path);':
        indent = ln[:len(ln) - len(ln.lstrip())]
        out.append('%s// 授权的文件可能尚不存在 → 预创建空占位文件,否则 bwrap 绑不上它' % indent)
        out.append('%ss.ensure_placeholder(&path);' % indent)
        hits += 1
io.open(p, 'w', encoding='utf-8').write('\n'.join(out))
print('插入 ensure_placeholder %d 处' % hits)
