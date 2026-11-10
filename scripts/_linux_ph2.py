#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""续:补齐两处 ensure_placeholder + snapshot/RunCtx/回收/bwrap bind。"""
import io

def patch(path, old, new, tag, count=1):
    s = io.open(path, encoding='utf-8').read()
    n = s.count(old)
    assert n == count, '%s: 期望 %d 处,实际 %d → %r' % (path, count, n, old[:60])
    io.open(path, 'w', encoding='utf-8').write(s.replace(old, new))
    print('patched', tag)

# ── unix/broker.rs:两处 widen 后补占位文件 ─────────────────────────────
patch('crates/aisbx/src/unix/broker.rs',
'''        s.widen(&path);
        s.audit.log(&json!(
            "event": "escalation.grant",''',
'''        s.widen(&path);
        // 同上:授权的文件可能尚不存在
        s.ensure_placeholder(&path);
        s.audit.log(&json!(
            "event": "escalation.grant",''',
'unix/broker.rs 策略放行占位文件')

patch('crates/aisbx/src/unix/broker.rs',
'''            s.widen(&path);
            s.audit.log(&json!(
                "event": "token.issued",''',
'''            s.widen(&path);
            // ⚠️ 这处最关键:Unix 的 authorize 就是「签 token + widen」,
            // launcher 靠 granted 变化触发重跑 → 目标文件必须此刻就存在,
            // 否则重跑时 bwrap 绑不上它(实测 T12「授权后重跑成功」就是这么红的)。
            s.ensure_placeholder(&path);
            s.audit.log(&json!(
                "event": "token.issued",''',
'unix/broker.rs authorize 占位文件')

patch('crates/aisbx/src/unix/broker.rs',
'''            granted: s.granted.clone(),''',
'''            granted: s.granted.clone(),
            placeholders: s.placeholders.clone(),''',
'unix/broker.rs snapshot 带 placeholders')

# ── unix/run.rs ─────────────────────────────────────────────────────────
patch('crates/aisbx/src/unix/run.rs',
'''pub struct RunCtx {
    pub attempt: u32,
    pub granted: Vec<String>,''',
'''pub struct RunCtx {
    pub attempt: u32,
    pub granted: Vec<String>,
    /// 宿主预创建的占位文件(授权「尚不存在的文件」时才有)。
    pub placeholders: Vec<String>,''',
'unix/run.rs RunCtx placeholders')

patch('crates/aisbx/src/unix/run.rs',
'''            attempt,
            granted: snap.granted.clone(),''',
'''            attempt,
            granted: snap.granted.clone(),
            placeholders: snap.placeholders.clone(),''',
'unix/run.rs ctx 带 placeholders')

patch('crates/aisbx/src/unix/run.rs',
'''    let mut code: i32;
    let mut attempt = 1u32;
    let mut prev_granted: usize;''',
'''    let mut code: i32;
    let mut attempt = 1u32;
    let mut prev_granted: usize;
    // 累计所有 attempt 的占位文件(任务结束时统一回收)
    let mut placeholders: Vec<String> = Vec::new();''',
'unix/run.rs placeholders 累加')

patch('crates/aisbx/src/unix/run.rs',
'''        let snap = broker.snapshot();
        prev_granted = snap.granted.len();''',
'''        let snap = broker.snapshot();
        prev_granted = snap.granted.len();
        for ph in &snap.placeholders {
            if !placeholders.iter().any(|x| x == ph) {
                placeholders.push(ph.clone());
            }
        }''',
'unix/run.rs 收集占位文件')

patch('crates/aisbx/src/unix/run.rs',
'''    flush();
    Ok(code)
}''',
'''    flush();

    // 回收占位文件:**只回收仍是空文件**的 —— 沙箱已写入内容的,
    // 那是用户要的结果,必须留下(与 Windows 侧同一语义)。
    for ph in &placeholders {
        let empty = std::fs::metadata(ph).map(|m| m.len() == 0).unwrap_or(false);
        if empty {
            let _ = std::fs::remove_file(ph);
        }
    }

    Ok(code)
}''',
'unix/run.rs 回收占位文件')

# ── linux/bwrap.rs:授权的**单文件**也要 bind ───────────────────────────
patch('crates/aisbx/src/linux/bwrap.rs',
'''    for p in &rw {
        if Path::new(p).is_dir() {
            v.push("--bind".into());
            v.push(p.clone());
            v.push(p.clone());
        }
    }''',
'''    for p in &rw {
        // 目录:策略白名单里的可写目录照旧 bind。
        // **授权的单文件**也必须 bind:bwrap 的 --bind 支持文件,而只读根
        // (--ro-bind / /)让所有文件默认只读 —— 不显式 bind 就写不了。
        // 授权的目标文件已由宿主预创建占位文件(见 state::ensure_placeholder),
        // 所以这里它一定存在。
        let is_granted_file = !Path::new(p).is_dir()
            && ctx.granted.iter().any(|g| canon(g) == *p);
        if Path::new(p).is_dir() || is_granted_file {
            v.push("--bind".into());
            v.push(p.clone());
            v.push(p.clone());
        }
    }''',
'bwrap.rs bind 单文件')
print('ALL PATCHED')
