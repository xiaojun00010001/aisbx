#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linux 侧「授权一个尚不存在的文件」:占位文件 + bwrap 单文件 bind。

与 Windows 的占位文件方案**同一套语义**(三平台交互一致):
  - 授权写一个尚不存在的文件时,宿主先预创建空占位文件;
  - bwrap 的 --bind 支持文件 → 显式 bind 该文件(只读根让所有文件默认只读);
  - 沙箱内只需「写」已存在的占位文件,不需要目录可写 → 授权粒度仍精确到单文件;
  - 任务结束回收**仍是空文件**的占位文件(写了内容的必须留下)。
"""
import io

def patch(path, old, new, tag, count=1):
    s = io.open(path, encoding='utf-8').read()
    n = s.count(old)
    assert n == count, '%s: 期望 %d 处,实际 %d → %r' % (path, count, n, old[:60])
    io.open(path, 'w', encoding='utf-8').write(s.replace(old, new))
    print('patched', tag)

# ── 1) core/state.rs:占位文件登记 + ensure_placeholder ────────────────
patch('crates/aisbx/src/core/state.rs',
'''    /// 用户同意后放宽的路径(B 契约:下一次执行的策略快照使用)
    pub granted: Vec<String>,''',
'''    /// 用户同意后放宽的路径(B 契约:下一次执行的策略快照使用)
    pub granted: Vec<String>,
    /// 授权「尚不存在的文件」时由宿主预创建的**空占位文件**。
    ///
    /// ⚠️ 为什么需要它:Linux 的 bwrap 用 `--bind <路径> <路径>` 授权可写路径,
    /// 而 bind 的**源路径必须存在**;沙箱里要创建的目标文件此刻还不存在 →
    /// 绑不上 → 授权形同虚设(实测 T12「授权后重跑成功」就是这么红的:
    /// retry 事件落了、文件却写不进)。macOS 的 Seatbelt 写的是规则、
    /// 不要求路径存在,所以不受影响 —— 这正是三平台行为不一致的一处。
    /// Windows 侧同理(icacls 不能对不存在的文件设 ACE),已在 broker 层
    /// 预创建占位文件;这里让 Unix 侧用**同一套语义**。
    pub placeholders: Vec<String>,''',
'state.rs placeholders 字段')

patch('crates/aisbx/src/core/state.rs',
'''            granted: Vec::new(),
            granted_nets: Vec::new(),''',
'''            granted: Vec::new(),
            placeholders: Vec::new(),
            granted_nets: Vec::new(),''',
'state.rs placeholders 初始化')

patch('crates/aisbx/src/core/state.rs',
'''    /// 新策略必须严格宽于旧策略:仅在既有白名单之外追加授权路径。
    pub fn widen(&mut self, path: &str) {''',
'''    /// 授权一个**尚不存在的文件**时,预创建空占位文件并登记。
    ///
    /// 目录不需要(它本来就存在);已存在的文件也不需要。
    /// 创建失败不阻断授权 —— 最坏情况退回「授权无效」,而不是「授权流程卡住」。
    pub fn ensure_placeholder(&mut self, path: &str) {
        let p = std::path::Path::new(path);
        if p.exists() || p.is_dir() {
            return;
        }
        if let Some(parent) = p.parent() {
            if !parent.is_dir() {
                return;
            }
        }
        if std::fs::File::create(p).is_ok() {
            if !self
                .placeholders
                .iter()
                .any(|x| super::decision::compare_key(x) == super::decision::compare_key(path))
            {
                self.placeholders.push(path.to_string());
            }
        }
    }

    /// 新策略必须严格宽于旧策略:仅在既有白名单之外追加授权路径。
    pub fn widen(&mut self, path: &str) {''',
'state.rs ensure_placeholder')

# ── 2) unix/broker.rs:授权时预创建占位文件 + snapshot 带上 ──────────────
patch('crates/aisbx/src/unix/broker.rs',
'''                s.widen(&t.path);''',
'''                s.widen(&t.path);
                // 授权的文件可能尚不存在 → 预创建占位文件,否则 bwrap 绑不上
                s.ensure_placeholder(&t.path);''',
'unix/broker.rs token 兑换占位文件')

patch('crates/aisbx/src/unix/broker.rs',
'''        s.widen(&path);
        s.audit.log(&json!(
            {
                "event": "escalation.grant", "op": "file", "path": path,''',
'''        s.widen(&path);
        // 同上:授权的文件可能尚不存在
        s.ensure_placeholder(&path);
        s.audit.log(&json!(
            {
                "event": "escalation.grant", "op": "file", "path": path,''',
'unix/broker.rs 策略放行占位文件')

patch('crates/aisbx/src/unix/broker.rs',
'''            granted: s.granted.clone(),''',
'''            granted: s.granted.clone(),
            placeholders: s.placeholders.clone(),''',
'unix/broker.rs snapshot 带 placeholders')

# ── 3) unix/run.rs:RunCtx 带占位文件 + 任务结束回收 ────────────────────
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

# ── 4) linux/bwrap.rs:授权的**单文件**也要 bind ────────────────────────
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
