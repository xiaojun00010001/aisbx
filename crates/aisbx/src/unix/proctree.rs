//! 进程组快照:把「内核违规日志里的 PID」归属到本次沙箱执行。
//!
//! 实测(2026-11-08, macOS 26.3):入口进程 PID=64904,而 Seatbelt violation
//! 日志里的 PID=64905——正好是入口 fork 出来的那个子 shell。原因是:
//! 内核上报的是【真正执行了违规操作的那个进程】的 PID,而 fork 会继承进程组。
//! 所以只按「入口 PID + 登记 PID」归属,必然漏掉所有 fork 出来的子孙进程
//! (shell 脚本、make、node 子进程、测试框架…都在内)。
//!
//! 做法:进程**存活期间**按 pgid 累积成员快照。因为:
//! - fork 继承 pgid → 覆盖整棵进程树,比逐个登记 PID 完整;
//! - 进程退出后再查 ps 就查不到它了 → 必须在还活着的时候采样。
//!
//! macOS 用 `ps -axo pid=,pgid=`;Linux 用 /proc/<pid>/stat 的 pgrp 字段(更便宜)。
//! 仅在策略显式开启 `broker.violation_capture` 时采样,默认路径零开销。

use std::collections::BTreeSet;

/// 取进程组 `pgid` 的全部存活成员 PID。失败时返回空(不静默当成「没有越界」)。
#[cfg(target_os = "macos")]
pub fn snapshot_pgid(pgid: u32) -> Vec<u32> {
    let out = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,pgid="])
        .output();
    let Ok(out) = out else { return Vec::new() };
    parse_ps(&String::from_utf8_lossy(&out.stdout), pgid)
}

/// Linux:/proc/<pid>/stat 第 5 个字段是 pgrp。比 fork 一次 ps 便宜得多。
#[cfg(target_os = "linux")]
pub fn snapshot_pgid(pgid: u32) -> Vec<u32> {
    let mut found = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if stat_pgrp(&stat) == Some(pgid) {
            found.push(pid);
        }
    }
    found
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn snapshot_pgid(_pgid: u32) -> Vec<u32> {
    Vec::new()
}

/// `ps -axo pid=,pgid=` 的输出形如 "  64904  64904"。
#[cfg(target_os = "macos")]
fn parse_ps(text: &str, pgid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(pid), Some(g)) = (it.next(), it.next()) else {
            continue;
        };
        let (Ok(pid), Ok(g)) = (pid.parse::<u32>(), g.parse::<u32>()) else {
            continue;
        };
        if g == pgid {
            out.push(pid);
        }
    }
    out
}

/// /proc/<pid>/stat:第 4 个字段是 comm(可能含空格与括号),故从最后一个 ')' 之后切分。
#[cfg(target_os = "linux")]
fn stat_pgrp(stat: &str) -> Option<u32> {
    let tail = stat.rsplit_once(')')?.1;
    let mut it = tail.split_whitespace();
    // 切分后依次为 state ppid pgrp ...
    let _state = it.next()?;
    let _ppid = it.next()?;
    it.next()?.parse::<u32>().ok()
}

/// 合并多个 PID 来源并去重排序。
/// ⚠️ 只有 macOS 的内核日志通道(L2)需要合并进程树 → 在只有 L1 的平台
/// (Linux)上无人调用。显式豁免,而不是删掉:它是 L2 归属判据的一部分。
#[allow(dead_code)]
pub fn merge_pids(groups: &[&[u32]]) -> Vec<u32> {
    let set: BTreeSet<u32> = groups.iter().flat_map(|g| g.iter().copied()).collect();
    set.into_iter().collect()
}

/// 当前的 (pid → pgid) 全表。用于把内核日志里的 PID 反查成进程组。
///
/// 这是**归属深层层级**的关键:内核日志只给 PID,而 kqueue 的 fork 事件
/// 只在父子间投递(实测违规进程比入口深 3 层,NOTE_FORK 只覆盖 1 层,
/// 递归注册也永远慢一步)。但 fork 会继承 pgid,所以只要违规进程**还活着**,
/// 就能用 pgid 精确判定它属于本次沙箱——与层级深度无关。
#[cfg(target_os = "macos")]
/// ⚠️ 同上:pid→pgid 反查是 L2 的兜底归属判据,只在 macOS 上被调用。
#[allow(dead_code)]
pub fn pgid_table() -> std::collections::HashMap<u32, u32> {
    let out = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,pgid="])
        .output();
    let Ok(out) = out else {
        return std::collections::HashMap::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(pid), Some(g)) = (it.next(), it.next()) else {
            continue;
        };
        if let (Ok(pid), Ok(g)) = (pid.parse::<u32>(), g.parse::<u32>()) {
            map.insert(pid, g);
        }
    }
    map
}

#[cfg(not(target_os = "macos"))]
/// 非 macOS 平台的桩实现:pid→pgid 反查是 **macOS 内核通道(L2)** 的兜底
/// 归属判据,只有 L1 的平台上没有调用者 → 显式豁免 dead_code。
#[allow(dead_code)]
pub fn pgid_table() -> std::collections::HashMap<u32, u32> {
    std::collections::HashMap::new()
}

/// 事件驱动的 fork 观察器(macOS kqueue `NOTE_FORK`)。
///
/// 为什么不用「定时跑 ps 采快照」:实测整条沙箱命令只跑 12ms,而子 shell
/// fork 出来、被拒、立刻退出——200ms 的采样间隔根本来不及看到它,
/// 快照式归属必然漏掉所有短命子进程(冒烟 T7f 就是这么红的)。
/// kqueue 的 fork 事件由内核投递,**即使进程已经退出事件仍在队列里**,
/// 因此不漏,也没有轮询开销。
///
/// 只覆盖「入口进程的直接子进程」这一层(内核只在父子间投递 fork 事件);
/// 更深层需要动态对子进程再注册,当前不追求。
#[cfg(target_os = "macos")]
pub struct ForkWatcher {
    kq: i32,
}

#[cfg(target_os = "macos")]
impl ForkWatcher {
    /// 监听 `pid` 的 fork/exit 事件。失败返回 None(调用方降级到采样式快照)。
    pub fn new(pid: u32) -> Option<Self> {
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return None;
        }
        // macOS 上 libc 把该结构体命名为 `kevent`(与 kevent() 函数同名,不同命名空间)。
        let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
        ev.filter = libc::EVFILT_PROC;
        ev.flags = libc::EV_ADD | libc::EV_ENABLE;
        ev.fflags = libc::NOTE_FORK | libc::NOTE_EXIT;
        ev.data = pid as isize;
        let rc = unsafe { libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if rc < 0 {
            unsafe { libc::close(kq) };
            return None;
        }
        Some(Self { kq })
    }

    /// 等待事件。返回 (新 fork 出来的子进程 PID, 被监控进程是否已退出)。
    /// `timeout_ms < 0` 表示无限等待。
    pub fn wait(&self, timeout_ms: i32) -> (Vec<u32>, bool) {
        let mut evs: [libc::kevent; 32] = unsafe { std::mem::zeroed() };
        let ts = if timeout_ms < 0 {
            std::ptr::null()
        } else {
            &libc::timespec {
                tv_sec: (timeout_ms / 1000) as libc::time_t,
                tv_nsec: ((timeout_ms % 1000) * 1_000_000) as libc::c_long,
            } as *const libc::timespec
        };
        let n = unsafe {
            libc::kevent(
                self.kq,
                std::ptr::null_mut(),
                0,
                evs.as_mut_ptr(),
                evs.len() as libc::c_int,
                ts,
            )
        };
        let mut forks = Vec::new();
        let mut exited = false;
        for ev in evs.iter().take(n.max(0) as usize) {
            if ev.fflags & libc::NOTE_FORK != 0 {
                forks.push(ev.data as u32);
            }
            if ev.fflags & libc::NOTE_EXIT != 0 {
                exited = true;
            }
        }
        (forks, exited)
    }
}

#[cfg(target_os = "macos")]
impl Drop for ForkWatcher {
    fn drop(&mut self) {
        unsafe { libc::close(self.kq) };
    }
}

#[cfg(not(target_os = "macos"))]
pub struct ForkWatcher;

#[cfg(not(target_os = "macos"))]
impl ForkWatcher {
    pub fn new(_pid: u32) -> Option<Self> {
        None
    }
    pub fn wait(&self, _timeout_ms: i32) -> (Vec<u32>, bool) {
        (Vec::new(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_ps_output() {
        let text = "  64904  64904\n  64905  64904\n  100   100\n  7 7\n";
        assert_eq!(parse_ps(text, 64904), vec![64904, 64905]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_stat_pgrp() {
        // comm 里带空格和括号的情形也必须正确切分
        let stat = "64904 (a b) S 64903 64904 64904 0 -1 4194304";
        assert_eq!(stat_pgrp(stat), Some(64904));
    }

    #[test]
    fn merges_and_dedups() {
        assert_eq!(merge_pids(&[&[3, 1, 2], &[2, 9]]), vec![1, 2, 3, 9]);
    }
}
