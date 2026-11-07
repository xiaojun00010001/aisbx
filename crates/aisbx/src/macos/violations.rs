//! P1 · macOS 内核违规日志自动采集(程序零配合)。
//!
//! 本机实测(2026-11-06, macOS 26.3):Seatbelt 每次拒绝都会由内核写出
//!   [com.apple.sandbox.reporting:violation]
//!   Sandbox: bash(24720) deny(1) file-write-create /Users/.../blocked.txt
//! 含进程 PID、被拒操作和**完整精确路径**,且带结构化 subsystem/category。
//! 这里按沙箱主进程 PID 精确归属,解析固定格式得到 path/access,
//! 不解析命令行、不读 stderr、不需要被跑的程序主动上报。
//!
//! 实测(2026-11-07, macOS 26.3):
//! - 内核对「由 sandbox-exec 直接 exec 的进程」会上报精确路径;
//! - 早期 `__unix_entry` 再 spawn 一层目标命令时内核不上报(孙进程归属不到),
//!   改为入口 `exec()` 目标命令、relay 拆成独立进程后,审计里能稳定拿到
//!   `/private/tmp/.../x.txt` 这样的精确路径,并驱动 B 契约授权后重跑成功;
//! - `(with report)` 修饰符不适用于 deny 动作(sandbox-exec 明确报错),不能靠它增强;
//! - 进程加载期顺带产生的 `/dev/dtracehelper`、`/dev/tty` 等系统设备拒绝已过滤。
//!
//! 覆盖边界(能力报告如实标 partial):需策略显式开启 `broker.violation_capture`;
//! 依赖统一日志秒级落盘与 `--last 1m` 时间窗;仅归属沙箱入口/登记 PID;
//! 更深层的 fork 子进程仍可能漏。采集为空时 launcher 产出
//! `violation.capture.miss`,不静默当作无越界。
//!
//! 下一步(P2/P3):macOS 用 Endpoint Security `ES_EVENT_TYPE_AUTH_OPEN`(需 entitlement
//! + 公证 + 系统扩展批准),Linux 用 fanotify `FAN_OPEN_PERM`,Windows 用 minifilter
//! `IRP_MJ_CREATE` 前置回调——三者都能同步裁决并直接给出精确路径,见 docs/06。

use std::process::Command;
use std::time::Duration;

pub struct Captured {
    pub path: String,
    pub access: String,
    pub pid: u32,
}

/// 查询最近窗口内的 Seatbelt 违规日志,按沙箱进程树 PID 精确归属。
/// 统一日志落盘有秒级延迟,实测在子进程刚退出时查询会漏,故重试 3 次。
pub fn collect(pids: &[u32]) -> Vec<Captured> {
    for attempt in 0..3 {
        let found = query(pids);
        if !found.is_empty() {
            return found;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(800));
        }
    }
    Vec::new()
}

fn query(pids: &[u32]) -> Vec<Captured> {
    let out = Command::new("/usr/bin/log")
        .args([
            "show",
            "--last",
            "1m",
            "--info",
            "--debug",
            "--style",
            "compact",
            "--predicate",
            "subsystem == \"com.apple.sandbox.reporting\" AND eventMessage CONTAINS \"deny\"",
        ])
        .output();
    let Ok(out) = out else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found = Vec::new();
    for line in text.lines() {
        if let Some(c) = parse_line(line, pids) {
            if !found.iter().any(|x: &Captured| x.path == c.path) {
                found.push(c);
            }
        }
    }
    found
}

fn parse_line(line: &str, pids: &[u32]) -> Option<Captured> {
    let pos = line.find("Sandbox: ")?;
    let s = &line[pos + "Sandbox: ".len()..];
    // s = "bash(24720) deny(1) file-write-create /path with spaces"
    let lp = s.find('(')?;
    let rp_rel = s[lp + 1..].find(')')?;
    let pid_str = &s[lp + 1..lp + 1 + rp_rel];
    let Ok(line_pid) = pid_str.parse::<u32>() else {
        return None;
    };
    if !pids.contains(&line_pid) {
        return None;
    }
    let rest = s[lp + 1 + rp_rel + 1..].trim_start();
    // rest = "deny(1) file-write-create /path with spaces"
    let mut it = rest.splitn(3, ' ');
    let _deny = it.next()?;
    let op = it.next()?;
    let path = it.next()?.trim();
    if path.is_empty() {
        return None;
    }
    let access = if op.starts_with("file-write") {
        "write"
    } else if op.starts_with("file-read") || op.starts_with("file-map") {
        "read"
    } else {
        return None; // mach-lookup / user-preference-read / iokit-* 等非文件越界
    };
    // 进程加载期会顺带触发 /dev/dtracehelper、/dev/tty 等系统设备拒绝,
    // 这些不是业务越界,不能变成给用户看的授权请求。
    if is_system_noise(path) {
        return None;
    }
    Some(Captured {
        path: path.to_string(),
        access: access.to_string(),
        pid: line_pid,
    })
}

fn is_system_noise(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/dev/", "/System/", "/usr/", "/Library/", "/Applications/",
        "/private/var/db/", "/private/var/root/", "/cores/", "/.vol/",
    ];
    PREFIXES.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_kernel_line() {
        let line = "2026-11-06 13:32:32.285 E  kernel[0:26c8ba] [com.apple.sandbox.reporting:violation] \
                    Sandbox: bash(24720) deny(1) file-write-create /Users/xj/ws/blocked.txt";
        let c = parse_line(line, &[12345, 24720]).unwrap();
        assert_eq!(c.path, "/Users/xj/ws/blocked.txt");
        assert_eq!(c.access, "write");
        assert!(parse_line(line, &[999]).is_none());
    }

    #[test]
    fn path_with_spaces_and_read_op() {
        let line = "Sandbox: sh(42) deny(1) file-read-data /tmp/a b/c.txt";
        let c = parse_line(line, &[42]).unwrap();
        assert_eq!(c.path, "/tmp/a b/c.txt");
        assert_eq!(c.access, "read");
    }

    #[test]
    fn ignores_non_file_operations() {
        assert!(parse_line("Sandbox: x(7) deny(1) mach-lookup com.apple.tccd", &[7]).is_none());
    }

    #[test]
    fn filters_system_device_noise_but_keeps_business_paths() {
        assert!(parse_line("Sandbox: x(7) deny(1) file-write-data /dev/dtracehelper", &[7]).is_none());
        assert!(parse_line("Sandbox: x(7) deny(1) file-write-data /dev/tty", &[7]).is_none());
        assert!(parse_line(
            "Sandbox: x(7) deny(1) file-write-create /private/tmp/ws/out/a.txt",
            &[7]
        )
        .is_some());
    }
}
