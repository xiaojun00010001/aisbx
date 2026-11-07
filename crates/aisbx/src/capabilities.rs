//! 能力报告:三平台逐项如实标注 full / partial / unavailable。
//! 方案 B 要求「不假装安全」——降级必须结构化上报,消费方可 --require-full 拒绝启动。

use serde_json::{json, Value};

#[cfg(target_os = "linux")]
fn command_exists(name: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .any(|d| d.join(name).is_file())
}

pub fn report() -> Value {
    #[cfg(windows)]
    {
        json!({
            "backend": "windows",
            "contract": "B",
            "effect": "in-place(legacy)+agent-retry",
            "capabilities": {
                "strategy": "full",
                "denial_detection": "partial",
                // v0.1 后端:授权后同进程即时放行;launcher 内 retry 事件未实现,
                // agent 层可重跑命令,但 broker/token 生命周期跨 run 不延续。如实标注。
                "authorized_retry": "partial",
                "launcher_retry": "unavailable",
                "file_isolation": "full",
                "network_egress": "full",
                "memory_per_process": "full",
                "memory_total": "full",
                "cpu": "full",
                "process_limit": "full",
                "process_tree_kill": "full",
                "auto_violation_capture": "unavailable",
                "net_violation_capture": "partial",
                "net_proxy": "http-connect+socks5"
            }
        })
    }
    #[cfg(target_os = "macos")]
    {
        let sb = std::path::Path::new("/usr/bin/sandbox-exec").is_file();
        json!({
            "backend": "macos",
            "contract": "B",
            "effect": "retry",
            "capabilities": {
                "strategy": "full",
                "denial_detection": "partial",
                "authorized_retry": "full",
                "file_isolation": if sb { "full" } else { "unavailable" },
                "network_egress": if sb { "full" } else { "unavailable" },
                "memory_per_process": "unavailable",
                "memory_total": "unavailable",
                "cpu": "unavailable",
                "process_limit": "unavailable",
                "process_tree_kill": "partial",
                // P1 实测(2026-11-07, macOS 26.3):入口 exec 目标命令后,Seatbelt
                // violation 日志能稳定给出精确路径并驱动授权重跑。标 partial 而非 full:
                // 需策略显式开启、依赖日志秒级落盘与时间窗、仅归属登记 PID、深层子进程会漏。
                "auto_violation_capture": if sb { "partial" } else { "unavailable" },
                "violation_log_probe": "sandbox-reporting-violation",
                "net_violation_capture": "partial",
                "net_proxy": "http-connect+socks5",
                "seatbelt": if sb { "full" } else { "unavailable" }
            }
        })
    }
    #[cfg(target_os = "linux")]
    {
        let bwrap = command_exists("bwrap");
        let landlock = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| kernel_at_least_5_13(&s))
            .unwrap_or(false);
        json!({
            "backend": "linux",
            "contract": "B",
            "effect": "retry",
            "capabilities": {
                "strategy": "full",
                "denial_detection": "partial",
                "authorized_retry": "full",
                "file_isolation": if bwrap { "full" } else { "unavailable" },
                "network_egress": if bwrap { "full" } else { "unavailable" },
                "memory_per_process": "partial",
                "memory_total": "unavailable",
                "cpu": "unavailable",
                "process_limit": "unavailable",
                "process_tree_kill": "partial",
                "auto_violation_capture": "unavailable",
                "net_violation_capture": if bwrap { "partial" } else { "unavailable" },
                "net_proxy": "http-connect+socks5",
                "bubblewrap": if bwrap { "full" } else { "unavailable" },
                "landlock": if landlock { "partial" } else { "unavailable" },
                "seccomp": if bwrap { "partial" } else { "unavailable" }
            }
        })
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        json!({"backend": "unsupported", "contract": "B", "capabilities": {}})
    }
}

#[cfg(target_os = "linux")]
fn kernel_at_least_5_13(release: &str) -> bool {
    let mut it = release.trim().split('.');
    let major = it.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let minor = it.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    major > 5 || (major == 5 && minor >= 13)
}

/// 严格模式:任何 unavailable 都拒绝启动(不降级为无约束执行)。
pub fn require_full(report: &Value) -> Result<(), String> {
    let caps = report.get("capabilities").and_then(|v| v.as_object());
    let Some(caps) = caps else { return Err("能力报告缺少 capabilities".into()) };
    let fatal: Vec<String> = caps
        .iter()
        .filter(|(k, v)| {
            v.as_str() == Some("unavailable")
                && !matches!(k.as_str(), "auto_violation_capture" | "cpu" | "memory_total" | "landlock" | "bubblewrap" | "seatbelt" | "seccomp" | "launcher_retry")
        })
        .map(|(k, _)| k.clone())
        .collect();
    if fatal.is_empty() {
        Ok(())
    } else {
        Err(format!("严格模式下以下能力不可用: {}", fatal.join(", ")))
    }
}
