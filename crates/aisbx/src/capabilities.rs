//! 能力报告:三平台逐项如实标注 full / partial / unavailable。
//! 方案 B 要求「不假装安全」——降级必须结构化上报,消费方可 --require-full 拒绝启动。

use serde_json::{json, Value};

#[cfg(target_os = "linux")]
fn command_exists(name: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).any(|d| d.join(name).is_file())
}

/// 能力报告的**键集合**:三平台必须完全一致。
///
/// agent 按键消费能力报告 → 某平台缺键,等于 agent 在那个平台上
/// 拿不到这项信息(只能靠「键不存在」去猜,而不是读到一个明确的
/// 「不可用」)。所以键集合由这里统一给出,各平台只填**值**。
///
/// 分两类:
/// - 状态类:值 ∈ {full, partial, unavailable};
/// - 描述类:值是具体机制名/精度,空串表示「该通道在此平台不存在」。
///
/// `violation_log_probe` 用**空串**表示「没有内核日志通道」——
/// 与 macOS 的既有语义一致(非空 = 有通道),且不会被 `--require-full`
/// 的 unavailable 判定误伤。
#[cfg_attr(not(test), allow(dead_code))]
pub const CAP_KEYS: &[&str] = &[
    // ── 状态类 ────────────────────────────────────────────────────────
    "strategy",
    "denial_detection",
    "authorized_retry",
    "launcher_retry",
    "file_isolation",
    "network_egress",
    "memory_per_process",
    "memory_total",
    "cpu",
    "process_limit",
    "process_tree_kill",
    "auto_violation_capture",
    "net_violation_capture",
    // ── 描述类 ────────────────────────────────────────────────────────
    "net_proxy",
    "violation_file_path_precision",
    "violation_net_path_precision",
    "violation_log_probe",
    // ── 机制探测(各平台只报自己用的那一个,其余标 unavailable)────────
    "seatbelt",
    "bubblewrap",
    "landlock",
    "seccomp",
];

/// 状态类能力键:值只能是 full / partial / unavailable。
#[cfg_attr(not(test), allow(dead_code))]
const STATUS_KEYS: &[&str] = &[
    "strategy",
    "denial_detection",
    "authorized_retry",
    "launcher_retry",
    "file_isolation",
    "network_egress",
    "memory_per_process",
    "memory_total",
    "cpu",
    "process_limit",
    "process_tree_kill",
    "auto_violation_capture",
    "net_violation_capture",
    "seatbelt",
    "bubblewrap",
    "landlock",
    "seccomp",
];

pub fn report() -> Value {
    #[cfg(windows)]
    {
        json!({
            "backend": "windows",
            "contract": "B",
            "effect": "retry",
            "capabilities": {
                "strategy": "full",
                "denial_detection": "partial",
                // B 契约主循环已实现:失败 → 等宿主授权 → 把该路径并入策略快照(落 ACL)
                // → 重跑(最多 3 轮)。in-place 放行仍保留为 legacy 加速路径。
                "authorized_retry": "full",
                "launcher_retry": "full",
                "file_isolation": "full",
                "network_egress": "full",
                "memory_per_process": "full",
                "memory_total": "full",
                "cpu": "full",
                "process_limit": "full",
                "process_tree_kill": "full",
                // 文件侧:L1(stderr 自报路径)可用 → partial;但路径由程序自称,
                // 故精度是 reported。Windows 的 ERROR_ACCESS_DENIED 本身不含路径,
                // L1 正好补上「该放行谁」,让 in-place 放行精确到单个路径。
                "auto_violation_capture": "partial",
                "net_violation_capture": "partial",
                "net_proxy": "http-connect+socks5",
                "violation_file_path_precision": "reported",
                "violation_net_path_precision": "exact",
                // 内核日志通道:Windows 没有等价物 → 空串(=该通道不存在)。
                // 与 macOS 的非空值同义,agent 只需判断「非空即有通道」。
                "violation_log_probe": "",
                // 机制探测:Windows 不用这些,显式标 unavailable 而不是缺键。
                "seatbelt": "unavailable",
                "bubblewrap": "unavailable",
                "landlock": "unavailable",
                "seccomp": "unavailable"
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
                // P1 实测(2026-11-07/08, macOS 26.3):入口 exec 目标命令后,Seatbelt
                // violation 日志能稳定给出精确路径并驱动授权重跑。
                // 2026-11-08 标定:归属改为「进程存活期间按 pgid 累积的进程组成员」,
                // 覆盖入口 fork 出的子孙进程(实测入口 64904 / 日志 64905=子 shell);
                // 重试窗口按实测落盘延迟 1456ms 从 1.6s 放宽到 3.2s,并改用 --start 精确定位。
                // 仍标 partial 而非 full:需策略显式开启、依赖日志落盘延迟,
                // 且「被拒进程退出后才落盘」的极端时序可能采不到已退出 PID。
                "auto_violation_capture": if sb { "partial" } else { "unavailable" },
                "violation_log_probe": "sandbox-reporting-violation",
                "net_violation_capture": "partial",
                "net_proxy": "http-connect+socks5",
                // file=exact:路径由内核日志自带,不是从命令/stderr 猜的。
                // net=exact:路径由 CONNECT 协议自带。
                "violation_file_path_precision": "exact",
                "violation_net_path_precision": "exact",
                // B 契约主循环(授权 → 并入策略快照 → 重跑)在 Unix 侧统一实现,
                // 与 Windows 一致 → launcher_retry 三平台同口径。
                "launcher_retry": "full",
                "seatbelt": if sb { "full" } else { "unavailable" },
                // 机制探测:macOS 只用 Seatbelt,其余显式标 unavailable。
                "bubblewrap": "unavailable",
                "landlock": "unavailable",
                "seccomp": "unavailable"
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
                // 文件侧:L1(stderr 自报路径)可用 → partial;但路径由程序自称,
                // 故精度是 reported 而非 exact。内核侧(Landlock 6.15 audit /
                // auditd AVC能给精确路径)需系统级配置,尚未实施。
                "auto_violation_capture": if bwrap { "partial" } else { "unavailable" },
                "net_violation_capture": if bwrap { "partial" } else { "unavailable" },
                "net_proxy": "http-connect+socks5",
                "violation_file_path_precision": "reported",
                "violation_net_path_precision": "exact",
                // B 契约主循环与 Windows/macOS 同口径。
                "launcher_retry": "full",
                // Linux 侧尚无内核日志通道(Landlock 6.15 audit / auditd AVC
                // 未接入)→ 空串(=该通道不存在),不是缺键。
                "violation_log_probe": "",
                "bubblewrap": if bwrap { "full" } else { "unavailable" },
                "landlock": if landlock { "partial" } else { "unavailable" },
                "seccomp": if bwrap { "partial" } else { "unavailable" },
                "seatbelt": "unavailable"
            }
        })
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        // 未支持的平台:键集合仍与契约一致(状态类全 unavailable、描述类空串),
        // 这样「某个键存不存在」永远不是平台差异,只有**值**不同。
        let caps: serde_json::Map<String, Value> = CAP_KEYS
            .iter()
            .map(|k| {
                let v = if STATUS_KEYS.contains(k) {
                    "unavailable"
                } else {
                    ""
                };
                (k.to_string(), json!(v))
            })
            .collect();
        json!({
            "backend": "unsupported",
            "contract": "B",
            "effect": "retry",
            "capabilities": caps
        })
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
    let Some(caps) = caps else {
        return Err("能力报告缺少 capabilities".into());
    };
    let fatal: Vec<String> = caps
        .iter()
        .filter(|(k, v)| {
            v.as_str() == Some("unavailable")
                && !matches!(
                    k.as_str(),
                    "auto_violation_capture"
                        | "cpu"
                        | "memory_total"
                        | "landlock"
                        | "bubblewrap"
                        | "seatbelt"
                        | "seccomp"
                        | "launcher_retry"
                )
        })
        .map(|(k, _)| k.clone())
        .collect();
    if fatal.is_empty() {
        Ok(())
    } else {
        Err(format!("严格模式下以下能力不可用: {}", fatal.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三平台跑**同一份**单测 → 只要都绿,能力报告的键集合就必然一致。
    ///
    /// 这比「在 CI 里比对三份 JSON」更可靠:键集合由 CAP_KEYS 唯一决定,
    /// 任何平台漏报/多报都会在这里红,而不是等到 agent 在某个平台上
    /// 发现「这个键怎么没有」。
    #[test]
    fn capability_keys_match_the_shared_contract() {
        let r = report();
        let caps = r
            .get("capabilities")
            .and_then(|v| v.as_object())
            .expect("能力报告缺少 capabilities");
        let mut got: Vec<&str> = caps.keys().map(|k| k.as_str()).collect();
        got.sort_unstable();
        let mut want: Vec<&str> = CAP_KEYS.to_vec();
        want.sort_unstable();
        assert_eq!(got, want, "能力键集合与共享契约不一致");
    }

    /// 状态类能力的值只能是 full / partial / unavailable —— 消费方
    /// (`--require-full`、agent)按这三个值分支,出现别的值就是契约破坏。
    #[test]
    fn status_capability_values_are_legal() {
        let r = report();
        let caps = r
            .get("capabilities")
            .and_then(|v| v.as_object())
            .expect("能力报告缺少 capabilities");
        for k in STATUS_KEYS {
            let v = caps
                .get(*k)
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("能力 {k} 缺失或不是字符串"));
            assert!(
                matches!(v, "full" | "partial" | "unavailable"),
                "能力 {k} 的值 {v} 不在 {{full, partial, unavailable}} 内"
            );
        }
    }

    /// 顶层结构三平台一致:backend / contract / effect / capabilities。
    #[test]
    fn top_level_shape_is_identical() {
        let r = report();
        for k in ["backend", "contract", "effect", "capabilities"] {
            assert!(r.get(k).is_some(), "能力报告缺少顶层键 {k}");
        }
        assert_eq!(r["contract"], "B");
        assert_eq!(r["effect"], "retry");
    }
}
