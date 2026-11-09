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
//! 实测(2026-11-08, macOS 26.3)——归属与时序标定,三项关键发现:
//!
//! 1. **内核上报的是「真正执行违规操作的那个进程」的 PID**,不是入口的。
//!    实测入口 PID=64904,而日志上报 64905=入口 fork 出来的子 shell。
//!    只按入口 PID 过滤 → 必然漏掉所有 fork 出来的子孙进程。
//!
//! 2. **违规进程可比入口深 3 层**(实测入口 84007,内核上报 84011)。
//!    - `kqueue` 的 `NOTE_FORK` 事件只在**父子之间**投递 → 只覆盖入口的直接
//!      子进程;递归注册也永远慢一步(注册第 2 层时它可能已 fork 出第 3 层)。
//!    - 采样式的 `ps` 快照同样不行:整条命令只跑 12ms,200ms 的采样间隔
//!      根本来不及看到那个 fork 出来的短命子进程。
//!    - **可行判据是进程组**:fork 继承 pgid,故只要违规进程**还活着**,
//!      就能用 pid→pgid 反查判定它属于本次沙箱 —— 与层级深度无关。
//!      因此归属分两级:①已知 PID 集合(入口 + kqueue 收集的 fork 后代 + 登记 PID)
//!      ②pid→pgid 反查(违规进程仍存活时)。两条都不成立 → 归入 unattributed。
//!
//! 3. **落盘延迟 ≈1456ms**(命令 12ms 结束 → 1467ms 后日志才可见)。
//!    原先 3 次 × 800ms 的重试窗口(共 1.6s)刚好卡在边缘,是真实的漏采源。
//!    现改为 8 次 × 400ms(共 3.2s),并用 `--start <命令开始时刻>` 代替
//!    `--last 1m`:既覆盖长命令(早期违规不落在窗口外),也减少无关日志扫描。
//!
//! 4. **`log stream` 实时订阅不可用**:实测普通用户权限下订阅
//!    `subsystem == "com.apple.sandbox.reporting"` 只能拿到过滤提示行、收不到
//!    任何 deny 行(kernel 的实时流对非 root 隐藏;已落盘的 `log show` 才能读到)。
//!    故保留 `log show` 轮询路线。
//!
//! 5. **同机其它应用的违规会落进同一个日志流**(实测捞到 Chrome 的
//!    `libsoda.so`、`wifip2pd` 的 mach-lookup)。所以「未能归属」的条目
//!    **不是**我们的越界:它们只进审计(`violation.unattributed`),
//!    **不进 violations 列表、不驱动授权** —— 否则等于让用户去授权一个毫不
//!    相干的路径,还能被用来伪造「真实拒绝」骗过 token 签发。
//!
//! 覆盖边界(能力报告如实标 partial):需策略显式开启 `broker.violation_capture`;
//! 依赖统一日志落盘延迟;短命且已退出的深层进程无法归属(降级为 unattributed);
//! 采集为空时 launcher 产出 `violation.capture.miss`,不静默当作无越界。
//!
//! 下一步(P2/P3):macOS 用 Endpoint Security `ES_EVENT_TYPE_AUTH_OPEN`(需 entitlement
//! + 公证 + 系统扩展批准),Linux 用 fanotify `FAN_OPEN_PERM`,Windows 用 minifilter
//!   `IRP_MJ_CREATE` 前置回调——三者都能同步裁决并直接给出精确路径,见 docs/08。

use std::process::Command;
use std::time::Duration;

pub struct Captured {
    pub path: String,
    pub access: String,
    pub pid: u32,
    /// 能否证明这次越界来自本次沙箱执行。
    /// false = 路径精确(内核给的),但没能归属到本次执行(短命进程已退出、
    /// 进程组反查不到)。这类条目**只进审计,不驱动授权** —— 同机其它应用的
    /// 违规会落进同一个日志流,当成越界就会去要用户授权无关路径。
    pub attributed: bool,
}

/// 落盘延迟实测 ≈1456ms(2026-11-08),重试窗口必须显著大于它。
const RETRIES: usize = 8;
const RETRY_INTERVAL_MS: u64 = 400;

/// 当前本地时刻,格式 "YYYY-MM-DD HH:MM:SS",用于 `log show --start`。
/// 必须在命令启动之前取,否则长命令的早期违规会落在窗口外。
pub fn now_timestamp() -> Option<String> {
    let out = Command::new("/bin/date")
        .arg("+%Y-%m-%d %H:%M:%S")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// 查询 Seatbelt 违规日志。
///
/// `pgid` 是沙箱进程组(入口 `setpgid(0,0)` 后即组长),`tree` 是事件驱动
/// (kqueue NOTE_FORK)收集到的后代 PID,`pids` 是沙箱入口登记的 PID。
///
/// 归属判定分两级(实测违规进程比入口深 3 层,见文件头说明):
/// - 主判据 `owned`:入口 + kqueue 收集到的 fork 后代 + 登记 PID;
/// - 兜底 `pgid` 反查:违规进程**还活着**时,用 pid→pgid 反查它是否属于本次
///   进程组——fork 继承 pgid,故这一条与层级深度无关。
///   两条都不成立 → `attributed=false`,路径仍然精确,但只是候选。
pub fn collect(
    pgid: u32,
    tree: &[u32],
    pids: &[u32],
    since: Option<&str>,
) -> (Vec<Captured>, Vec<Captured>) {
    let owned = crate::unix::proctree::merge_pids(&[tree, pids, &[pgid]]);
    let mut fallback: Vec<Captured> = Vec::new();
    for attempt in 0..RETRIES {
        let (attributed, unattributed) = query(&owned, pgid, since);
        if !attributed.is_empty() {
            return (attributed, Vec::new());
        }
        if !unattributed.is_empty() {
            // 日志已落盘,但相关进程已退出 → 再等也不会变得可归属。
            fallback = unattributed;
            break;
        }
        if attempt + 1 < RETRIES {
            std::thread::sleep(Duration::from_millis(RETRY_INTERVAL_MS));
        }
    }
    (Vec::new(), fallback)
}

fn query(owned: &[u32], pgid: u32, since: Option<&str>) -> (Vec<Captured>, Vec<Captured>) {
    let mut c = Command::new("/usr/bin/log");
    c.args(["show", "--info", "--debug", "--style", "compact"]);
    match since {
        // --start 精确到命令开始时刻:长命令不漏早期违规,也不会扫到无关历史。
        Some(ts) => {
            c.arg("--start");
            c.arg(ts);
        }
        None => {
            c.args(["--last", "2m"]);
        }
    }
    c.args([
        "--predicate",
        "subsystem == \"com.apple.sandbox.reporting\" AND eventMessage CONTAINS \"deny\"",
    ]);
    let Ok(out) = c.output() else {
        return (Vec::new(), Vec::new());
    };
    if !out.status.success() {
        return (Vec::new(), Vec::new());
    }
    // 每次查询都刷新一次进程表:违规进程若还活着,这是唯一能归属它的机会。
    let table = crate::unix::proctree::pgid_table();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut attributed: Vec<Captured> = Vec::new();
    let mut unattributed: Vec<Captured> = Vec::new();
    for line in text.lines() {
        if let Some(c) = parse_line(line, owned, pgid, &table) {
            if c.attributed {
                if !attributed.iter().any(|x: &Captured| x.path == c.path) {
                    attributed.push(c);
                }
            } else if is_relevant_unattributed(&c.access, &c.path)
                && unattributed.len() < UNATTRIBUTED_LIMIT
                && !unattributed.iter().any(|x: &Captured| x.path == c.path)
            {
                unattributed.push(c);
            }
        }
    }
    (attributed, unattributed)
}

/// 未归属条目里,哪些还可能是我们的越界?
///
/// 本项目的 macOS profile 是 `(allow file-read*)` —— **读几乎不会被拒**,
/// 我们的越界绝大多数是「写」。所以:
/// - write:一律可能是我们的(保持宽松,宁可多报);
/// - read:只有命中我们 profile 里**显式 deny 的凭据目录**才可能是我们的
///   (.ssh/.aws/.gnupg/.kube/.docker),其余(如 Chrome 读自己的 so)一律丢弃。
///   这样能把同机噪音从审计里滤掉大半。
fn is_relevant_unattributed(access: &str, path: &str) -> bool {
    if access == "write" {
        return true;
    }
    const CRED: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".docker"];
    CRED.iter().any(|c| path.contains(&format!("/{c}/")))
}

/// 未归属条目的上报上限:同机其它进程可能持续产生违规,不能无限膨胀。
const UNATTRIBUTED_LIMIT: usize = 20;

fn parse_line(
    line: &str,
    owned: &[u32],
    pgid: u32,
    table: &std::collections::HashMap<u32, u32>,
) -> Option<Captured> {
    let pos = line.find("Sandbox: ")?;
    let s = &line[pos + "Sandbox: ".len()..];
    // s = "bash(24720) deny(1) file-write-create /path with spaces"
    let lp = s.find('(')?;
    let rp_rel = s[lp + 1..].find(')')?;
    let pid_str = &s[lp + 1..lp + 1 + rp_rel];
    let Ok(line_pid) = pid_str.parse::<u32>() else {
        return None;
    };
    // 归属判定:已知 PID 集合,或该进程仍存活且其进程组就是本次沙箱的进程组。
    let attributed =
        owned.contains(&line_pid) || table.get(&line_pid).map(|g| *g == pgid).unwrap_or(false);
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
        attributed,
    })
}

fn is_system_noise(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/dev/",
        "/System/",
        "/usr/",
        "/Library/",
        "/Applications/",
        "/private/var/db/",
        "/private/var/root/",
        "/cores/",
        "/.vol/",
    ];
    PREFIXES.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn no_table() -> HashMap<u32, u32> {
        HashMap::new()
    }

    #[test]
    fn parses_real_kernel_line() {
        let line =
            "2026-11-06 13:32:32.285 E  kernel[0:26c8ba] [com.apple.sandbox.reporting:violation] \
                    Sandbox: bash(24720) deny(1) file-write-create /Users/xj/ws/blocked.txt";
        let c = parse_line(line, &[12345, 24720], 999, &no_table()).unwrap();
        assert_eq!(c.path, "/Users/xj/ws/blocked.txt");
        assert_eq!(c.access, "write");
        assert!(c.attributed);
    }

    #[test]
    fn path_with_spaces_and_read_op() {
        let line = "Sandbox: sh(42) deny(1) file-read-data /tmp/a b/c.txt";
        let c = parse_line(line, &[42], 7, &no_table()).unwrap();
        assert_eq!(c.path, "/tmp/a b/c.txt");
        assert_eq!(c.access, "read");
    }

    #[test]
    fn ignores_non_file_operations() {
        assert!(parse_line(
            "Sandbox: x(7) deny(1) mach-lookup com.apple.tccd",
            &[7],
            1,
            &no_table()
        )
        .is_none());
    }

    #[test]
    fn filters_system_device_noise_but_keeps_business_paths() {
        assert!(parse_line(
            "Sandbox: x(7) deny(1) file-write-data /dev/dtracehelper",
            &[7],
            1,
            &no_table()
        )
        .is_none());
        assert!(parse_line(
            "Sandbox: x(7) deny(1) file-write-data /dev/tty",
            &[7],
            1,
            &no_table()
        )
        .is_none());
        assert!(parse_line(
            "Sandbox: x(7) deny(1) file-write-create /private/tmp/ws/out/a.txt",
            &[7],
            1,
            &no_table()
        )
        .is_some());
    }

    /// 归属降级:进程已退出且不在已知集合内 → 路径仍然精确,但 attributed=false。
    /// 实测:违规进程可比入口深 3 层,短命进程退出后无法反查进程组。
    #[test]
    fn unowned_pid_is_kept_but_marked_unattributed() {
        let line = "Sandbox: bash(77793) deny(1) file-write-create /private/tmp/x.txt";
        let c = parse_line(line, &[77790], 77790, &no_table()).unwrap();
        assert_eq!(c.path, "/private/tmp/x.txt");
        assert!(!c.attributed);
    }

    /// 兜底判据:进程还活着 → 用 pid→pgid 反查,判定它属于本次沙箱进程组。
    /// 这一条与层级深度无关(fork 继承 pgid),是深层次归属的主力。
    #[test]
    fn pgid_reverse_lookup_attributes_any_depth() {
        let line = "Sandbox: bash(77793) deny(1) file-write-create /private/tmp/x.txt";
        let mut table = HashMap::new();
        table.insert(77793, 77790); // 违规进程属于本次沙箱的进程组
        let c = parse_line(line, &[77790], 77790, &table).unwrap();
        assert!(c.attributed);
    }
}
