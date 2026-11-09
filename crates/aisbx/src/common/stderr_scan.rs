//! L1 · 从被跑程序的 stderr 里提取「被拒的路径」（跨平台）。
//!
//! 原理:内核只回 `EACCES`/`ERROR_ACCESS_DENIED`(不含路径);**路径是程序自己
//! 拼进错误消息的**。
//! 实测(macOS 26.3,同一份 Seatbelt profile 下被拒):
//!
//! ```text
//! /bin/sh:  /path/x.txt: Operation not permitted                    ← 有路径
//! touch:    /path/x.txt: Operation not permitted                    ← 有路径
//! python3:  PermissionError: [Errno 1] Operation not permitted: '/path/x.txt'  ← 有路径
//! burn(Rust): write failed: Permission denied (os error 13)         ← 【无路径】
//! ```
//!
//! Windows 侧(.NET / PowerShell / Python 的实测形态):
//!
//! ```text
//! Get-Content: Access to the path 'C:\ws\out.txt' is denied.
//! System.UnauthorizedAccessException: Access to the path 'C:\ws\out.txt' is denied.
//! PermissionError: [Errno 13] Permission denied: 'C:\\ws\\out.txt'
//! ```
//!
//! 结论:L1 的覆盖率**取决于程序生态**,不是 100%——Rust/Go/C 这类直接抛
//! `errno` / `GetLastError` 的运行时不会把路径拼进消息。
//!
//! 精度与信任边界:
//! - 归属**确定**:stderr 来自本次执行的进程,不是同机其它人的日志(这正是
//!   它相对 L2 内核日志的优势——L2 会混进同机其它应用的违规)。
//! - 路径**不可信**:程序可以自称一个无害路径骗过采集器。因此本层的
//!   `precision` 恒为 `reported`,**只用于生成授权请求,绝不自动放行**。
//!
//! 与 L2 互补:L2 路径精确但可能归属不上(短命深层进程);L1 归属确定但路径
//! 靠程序自称。两者合起来才能既知道「是谁」又知道「要什么」。

/// 拒绝语义关键词:同一行里出现其一,才认为这一行是权限拒绝。
const DENY_MARKERS: &[&str] = &[
    // Unix
    "Operation not permitted",
    "operation not permitted",
    "Permission denied",
    "permission denied",
    "EACCES",
    "EPERM",
    "not permitted",
    // Windows
    "Access is denied",
    "access is denied",
    "Access to the path",
    "UnauthorizedAccess",
    "is denied",
    "拒绝",
];

/// Unix 系统噪声路径前缀:进程加载期/工具链自身产生的拒绝,不是业务越界。
/// 含常见系统程序目录——`/bin/sh: /path/x: Operation not permitted` 这类消息里
/// 第一个绝对路径是**程序自身**的路径,不是被拒的目标。
const NOISE_PREFIXES: &[&str] = &[
    "/dev/",
    "/System/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/Library/",
    "/Applications/",
    "/private/var/db/",
    "/private/var/root/",
    "/cores/",
    "/.vol/",
    "/tmp/xcrun",
];

/// 噪声**形态**(而非目录前缀):命中即视为工具链/运行时自身的噪声。
///
/// ⚠️ 不要把 `/var/folders/` 整目录当噪声前缀:macOS 的 `TMPDIR` 正在
/// `/var/folders/…`,用户的真实目标也常落在那里——整目录过滤会让 L1 通道
/// 在这些路径上**整个失灵**(实测踩过)。故只匹配具体的已知噪声形态。
const NOISE_PATTERNS: &[&str] = &[
    "/com.apple.", // macOS 工具链缓存:/var/folders/…/T/com.apple.python/…
    ".com.apple.",
    "xcrun_db", // /tmp/xcrun_db-XXXX
    "/.vol/",
];

/// Windows 系统噪声前缀(小写比较):系统目录不是业务越界目标。
const WIN_NOISE_PREFIXES: &[&str] = &[
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\",
];

/// 从一行 stderr 里提取被拒的绝对路径与访问类型。
///
/// 只在**同行**同时满足「有拒绝语义」+「有绝对路径」时才返回,且只返回第一个
/// 候选路径(一行里第一个路径通常就是主因)。
///
/// `access` 是启发式:多数消息不区分读写,这里按是否出现 "read" 推断。
/// 本项目的策略是「读几乎全放行」(macOS `allow file-read*`、Linux 只读根、
/// Windows AppContainer 的读 ACL 较宽),所以实际发生的越界绝大多数是写。
pub fn extract_denied(line: &str) -> Option<(String, &'static str)> {
    if !DENY_MARKERS.iter().any(|m| line.contains(m)) {
        return None;
    }
    let path = find_path(line)?;
    let access = if line.contains("read") {
        "read"
    } else {
        "write"
    };
    Some((path, access))
}

/// 只取路径(便捷包装,测试用)。
#[cfg(test)]
pub fn extract_denied_path(line: &str) -> Option<String> {
    extract_denied(line).map(|(p, _)| p)
}

/// 在一行里找出第一个像绝对路径的候选。
fn find_path(line: &str) -> Option<String> {
    // ① 引号包裹的路径最可靠(Python 的异常、.NET 的异常、多数工具的错误模板都带引号)
    for quote in ['\'', '"'] {
        let mut rest = line;
        while let Some(start) = rest.find(quote) {
            let after = &rest[start + 1..];
            let Some(end) = after.find(quote) else { break };
            let cand = &after[..end];
            if is_candidate_path(cand) {
                return Some(unescape_windows_path(cand));
            }
            rest = &after[end + 1..];
        }
    }
    // ② 退化:取行内【最后一个】像绝对路径的 token。
    //    必须是最后一个而不是第一个:`/bin/sh: /path/x.txt: Operation not permitted`
    //    里第一个绝对路径是程序自身(/bin/sh),被拒的目标在后面。
    let mut last: Option<String> = None;
    for tok in line.split_whitespace() {
        let cleaned = trim_trailing_punct(tok);
        if is_candidate_path(cleaned) {
            last = Some(cleaned.to_string());
        }
    }
    last.map(|p| unescape_windows_path(&p))
}

/// Python 的 `repr` 会把反斜杠转义成双反斜杠(`'C:\\ws\\x.txt'`),
/// 直接用会让路径多一层反斜杠、与 ACL 授权的字面路径对不上。还原它。
fn unescape_windows_path(p: &str) -> String {
    if p.contains("\\\\") {
        p.replace("\\\\", "\\")
    } else {
        p.to_string()
    }
}

/// 是否是「绝对路径」:Unix `/...`、Windows 盘符 `C:\...`/`C:/...`、UNC `\\...`。
pub fn is_absolute_path(p: &str) -> bool {
    if p.starts_with('/') {
        return true;
    }
    if p.starts_with("\\\\") {
        return true; // UNC
    }
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// 是否像一个「值得上报的被拒路径」。
fn is_candidate_path(p: &str) -> bool {
    if p.len() < 2 || !is_absolute_path(p) {
        return false;
    }
    if is_noise(p) {
        return false;
    }
    // 含控制字符或换行的不看
    if p.chars().any(|c| c.is_control()) {
        return false;
    }
    // 纯 '/' 或 '/xxx' 这种太短的片段没有授权价值
    p.trim_matches(['/', '\\']).len() >= 3
}

/// 系统噪声路径(Unix 前缀精确匹配 + 形态匹配;Windows 前缀大小写不敏感)。
fn is_noise(p: &str) -> bool {
    if NOISE_PREFIXES.iter().any(|n| p.starts_with(n)) {
        return true;
    }
    if NOISE_PATTERNS.iter().any(|n| p.contains(n)) {
        return true;
    }
    let lp = p.to_lowercase();
    WIN_NOISE_PREFIXES.iter().any(|n| lp.starts_with(n))
}

/// 去掉 token 尾部的标点(sh 的 "/path/x.txt:" → "/path/x.txt")。
fn trim_trailing_punct(tok: &str) -> &str {
    tok.trim_end_matches([':', ',', ';', '.', ')', ']', '"', '\''])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_shell_style_path() {
        let line = "/bin/sh: /Users/x/ws/out.txt: Operation not permitted";
        assert_eq!(
            extract_denied_path(line),
            Some("/Users/x/ws/out.txt".to_string())
        );
    }

    #[test]
    fn extracts_python_quoted_path() {
        let line = "PermissionError: [Errno 1] Operation not permitted: '/Users/x/ws/o.txt'";
        assert_eq!(
            extract_denied_path(line),
            Some("/Users/x/ws/o.txt".to_string())
        );
    }

    #[test]
    fn extracts_touch_style_path() {
        let line = "touch: /var/tmp/blocked.txt: Operation not permitted";
        assert_eq!(
            extract_denied_path(line),
            Some("/var/tmp/blocked.txt".to_string())
        );
    }

    #[test]
    fn rust_style_error_has_no_path() {
        // Rust 标准库不把路径拼进 io::Error 的 Display —— L1 在这种程序上无解,
        // 这是实测确认的固有边界,不能靠猜补出来。
        let line = "write failed: Permission denied (os error 13)";
        assert_eq!(extract_denied_path(line), None);
    }

    #[test]
    fn ignores_lines_without_denial_semantics() {
        assert_eq!(extract_denied_path("reading /Users/x/ws/ok.txt"), None);
        assert_eq!(extract_denied_path("wrote /Users/x/ws/out.txt"), None);
    }

    #[test]
    fn filters_system_noise() {
        let line = "/bin/sh: /dev/dtracehelper: Operation not permitted";
        assert_eq!(extract_denied_path(line), None);
        let line2 = "python3: error: couldn't create cache file '/tmp/xcrun_db-abc' (errno=Operation not permitted)";
        assert_eq!(extract_denied_path(line2), None);
    }

    #[test]
    fn keeps_user_paths_under_var_folders() {
        // macOS 的 TMPDIR 就在 /var/folders 下——用户的真实目标也常落在这里。
        // 整目录当噪声会让 L1 通道在这些路径上整个失灵(实测踩过)。
        let line = "sh: /var/folders/ab/cd/T/out/result.txt: Operation not permitted";
        assert_eq!(
            extract_denied_path(line),
            Some("/var/folders/ab/cd/T/out/result.txt".to_string())
        );
    }

    #[test]
    fn still_filters_toolchain_cache_under_var_folders() {
        let line = "python3: /var/folders/ab/cd/T/com.apple.python/x: Operation not permitted";
        assert_eq!(extract_denied_path(line), None);
    }

    #[test]
    fn distinguishes_access_kind_by_heuristic() {
        let w = extract_denied("sh: /a/b.txt: Operation not permitted").unwrap();
        assert_eq!(w.1, "write");
        let r = extract_denied("cat: /a/b.txt: Permission denied (read)").unwrap();
        assert_eq!(r.1, "read");
    }

    // ---- Windows 形态 ----

    #[test]
    fn recognises_windows_absolute_paths() {
        assert!(is_absolute_path("C:\\ws\\out.txt"));
        assert!(is_absolute_path("C:/ws/out.txt"));
        assert!(is_absolute_path("\\\\server\\share\\x"));
        assert!(is_absolute_path("/unix/path"));
        assert!(!is_absolute_path("out.txt"));
        assert!(!is_absolute_path("C:"));
    }

    #[test]
    fn extracts_powershell_denied_path() {
        let line = "Get-Content: Access to the path 'C:\\ws\\out.txt' is denied.";
        assert_eq!(
            extract_denied_path(line),
            Some("C:\\ws\\out.txt".to_string())
        );
    }

    #[test]
    fn extracts_dotnet_unauthorized_path() {
        let line =
            "System.UnauthorizedAccessException: Access to the path 'C:\\ws\\out.txt' is denied.";
        assert_eq!(
            extract_denied_path(line),
            Some("C:\\ws\\out.txt".to_string())
        );
    }

    #[test]
    fn extracts_windows_python_denied_path() {
        let line = "PermissionError: [Errno 13] Permission denied: 'C:\\\\ws\\\\out.txt'";
        assert_eq!(
            extract_denied_path(line),
            Some("C:\\ws\\out.txt".to_string())
        );
    }

    #[test]
    fn filters_windows_system_noise() {
        let line = "Get-Content: Access to the path 'C:\\Windows\\System32\\x.dll' is denied.";
        assert_eq!(extract_denied_path(line), None);
    }
}
