//! 裁决公共逻辑:路径规范化与前缀匹配、访问级别、TTY 判定。
//!
//! 关键:`real_path`(给 OS 用)与 `compare_key`(仅比较用)必须分离。
//! 早期版本把真实路径转成反斜杠形式后存进授权列表,导致 Linux/macOS
//! 无法用它生成 bwrap bind / Seatbelt subpath 规则。

use crate::common::expand_path;

/// 给 OS 用的真实路径:展开环境变量 + 解析符号链接(macOS /tmp → /private/tmp)。
/// 不存在的文件回退到父目录的真实路径 + 文件名。
pub fn real_path(p: &str) -> String {
    let expanded = expand_path(p);
    if let Ok(c) = std::fs::canonicalize(&expanded) {
        return c.to_string_lossy().to_string();
    }
    let path = std::path::Path::new(&expanded);
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(c) = std::fs::canonicalize(parent) {
            return c.join(name).to_string_lossy().to_string();
        }
    }
    expanded
}

/// 仅用于比较:统一分隔符与大小写。
pub fn compare_key(p: &str) -> String {
    real_path(p)
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

pub fn is_prefix_hit(list: &[String], path: &str) -> bool {
    let p = compare_key(path);
    list.iter().any(|base| {
        let b = compare_key(base);
        p == b || p.starts_with(&format!("{b}\\"))
    })
}

/// write token 可满足 read 请求;read token 只满足 read。
pub fn access_satisfied(granted: &str, requested: &str) -> bool {
    granted.eq_ignore_ascii_case("write") || granted.eq_ignore_ascii_case(requested)
}

/// 真正的 isatty 判定:非交互终端一律 fail-closed。
pub fn has_tty() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}
