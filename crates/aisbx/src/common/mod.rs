//! 跨平台公共工具:策略加载、路径展开、参数引号、L1 越界路径解析。

pub mod pending;
pub mod stderr_scan;

use aisbx_policy::Policy;
use std::path::PathBuf;

/// 路径前缀匹配(只统一分隔符与大小写,**不**解析符号链接)。
///
/// Windows 侧专用:ACL 授权的是字面路径,而 stderr 里报的是同一个字面路径;
/// 若走 `canonicalize` 会被改写成 `\\?\C:\...` 形式,反而匹配不上。
#[cfg_attr(not(windows), allow(dead_code))]
pub fn path_prefix_hit(list: &[String], path: &str) -> bool {
    let key = |p: &str| {
        p.replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    let p = key(path);
    list.iter().any(|base| {
        let b = key(base);
        p == b || p.starts_with(&format!("{b}\\"))
    })
}

pub fn load_policy(file: &str) -> Result<Policy, String> {
    let raw = std::fs::read_to_string(file).map_err(|e| format!("读取策略失败 {file}: {e}"))?;
    Policy::parse(&raw)
}

/// 展开 %VAR% 形式的环境变量(Windows 习惯写法,非 Windows 也容忍)
#[cfg_attr(not(windows), allow(dead_code))]
pub fn expand_path(p: &str) -> String {
    if !p.contains('%') {
        return p.to_string();
    }
    let mut out = String::with_capacity(p.len());
    let mut rest = p;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        match tail.find('%') {
            Some(end) => {
                let name = &tail[..end];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => out.push_str(&rest[start..start + 1 + end + 1]),
                }
                rest = &tail[end + 1..];
            }
            None => {
                out.push('%');
                rest = tail;
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn expand_all(paths: &[String]) -> Vec<PathBuf> {
    paths
        .iter()
        .map(|p| PathBuf::from(expand_path(p)))
        .collect()
}

/// Windows 命令行参数加引号(RC 规则)
#[cfg_attr(not(windows), allow(dead_code))]
pub fn quote_arg(s: &str) -> String {
    if !s.is_empty() && !s.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return s.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in s.chars() {
        match c {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}
