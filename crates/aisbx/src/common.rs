//! 跨平台公共工具:策略加载、路径展开、参数引号。

use aisbx_policy::Policy;
use std::path::PathBuf;

pub fn load_policy(file: &str) -> Result<Policy, String> {
    let raw = std::fs::read_to_string(file).map_err(|e| format!("读取策略失败 {file}: {e}"))?;
    Policy::parse(&raw)
}

/// 展开 %VAR% 形式的环境变量(Windows 习惯写法,非 Windows 也容忍)
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

pub fn expand_all(paths: &[String]) -> Vec<PathBuf> {
    paths.iter().map(|p| PathBuf::from(expand_path(p))).collect()
}

/// Windows 命令行参数加引号(RC 规则)
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
