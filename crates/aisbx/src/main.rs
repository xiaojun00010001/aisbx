mod common;

use common::load_policy;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match dispatch(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("aisbx: 错误: {e}");
            eprintln!("用法: aisbx run -p <policy.json> -- <命令> [参数...]");
            eprintln!("      aisbx escalate -p <policy.json> --path <路径> --access read|write [--token <tok>]");
            eprintln!("      aisbx authorize -p <policy.json> --path <路径> --access read|write [--ttl-seconds 300]");
            eprintln!("      aisbx policy-check -p <policy.json>");
            2
        }
    };
    std::process::exit(code);
}

fn dispatch(args: &[String]) -> Result<i32, String> {
    match args.first().map(|s| s.as_str()) {
        Some("policy-check") => cmd_policy_check(rest_after(args, 1)),
        Some("run") => cmd_run(rest_after(args, 1)),
        Some("escalate") => cmd_escalate(rest_after(args, 1)),
        Some("authorize") => cmd_authorize(rest_after(args, 1)),
        Some("--help") | Some("-h") | Some("help") | None => {
            println!("aisbx - agent 本地沙箱 (Windows: AppContainer + Job Object + 授权 broker)");
            Ok(0)
        }
        Some(other) => Err(format!("未知子命令 {other}")),
    }
}

fn rest_after(args: &[String], n: usize) -> &[String] {
    args.get(n..).unwrap_or(&[])
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn cmd_policy_check(args: &[String]) -> Result<i32, String> {
    let p = flag_value(args, "-p").or_else(|| flag_value(args, "--policy"))
        .ok_or("缺少 -p <policy>")?;
    let policy = load_policy(&p)?;
    println!("策略合法: task={} write={} read={} deny_escalation={}",
        policy.task,
        policy.filesystem.write.len(),
        policy.filesystem.read.len(),
        policy.filesystem.deny_escalation.len(),
    );
    Ok(0)
}

fn cmd_run(args: &[String]) -> Result<i32, String> {
    let policy_file = flag_value(args, "-p").or_else(|| flag_value(args, "--policy"))
        .ok_or("缺少 -p <policy>")?;
    let sep = args.iter().position(|a| a == "--")
        .ok_or("缺少 -- <命令> 分隔符")?;
    let cmd: Vec<String> = args[sep + 1..].to_vec();
    if cmd.is_empty() {
        return Err("沙箱内命令为空".into());
    }
    let json = args.iter().any(|a| a == "--json");
    let policy = load_policy(&policy_file)?;
    #[cfg(windows)]
    {
        return crate::run::run_windows(&policy, &policy_file, &cmd, json);
    }
    #[cfg(not(windows))]
    {
        let _ = (policy, json);
        Err("aisbx 的沙箱后端目前仅支持 Windows(run/escalate 需在 Windows 上执行)".into())
    }
}

fn cmd_escalate(args: &[String]) -> Result<i32, String> {
    let policy_file = flag_value(args, "-p").or_else(|| flag_value(args, "--policy"))
        .ok_or("缺少 -p <policy>")?;
    let path = flag_value(args, "--path").ok_or("缺少 --path")?;
    let access = flag_value(args, "--access").unwrap_or_else(|| "read".into());
    if !matches!(access.as_str(), "read" | "write") {
        return Err("--access 只允许 read|write".into());
    }
    let token = flag_value(args, "--token").or_else(|| flag_value(args, "--token-file").and_then(|f| std::fs::read_to_string(f).ok().map(|s| s.trim().to_string()))).unwrap_or_default();
    let policy = load_policy(&policy_file)?;
    #[cfg(windows)]
    {
        return crate::win::broker::escalate_client(&policy, &path, &access, &token);
    }
    #[cfg(not(windows))]
    {
        let _ = (policy, path, access, token);
        Err("escalate 仅支持 Windows".into())
    }
}

/// 宿主侧:agent 框架在用户同意后调用,向运行中 broker 签发一次性授权 token。
fn cmd_authorize(args: &[String]) -> Result<i32, String> {
    let policy_file = flag_value(args, "-p").or_else(|| flag_value(args, "--policy"))
        .ok_or("缺少 -p <policy>")?;
    let path = flag_value(args, "--path").ok_or("缺少 --path")?;
    let access = flag_value(args, "--access").unwrap_or_else(|| "write".into());
    if !matches!(access.as_str(), "read" | "write") {
        return Err("--access 只允许 read|write".into());
    }
    let ttl: u64 = flag_value(args, "--ttl-seconds").and_then(|v| v.parse().ok()).unwrap_or(300);
    let policy = load_policy(&policy_file)?;
    #[cfg(windows)]
    {
        return crate::win::broker::authorize_client(&policy, &path, &access, ttl);
    }
    #[cfg(not(windows))]
    {
        let _ = (policy, path, access, ttl);
        Err("authorize 仅支持 Windows".into())
    }
}

#[cfg(windows)]
mod run;
#[cfg(windows)]
mod win;
