mod backend;
mod capabilities;
mod common;

#[cfg(unix)]
mod core;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod run;
#[cfg(windows)]
mod win;

use common::load_policy;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match dispatch(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("aisbx: 错误: {e}");
            eprintln!("用法: aisbx run -p <policy.json> [--json] [--require-full] -- <命令> [参数...]");
            eprintln!("      aisbx escalate -p <policy.json> --path <路径> --access read|write [--token <tok>]");
            eprintln!("      aisbx escalate --op net --host <host> --ip <ip> --port <port>");
            eprintln!("      aisbx authorize -p <policy.json> --path <路径> --access read|write [--ttl-seconds 300]");
            eprintln!("      aisbx capabilities [--json]");
            eprintln!("      aisbx policy-check -p <policy.json>");
            2
        }
    };
    std::process::exit(code);
}

fn dispatch(args: &[String]) -> Result<i32, String> {
    match args.first().map(|s| s.as_str()) {
        Some("policy-check") => cmd_policy_check(rest_after(args, 1)),
        Some("capabilities") => {
            let r = capabilities::report();
            println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            Ok(0)
        }
        Some("run") => cmd_run(rest_after(args, 1)),
        Some("escalate") => cmd_escalate(rest_after(args, 1)),
        Some("authorize") => cmd_authorize(rest_after(args, 1)),
        Some("status") => cmd_status(rest_after(args, 1)),
        Some("__linux_helper") => {
            #[cfg(target_os = "linux")]
            {
                return linux::helper::linux_helper(rest_after(args, 1));
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("__linux_helper 仅用于 Linux".into())
            }
        }
        Some("--help") | Some("-h") | Some("help") | None => {
            println!("aisbx - agent 本地沙箱 (后端: {})", backend::backend_name());
            println!("  契约 B: 策略配置 → 拒绝感知 → 用户授权 → 重新执行");
            println!("  run / escalate / authorize / capabilities / policy-check");
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

fn policy_arg(args: &[String]) -> Result<String, String> {
    flag_value(args, "-p")
        .or_else(|| flag_value(args, "--policy"))
        .ok_or_else(|| "缺少 -p <policy>".to_string())
}

fn cmd_policy_check(args: &[String]) -> Result<i32, String> {
    let p = policy_arg(args)?;
    let policy = load_policy(&p)?;
    println!(
        "策略合法: task={} write={} read={} deny_escalation={}",
        policy.task,
        policy.filesystem.write.len(),
        policy.filesystem.read.len(),
        policy.filesystem.deny_escalation.len(),
    );
    Ok(0)
}

fn cmd_run(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or("缺少 -- <命令> 分隔符")?;
    let cmd: Vec<String> = args[sep + 1..].to_vec();
    if cmd.is_empty() {
        return Err("沙箱内命令为空".into());
    }
    let json = args.iter().any(|a| a == "--json");
    let policy = load_policy(&policy_file)?;
    if args.iter().any(|a| a == "--require-full") {
        let report = capabilities::report();
        capabilities::require_full(&report)?;
    }

    #[cfg(windows)]
    {
        return crate::run::run_windows(&policy, &policy_file, &cmd, json);
    }
    #[cfg(target_os = "linux")]
    {
        return linux::run_linux(&policy, &policy_file, &cmd, json);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::run_macos(&policy, &policy_file, &cmd, json);
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (policy, json);
        Err("该平台暂无沙箱后端".into())
    }
}

fn cmd_escalate(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let op = flag_value(args, "--op").unwrap_or_else(|| "file".into());
    let path = flag_value(args, "--path").unwrap_or_default();
    let access = flag_value(args, "--access").unwrap_or_else(|| "read".into());
    if !matches!(access.as_str(), "read" | "write") {
        return Err("--access 只允许 read|write".into());
    }
    if op == "file" && path.is_empty() {
        return Err("缺少 --path".into());
    }
    let token = flag_value(args, "--token")
        .or_else(|| {
            flag_value(args, "--token-file")
                .and_then(|f| std::fs::read_to_string(f).ok().map(|s| s.trim().to_string()))
        })
        .unwrap_or_default();
    let policy = load_policy(&policy_file)?;

    #[cfg(windows)]
    {
        if op != "file" {
            return Err("Windows 后端的 --op net CLI 尚未封装(见 docs/03 §2.2)".into());
        }
        return crate::win::broker::escalate_client(&policy, &path, &access, &token);
    }
    #[cfg(unix)]
    {
        use crate::core::protocol::EscRequest;
        let req = EscRequest {
            op,
            path,
            access,
            host: flag_value(args, "--host").unwrap_or_default(),
            ip: flag_value(args, "--ip").unwrap_or_default(),
            port: flag_value(args, "--port")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            token,
            command_id: std::env::var("AISBX_COMMAND_ID").unwrap_or_default(),
            requested_by: serde_json::json!({
                "pid": std::process::id(),
                "exe": std::env::current_exe().map(|e| e.display().to_string()).unwrap_or_default()
            }),
        };
        let _ = policy;
        unix::broker::escalate_client(&req)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (policy, op, path, access, token);
        Err("escalate 仅支持 Windows/Linux/macOS".into())
    }
}

/// 宿主侧:agent 框架取得用户同意后调用,向运行中的 broker 签发一次性授权 token。
fn cmd_authorize(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let path = flag_value(args, "--path").ok_or("缺少 --path")?;
    let access = flag_value(args, "--access").unwrap_or_else(|| "write".into());
    if !matches!(access.as_str(), "read" | "write") {
        return Err("--access 只允许 read|write".into());
    }
    let ttl: u64 = flag_value(args, "--ttl-seconds")
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let policy = load_policy(&policy_file)?;

    #[cfg(windows)]
    {
        return crate::win::broker::authorize_client(&policy, &path, &access, ttl);
    }
    #[cfg(unix)]
    {
        unix::broker::authorize_client(&policy, &path, &access, ttl)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (policy, path, access, ttl);
        Err("authorize 仅支持 Windows/Linux/macOS".into())
    }
}

fn cmd_status(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let policy = load_policy(&policy_file)?;
    #[cfg(unix)]
    {
        println!("{}", unix::broker::status_client(&policy)?);
        Ok(0)
    }
    #[cfg(not(unix))]
    {
        let _ = policy;
        println!("{{\"backend\":\"windows\",\"status\":\"ok\"}}");
        Ok(0)
    }
}
