mod backend;
mod capabilities;
mod common;

#[cfg(unix)]
mod core;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod run;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod win;

use aisbx_protocol::{Access, EscalationRequest, Grant};
use backend::{backend, backend_name, Backend};
use common::load_policy;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match dispatch(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("aisbx: 错误: {e}");
            eprintln!(
                "用法: aisbx run -p <policy.json> [--json] [--require-full] -- <命令> [参数...]"
            );
            eprintln!("      aisbx escalate -p <policy.json> --path <路径> --access read|write [--token <tok>]");
            eprintln!("      aisbx escalate --op net --host <host> --ip <ip> --port <port>");
            eprintln!("      aisbx authorize -p <policy.json> --path <路径> --access read|write [--ttl-seconds 300]");
            eprintln!("      aisbx authorize -p <policy.json> --host <域名> [--port 443]  # 放行代理观察到的目标(仅本次任务)");
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
            // 该平台上这个 return 确实是多余的(后面没有别的分支了),
            // 但它同时也是「Linux 专属分支」的必要写法 —— 保留语义,
            // 只豁免 lint:本机(macOS)无法编译验证 Linux 分支,改控制流风险太高。
            #[allow(clippy::needless_return)]
            {
                return linux::helper::linux_helper(rest_after(args, 1));
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("__linux_helper 仅用于 Linux".into())
            }
        }
        Some("__unix_entry") => {
            #[cfg(unix)]
            {
                unix::relay::entry(rest_after(args, 1))
            }
            #[cfg(not(unix))]
            {
                Err("__unix_entry 仅用于 Unix".into())
            }
        }
        Some("__relay_only") => {
            #[cfg(unix)]
            {
                unix::relay::relay_only(rest_after(args, 1))
            }
            #[cfg(not(unix))]
            {
                Err("__relay_only 仅用于 Unix".into())
            }
        }
        Some("--help") | Some("-h") | Some("help") | None => {
            println!("aisbx - agent 本地沙箱 (后端: {})", backend().name());
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

    backend().run(&policy, &policy_file, &cmd, json)
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
            flag_value(args, "--token-file").and_then(|f| {
                std::fs::read_to_string(f)
                    .ok()
                    .map(|s| s.trim().to_string())
            })
        })
        .unwrap_or_default();
    let policy = load_policy(&policy_file)?;

    // 平台差异在此**显式声明**，不再等 broker 运行时报错（docs/11 S3）。
    if op == "net" && !backend().supports_net_escalation() {
        return Err(format!(
            "当前后端({})不支持 --op net；见 docs/03 §2.2",
            backend_name()
        ));
    }

    let req = EscalationRequest {
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
        pid: 0,
        requested_by: serde_json::json!({
            "pid": std::process::id(),
            "exe": std::env::current_exe().map(|e| e.display().to_string()).unwrap_or_default()
        }),
    };
    // 底层 client 仍按原样把 broker 应答 JSON 打到 stdout（CLI 行为不变）。
    let decision = backend().escalate(&policy, &req)?;
    Ok(if decision.granted { 0 } else { 1 })
}

/// 宿主侧:agent 框架取得用户同意后调用,向运行中的 broker 签发一次性授权 token。
fn cmd_authorize(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let policy = load_policy(&policy_file)?;

    // P0:放行代理真实观察到的网络目标(仅本次任务,运行中即时生效,不需重跑)。
    let grant = if let Some(host) = flag_value(args, "--host") {
        let port: u16 = flag_value(args, "--port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(443);
        if host.is_empty() || port == 0 {
            return Err("--host/--port 非法".into());
        }
        Grant::Net { host, port }
    } else {
        let path = flag_value(args, "--path").ok_or("缺少 --path 或 --host")?;
        let access = flag_value(args, "--access").unwrap_or_else(|| "write".into());
        if !matches!(access.as_str(), "read" | "write") {
            return Err("--access 只允许 read|write".into());
        }
        let ttl: u64 = flag_value(args, "--ttl-seconds")
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        Grant::File {
            path,
            access: if access == "write" {
                Access::Write
            } else {
                Access::Read
            },
            ttl_seconds: ttl,
        }
    };

    backend().grant(&policy, &grant)
}

fn cmd_status(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let policy = load_policy(&policy_file)?;
    let status = backend().status(&policy)?;
    println!("{}", status.to_line());
    Ok(0)
}
