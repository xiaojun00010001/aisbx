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
            eprintln!("      aisbx status -p <policy.json>                       # 待授权项(含 id/grant,可直接 approve)");
            eprintln!("      aisbx approve -p <policy.json> --pending <id>       # 按 status.pending[].id 授权(P1)");
            eprintln!("      aisbx guard -p <policy.json> --approve-cmd <exe> -- <命令>  # 一条命令完成失败→授权→重跑(P1)");
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
        Some("approve") => cmd_approve(rest_after(args, 1)),
        Some("guard") => cmd_guard(rest_after(args, 1)),
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
            println!("  run / escalate / authorize / status / approve / guard / capabilities / policy-check");
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

/// 高层命令：把「起 run → 轮询 status → 授权 → 等重跑」收回沙箱内部。
///
/// 用法：`aisbx guard -p p.json --approve-cmd <exe> -- <cmd> [args...]`
/// 审批回调从 stdin 读一条 pending JSON，stdout 输出 `approve` 表示同意，其它一律拒绝。
/// 没有 --approve-cmd 时直接退化为普通 run（不自动放行，fail-closed）。
fn cmd_guard(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or("缺少 -- <命令> 分隔符")?;
    let cmd: Vec<String> = args[sep + 1..].to_vec();
    if cmd.is_empty() {
        return Err("沙箱内命令为空".into());
    }
    let approve_cmd = flag_value(args, "--approve-cmd");
    let policy = load_policy(&policy_file)?;

    // 无审批回调：不自动放行（fail-closed），退化为普通 run。
    let Some(approve_cmd) = approve_cmd else {
        return backend().run(&policy, &policy_file, &cmd, false);
    };

    // 后台起 run，主线程轮询 status 并按回调决策。
    let run_args = args.to_vec();
    let run_policy_file = policy_file.clone();
    let child = std::thread::spawn(move || {
        // 子线程重新加载策略（&Policy 不能跨线程），只执行 run（不带 guard 专属参数）
        let p = match load_policy(&run_policy_file) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        let sep = run_args.iter().position(|a| a == "--").unwrap_or(0);
        let run_cmd: Vec<String> = run_args[sep + 1..].to_vec();
        backend().run(&p, &run_policy_file, &run_cmd, false)
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut approved: std::collections::HashSet<String> = std::collections::HashSet::new();
    while std::time::Instant::now() < deadline && !child.is_finished() {
        if let Ok(st) = backend().status(&policy) {
            let st = st.with_ids_and_grants(300);
            for p in st.actionable_pending() {
                if p.id.is_empty() || approved.contains(&p.id) {
                    continue;
                }
                let input = serde_json::to_string(p).unwrap_or_default();
                let mut child_proc = std::process::Command::new(&approve_cmd)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("启动审批回调失败: {e}"))?;
                if let Some(mut si) = child_proc.stdin.take() {
                    use std::io::Write;
                    let _ = writeln!(si, "{input}");
                }
                let out = child_proc
                    .wait_with_output()
                    .map_err(|e| format!("审批回调执行失败: {e}"))?;
                let verdict = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if verdict == "approve" {
                    if let Some(g) = p.grant.clone().or_else(|| p.make_grant(300)) {
                        let _ = backend().grant(&policy, &g);
                    }
                    approved.insert(p.id.clone());
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(child.join().unwrap_or(Ok(1)).unwrap_or(1))
}

fn cmd_status(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let policy = load_policy(&policy_file)?;
    // P1:为每条 pending 补 id / grant，agent 可直接拿去 approve。
    // 旧字段与取值不变；新字段用 skip_serializing_if 避免给空 pending 增噪。
    let status = backend().status(&policy)?.with_ids_and_grants(300);
    println!("{}", status.to_line());
    Ok(0)
}

/// 按 `status.pending[].id` 授权——agent 不必自己把 pending 映射成 --path/--host。
///
/// 流程：status(补 id/grant) → 按 id 查找 → 校验 attributed（未归属不授权）
/// → 调 backend().grant。不引入新的 broker 协议，复用 authorize 通道。
fn cmd_approve(args: &[String]) -> Result<i32, String> {
    let policy_file = policy_arg(args)?;
    let id = flag_value(args, "--pending")
        .ok_or("缺少 --pending <id>（id 来自 `aisbx status` 的 pending[].id）")?;
    let policy = load_policy(&policy_file)?;
    let status = backend().status(&policy)?.with_ids_and_grants(300);
    let p = status.pending_by_id(&id).ok_or_else(|| {
        format!(
            "找不到待授权项 {id}（可能已被授权/任务已结束）；当前 pending: {:?}",
            status
                .pending
                .iter()
                .map(|x| x.id.as_str())
                .collect::<Vec<_>>()
        )
    })?;
    if !p.attributed {
        return Err(format!(
            "待授权项 {id} 未能归属到本次执行，拒绝授权（见 docs/08 §3.5）"
        ));
    }
    let grant = p
        .grant
        .clone()
        .or_else(|| p.make_grant(300))
        .ok_or_else(|| format!("待授权项 {id} 无法生成授权参数"))?;
    backend().grant(&policy, &grant)
}
