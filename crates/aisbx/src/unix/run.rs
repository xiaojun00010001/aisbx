//! 方案 B 的 launcher 重试循环(Unix 共用)。
//! 授权不修改运行中的进程,而是把放宽后的路径并入【下一次执行的策略快照】重新 spawn。

use std::ffi::c_int;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use aisbx_policy::Policy;
use serde_json::json;

use super::broker::Broker;
use crate::core::tokens::random_token;

/// 子进程退出后等待宿主 agent 完成用户授权的最长时间。
const WAIT_AUTH_SECS: u64 = 20;
const MAX_ATTEMPTS: u32 = 3;

pub struct RunCtx {
    pub attempt: u32,
    pub granted: Vec<String>,
    pub token: String,
    pub broker_dir: PathBuf,
    pub command_id: String,
    pub policy_file: String,
}

/// `make_argv` 由 Linux/macOS 平台后端提供:按当前策略快照生成沙箱包装命令。
pub fn run_loop<F>(
    policy: &Policy,
    policy_file: &str,
    cmd: &[String],
    json: bool,
    make_argv: F,
) -> Result<i32, String>
where
    F: Fn(&Policy, &[String], &RunCtx) -> Result<Vec<String>, String>,
{
    let command_id = random_token();
    let broker = Broker::start(policy, &command_id)?;
    let emit = |v: serde_json::Value| {
        broker.emit(v.clone());
        if json {
            println!("{v}");
        }
    };

    let mut code: i32;
    let mut attempt = 1u32;
    let mut prev_granted: usize;

    loop {
        {
            let mut s = broker.state.lock().unwrap_or_else(|p| p.into_inner());
            s.attempt = attempt;
        }
        let snap = broker.snapshot();
        prev_granted = snap.granted.len();
        let ctx = RunCtx {
            attempt,
            granted: snap.granted.clone(),
            token: snap.token.clone(),
            broker_dir: broker.dir.clone(),
            command_id: command_id.clone(),
            policy_file: policy_file.to_string(),
        };

        let argv = make_argv(policy, cmd, &ctx)?;
        emit(json!({"event": "spawned", "attempt": attempt, "cmd": cmd}));
        code = spawn(&argv, &ctx, policy)?;
        emit(json!({"event": "exit", "attempt": attempt, "code": code}));

        if code == 0 || attempt >= MAX_ATTEMPTS {
            break;
        }

        // 等待真实拒绝之后的用户授权。授权到达 => 以新策略快照重跑。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(WAIT_AUTH_SECS);
        let mut widened = false;
        while std::time::Instant::now() < deadline {
            let now = broker.snapshot();
            if now.granted.len() > prev_granted {
                widened = true;
                break;
            }
            // 只等待「需要用户授权」的拒绝;黑名单/网络拒绝不等待
            if !now.needs_approval {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !widened {
            break;
        }

        {
            let mut s = broker.state.lock().unwrap_or_else(|p| p.into_inner());
            s.retries = attempt;
        }
        emit(json!({
            "event": "retry", "from": attempt, "to": attempt + 1,
            "reason": "user-approved", "command_id": command_id
        }));
        attempt += 1;
    }

    Ok(code)
}

fn spawn(argv: &[String], ctx: &RunCtx, policy: &aisbx_policy::Policy) -> Result<i32, String> {
    let program = argv.first().ok_or("空的沙箱命令")?;
    let mut c = Command::new(program);
    c.args(&argv[1..]);
    c.stdin(Stdio::null());
    c.stdout(Stdio::inherit());
    c.stderr(Stdio::inherit());
    c.env("AISBX_ATTEMPT", ctx.attempt.to_string());
    c.env("AISBX_BROKER_DIR", &ctx.broker_dir);
    c.env("AISBX_COMMAND_ID", &ctx.command_id);
    c.env("AISBX_GRANTED_PATHS", ctx.granted.join(":"));
    c.env("AISBX_POLICY_FILE", &ctx.policy_file);
    if let Ok(exe) = std::env::current_exe() {
        c.env("AISBX_CLI", exe.to_string_lossy().to_string());
    }
    if !ctx.token.is_empty() {
        c.env("AISBX_TOKEN", &ctx.token);
    }
    if let Ok(p) = std::env::var("PATH") {
        c.env("PATH", p);
    }
    if let Ok(h) = std::env::var("HOME") {
        c.env("HOME", h);
    }
    c.env("TMPDIR", std::env::temp_dir());

    // RLIMIT_NPROC 按【用户】计数,不是每任务配额:设成策略值会连 fork 都失败(EAGAIN),
    // 故不使用;macOS 也没有 cgroups 等价物,进程数上限在能力报告中标 unavailable。
    // RLIMIT_AS 是虚拟地址空间(与 Job 的 commit 限额语义不同),仅 Linux 生效且取安全下限,
    // 避免小配额导致 Rust 二进制自身无法启动。
    let mem = policy
        .resources
        .memory_mb_per_process
        .map(|mb| mb.max(512));
    unsafe {
        c.pre_exec(move || {
            libc::setpgid(0, 0);
            #[cfg(target_os = "linux")]
            if let Some(mb) = mem {
                let r = libc::rlimit {
                    rlim_cur: mb.saturating_mul(1024 * 1024) as libc::rlim_t,
                    rlim_max: mb.saturating_mul(1024 * 1024) as libc::rlim_t,
                };
                libc::setrlimit(libc::RLIMIT_AS, &r);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = mem;
            Ok(())
        });
    }

    let mut child = c.spawn().map_err(|e| format!("启动沙箱命令失败: {e}"))?;
    let pgid = child.id() as c_int;
    let status = child.wait().map_err(|e| format!("等待沙箱命令失败: {e}"))?;
    // 兜底:pre_exec 已 setpgid(0,0),组长 pid 即 child.id();负号作用于整个进程组
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    Ok(status.code().unwrap_or(if status.success() { 0 } else { 1 }))
}
