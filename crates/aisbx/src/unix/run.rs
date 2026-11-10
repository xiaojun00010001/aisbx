//! 方案 B 的 launcher 重试循环(Unix 共用)。
//! 授权不修改运行中的进程,而是把放宽后的路径并入【下一次执行的策略快照】重新 spawn。

use std::ffi::c_int;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use aisbx_policy::Policy;
use serde_json::json;

use super::broker::Broker;
use crate::core::decision;
use crate::core::tokens::random_token;

/// 子进程退出后等待宿主 agent 完成用户授权的最长时间。
const WAIT_AUTH_SECS: u64 = 20;
const MAX_ATTEMPTS: u32 = 3;

/// 等待子进程/事件的轮询间隔(ms):决定命令结束后的最大额外延迟。
const POLL_MS: u64 = 20;

pub struct RunCtx {
    pub attempt: u32,
    pub granted: Vec<String>,
    pub token: String,
    pub broker_dir: PathBuf,
    pub command_id: String,
    pub policy_file: String,
    /// 沙箱内 relay 监听端口。Linux 的 bwrap --clearenv 要求显式 --setenv,
    /// 因此必须由 make_argv 拿到同一个值,不能只靠 spawn 的进程环境继承。
    pub relay_port: u16,
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

    // 后台线程(代理 / 内核日志采集)的事件已由 emit_event 写入审计,
    // 这里只负责转发到 --json 事件流,避免同一事件在审计里出现两次。
    let flush = || {
        for e in broker.drain_events() {
            if json {
                println!("{e}");
            }
        }
    };

    let mut code: i32;
    let mut attempt = 1u32;
    let mut prev_granted: usize;

    loop {
        flush();
        {
            let mut s = broker.state.lock().unwrap_or_else(|p| p.into_inner());
            s.attempt = attempt;
        }
        let snap = broker.snapshot();
        prev_granted = snap.granted.len();
        // 每次 attempt 换一个端口,避免上一次 relay 残留占用(TIME_WAIT / 进程组回收延迟)。
        let relay_port = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);
        let ctx = RunCtx {
            attempt,
            granted: snap.granted.clone(),
            token: snap.token.clone(),
            broker_dir: broker.dir.clone(),
            command_id: command_id.clone(),
            policy_file: policy_file.to_string(),
            relay_port,
        };

        let argv = make_argv(policy, cmd, &ctx)?;
        // 采集窗口起点:必须在 spawn 之前取,否则长命令的早期违规会落在窗口外。
        #[cfg(target_os = "macos")]
        let since = if policy.broker.capture_violations() {
            crate::macos::violations::now_timestamp()
        } else {
            None
        };
        emit(json!({"event": "spawned", "attempt": attempt, "cmd": cmd}));
        let outcome = spawn(&argv, &ctx, policy)?;
        code = outcome.code;
        emit(json!({"event": "exit", "attempt": attempt, "code": code}));
        flush();

        // P1: macOS 内核违规日志自动采集。程序零配合——被拒的精确路径由内核日志给出。
        // 仅当策略显式开启时生效,避免改变既有冒烟行为。
        #[cfg(target_os = "macos")]
        if policy.broker.capture_violations() {
            let mut pids = vec![outcome.pid];
            pids.extend(broker.sandbox_pids());
            // 归属集合 = 进程存活期间累积的进程组成员(覆盖整棵进程树)+ 登记 PID。
            // 只按入口 PID 归属会漏掉 fork 出来的子孙进程(实测入口 64904、
            // 内核日志上报 64905=入口 fork 出的子 shell)。
            let tree = &outcome.tree;
            let (attributed, unattributed) =
                crate::macos::violations::collect(outcome.pid, tree, &pids, since.as_deref());
            if attributed.is_empty() && unattributed.is_empty() {
                // 不静默失败:外层 agent 必须能区分「没有越界」与「尝试采集但内核没给」。
                let mut s = broker.state.lock().unwrap_or_else(|p| p.into_inner());
                s.emit_event(json!({
                    "event": "violation.capture.miss", "source": "sandbox-log",
                    "attempt": attempt, "pgid": outcome.pid, "pids": pids,
                    "tree_size": tree.len(),
                    "reason": "kernel produced no attributable violation log for this process"
                }));
            }
            for v in attributed {
                let mut s = broker.state.lock().unwrap_or_else(|p| p.into_inner());
                s.external_file_violation(&v.path, &v.access, v.pid, true);
            }
            for v in unattributed {
                // 只进审计:未能归属 ≠ 是我们的越界,绝不能驱动授权。
                let mut s = broker.state.lock().unwrap_or_else(|p| p.into_inner());
                s.unattributed_file_violation(&v.path, &v.access, v.pid);
            }
            flush();
        }
        #[cfg(not(target_os = "macos"))]
        let _ = outcome.pid;

        // 回收整个进程组:入口退出后,它 fork 出来的后台进程可能还活着。
        // (pre_exec 已 setpgid(0,0),组长 pid 即 child.id();负号作用于整个进程组。)
        // 必须放在采集之后:内核违规日志的归属判定依赖进程组里的进程还活着
        // ——违规进程一旦退出,就无法再反查它属于哪个进程组,归属只能降级。
        unsafe {
            libc::kill(-(outcome.pgid as i32), libc::SIGKILL);
        }

        // L1:进程组已回收 → stderr 管道 EOF → 取回程序自称的被拒路径。
        // 归属是确定的(stderr 来自本次执行的进程),但路径是程序【自称】的,
        // 所以 precision=reported:只用于生成授权请求,绝不自动放行。
        let self_reported = match &outcome.stderr_rx {
            Some(rx) => rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap_or_default(),
            None => Vec::new(),
        };
        if !self_reported.is_empty() {
            for (p, access) in self_reported {
                // 只保留「不在白名单内」的路径:白名单内的路径本就不该被拒,出现即噪声。
                let canon = decision::real_path(&p);
                let allowed = decision::is_prefix_hit(&policy.filesystem.write, &canon)
                    || decision::is_prefix_hit(&policy.filesystem.read, &canon);
                if allowed {
                    continue;
                }
                let mut s = broker.state.lock().unwrap_or_else(|x| x.into_inner());
                s.self_reported_file_violation(&canon, &access);
            }
            flush();
        }

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
            flush();
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        flush();
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

    flush();
    Ok(code)
}

pub struct SpawnOutcome {
    pub code: i32,
    pub pid: u32,
    /// 进程组 ID(入口 setpgid(0,0) 后即组长)。负号 kill 即作用于整个进程组。
    pub pgid: u32,
    /// 进程组成员快照:仅在 `broker.violation_capture` 开启时于【进程存活期间】累积。
    /// fork 继承 pgid,故它覆盖整棵进程树——内核违规日志上报的是真正执行违规的
    /// 那个进程的 PID(实测:入口 64904,日志里 64905=入口 fork 出的子 shell),
    /// 只按入口 PID 归属会漏掉所有子孙进程。
    /// 进程树快照。⚠️ 只有 macOS 内核通道(L2)会读它 → Linux 上无人读取。
    #[allow(dead_code)]
    pub tree: Vec<u32>,
    /// L1 通道:程序自称的被拒路径。**必须在 kill 进程组之后**接收——
    /// 之前管道还没 EOF(孙进程也持有 stderr),会白等。
    pub stderr_rx: Option<std::sync::mpsc::Receiver<Vec<(String, String)>>>,
}

fn spawn(
    argv: &[String],
    ctx: &RunCtx,
    policy: &aisbx_policy::Policy,
) -> Result<SpawnOutcome, String> {
    let program = argv.first().ok_or("空的沙箱命令")?;
    let mut c = Command::new(program);
    c.args(&argv[1..]);
    c.stdin(Stdio::null());
    c.stdout(Stdio::inherit());
    // L1(stderr 自报路径)需要捕获 stderr:改用管道 + 转发线程。
    // 仅在开启 violation_capture 时改管道 → 默认路径逐字节不变(零回归风险)。
    let capture_stderr = policy.broker.capture_violations();
    if capture_stderr {
        c.stderr(Stdio::piped());
    } else {
        c.stderr(Stdio::inherit());
    }
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

    // P0:沙箱内 relay 端口。macOS 靠环境继承即可;Linux 还需 bwrap --setenv
    // (见 bwrap.rs),两边用的是同一个 ctx.relay_port。
    c.env("AISBX_RELAY_PORT", ctx.relay_port.to_string());

    // RLIMIT_NPROC 按【用户】计数,不是每任务配额:设成策略值会连 fork 都失败(EAGAIN),
    // 故不使用;macOS 也没有 cgroups 等价物,进程数上限在能力报告中标 unavailable。
    // RLIMIT_AS 是虚拟地址空间(与 Job 的 commit 限额语义不同),仅 Linux 生效且取安全下限,
    // 避免小配额导致 Rust 二进制自身无法启动。
    let mem = policy.resources.memory_mb_per_process.map(|mb| mb.max(512));
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
    let pid = child.id();
    let pgid = pid as c_int;

    // L1:转发 stderr 的同时扫描被拒路径。stderr 管道要等【整个进程组】被回收
    // 才会 EOF(孙进程也持有它),故结果经 channel 交回,由调用方在 kill 之后接收。
    let (tx, rx) = std::sync::mpsc::channel::<Vec<(String, String)>>();
    if capture_stderr {
        if let Some(err) = child.stderr.take() {
            std::thread::spawn(move || {
                use std::io::{BufRead, Write};
                let mut found: Vec<(String, String)> = Vec::new();
                let mut reader = std::io::BufReader::new(err);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            // 原样转发:改管道后必须转发,否则用户看不到程序输出
                            let _ = std::io::stderr().write_all(line.as_bytes());
                            if let Some((p, a)) = crate::common::stderr_scan::extract_denied(&line)
                            {
                                if !found.iter().any(|(x, _): &(String, String)| *x == p) {
                                    found.push((p, a.to_string()));
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tx.send(found);
            });
        }
    } else {
        drop(tx);
    }

    // 归属集合:覆盖「入口 + 入口 fork 出来的子进程」。
    // 事件驱动(kqueue NOTE_FORK)为主:内核投递的 fork 事件即使进程已退出
    // 仍在队列里,故不漏短命子进程(实测整条命令只跑 12ms,采样式快照必漏);
    // ps 快照作为兜底,覆盖 kqueue 不可用时仍存活的成员。
    let capture = cfg!(target_os = "macos") && policy.broker.capture_violations();
    let watcher = if capture {
        crate::unix::proctree::ForkWatcher::new(pid)
    } else {
        None
    };
    let mut tree: Vec<u32> = vec![pid];
    if capture {
        for p in crate::unix::proctree::snapshot_pgid(pgid as u32) {
            if !tree.contains(&p) {
                tree.push(p);
            }
        }
    }
    let status = loop {
        if let Some(w) = &watcher {
            // ① 先取已入队的 fork 事件(非阻塞):这是退出前最后一次机会,不能漏。
            let (forks, _) = w.wait(0);
            for p in forks {
                if !tree.contains(&p) {
                    tree.push(p);
                }
            }
            // ② 再看子进程是否已退出。
            let st = match child.try_wait() {
                Ok(Some(st)) => Some(st),
                Ok(None) => None,
                Err(e) => return Err(format!("等待沙箱命令失败: {e}")),
            };
            if let Some(st) = st {
                // 退出瞬间可能还有刚入队的 fork 事件,再取一次。
                let (forks, _) = w.wait(0);
                for p in forks {
                    if !tree.contains(&p) {
                        tree.push(p);
                    }
                }
                break st;
            }
            // ③ 阻塞等下一个事件(不忙轮询)。
            let (forks, _) = w.wait(POLL_MS as i32);
            for p in forks {
                if !tree.contains(&p) {
                    tree.push(p);
                }
            }
        } else {
            match child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(POLL_MS)),
                Err(e) => return Err(format!("等待沙箱命令失败: {e}")),
            }
        }
    };
    // 注意:这里【不】kill 进程组。采集内核违规日志需要进程组里的进程还活着
    // (违规进程退出后无法反查其进程组,归属就降级)。回收由调用方在采集之后做。
    Ok(SpawnOutcome {
        code: status
            .code()
            .unwrap_or(if status.success() { 0 } else { 1 }),
        pid,
        pgid: pgid as u32,
        tree,
        stderr_rx: if capture_stderr { Some(rx) } else { None },
    })
}
