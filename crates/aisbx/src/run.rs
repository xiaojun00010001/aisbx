//! `aisbx run` 编排:策略 -> SID -> ACL -> token -> Job -> broker -> 进程 -> 等待 -> 清理。

use windows_sys::Win32::System::JobObjects::{
    JobObjectBasicProcessIdList, QueryInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use aisbx_policy::Policy;

use crate::common::expand_all;
use crate::win::{acl, broker, job, loopback, netproxy, proc, token};

/// capability SID 常量表(well-known)
const CAP_INTERNET_CLIENT: &str = "S-1-15-3-1";
const CAP_PRIVATE_NETWORK: &str = "S-1-15-3-3";

pub fn run_windows(
    policy: &Policy,
    policy_file: &str,
    cmd: &[String],
    json: bool,
) -> Result<i32, String> {
    let emit = |e: serde_json::Value| {
        if json {
            println!("{e}");
        }
    };
    let trace = |stage: &str| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        eprintln!("[aisbx-trace {ts}] {stage}");
    };

    // 1. 任务级 package SID(一次任务一次,token/Job/ACL/授权缓存全部挂在这上面)
    trace("stage1 package-sid");
    let package_sid = token::generate_package_sid(&policy.task)?;
    emit(serde_json::json!({"event": "sid", "sid": &package_sid}));

    // 2. 路径展开
    trace("stage2 expand");
    let write_dirs = expand_all(&policy.filesystem.write);
    let read_dirs = expand_all(&policy.filesystem.read);
    let cwd = write_dirs.first().map(|p| p.display().to_string());

    // 3. 白名单 ACL:写目录(M) / 读目录(RX) / 策略文件(R,供沙箱内 escalate 读取)
    trace("stage3 acl");
    for d in &write_dirs {
        acl::grant_dir(&package_sid, &d.display().to_string(), true)?;
    }
    for d in &read_dirs {
        acl::grant_dir(&package_sid, &d.display().to_string(), false)?;
    }
    acl::grant_file(&package_sid, policy_file, false)?;
    let mut granted_paths: Vec<String> = write_dirs
        .iter()
        .chain(read_dirs.iter())
        .map(|p| p.display().to_string())
        .collect();
    granted_paths.push(policy_file.to_string());

    // 4. 网络:回环例外(不开 internet capability)
    //    写入失败不阻断整个任务:exception 表打满时仍可完成文件/资源等隔离验证,
    //    回环可达性由 T4 断言真实反映。
    trace("stage4 loopback");
    if policy.network.loopback {
        match loopback::exempt_loopback(&package_sid) {
            Ok(()) => emit(serde_json::json!({"event": "network", "loopback": true})),
            Err(e) => {
                eprintln!("aisbx: 警告: 回环例外写入失败,将在无回环能力下继续: {e}");
                emit(serde_json::json!({"event": "network", "loopback": false, "error": e}));
            }
        }
    }

    // 5. LowBox token(internet=true 时注入 capability)
    trace("stage5 lowbox-token");
    let mut caps: Vec<&str> = Vec::new();
    if policy.network.internet {
        caps.push(CAP_INTERNET_CLIENT);
        caps.push(CAP_PRIVATE_NETWORK);
    }
    let h_token = unsafe { token::create_lowbox_token(&package_sid, &caps)? };

    // 6. Job 预算
    trace("stage6 job");
    let jb = job::create(&policy.resources)?;

    // 7. broker 管道(必须先于进程,沙箱内才能连上)
    trace("stage7 broker");
    let broker = broker::start_server(policy, &package_sid);

    // 7b. P0 网络代理:宿主回环监听 + 注入代理环境变量。
    //     AppContainer 已有回环例外,沙箱内程序通过 HTTP(S)_PROXY 连到宿主代理,
    //     代理从 CONNECT 拿到真实 host:port,不需要程序改造、不需要解析命令。
    let netproxy = netproxy::start(broker.net_state.clone(), broker.audit.clone())?;
    let saved_env = install_proxy_env(netproxy.port);
    emit(serde_json::json!({"event": "proxy", "port": netproxy.port, "mode": "http-connect"}));

    // 8~9. 执行循环(B 契约:授权后把该路径并入策略快照并重跑)。
    //
    // 语义与 Unix 侧(run_loop)对齐:
    // - 每轮把「宿主已授权的路径」并入本轮白名单(落 ACL)——这就是更宽的策略快照;
    // - 命令失败后,只有存在「需要用户授权」的拒绝才等待(有上限),其它失败直接退出;
    // - 授权到达 → 重跑(最多 MAX_ATTEMPTS 轮)。
    //
    // 注:Windows 仍保留「运行中 in-place 放行」(broker 收到 token 即落 ACE),
    // 但它只是 legacy 加速路径——**重跑才是主线**,两者不冲突:
    // in-place 生效后命令若已成功,本轮 code==0 直接退出,不会重跑。
    const WAIT_AUTH_SECS: u64 = 20;
    const MAX_ATTEMPTS: u32 = 3;
    let mut attempt: u32 = 1;
    let mut code: u32;
    loop {
        // 8a. 已授权路径并入本轮白名单(落 ACL)——「更宽的策略快照」
        {
            let granted = broker
                .granted_paths
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            for g in granted.iter() {
                if granted_paths.iter().any(|x| x.eq_ignore_ascii_case(g)) {
                    continue;
                }
                // 授权路径可能尚不存在(被拒的正是「要创建的文件」),
                // 故用 grant_path:它会改为对父目录授可继承 ACE。
                match acl::grant_path_precise(&package_sid, g, true) {
                    Ok(target) => {
                        granted_paths.push(g.clone());
                        // 任务结束统一撤销(C20:不留持久 ACL 残余)
                        if let Ok(mut list) = broker.granted_acl.lock() {
                            list.push(target);
                        }
                    }
                    Err(e) => eprintln!("aisbx: 警告: 授权路径落 ACL 失败 {g}: {e}"),
                }
            }
        }

        // 8b. 创建(挂起) -> 入 Job -> 恢复
        trace("stage8 spawn");
        // L1(stderr 自报路径):开启采集时把子进程 stderr 接到管道,父进程边读边转发
        // (用户可见性不变)边扫描被拒路径。默认不接管 stderr,行为逐字节不变。
        let capture_stderr = policy.broker.capture_violations();
        let (child, stderr_rx) = if capture_stderr {
            let (r, w) = proc::create_stderr_pipe()?;
            let c = proc::spawn_suspended_with_stderr(h_token, cmd, cwd.as_deref(), w)?;
            // 父进程侧必须关掉写端,否则管道永远不 EOF
            unsafe { windows_sys::Win32::Foundation::CloseHandle(w) };
            let (tx, rx) = std::sync::mpsc::channel::<Vec<(String, String)>>();
            std::thread::spawn(move || {
                let found = proc::read_stderr_scan(r);
                let _ = tx.send(found);
            });
            (c, Some(rx))
        } else {
            (proc::spawn_suspended(h_token, cmd, cwd.as_deref())?, None)
        };
        jb.assign(child.process)?;
        child.resume()?;
        emit(serde_json::json!({"event": "spawned", "cmd": cmd, "attempt": attempt}));

        // 9. 等待主进程退出,再等 Job 内全部子孙进程收敛(KILL_ON_JOB_CLOSE 兜底)
        trace("stage9 wait-child");
        code = child.wait_exit_code()?;
        trace("stage9b wait-job");
        // 有限等待 + 兜底强杀:Job 内进程不收敛时避免无限挂起,并枚举残留 PID 供诊断
        let wr = unsafe { WaitForSingleObject(jb.handle, 2_000) };
        if wr != 0 {
            let mut buf = [0u8; 4096];
            let mut ret: u32 = 0;
            let ok = unsafe {
                QueryInformationJobObject(
                    jb.handle,
                    JobObjectBasicProcessIdList,
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    buf.len() as u32,
                    &mut ret,
                )
            };
            let n = if ok != 0 {
                usize::from_ne_bytes(buf[0..8].try_into().unwrap())
            } else {
                0
            };
            if n == 0 {
                // Job 已空但句柄未转 signaled:无需强杀(KILL_ON_JOB_CLOSE 兜底)
            } else {
                let mut pids = String::new();
                for i in 0..n.min(16) {
                    let pid = usize::from_ne_bytes(buf[8 + i * 8..16 + i * 8].try_into().unwrap());
                    pids.push_str(&pid.to_string());
                    pids.push(' ');
                }
                eprintln!("aisbx: 警告: Job 内残留进程 {n} 个({pids}),2s 未收敛,强制终止");
                unsafe { TerminateJobObject(jb.handle, 1) };
            }
        }

        // 9c. L1:程序自报路径。归属确定(stderr 来自本次执行的进程),但路径是
        // 程序【自称】的,可被伪造 → precision=reported,只用于生成授权请求。
        // 这对 Windows 尤其关键:`ERROR_ACCESS_DENIED` 本身**不含路径**,而 Windows
        // 是唯一能「运行中精确放行」的平台(追加 ACE 即刻生效)——L1 正好补上
        // 「该放行谁」这一环,让 in-place 放行从「整条命令豁免」变成「只开这一个路径」。
        if let Some(rx) = stderr_rx {
            if let Ok(found) = rx.recv_timeout(std::time::Duration::from_secs(2)) {
                for (p, access) in found {
                    // 白名单内的路径本不该被拒,出现即噪声
                    let allowed = policy
                        .filesystem
                        .write
                        .iter()
                        .chain(policy.filesystem.read.iter())
                        .any(|base| crate::common::path_prefix_hit(std::slice::from_ref(base), &p));
                    if allowed {
                        continue;
                    }
                    broker.audit.log(&serde_json::json!({
                        "event": "violation", "kind": "file", "path": p, "access": access,
                        "precision": "reported", "attributed": true,
                        "source": "stderr-selfreport", "reason": "needs-approval"
                    }));
                    emit(serde_json::json!({
                        "event": "violation.captured", "source": "stderr-selfreport",
                        "path": p, "access": access, "attributed": true, "precision": "reported"
                    }));
                    // 采集到越界 → 需要用户授权(launcher 才会等待并重跑)
                    broker
                        .needs_approval
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    // 记入待授权列表:`aisbx status` 会把它交给 agent 去问用户
                    if let Ok(mut pend) = broker.pending.lock() {
                        pend.push(crate::common::pending::PendingViolation {
                            kind: "file".into(),
                            path: p.clone(),
                            access: access.clone(),
                            host: String::new(),
                            port: 0,
                            source: "stderr-selfreport".into(),
                            precision: "reported".into(),
                            attributed: true,
                        });
                    }
                }
            }
        }

        emit(serde_json::json!({"event": "exit", "attempt": attempt, "code": code}));

        // 9d. 等宿主授权(B 契约)。只在「需要用户授权」时等(有上限);
        //     黑名单 / 策略拒绝等不等待,直接退出。
        if code == 0 || attempt >= MAX_ATTEMPTS {
            break;
        }
        if !broker
            .needs_approval
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        let before = broker.granted_paths.lock().map(|g| g.len()).unwrap_or(0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(WAIT_AUTH_SECS);
        let mut widened = false;
        while std::time::Instant::now() < deadline {
            let now = broker.granted_paths.lock().map(|g| g.len()).unwrap_or(0);
            if now > before {
                widened = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !widened {
            break;
        }
        emit(serde_json::json!({
            "event": "retry", "from": attempt, "to": attempt + 1, "reason": "user-approved"
        }));
        attempt += 1;
    }

    // 10. 清理:撤 ACL、回收回环例外、恢复环境、关句柄(SID/token/Job 随对象废弃)
    trace("stage10 cleanup");
    restore_proxy_env(saved_env);
    drop(netproxy);
    // C20:撤销运行中提权新落的 ACE(此前只撤启动白名单,会留下持久 ACL 残余)。
    if let Ok(list) = broker.granted_acl.lock() {
        for p in list.iter() {
            acl::revoke(&package_sid, p);
        }
    }
    for p in &granted_paths {
        acl::revoke(&package_sid, p);
    }
    let _ = &broker; // 句柄内的 stop 在 run_windows 返回时统一释放
    if policy.network.loopback {
        loopback::revoke_loopback(&package_sid);
    }
    unsafe { token::drop_token(h_token) };
    Ok(code as i32)
}

const PROXY_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// CreateProcessAsUserW 传 NULL 环境 = 继承宿主环境,因此 set_var 即可注入代理变量。
/// 返回原值,任务结束后恢复,避免污染宿主线程后续任务。
fn install_proxy_env(port: u16) -> Vec<(&'static str, Option<String>)> {
    let saved: Vec<(&'static str, Option<String>)> = PROXY_KEYS
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
    let http_proxy = format!("http://127.0.0.1:{port}");
    for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
        std::env::set_var(k, &http_proxy);
    }
    // 同一代理端口按首字节分流:0x05 = SOCKS5,否则 HTTP CONNECT。
    let socks_proxy = format!("socks5h://127.0.0.1:{port}");
    std::env::set_var("ALL_PROXY", &socks_proxy);
    std::env::set_var("all_proxy", &socks_proxy);
    std::env::set_var("NO_PROXY", "localhost,127.0.0.1,::1");
    std::env::set_var("no_proxy", "localhost,127.0.0.1,::1");
    saved
}

fn restore_proxy_env(saved: Vec<(&'static str, Option<String>)>) {
    for (k, v) in saved {
        match v {
            Some(x) => std::env::set_var(k, x),
            None => std::env::remove_var(k),
        }
    }
}
