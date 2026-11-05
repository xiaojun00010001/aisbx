//! `aisbx run` 编排:策略 -> SID -> ACL -> token -> Job -> broker -> 进程 -> 等待 -> 清理。

use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

use aisbx_policy::Policy;

use crate::common::expand_all;
use crate::win::{acl, broker, job, loopback, proc, token};

/// capability SID 常量表(well-known)
const CAP_INTERNET_CLIENT: &str = "S-1-15-3-1";
const CAP_PRIVATE_NETWORK: &str = "S-1-15-3-3";

pub fn run_windows(policy: &Policy, policy_file: &str, cmd: &[String], json: bool) -> Result<i32, String> {
    let emit = |e: serde_json::Value| if json { println!("{e}"); };

    // 1. 任务级 package SID(一次任务一次,token/Job/ACL/授权缓存全部挂在这上面)
    let package_sid = token::generate_package_sid(&policy.task)?;
    emit(serde_json::json!({"event": "sid", "sid": &package_sid}));

    // 2. 路径展开
    let write_dirs = expand_all(&policy.filesystem.write);
    let read_dirs = expand_all(&policy.filesystem.read);
    let cwd = write_dirs.first().map(|p| p.display().to_string());

    // 3. 白名单 ACL:写目录(M) / 读目录(RX) / 策略文件(R,供沙箱内 escalate 读取)
    for d in &write_dirs {
        acl::grant_dir(&package_sid, &d.display().to_string(), true)?;
    }
    for d in &read_dirs {
        acl::grant_dir(&package_sid, &d.display().to_string(), false)?;
    }
    acl::grant_file(&package_sid, policy_file, false)?;
    let mut granted_paths: Vec<String> = write_dirs.iter().chain(read_dirs.iter())
        .map(|p| p.display().to_string()).collect();
    granted_paths.push(policy_file.to_string());

    // 4. 网络:回环例外(不开 internet capability)
    //    写入失败不阻断整个任务:exception 表打满时仍可完成文件/资源等隔离验证,
    //    回环可达性由 T4 断言真实反映。
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
    let mut caps: Vec<&str> = Vec::new();
    if policy.network.internet {
        caps.push(CAP_INTERNET_CLIENT);
        caps.push(CAP_PRIVATE_NETWORK);
    }
    let h_token = unsafe { token::create_lowbox_token(&package_sid, &caps)? };

    // 6. Job 预算
    let jb = job::create(&policy.resources)?;

    // 7. broker 管道(必须先于进程,沙箱内才能连上)
    let _stop = broker::start_server(policy, &package_sid);

    // 8. 创建(挂起) -> 入 Job -> 恢复
    let child = proc::spawn_suspended(h_token, cmd, cwd.as_deref())?;
    jb.assign(child.process)?;
    child.resume()?;
    emit(serde_json::json!({"event": "spawned", "cmd": cmd}));

    // 9. 等待主进程退出,再等 Job 内全部子孙进程收敛(KILL_ON_JOB_CLOSE 兜底)
    let code = child.wait_exit_code()?;
    unsafe { WaitForSingleObject(jb.handle, INFINITE) };

    // 10. 清理:撤 ACL、回收回环例外、关句柄(SID/token/Job 随对象废弃)
    for p in &granted_paths {
        acl::revoke(&package_sid, p);
    }
    if policy.network.loopback {
        loopback::revoke_loopback(&package_sid);
    }
    unsafe { token::drop_token(h_token) };
    emit(serde_json::json!({"event": "exit", "code": code}));
    Ok(code as i32)
}
