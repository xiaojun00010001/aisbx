//! bubblewrap 参数生成(方案 B 的 Linux 静态隔离层)。
//! 只读根 + 白名单/授权目录 bind + 空 /tmp + 独立 netns + 禁止嵌套 userns(反逃逸)。

use std::path::Path;

use aisbx_policy::Policy;

use crate::unix::run::RunCtx;

fn command_exists(name: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).any(|d| d.join(name).is_file())
}

fn canon(p: &str) -> String {
    std::fs::canonicalize(p)
        .map(|x| x.to_string_lossy().to_string())
        .unwrap_or_else(|_| p.to_string())
}

pub fn argv(policy: &Policy, cmd: &[String], ctx: &RunCtx) -> Result<Vec<String>, String> {
    if !command_exists("bwrap") {
        return Err("bubblewrap 不可用:拒绝以无约束方式执行(fail-closed)".into());
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("取当前可执行文件路径失败: {e}"))?
        .to_string_lossy()
        .to_string();

    let mut v: Vec<String> = vec![
        "bwrap".into(),
        "--ro-bind".into(), "/".into(), "/".into(),
        "--tmpfs".into(), "/tmp".into(),
        "--dev".into(), "/dev".into(),
        "--unshare-user".into(),  // --disable-userns 依赖 user namespace
        "--unshare-pid".into(),
        "--unshare-net".into(),   // 外网默认全断;helper 里把 lo 置 up 放行回环
        "--disable-userns".into(), // 防沙箱内自建 userns 后 mount/umount 拆掉只读 bind
        "--clearenv".into(),
    ];

    // 只读挂载必须排在可写 bind 之前:bwrap 按顺序挂载,后出现的 ro-bind
    // (尤其策略文件父目录)会覆盖其下已建立的 rw bind,使白名单/授权目录变只读。
    let broker_dir = ctx.broker_dir.to_string_lossy().to_string();
    v.push("--ro-bind".into());
    v.push(broker_dir.clone());
    v.push(broker_dir.clone());
    // --tmpfs /tmp 会隐藏 /tmp 下的策略文件;沙箱内 `aisbx escalate -p` 需要读它
    if let Some(parent) = Path::new(&ctx.policy_file).parent() {
        let dir = canon(&parent.to_string_lossy());
        if Path::new(&dir).is_dir() {
            v.push("--ro-bind".into());
            v.push(dir.clone());
            v.push(dir);
        }
    }

    // 策略白名单 + 本次已授权路径(B 契约:授权只影响下一次执行的策略快照)
    let mut rw: Vec<String> = policy
        .filesystem
        .write
        .iter()
        .map(|p| canon(&crate::common::expand_path(p)))
        .collect();
    rw.extend(ctx.granted.iter().map(|p| canon(p)));
    rw.sort();
    rw.dedup();
    for p in &rw {
        if Path::new(p).is_dir() {
            v.push("--bind".into());
            v.push(p.clone());
            v.push(p.clone());
        }
    }
    for p in &policy.filesystem.read {
        let c = canon(&crate::common::expand_path(p));
        if Path::new(&c).is_dir() {
            v.push("--ro-bind".into());
            v.push(c.clone());
            v.push(c);
        }
    }

    let envs: Vec<(&str, String)> = vec![
        ("AISBX_ATTEMPT", ctx.attempt.to_string()),
        ("AISBX_BROKER_DIR", broker_dir),
        ("AISBX_COMMAND_ID", ctx.command_id.clone()),
        ("AISBX_GRANTED_PATHS", ctx.granted.join(":")),
        ("AISBX_POLICY_FILE", ctx.policy_file.clone()),
        ("AISBX_TOKEN", ctx.token.clone()),
        (
            "AISBX_CLI",
            std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        ),
        ("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())),
        ("HOME", std::env::var("HOME").unwrap_or_default()),
    ];
    for (k, val) in envs {
        v.push("--setenv".into());
        v.push(k.into());
        v.push(val);
    }

    v.push("--".into());
    v.push(exe);
    v.push("__linux_helper".into());
    v.push(serde_json::to_string(cmd).map_err(|e| format!("序列化命令失败: {e}"))?);
    Ok(v)
}
