//! Seatbelt(SBPL)profile 生成器。基线经 macOS 26.3 真机验证:
//! `(deny default)` + 白名单写 + 仅回环网络,Rust 二进制可正常 exec。

use aisbx_policy::Policy;

use crate::core::decision;
use crate::unix::run::RunCtx;

fn canon(p: &str) -> String {
    decision::real_path(&crate::common::expand_path(p))
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn profile(policy: &Policy, ctx: &RunCtx) -> String {
    let mut out = String::from("(version 1)\n(deny default)\n");
    // 读取:允许系统,显式拒绝常见凭据目录
    out.push_str("(allow file-read*)\n");
    if let Ok(home) = std::env::var("HOME") {
        for sub in [".ssh", ".aws", ".gnupg", ".kube", ".docker"] {
            let p = canon(&format!("{home}/{sub}"));
            out.push_str(&format!("(deny file-read* (subpath \"{}\"))\n", esc(&p)));
        }
    }
    // broker 的 Unix domain socket:deny default 会连 UDS connect 一起挡。
    // 实测 (local unix-socket (subpath ...)) 能精确限定到单个 socket,不放开外网、
    // 也不放开其它本机 socket(避免 docker.sock 类逃逸);两种路径拼写都登记以兼容 /var ↔ /private/var。
    let broker_dir = canon(&ctx.broker_dir.to_string_lossy());
    let esc_canon = format!("{broker_dir}/esc.sock");
    let esc_raw = ctx.broker_dir.join("esc.sock").to_string_lossy().to_string();
    out.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", esc(&broker_dir)));
    out.push_str(&format!("(allow network* (local unix-socket (subpath \"{}\")))\n", esc(&esc_canon)));
    out.push_str(&format!("(allow network* (local unix-socket (subpath \"{}\")))\n", esc(&esc_raw)));
    // 写入:仅策略白名单 + 用户授权路径(B 契约:授权进入下一次执行的策略快照)
    out.push_str("(allow file-write* (literal \"/dev/null\"))\n");
    let mut writable: Vec<String> = policy
        .filesystem
        .write
        .iter()
        .map(|p| canon(&crate::common::expand_path(p)))
        .collect();
    writable.extend(ctx.granted.iter().map(|p| canon(p)));
    writable.sort();
    writable.dedup();
    for p in writable {
        if !p.is_empty() {
            out.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", esc(&p)));
        }
    }
    // 运行所需的最小能力
    out.push_str("(allow process-exec)\n(allow process-fork)\n(allow sysctl-read)\n");
    out.push_str("(allow mach-lookup)\n(allow file-map-executable)\n");
    // 网络:仅回环。
    // 注意:不能加 (allow network* (local ip "localhost:*"))——任何出站连接的 local ip
    // 都是本机接口,那条规则会匹配并放开【所有】外网连接(实测 1.1.1.1 从 EPERM 变 timeout)。
    // 只给 remote=localhost 的 allow,其余由 deny default 拒绝(实测外网 EPERM errno=1)。
    out.push_str("(allow network* (remote ip \"localhost:*\"))\n");
    out
}

/// 生成 `sandbox-exec -p <profile> <cmd...>`
pub fn argv(policy: &Policy, cmd: &[String], ctx: &RunCtx) -> Result<Vec<String>, String> {
    if !std::path::Path::new("/usr/bin/sandbox-exec").is_file() {
        return Err("sandbox-exec 不可用:拒绝以无约束方式执行(fail-closed)".into());
    }
    let p = profile(policy, ctx);
    let mut v = vec![
        "/usr/bin/sandbox-exec".to_string(),
        "-p".to_string(),
        p,
    ];
    v.extend(cmd.iter().cloned());
    Ok(v)
}
