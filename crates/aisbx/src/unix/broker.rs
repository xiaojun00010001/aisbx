//! UDS broker:两条通道(沙箱内提权 / 宿主控制),共享一次 run 的状态。
//! 方案 B 闭环:拒绝 → violation(真实拒绝) → authorize(签发+放宽) → launcher 重跑。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aisbx_policy::{EscalationMode, Policy};
use serde_json::{json, Value};

use crate::core::decision;
use crate::core::protocol::{self, EscRequest};
use crate::core::state::State;

pub struct Broker {
    pub state: Arc<Mutex<State>>,
    pub dir: PathBuf,
    stop: Arc<AtomicBool>,
}

/// 运行时目录固定为 $TMPDIR/aisbx-<task>:宿主 authorize 只需 policy.task 即可找到控制通道。
pub fn runtime_dir(task: &str) -> PathBuf {
    std::env::temp_dir().join(format!("aisbx-{task}"))
}

impl Broker {
    pub fn start(policy: &Policy, command_id: &str) -> Result<Self, String> {
        let dir = runtime_dir(&policy.task);
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建 broker 目录失败: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let esc_path = dir.join("esc.sock");
        let ctl_path = dir.join("ctl.sock");
        let _ = std::fs::remove_file(&esc_path);
        let _ = std::fs::remove_file(&ctl_path);

        let state = Arc::new(Mutex::new(State::new(policy.clone(), command_id.to_string())));
        let stop = Arc::new(AtomicBool::new(false));

        let esc = bind(&esc_path)?;
        let ctl = bind(&ctl_path)?;
        spawn_server(esc, state.clone(), stop.clone(), false);
        spawn_server(ctl, state.clone(), stop.clone(), true);
        Ok(Self { state, dir, stop })
    }

    pub fn snapshot(&self) -> RunSnapshot {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        RunSnapshot {
            granted: s.granted.clone(),
            violations: s.violations.len(),
            token: s.last_token.clone(),
            command_id: s.command_id.clone(),
            needs_approval: s.needs_approval,
        }
    }

    pub fn emit(&self, event: Value) {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.audit.log(&event);
    }
}

#[allow(dead_code)]
#[derive(Clone, Default)]
pub struct RunSnapshot {
    pub granted: Vec<String>,
    pub violations: usize,
    pub token: String,
    pub command_id: String,
    pub needs_approval: bool,
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_file(self.dir.join("esc.sock"));
        let _ = std::fs::remove_file(self.dir.join("ctl.sock"));
        let _ = std::fs::remove_dir(&self.dir);
    }
}

fn bind(path: &Path) -> Result<UnixListener, String> {
    let l = UnixListener::bind(path).map_err(|e| format!("绑定 {} 失败: {e}", path.display()))?;
    l.set_nonblocking(true).map_err(|e| format!("set_nonblocking: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(l)
}

fn spawn_server(l: UnixListener, state: Arc<Mutex<State>>, stop: Arc<AtomicBool>, control: bool) {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match l.accept() {
                Ok((stream, _)) => {
                    let req_line = {
                        let mut reader = BufReader::new(&stream);
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => String::new(),
                            Ok(_) => line,
                        }
                    };
                    if req_line.trim().is_empty() {
                        continue;
                    }
                    let reply = if control {
                        handle_control(&state, &req_line)
                    } else {
                        handle_escalate(&state, &req_line)
                    };
                    if let Ok(mut w) = stream.try_clone() {
                        let _ = writeln!(w, "{reply}");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
}

fn handle_escalate(state: &Arc<Mutex<State>>, line: &str) -> String {
    let req: EscRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return protocol::denied(&format!("请求解析失败: {e}")),
    };
    let mut s = state.lock().unwrap_or_else(|p| p.into_inner());

    // command_id 由宿主注入,沙箱内不可伪造
    if !req.command_id.is_empty() && req.command_id != s.command_id {
        return protocol::denied("command_id 不匹配");
    }

    match req.op.as_str() {
        "file" => decide_file(&mut s, &req),
        "net" => {
            s.violation(&req, "net", "network-egress-denied");
            s.audit.log(&json!({
                "event": "escalation.deny", "op": "net",
                "host": req.host, "ip": req.ip, "port": req.port,
                "reason": "network-escalation-unsupported"
            }));
            protocol::denied("外网默认拒绝;按主机放行需代理(见 docs/05)")
        }
        other => protocol::denied(&format!("未知操作 {other}")),
    }
}

fn decide_file(s: &mut State, req: &EscRequest) -> String {
    let path = decision::real_path(&req.path);

    // 1) 不可授权黑名单:fail-closed,token 也救不回
    if decision::is_prefix_hit(&s.policy.filesystem.deny_escalation, &path) {
        s.violation(req, "file", "deny_escalation");
        s.audit.log(&json!({
            "event": "escalation.deny", "op": "file", "path": path,
            "reason": "deny_escalation"
        }));
        return protocol::denied("路径在不可授权黑名单内");
    }

    // 2) token 快速路径:一次性消费,重放必拒
    if !req.token.is_empty() {
        return match s.tokens.redeem(&req.token, &path, &req.access) {
            Ok(t) => {
                s.widen(&t.path);
                s.audit.log(&json!({
                    "event": "token.redeemed", "path": path, "access": req.access,
                    "command_id": s.command_id
                }));
                protocol::granted("已按授权 token 放宽下一次执行策略")
            }
            Err(e) => {
                s.audit.log(&json!({"event": "token.reject", "path": path, "reason": e}));
                protocol::denied(&format!("授权 token 校验失败: {e}"))
            }
        };
    }

    // 3) 策略裁决
    let mode = s.policy.escalation_mode();
    let auto_ok = matches!(mode, EscalationMode::Auto)
        && decision::is_prefix_hit(&s.policy.filesystem.allow_escalation, &path);
    let prompt_ok = matches!(mode, EscalationMode::Prompt) && decision::has_tty();

    if auto_ok || prompt_ok {
        s.widen(&path);
        s.audit.log(&json!({
            "event": "escalation.grant", "op": "file", "path": path,
            "access": req.access, "reason": format!("{mode:?}")
        }));
        return protocol::granted("策略已允许,下一次执行生效");
    }

    // 4) 需要用户授权:记录真实 violation,要求宿主签发后重跑
    s.violation(req, "file", "needs-approval");
    s.audit.log(&json!({
        "event": "escalation.deny", "op": "file", "path": path,
        "reason": format!("{mode:?}:user-or-policy"), "retry_required": true
    }));
    protocol::needs_approval("需要用户授权后重新执行")
}

fn handle_control(state: &Arc<Mutex<State>>, line: &str) -> String {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return protocol::denied(&format!("请求解析失败: {e}")),
    };
    let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let mut s = state.lock().unwrap_or_else(|p| p.into_inner());

    match op {
        "issue" => {
            let path = decision::real_path(req.get("path").and_then(|v| v.as_str()).unwrap_or(""));
            let access = req.get("access").and_then(|v| v.as_str()).unwrap_or("write");
            let ttl = req.get("ttl_seconds").and_then(|v| v.as_u64()).unwrap_or(300);
            if path.is_empty() || !matches!(access, "read" | "write") {
                return protocol::denied("path 为空或 access 非法");
            }
            // 只允许基于真实发生过的拒绝发起授权
            if !s.has_real_violation(&path) {
                s.audit.log(&json!({"event": "authorize.reject", "path": path, "reason": "no-real-violation"}));
                return protocol::denied("无真实拒绝记录,拒绝签发 token");
            }
            if decision::is_prefix_hit(&s.policy.filesystem.deny_escalation, &path) {
                return protocol::denied("路径在不可授权黑名单内");
            }
            let cid = s.command_id.clone();
            let token = s.tokens.issue(&path, access, ttl, &cid);
            s.last_token = token.clone();
            s.widen(&path);
            s.audit.log(&json!({
                "event": "token.issued", "path": path, "access": access, "ttl_seconds": ttl
            }));
            json!({"granted": true, "token": token, "path": path, "access": access, "expires_in": ttl}).to_string()
        }
        "status" => {
            json!({
                "attempt": s.attempt,
                "violations": s.violations.len(),
                "granted": s.granted,
                "retries": s.retries
            }).to_string()
        }
        other => protocol::denied(&format!("未知控制操作 {other}")),
    }
}

/// 沙箱内 `aisbx escalate`:连接 esc.sock(路径由 launcher 注入环境变量)。
pub fn escalate_client(req: &EscRequest) -> Result<i32, String> {
    let dir = std::env::var("AISBX_BROKER_DIR")
        .map_err(|_| "不在沙箱内:缺少 AISBX_BROKER_DIR".to_string())?;
    let reply = request(Path::new(&dir).join("esc.sock"), &serde_json::to_string(req).unwrap())?;
    println!("{reply}");
    let v: Value = serde_json::from_str(&reply).unwrap_or_default();
    Ok(if v.get("granted").and_then(|x| x.as_bool()).unwrap_or(false) { 0 } else { 1 })
}

/// 宿主侧 `aisbx authorize`:只需 policy.task 即可定位 ctl.sock。
pub fn authorize_client(policy: &Policy, path: &str, access: &str, ttl: u64) -> Result<i32, String> {
    let sock = runtime_dir(&policy.task).join("ctl.sock");
    let body = json!({"op":"issue","path":path,"access":access,"ttl_seconds":ttl}).to_string();
    let reply = request(sock, &body)?;
    println!("{reply}");
    let v: Value = serde_json::from_str(&reply).unwrap_or_default();
    Ok(if v.get("granted").and_then(|x| x.as_bool()).unwrap_or(false) { 0 } else { 1 })
}

/// 宿主侧查询状态(冒烟脚本轮询用)。
pub fn status_client(policy: &Policy) -> Result<String, String> {
    request(runtime_dir(&policy.task).join("ctl.sock"), r#"{"op":"status"}"#)
}

fn request(sock: PathBuf, body: &str) -> Result<String, String> {
    let mut s = UnixStream::connect(&sock)
        .map_err(|e| format!("连接 {} 失败: {e}(任务未运行?)", sock.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    writeln!(s, "{body}").map_err(|e| format!("写请求失败: {e}"))?;
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).map_err(|e| format!("读应答失败: {e}"))?;
    if line.trim().is_empty() {
        return Err("broker 无应答".into());
    }
    Ok(line.trim().to_string())
}
