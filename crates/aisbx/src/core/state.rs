//! 一次 `run` 的共享状态:broker 线程与 launcher 重试循环共用。

use aisbx_policy::Policy;

use super::audit::Audit;
use super::protocol::EscRequest;
use super::tokens::TokenStore;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Violation {
    pub event: String,
    pub attempt: u32,
    pub kind: String,
    pub path: String,
    pub access: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub reason: String,
    pub command_id: String,
}

pub struct State {
    pub policy: Policy,
    pub audit: Audit,
    pub tokens: TokenStore,
    pub violations: Vec<Violation>,
    /// 用户同意后放宽的路径(B 契约:下一次执行的策略快照使用)
    pub granted: Vec<String>,
    pub attempt: u32,
    pub retries: u32,
    pub last_token: String,
    pub command_id: String,
    /// 是否存在「需要用户授权」的真实拒绝(launcher 只为此等待)
    pub needs_approval: bool,
}

impl State {
    pub fn new(policy: Policy, command_id: String) -> Self {
        let audit = Audit::new(policy.broker.audit_log.as_deref());
        Self {
            policy,
            audit,
            tokens: TokenStore::default(),
            violations: Vec::new(),
            granted: Vec::new(),
            attempt: 1,
            retries: 0,
            last_token: String::new(),
            command_id,
            needs_approval: false,
        }
    }

    /// 记录一次真实拒绝。B 契约要求:只能由真实发生的拒绝触发授权。
    pub fn violation(&mut self, req: &EscRequest, kind: &str, reason: &str) {
        let v = Violation {
            event: "violation".into(),
            attempt: self.attempt,
            kind: kind.into(),
            path: req.path.clone(),
            access: req.access.clone(),
            host: req.host.clone(),
            ip: req.ip.clone(),
            port: req.port,
            reason: reason.into(),
            command_id: self.command_id.clone(),
        };
        if reason == "needs-approval" {
            self.needs_approval = true;
        }
        self.audit.log(&serde_json::to_value(&v).unwrap_or_default());
        self.violations.push(v);
    }

    /// 是否已有针对该目标的真实拒绝(防伪造 violation 反复试探)。
    pub fn has_real_violation(&self, path: &str) -> bool {
        self.violations.iter().any(|v| {
            if v.kind != "file" {
                return false;
            }
            // 程序上报的是具体文件,agent 授权的可能是其父目录:双向前缀都算相关
            super::decision::is_prefix_hit(std::slice::from_ref(&v.path), path)
                || super::decision::is_prefix_hit(&[path.to_string()], &v.path)
        })
    }

    /// 新策略必须严格宽于旧策略:仅在既有白名单之外追加授权路径。
    pub fn widen(&mut self, path: &str) {
        if !self.granted.iter().any(|p| super::decision::compare_key(p) == super::decision::compare_key(path)) {
            let in_policy = super::decision::is_prefix_hit(&self.policy.filesystem.write, path)
                || super::decision::is_prefix_hit(&self.policy.filesystem.read, path);
            if !in_policy {
                self.granted.push(path.to_string());
            }
        }
    }
}
