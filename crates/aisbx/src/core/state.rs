//! 一次 `run` 的共享状态:broker 线程与 launcher 重试循环共用。

use aisbx_policy::Policy;
use serde_json::{json, Value};

use super::audit::Audit;
use super::protocol::EscRequest;
use super::tokens::TokenStore;

/// 一次真实越界。三平台、三种采集来源统一成同一条对外事件。
/// source: "explicit"(程序主动上报) | "proxy"(网络代理) | "sandbox-log"(内核违规日志)
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
    pub source: String,
}

impl Violation {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

pub struct State {
    pub policy: Policy,
    pub audit: Audit,
    pub tokens: TokenStore,
    pub violations: Vec<Violation>,
    /// 用户同意后放宽的路径(B 契约:下一次执行的策略快照使用)
    pub granted: Vec<String>,
    /// 本次任务已放行的网络目标(host:port 或 host)。代理运行中可热更新,不需重跑。
    pub granted_nets: Vec<String>,
    /// 沙箱入口登记的真实目标进程 PID,供内核违规日志按 PID 精确归属。
    pub child_pids: Vec<u32>,
    /// 后台线程(代理/日志采集)产生的待发事件,由 launcher drain 后统一 emit。
    pub events: Vec<Value>,
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
            granted_nets: Vec::new(),
            child_pids: Vec::new(),
            events: Vec::new(),
            attempt: 1,
            retries: 0,
            last_token: String::new(),
            command_id,
            needs_approval: false,
        }
    }

    /// 后台线程统一入口:写审计 + 排队给 launcher 发 --json 事件。
    pub fn emit_event(&mut self, event: Value) {
        self.audit.log(&event);
        self.events.push(event);
    }

    /// 记一次网络越界(由必经代理观察到的真实 CONNECT,非解析命令得来)。
    pub fn net_violation(&mut self, host: &str, ip: &str, port: u16, reason: &str) {
        let v = Violation {
            event: "violation".into(),
            attempt: self.attempt,
            kind: "net".into(),
            path: String::new(),
            access: String::new(),
            host: host.into(),
            ip: ip.into(),
            port,
            reason: reason.into(),
            command_id: self.command_id.clone(),
            source: "proxy".into(),
        };
        self.emit_event(v.to_value());
        self.violations.push(v);
    }

    /// 记一次内核违规日志采集到的文件越界(P1,程序零配合)。
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn external_file_violation(&mut self, path: &str, access: &str, pid: u32) {
        if self
            .violations
            .iter()
            .any(|v| v.kind == "file" && v.path == path && v.source == "sandbox-log")
        {
            return; // 同一路径去重:重跑时不应重复上报
        }
        let v = Violation {
            event: "violation".into(),
            attempt: self.attempt,
            kind: "file".into(),
            path: path.into(),
            access: access.into(),
            host: String::new(),
            ip: String::new(),
            port: 0,
            reason: "needs-approval".into(),
            command_id: self.command_id.clone(),
            source: "sandbox-log".into(),
        };
        self.emit_event(json!({
            "event": "violation.captured", "source": "sandbox-log",
            "path": path, "access": access, "pid": pid, "command_id": self.command_id
        }));
        self.emit_event(v.to_value());
        self.violations.push(v);
        self.needs_approval = true;
    }

    /// 运行中放行一个网络目标(仅本次任务,不写回基线策略文件)。
    pub fn grant_net(&mut self, host: &str, port: u16) {
        let key = Self::net_key(host, port);
        if !self.granted_nets.contains(&key) {
            self.granted_nets.push(key.clone());
        }
        self.emit_event(json!({
            "event": "net.grant", "host": host, "port": port,
            "target": key, "scope": "task", "command_id": self.command_id
        }));
    }

    pub fn net_allowed(&self, host: &str, port: u16) -> bool {
        let key = Self::net_key(host, port);
        self.granted_nets.iter().any(|k| k == &key || k == host)
    }

    pub fn net_key(host: &str, port: u16) -> String {
        format!("{}:{}", host.to_ascii_lowercase(), port)
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
            source: "explicit".into(),
        };
        if reason == "needs-approval" {
            self.needs_approval = true;
        }
        self.audit.log(&v.to_value());
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
