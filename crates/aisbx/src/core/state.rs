//! 一次 `run` 的共享状态:broker 线程与 launcher 重试循环共用。

use aisbx_policy::Policy;
use serde_json::{json, Value};

use super::audit::Audit;
use super::protocol::EscRequest;
use super::tokens::TokenStore;
use crate::common::pending::PendingViolation;

/// 一次真实越界。三平台、三种采集来源统一成同一条对外事件。
/// source: "explicit"(程序主动上报) | "proxy"(网络代理) | "sandbox-log"(内核违规日志)
///
/// `precision` 标注这条越界信息的路径精度,决定它能被用到什么程度:
/// - "exact":内核或协议**自带**的精确绝对路径(Seatbelt violation 日志、
///   代理 CONNECT 目标)。可直接用于生成授权请求。
/// - "reported":程序**自己声称**的路径(stderr 自报 / 沙箱内主动 escalate)。
///   可用于生成授权请求(最坏情况是多问一次用户),**不可用于自动放行**——
///   被沙箱约束的程序可以自称一个无害路径来骗过采集器。
/// - "none":拿不到具体目标。
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
    pub precision: String,
    /// 能否证明这次越界来自本次沙箱执行。
    /// false = 路径精确(内核给的),但没能归属到本次执行(例如违规进程已退出
    /// 且不在已知 PID 集合内)。这类条目只能用于生成授权请求,**不能自动放行**。
    pub attributed: bool,
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
            // CONNECT 目标由协议自带,不是我们从命令里猜的 → 精确。
            precision: "exact".into(),
            // 代理是自己在数据路径上观察到的 → 天然归属于本次执行。
            attributed: true,
        };
        self.emit_event(v.to_value());
        self.violations.push(v);
    }

    /// 记一次内核违规日志采集到的文件越界(P1,程序零配合)。
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn external_file_violation(
        &mut self,
        path: &str,
        access: &str,
        pid: u32,
        attributed: bool,
    ) {
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
            // 内核日志自带被拒的完整精确路径 → 精确。
            precision: "exact".into(),
            attributed,
        };
        self.emit_event(json!({
            "event": "violation.captured", "source": "sandbox-log",
            "path": path, "access": access, "pid": pid,
            "attributed": attributed, "command_id": self.command_id
        }));
        self.emit_event(v.to_value());
        self.violations.push(v);
        self.needs_approval = true;
    }

    /// 记一次【未能归属到本次执行】的内核违规日志条目。
    ///
    /// 它**不是**我们的越界:极可能是同机其它沙箱/应用的违规(实测能捞到
    /// Chrome、wifip2pd 的记录)。所以它只进审计与事件流,**不进 violations
    /// 列表、不置 needs_approval** —— 否则等于让用户去授权一个毫不相干的
    /// 路径(真实越权风险),而且还能被拿来伪造「真实拒绝」骗过 token 签发。
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn unattributed_file_violation(&mut self, path: &str, access: &str, pid: u32) {
        self.emit_event(json!({
            "event": "violation.unattributed", "source": "sandbox-log",
            "path": path, "access": access, "pid": pid, "attributed": false,
            "reason": "not attributable to this execution", "command_id": self.command_id
        }));
    }

    /// 记一次【程序自报】的文件越界(L1:从被跑程序的 stderr 里提取)。
    ///
    /// 归属**确定**(stderr 来自本次执行的进程,不像内核日志会混进同机其它
    /// 应用的违规),但路径是程序**自称**的,可被伪造 → `precision="reported"`,
    /// 只用于生成授权请求,**绝不自动放行**。
    ///
    /// 若同一路径已被内核日志(L2)采集,这里跳过:L2 的路径是内核给的,更可信。
    pub fn self_reported_file_violation(&mut self, path: &str, access: &str) {
        if self
            .violations
            .iter()
            .any(|v| v.kind == "file" && v.path == path)
        {
            return;
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
            source: "stderr-selfreport".into(),
            precision: "reported".into(),
            attributed: true,
        };
        self.needs_approval = true;
        self.emit_event(v.to_value());
        self.violations.push(v);
    }

    /// 等待用户授权的越界列表(可直接呈现给用户)。
    ///
    /// 只取 `reason == "needs-approval"` 的条目:黑名单拒绝、策略拒绝等
    /// 不该拿去问用户(问了也是白问——策略已经定了)。
    pub fn pending(&self) -> Vec<PendingViolation> {
        self.violations
            .iter()
            .filter(|v| v.reason == "needs-approval")
            .map(|v| PendingViolation {
                kind: v.kind.clone(),
                path: v.path.clone(),
                access: v.access.clone(),
                host: v.host.clone(),
                port: v.port,
                source: v.source.clone(),
                precision: v.precision.clone(),
                attributed: v.attributed,
            })
            .collect()
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
            // 程序自己声称的路径,可被伪造 → 只能用于生成授权请求,不能自动放行。
            precision: "reported".into(),
            // 程序是本次沙箱内的进程,自报即归属于本次执行。
            attributed: true,
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
        if !self
            .granted
            .iter()
            .any(|p| super::decision::compare_key(p) == super::decision::compare_key(path))
        {
            let in_policy = super::decision::is_prefix_hit(&self.policy.filesystem.write, path)
                || super::decision::is_prefix_hit(&self.policy.filesystem.read, path);
            if !in_policy {
                self.granted.push(path.to_string());
            }
        }
    }
}
