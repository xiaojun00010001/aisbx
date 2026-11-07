//! aisbx 策略模型。
//!
//! 策略是 agent 框架与沙箱之间唯一的契约:文件白名单、网络开关、资源预算、
//! 提权模式全部声明在这里。平台后端(Windows)按策略实例化 AppContainer/Job。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 提权裁决模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EscalationMode {
    /// 越界请求弹到终端问用户(非 TTY 自动 fail-closed 拒绝)
    Prompt,
    /// 按 allow 规则自动授权,不在 allow 内一律拒绝
    Auto,
    /// 一律拒绝(最严格)
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// 任务标识,决定 package SID 与 broker 管道名(每次任务唯一)
    pub task: String,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub resources: ResourcePolicy,
    pub broker: BrokerPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct FilesystemPolicy {
    /// 可读写目录(白名单,授予 package SID Modify ACE,含子树继承)
    pub write: Vec<String>,
    /// 只读目录(授予 Read+Execute,不含写/删)
    pub read: Vec<String>,
    /// 禁止通过提权授权的路径前缀(不可授权黑名单,防用户手滑击穿敏感区)
    pub deny_escalation: Vec<String>,
    /// 提权自动放行前缀(仅 escalation=auto 时生效;prompt/deny 模式不读此表)
    pub allow_escalation: Vec<String>,
    /// 提权裁决模式,默认 prompt
    pub escalation: Option<EscalationMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkPolicy {
    /// 放行本地回环(默认 true)。实现:CheckNetIsolation 按 package SID 加例外
    pub loopback: bool,
    /// 放行外网(默认 false)。实现:向 LowBox token 注入 internetClient capability
    pub internet: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self { loopback: true, internet: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ResourcePolicy {
    /// 单进程内存上限(MB)
    pub memory_mb_per_process: Option<u64>,
    /// 全任务(所有子进程合计)内存上限(MB)
    pub memory_mb_total: Option<u64>,
    /// CPU 硬上限百分比 1..=100
    pub cpu_percent: Option<u16>,
    /// 存活进程数上限(防 fork 炸弹)
    pub active_processes: Option<u32>,
    /// 磁盘 IOPS 上限
    pub max_iops: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct BrokerPolicy {
    /// 审计日志(JSONL)输出文件
    pub audit_log: Option<PathBuf>,
    /// 覆盖 broker 管道名(默认 aisbx-<task>)
    pub pipe_name: Option<String>,
    /// 启用内核违规日志自动采集(P1)。默认 false:新能力不改变既有行为。
    /// 目前仅 macOS 的 Seatbelt violation 日志支持,其他平台如实标注 unavailable。
    pub violation_capture: Option<bool>,
}

impl BrokerPolicy {
    pub fn capture_violations(&self) -> bool {
        self.violation_capture.unwrap_or(false)
    }
}

impl Policy {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let p: Policy = serde_json::from_str(raw).map_err(|e| format!("策略解析失败: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.task.is_empty() {
            return Err("task 不能为空".into());
        }
        // task 只允许安全字符,用于构造管道名/SID 标签
        if !self.task.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("task 只允许字母数字与 - _".into());
        }
        if let Some(m) = self.filesystem.escalation {
            let _ = m;
        }
        if let Some(cpu) = self.resources.cpu_percent {
            if !(1..=100).contains(&cpu) {
                return Err(format!("cpu_percent 必须在 1..=100,当前 {cpu}"));
            }
        }
        if let Some(n) = self.resources.active_processes {
            if n == 0 {
                return Err("active_processes 必须大于 0".into());
            }
        }
        Ok(())
    }

    pub fn escalation_mode(&self) -> EscalationMode {
        self.filesystem.escalation.unwrap_or(EscalationMode::Prompt)
    }

    pub fn pipe_name(&self) -> String {
        self.broker.pipe_name.clone().unwrap_or_else(|| format!("aisbx-{}", self.task))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{
        "task": "smoke-1",
        "filesystem": {
            "write": ["C:\\agent\\ws", "%TEMP%"],
            "read": ["C:\\agent\\sdk"],
            "deny_escalation": ["%USERPROFILE%\\.ssh"],
            "allow_escalation": ["%USERPROFILE%\\.cargo"],
            "escalation": "prompt"
        },
        "network": {"loopback": true, "internet": false},
        "resources": {"memory_mb_per_process": 512, "memory_mb_total": 2048, "cpu_percent": 50, "active_processes": 32},
        "broker": {"audit_log": "C:\\agent\\audit\\smoke-1.jsonl"}
    }"#;

    #[test]
    fn parse_minimal() {
        let p = Policy::parse(r#"{ "task": "t1" }"#).unwrap();
        assert_eq!(p.task, "t1");
        assert!(p.filesystem.write.is_empty());
        assert!(p.network.loopback && !p.network.internet); // 默认仅回环
        assert_eq!(p.escalation_mode(), EscalationMode::Prompt); // 默认 prompt
        assert_eq!(p.pipe_name(), "aisbx-t1");
    }

    #[test]
    fn parse_full_contract() {
        let p = Policy::parse(BASE).unwrap();
        assert_eq!(p.filesystem.write.len(), 2);
        assert_eq!(p.filesystem.deny_escalation.len(), 1);
        assert_eq!(p.resources.cpu_percent, Some(50));
        assert_eq!(p.pipe_name(), "aisbx-smoke-1");
    }

    #[test]
    fn reject_bad_task() {
        assert!(Policy::parse(r#"{ "task": "" }"#).is_err()); // 空
        assert!(Policy::parse(r#"{ "task": "a b/c" }"#).is_err()); // 非法字符(进管道名)
    }

    #[test]
    fn reject_bad_cpu_and_zero_procs() {
        let raw = r#"{ "task": "t", "resources": { "cpu_percent": 101 } }"#;
        assert!(Policy::parse(raw).is_err());
        let raw = r#"{ "task": "t", "resources": { "active_processes": 0 } }"#;
        assert!(Policy::parse(raw).is_err());
    }

    #[test]
    fn reject_unknown_fields() {
        // deny_unknown_fields:拼错键名必须失败,不能静默吞掉策略项
        assert!(Policy::parse(r#"{ "task": "t", "filesystemm": {} }"#).is_err());
    }

    #[test]
    fn escalation_modes() {
        for (raw, want) in [
            (r#"{ "task": "t", "filesystem": { "escalation": "auto" } }"#, EscalationMode::Auto),
            (r#"{ "task": "t", "filesystem": { "escalation": "deny" } }"#, EscalationMode::Deny),
            (r#"{ "task": "t" }"#, EscalationMode::Prompt),
        ] {
            assert_eq!(Policy::parse(raw).unwrap().escalation_mode(), want);
        }
    }

    #[test]
    fn pipe_name_override() {
        let p = Policy::parse(r#"{ "task": "t", "broker": { "pipe_name": "custom" } }"#).unwrap();
        assert_eq!(p.pipe_name(), "custom");
    }

    #[test]
    fn violation_capture_defaults_off() {
        let p = Policy::parse(r#"{ "task": "t" }"#).unwrap();
        assert!(!p.broker.capture_violations());
        let p = Policy::parse(r#"{ "task": "t", "broker": { "violation_capture": true } }"#).unwrap();
        assert!(p.broker.capture_violations());
    }
}
