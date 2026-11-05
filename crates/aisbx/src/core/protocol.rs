//! broker 单行 JSON 协议。Unix 侧走 UDS,Windows 侧沿用命名管道既有协议。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EscRequest {
    /// "file" | "net"
    pub op: String,
    pub path: String,
    /// read | write
    pub access: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    /// 宿主 `authorize` 签发的一次性 token
    pub token: String,
    /// 由宿主 launcher 生成、不可被沙箱内程序伪造
    pub command_id: String,
    pub requested_by: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Reply {
    pub granted: bool,
    pub reason: String,
    /// 方案 B:授权后统一以「重新执行命令」生效,取值 in-place | retry | none
    pub effect: String,
    pub retry_required: bool,
}

pub fn granted(reason: &str) -> String {
    serde_json::to_string(&Reply {
        granted: true,
        reason: reason.into(),
        effect: "retry".into(),
        retry_required: true,
    })
    .unwrap()
}

pub fn denied(reason: &str) -> String {
    serde_json::to_string(&Reply {
        granted: false,
        reason: reason.into(),
        effect: "none".into(),
        retry_required: false,
    })
    .unwrap()
}

/// 需要用户授权:不是「拒绝」,而是要求宿主 agent 拿到同意后再发起重执行。
pub fn needs_approval(reason: &str) -> String {
    serde_json::to_string(&Reply {
        granted: false,
        reason: reason.into(),
        effect: "retry".into(),
        retry_required: true,
    })
    .unwrap()
}
