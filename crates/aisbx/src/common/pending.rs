//! 一条「等待用户授权」的越界 —— 可直接呈现给用户/agent 的结构化信息。
//!
//! 这是 B 契约闭环的关键一环:agent 拿到它就知道**该问用户授权什么**,
//! 而不是只拿到「有 N 次越界」这种没法拿去问的数字。
//!
//! `precision` 与 `attributed` 是两个正交维度,都必须透传给用户:
//! - `precision`:路径精度。`exact`=内核/协议自带;`reported`=程序自称(可伪造);
//! - `attributed`:能否证明来自本次执行。false 时多半是同机其它进程,不应据此授权。

/// 一条待授权的越界(文件或网络)。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct PendingViolation {
    /// `file` | `net`
    pub kind: String,
    pub path: String,
    pub access: String,
    pub host: String,
    pub port: u16,
    /// 来源:`sandbox-log` | `stderr-selfreport` | `proxy` | `explicit`
    pub source: String,
    /// 路径精度:`exact` | `reported` | `none`
    pub precision: String,
    /// 能否证明来自本次沙箱执行
    pub attributed: bool,
}
