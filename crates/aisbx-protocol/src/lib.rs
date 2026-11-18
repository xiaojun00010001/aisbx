//! 平台无关的 aisbx 交互协议类型。
//!
//! 目标（`docs/11` P0-a）：把目前散落在 `core/protocol.rs`、`common/pending.rs`、
//! `capabilities.rs` 以及两个 `status_client` 中的「对外契约」收拢成一套**强类型**，
//! 让三平台同形由类型系统保证，而不是靠 `contract_check.py` 事后比对。
//!
//! 兼容原则：所有类型的 `serde` 表示与现有 JSON **逐字段兼容**——
//! `Pending` 仍是扁平结构（`kind` 判别字段 + `path`/`host`/`port` 等），
//! 老 agent 不需要改解析代码；新增的枚举只在反序列化时收紧非法值。

use serde::{Deserialize, Serialize};

/// 越界访问类型。与现有 `kind` 字段取值一致：`file` / `net`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationKind {
    File,
    Net,
}

/// 访问权限。与现有 `access` 字段取值一致：`read` / `write`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    #[default]
    Read,
    Write,
}

/// 路径精度。`exact`=内核/协议自带；`reported`=程序自称（可伪造）；`none`=未知。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Precision {
    Exact,
    #[default]
    Reported,
    None,
}

/// 感知来源。与现有 `source` 取值一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Source {
    /// macOS 内核 Seatbelt violation 日志
    #[serde(rename = "sandbox-log")]
    SandboxLog,
    /// 程序 stderr 自报（可伪造）
    #[serde(rename = "stderr-selfreport")]
    StderrSelfReport,
    /// 宿主代理（HTTP CONNECT / SOCKS5）
    #[serde(rename = "proxy")]
    Proxy,
    /// 程序主动 `aisbx escalate`
    #[default]
    #[serde(rename = "explicit")]
    Explicit,
}

/// 授权应答的生效方式。与现有 `effect` 取值一致：`none` / `retry` / `in-place`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Effect {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "retry")]
    Retry,
    #[serde(rename = "in-place")]
    InPlace,
}

/// 一条待授权越界——`status.pending[]` 的元素。
///
/// **保持扁平**：字段与 `common/pending.rs::PendingViolation` 完全一致。
/// 平台差异只体现在 `kind` 与哪些字段为空，调用方用 `kind` 判别。
/// P1 新增 `id` / `grant` 两个**可选**字段：agent 可直接拿 `grant` 回填 `approve`，
/// 不必自己把 pending 映射成 CLI 参数；旧 agent 忽略这两个字段即可。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PendingViolation {
    /// `file` | `net`
    pub kind: String,
    pub path: String,
    pub access: String,
    pub host: String,
    pub port: u16,
    /// `sandbox-log` | `stderr-selfreport` | `proxy` | `explicit`
    pub source: String,
    /// `exact` | `reported` | `none`
    pub precision: String,
    pub attributed: bool,
    /// P1:稳定标识（按 pending 内容派生），供 `aisbx approve --pending <id>` 消费。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// P1:可直接回填 `approve` 的授权参数。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
}

impl PendingViolation {
    /// 判别这条越界是文件还是网络。未知 kind 返回 `None`（不 panic，便于消费方 fail-closed）。
    pub fn kind(&self) -> Option<ViolationKind> {
        match self.kind.as_str() {
            "file" => Some(ViolationKind::File),
            "net" => Some(ViolationKind::Net),
            _ => None,
        }
    }

    /// 把精度解析为强类型；非法值（契约破坏）返回 `None`。
    pub fn precision(&self) -> Option<Precision> {
        match self.precision.as_str() {
            "exact" => Some(Precision::Exact),
            "reported" => Some(Precision::Reported),
            "none" => Some(Precision::None),
            _ => None,
        }
    }

    /// 面向用户的可读摘要：可直接填进授权提示。
    pub fn summary(&self) -> String {
        match self.kind() {
            Some(ViolationKind::File) => format!("{} {}", self.access, self.path),
            Some(ViolationKind::Net) => format!("net {}:{}", self.host, self.port),
            None => format!("unknown violation: {}", self.kind),
        }
    }

    /// 按内容派生稳定 id（不依赖数组下标，避免 pending 顺序变化导致 id 漂移）。
    /// 格式：`f-<hash>` / `n-<hash>`，8 位十六进制。
    pub fn derive_id(&self) -> String {
        // FNV-1a 64bit：无依赖、确定性足够（仅用于同一任务内区分 pending 项）。
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in self.summary().bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        let prefix = match self.kind() {
            Some(ViolationKind::File) => 'f',
            Some(ViolationKind::Net) => 'n',
            None => 'u',
        };
        format!("{prefix}-{h:08x}")
    }

    /// 生成可直接回填 `approve` 的授权参数（默认 TTL 300s）。
    pub fn make_grant(&self, ttl: u64) -> Option<Grant> {
        Grant::from_pending(self, ttl)
    }
}

/// `aisbx status` 的完整输出。字段与三平台 `status_client` 的现有输出一致。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub attempt: u32,
    pub backend: String,
    #[serde(default)]
    pub granted_nets: Vec<String>,
    #[serde(default)]
    pub granted_paths: Vec<String>,
    pub needs_approval: bool,
    #[serde(default)]
    pub pending: Vec<PendingViolation>,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub violations_total: u32,
}

impl Status {
    /// 从 `status_client` 返回的单行 JSON 解析。
    pub fn parse(line: &str) -> Result<Self, String> {
        serde_json::from_str(line).map_err(|e| format!("status JSON 解析失败: {e}"))
    }

    /// 需要用户授权的越界项（过滤掉 `attributed=false` 的未归属条目）。
    ///
    /// 对齐 `docs/08` §3.5 的规则：未归属条目只进审计，不驱动授权。
    pub fn actionable_pending(&self) -> impl Iterator<Item = &PendingViolation> {
        self.pending
            .iter()
            .filter(|p| p.attributed && p.kind().is_some())
    }

    /// 为所有可操作项补上 `id` 与 `grant`（幂等；已有值不覆盖）。
    /// 由 `aisbx status` 调用，让 agent 拿到即可直接授权。
    pub fn with_ids_and_grants(mut self, ttl: u64) -> Self {
        for p in &mut self.pending {
            if p.id.is_empty() {
                p.id = p.derive_id();
            }
            if p.grant.is_none() {
                p.grant = p.make_grant(ttl);
            }
        }
        self
    }

    /// 按 id 查找可操作项。
    pub fn pending_by_id(&self, id: &str) -> Option<&PendingViolation> {
        self.actionable_pending().find(|p| p.id == id)
    }

    /// 序列化为单行 JSON（保留字段顺序由 serde 决定，消费方按字段名取值）。
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// `aisbx escalate` 的请求（沙箱内 → broker）。
///
/// 强类型版本：用 `kind` 区分文件/网络，但 `serde` 形状与现有
/// `core/protocol.rs::EscRequest` 一致，`--op net` 的参数仍在顶层。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationRequest {
    /// `file` | `net`
    pub op: String,
    pub path: String,
    /// `read` | `write`
    pub access: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    /// 一次性 token（可为空）
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub command_id: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub requested_by: serde_json::Value,
}

impl EscalationRequest {
    pub fn kind(&self) -> Option<ViolationKind> {
        match self.op.as_str() {
            "file" => Some(ViolationKind::File),
            "net" => Some(ViolationKind::Net),
            _ => None,
        }
    }

    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// broker 的应答（与 `core/protocol.rs::Reply` 字段一致）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Decision {
    pub granted: bool,
    pub reason: String,
    /// `none` | `retry` | `in-place`
    pub effect: String,
    pub retry_required: bool,
}

impl Decision {
    pub fn parse(line: &str) -> Result<Self, String> {
        serde_json::from_str(line).map_err(|e| format!("应答 JSON 解析失败: {e}"))
    }

    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// 语义 helper：`granted=false && retry_required=true` 表示「需要宿主授权后重跑」，
    /// 而不是「拒绝」。对齐 `core/protocol.rs::needs_approval`。
    pub fn needs_approval(&self) -> bool {
        !self.granted && self.retry_required
    }

    /// 终态拒绝：granted=false 且不是 needs_approval。
    pub fn denied_like(&self) -> bool {
        !self.granted && !self.retry_required
    }

    pub fn granted(reason: &str) -> Self {
        Self {
            granted: true,
            reason: reason.into(),
            effect: "retry".into(),
            retry_required: true,
        }
    }

    pub fn denied(reason: &str) -> Self {
        Self {
            granted: false,
            reason: reason.into(),
            effect: "none".into(),
            retry_required: false,
        }
    }

    pub fn approval_required(reason: &str) -> Self {
        Self {
            granted: false,
            reason: reason.into(),
            effect: "retry".into(),
            retry_required: true,
        }
    }
}

/// 宿主 `authorize` 的授权请求。
///
/// 用于 P1 的 `aisbx approve <session> --pending <id>`：
/// 由 `status.pending[]` 直接生成，agent 不必手工拼 CLI 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Grant {
    File {
        path: String,
        access: Access,
        #[serde(default = "default_ttl")]
        ttl_seconds: u64,
    },
    Net {
        host: String,
        port: u16,
    },
}

fn default_ttl() -> u64 {
    300
}

impl Grant {
    /// 从一条待授权越界生成授权请求（P1 的 `--from-status` 基础）。
    pub fn from_pending(p: &PendingViolation, ttl: u64) -> Option<Self> {
        match p.kind()? {
            ViolationKind::File => Some(Grant::File {
                path: p.path.clone(),
                access: match p.access.as_str() {
                    "write" => Access::Write,
                    _ => Access::Read,
                },
                ttl_seconds: ttl,
            }),
            ViolationKind::Net => Some(Grant::Net {
                host: p.host.clone(),
                port: p.port,
            }),
        }
    }

    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// 能力等级。与 `capabilities.rs` 的值域一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapLevel {
    Full,
    Partial,
    Unavailable,
}

/// 结构化的能力报告（P0-d 的过渡形态：与平铺键并存，不替换）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub backend: String,
    pub contract: String,
    pub effect: String,
    /// 逐项能力（平铺键阶段先复用 `serde_json::Value`，P0-c 再收紧为强类型 map）。
    pub capabilities: serde_json::Value,
}

/// 结构化的能力分组视图（P0-d）：把平铺键按语义归类，便于 agent 按领域判断。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGroups {
    pub fs: FsCapabilities,
    pub net: NetCapabilities,
    pub resources: ResourceCapabilities,
    pub detection: DetectionCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsCapabilities {
    pub isolation: CapLevel,
    pub authorized_retry: CapLevel,
    pub launcher_retry: CapLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetCapabilities {
    pub egress: CapLevel,
    pub violation_capture: CapLevel,
    /// 描述类：`http-connect+socks5` 或空串
    pub proxy: String,
    pub path_precision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCapabilities {
    pub memory_per_process: CapLevel,
    pub memory_total: CapLevel,
    pub cpu: CapLevel,
    pub process_limit: CapLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionCapabilities {
    pub auto_violation: CapLevel,
    pub file_path_precision: String,
    pub log_probe: String,
}

impl Capabilities {
    pub fn parse(raw: &str) -> Result<Self, String> {
        serde_json::from_str(raw).map_err(|e| format!("能力报告解析失败: {e}"))
    }

    /// 把平铺能力键归类成结构化视图。
    ///
    /// 缺失或非法值一律降级为 `Unavailable`（fail-closed：不假装有能力）。
    /// 与平铺视图同源，避免两份数据漂移。
    pub fn groups(&self) -> CapabilityGroups {
        let level = |k: &str| self.level(k).unwrap_or(CapLevel::Unavailable);
        let desc = |k: &str| {
            self.capabilities
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        CapabilityGroups {
            fs: FsCapabilities {
                isolation: level("file_isolation"),
                authorized_retry: level("authorized_retry"),
                launcher_retry: level("launcher_retry"),
            },
            net: NetCapabilities {
                egress: level("network_egress"),
                violation_capture: level("net_violation_capture"),
                proxy: desc("net_proxy"),
                path_precision: desc("violation_net_path_precision"),
            },
            resources: ResourceCapabilities {
                memory_per_process: level("memory_per_process"),
                memory_total: level("memory_total"),
                cpu: level("cpu"),
                process_limit: level("process_limit"),
            },
            detection: DetectionCapabilities {
                auto_violation: level("auto_violation_capture"),
                file_path_precision: desc("violation_file_path_precision"),
                log_probe: desc("violation_log_probe"),
            },
        }
    }

    /// 读取某个能力项；缺失返回 `None`（契约要求键集合严格相等，缺失即破坏）。
    pub fn level(&self, key: &str) -> Option<CapLevel> {
        match self.capabilities.get(key)?.as_str()? {
            "full" => Some(CapLevel::Full),
            "partial" => Some(CapLevel::Partial),
            "unavailable" => Some(CapLevel::Unavailable),
            _ => None, // 描述类键（net_proxy / 精度）不是等级，返回 None
        }
    }

    /// `--require-full` 的强类型实现：任一状态类能力为 partial/unavailable 即拒绝。
    pub fn require_full(&self, keys: &[&str]) -> Result<(), String> {
        for key in keys {
            match self.level(key) {
                Some(CapLevel::Full) => {}
                other => {
                    return Err(format!(
                        "能力 {} 未达 full（当前 {:?}），--require-full 拒绝启动",
                        key, other
                    ))
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_FILE: &str = r#"{"attempt":1,"backend":"unix","granted_nets":[],"granted_paths":[],"needs_approval":true,"pending":[{"access":"write","attributed":true,"host":"","kind":"file","path":"/tmp/x.txt","port":0,"precision":"reported","source":"explicit"}],"retries":0,"violations_total":2}"#;

    const STATUS_NET: &str = r#"{"attempt":1,"backend":"windows","granted_nets":[],"granted_paths":[],"needs_approval":false,"pending":[{"access":"","attributed":true,"host":"example.com","ip":"","kind":"net","path":"","port":443,"precision":"exact","source":"proxy"}],"retries":0,"violations_total":1}"#;

    #[test]
    fn status_roundtrip_file_pending() {
        let s = Status::parse(STATUS_FILE).unwrap();
        assert_eq!(s.attempt, 1);
        assert_eq!(s.pending.len(), 1);
        let p = &s.pending[0];
        assert_eq!(p.kind(), Some(ViolationKind::File));
        assert_eq!(p.precision(), Some(Precision::Reported));
        assert_eq!(p.summary(), "write /tmp/x.txt");
        assert_eq!(s.actionable_pending().count(), 1);
        // 序列化后再解析，字段不丢
        let s2 = Status::parse(&s.to_line()).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn status_roundtrip_net_pending() {
        let s = Status::parse(STATUS_NET).unwrap();
        let p = &s.pending[0];
        assert_eq!(p.kind(), Some(ViolationKind::Net));
        assert_eq!(p.precision(), Some(Precision::Exact));
        assert_eq!(p.summary(), "net example.com:443");
    }

    #[test]
    fn unattributed_pending_is_not_actionable() {
        let mut s = Status::parse(STATUS_FILE).unwrap();
        s.pending[0].attributed = false;
        assert_eq!(s.actionable_pending().count(), 0);
    }

    #[test]
    fn unknown_kind_is_not_actionable() {
        let mut s = Status::parse(STATUS_FILE).unwrap();
        s.pending[0].kind = "bogus".into();
        assert_eq!(s.pending[0].kind(), None);
        assert_eq!(s.actionable_pending().count(), 0);
    }

    #[test]
    fn decision_semantics() {
        let need = Decision::approval_required("需要用户授权");
        assert!(need.needs_approval());
        let deny = Decision::denied("黑名单");
        assert!(!deny.needs_approval());
        let ok = Decision::granted("已授权");
        assert!(!ok.needs_approval());
        assert_eq!(Decision::parse(&need.to_line()).unwrap(), need);
    }

    #[test]
    fn grant_from_pending_file_and_net() {
        let sf = Status::parse(STATUS_FILE).unwrap();
        let gf = Grant::from_pending(&sf.pending[0], 120).unwrap();
        assert_eq!(
            gf,
            Grant::File {
                path: "/tmp/x.txt".into(),
                access: Access::Write,
                ttl_seconds: 120
            }
        );
        assert!(gf.to_line().contains("\"kind\":\"file\""));

        let sn = Status::parse(STATUS_NET).unwrap();
        let gn = Grant::from_pending(&sn.pending[0], 300).unwrap();
        assert_eq!(
            gn,
            Grant::Net {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn capabilities_level_and_require_full() {
        let c = Capabilities::parse(
            r#"{"backend":"macos","contract":"B","effect":"retry","capabilities":{"file_isolation":"full","cpu":"unavailable","net_proxy":"http-connect+socks5"}}"#,
        )
        .unwrap();
        assert_eq!(c.level("file_isolation"), Some(CapLevel::Full));
        assert_eq!(c.level("cpu"), Some(CapLevel::Unavailable));
        assert_eq!(c.level("net_proxy"), None); // 描述类键不是等级
        assert!(c.require_full(&["file_isolation"]).is_ok());
        assert!(c.require_full(&["cpu"]).is_err());
    }

    #[test]
    fn capability_groups_from_flat_keys() {
        let c = Capabilities::parse(
            r#"{"backend":"macos","contract":"B","effect":"retry","capabilities":{
                "file_isolation":"full","authorized_retry":"full","launcher_retry":"full",
                "network_egress":"full","net_violation_capture":"partial",
                "net_proxy":"http-connect+socks5","violation_net_path_precision":"exact",
                "memory_per_process":"unavailable","memory_total":"unavailable",
                "cpu":"unavailable","process_limit":"unavailable",
                "auto_violation_capture":"partial","violation_file_path_precision":"exact",
                "violation_log_probe":"sandbox-reporting-violation"}}"#,
        )
        .unwrap();
        let g = c.groups();
        assert_eq!(g.fs.isolation, CapLevel::Full);
        assert_eq!(g.net.egress, CapLevel::Full);
        assert_eq!(g.net.violation_capture, CapLevel::Partial);
        assert_eq!(g.net.proxy, "http-connect+socks5");
        assert_eq!(g.resources.cpu, CapLevel::Unavailable);
        assert_eq!(g.detection.file_path_precision, "exact");
    }

    #[test]
    fn capability_groups_missing_keys_are_unavailable() {
        let c = Capabilities::parse(
            r#"{"backend":"x","contract":"B","effect":"retry","capabilities":{}}"#,
        )
        .unwrap();
        let g = c.groups();
        assert_eq!(g.fs.isolation, CapLevel::Unavailable);
        assert_eq!(g.resources.memory_total, CapLevel::Unavailable);
    }

    #[test]
    fn escalation_request_roundtrip() {
        let req = EscalationRequest {
            op: "net".into(),
            path: String::new(),
            access: "read".into(),
            host: "example.com".into(),
            ip: "1.1.1.1".into(),
            port: 443,
            token: String::new(),
            command_id: "abc".into(),
            pid: 42,
            requested_by: serde_json::json!({"pid": 42}),
        };
        assert_eq!(req.kind(), Some(ViolationKind::Net));
        assert_eq!(
            serde_json::from_str::<EscalationRequest>(&req.to_line()).unwrap(),
            req
        );
    }
}
