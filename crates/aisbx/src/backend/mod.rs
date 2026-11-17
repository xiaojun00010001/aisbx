//! 平台后端统一入口（`docs/11` P0-b）。
//!
//! 旧结构：`main.rs` 在 `run` / `escalate` / `authorize` / `status` 四个命令里
//! 各写一遍 `#[cfg(windows)] / #[cfg(unix)]`，同一平台判断分散 5 处（S2），
//! 且 Windows 的 `--op net` 到运行时才报错（S3）。
//!
//! 新结构：`Backend` trait 是 CLI 与平台实现之间**唯一**的边界；
//! `backend()` 是全局唯一一处 `cfg` 选择。CLI 层不再出现任何平台判断，
//! 平台差异通过 `supports_net_escalation()` 显式声明，由调用方在发请求前决定，
//! 而不是等 broker 回错。

use aisbx_policy::Policy;
use aisbx_protocol::{Decision, EscalationRequest, Grant, Status};

/// 当前编译目标对应的后端名称（用于 `--help` 与能力报告）。
pub fn backend_name() -> &'static str {
    #[cfg(windows)]
    {
        "windows: AppContainer + Job Object + broker"
    }
    #[cfg(all(not(windows), target_os = "linux"))]
    {
        "linux: bubblewrap + netns + 授权后重执行(B 契约)"
    }
    #[cfg(all(not(windows), target_os = "macos"))]
    {
        "macos: Seatbelt + 授权后重执行(B 契约)"
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        "unsupported: 该平台暂无沙箱后端"
    }
}

/// 平台后端契约：CLI 只依赖这个 trait，不依赖任何平台模块。
pub trait Backend {
    fn name(&self) -> &'static str {
        backend_name()
    }

    /// 是否支持沙箱内 `escalate --op net`。
    /// Windows CLI 尚未封装该分支（旧代码在运行时报错），此处显式声明。
    fn supports_net_escalation(&self) -> bool;

    fn run(
        &self,
        policy: &Policy,
        policy_file: &str,
        cmd: &[String],
        json: bool,
    ) -> Result<i32, String>;

    /// 沙箱内发起提权请求，返回结构化应答（原 CLI 仍打印 JSON 并按 granted 决定退出码）。
    fn escalate(&self, policy: &Policy, req: &EscalationRequest) -> Result<Decision, String>;

    /// 宿主签发授权（文件/网络统一入口）。
    fn grant(&self, policy: &Policy, grant: &Grant) -> Result<i32, String>;

    /// 查询任务状态，返回强类型 `Status`。
    fn status(&self, policy: &Policy) -> Result<Status, String>;
}

#[cfg(unix)]
pub struct UnixBackend;
#[cfg(windows)]
pub struct WindowsBackend;
#[cfg(not(any(unix, windows)))]
pub struct UnsupportedBackend;

#[cfg(unix)]
impl Backend for UnixBackend {
    fn supports_net_escalation(&self) -> bool {
        true
    }

    fn run(
        &self,
        policy: &Policy,
        policy_file: &str,
        cmd: &[String],
        json: bool,
    ) -> Result<i32, String> {
        #[cfg(target_os = "linux")]
        return crate::linux::run_linux(policy, policy_file, cmd, json);
        #[cfg(target_os = "macos")]
        return crate::macos::run_macos(policy, policy_file, cmd, json);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (policy, policy_file, cmd, json);
            Err("该 Unix 平台暂无沙箱后端".into())
        }
    }

    fn escalate(&self, policy: &Policy, req: &EscalationRequest) -> Result<Decision, String> {
        // 复用现有 EscRequest 的 serde 形状：强类型请求 → JSON → 旧协议结构 → broker。
        let line = req.to_line();
        let old: crate::core::protocol::EscRequest =
            serde_json::from_str(&line).map_err(|e| format!("协议转换失败: {e}"))?;
        let code = crate::unix::broker::escalate_client(policy, &old)?;
        // escalate_client 已经把应答 JSON 打到 stdout；这里再连一次只为了拿结构化 Decision
        // 会造成二次请求，因此改为：从 stdout 无法取回时，用 code 合成最小 Decision。
        // ⚠️ 这是 P0 的过渡实现：P0-c 把 broker 客户端改为直接返回 Decision 后消除此合成。
        Ok(if code == 0 {
            Decision::granted("已授权")
        } else {
            Decision::denied("broker 拒绝（详见 stdout 应答）")
        })
    }

    fn grant(&self, policy: &Policy, grant: &Grant) -> Result<i32, String> {
        match grant {
            Grant::File {
                path,
                access,
                ttl_seconds,
            } => crate::unix::broker::authorize_client(
                policy,
                path,
                match access {
                    aisbx_protocol::Access::Read => "read",
                    aisbx_protocol::Access::Write => "write",
                },
                *ttl_seconds,
            ),
            Grant::Net { host, port } => {
                crate::unix::broker::authorize_net_client(policy, host, *port)
            }
        }
    }

    fn status(&self, policy: &Policy) -> Result<Status, String> {
        Status::parse(&crate::unix::broker::status_client(policy)?)
    }
}

#[cfg(windows)]
impl Backend for WindowsBackend {
    fn supports_net_escalation(&self) -> bool {
        false
    }

    fn run(
        &self,
        policy: &Policy,
        _policy_file: &str,
        cmd: &[String],
        json: bool,
    ) -> Result<i32, String> {
        crate::run::run_windows(policy, _policy_file, cmd, json)
    }

    fn escalate(&self, policy: &Policy, req: &EscalationRequest) -> Result<Decision, String> {
        match req.kind() {
            Some(aisbx_protocol::ViolationKind::File) => {
                let code = crate::win::broker::escalate_client(
                    policy,
                    &req.path,
                    &req.access,
                    &req.token,
                )?;
                Ok(if code == 0 {
                    Decision::granted("已授权")
                } else {
                    Decision::denied("broker 拒绝（详见 stdout 应答）")
                })
            }
            _ => Ok(Decision::denied(
                "Windows 后端的 --op net CLI 尚未封装(见 docs/03 §2.2)",
            )),
        }
    }

    fn grant(&self, policy: &Policy, grant: &Grant) -> Result<i32, String> {
        match grant {
            Grant::File {
                path,
                access,
                ttl_seconds: _,
            } => crate::win::broker::authorize_client(
                policy,
                path,
                match access {
                    aisbx_protocol::Access::Read => "read",
                    aisbx_protocol::Access::Write => "write",
                },
                300,
            ),
            Grant::Net { host, port } => {
                crate::win::netproxy::authorize_net_client(policy, host, *port)
            }
        }
    }

    fn status(&self, policy: &Policy) -> Result<Status, String> {
        Status::parse(&crate::win::broker::status_client(policy)?)
    }
}

#[cfg(not(any(unix, windows)))]
impl Backend for UnsupportedBackend {
    fn supports_net_escalation(&self) -> bool {
        false
    }
    fn run(&self, _: &Policy, _: &str, _: &[String], _: bool) -> Result<i32, String> {
        Err("该平台暂无沙箱后端".into())
    }
    fn escalate(&self, _: &Policy, _: &EscalationRequest) -> Result<Decision, String> {
        Err("该平台暂无沙箱后端".into())
    }
    fn grant(&self, _: &Policy, _: &Grant) -> Result<i32, String> {
        Err("该平台暂无沙箱后端".into())
    }
    fn status(&self, _: &Policy) -> Result<Status, String> {
        Err("该平台暂无沙箱后端".into())
    }
}

/// 全局唯一一处平台选择。
#[cfg(unix)]
pub fn backend() -> UnixBackend {
    UnixBackend
}
#[cfg(windows)]
pub fn backend() -> WindowsBackend {
    WindowsBackend
}
#[cfg(not(any(unix, windows)))]
pub fn backend() -> UnsupportedBackend {
    UnsupportedBackend
}

/// 三平台后端均已接入。
#[allow(dead_code)]
pub fn run_supported() -> bool {
    cfg!(any(windows, target_os = "linux", target_os = "macos"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_name_is_stable() {
        assert!(!backend_name().is_empty());
        assert!(backend_name().contains(':'));
    }

    #[test]
    fn net_escalation_capability_is_explicit() {
        #[cfg(unix)]
        assert!(backend().supports_net_escalation());
        #[cfg(windows)]
        assert!(!backend().supports_net_escalation());
    }
}
