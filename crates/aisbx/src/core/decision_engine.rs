//! 平台无关的文件越界裁决引擎（`docs/11` P0-c）。
//!
//! 之前 Unix 与 Windows 各写一份 `decide_file`：黑名单前置 → token → 模式裁决
//! 的顺序靠「两边都写对了」保证，改一处忘另一处就会语义漂移（S4）。
//! 这里把**裁决顺序与判定**收成一份纯逻辑：引擎返回 `Outcome`，
//! 列出调用方应执行的副作用（审计、落地授权、置 pending），
//! 自己不碰 OS 资源、不持有平台状态，因此可单测、无借用冲突。
//!
//! 关键不变量（`docs/08` §3.2，三平台必须一致）：
//! 1. `deny_escalation` 黑名单**前置**，token 也救不回；
//! 2. token 是快速路径，重放 / 路径不符 / access 不足一律拒绝；
//! 3. `Deny` / `Auto` 未命中是**终态拒绝**，不置 needs_approval、不邀请宿主；
//! 4. 只有 `Prompt` 且无 TTY 才返回 `needs_approval`（邀请宿主签 token 后重跑）。

use aisbx_policy::{EscalationMode, Policy};
use aisbx_protocol::Decision;

use crate::core::decision;

/// token 兑换成功后返回的绑定信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenGrant {
    pub path: String,
    pub access: String,
}

/// 裁决输入：从平台请求的 JSON 里提取出的最小信息集。
#[derive(Debug, Clone)]
pub struct FileRequest<'a> {
    pub path: &'a str,
    pub access: &'a str,
    pub token: &'a str,
}

/// 裁决产出：强类型判定 + 平台应执行的副作用清单。
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub decision: Decision,
    /// 应落审计的事件（引擎按三平台统一口径填好字段）。
    pub audits: Vec<serde_json::Value>,
    /// 应落地授权的路径（Unix 加宽快照 / Windows 落 ACL）；bool=是否 write。
    pub grant_path: Option<(String, bool)>,
    /// 是否应置 `needs_approval`（launcher 只为此等待宿主授权）。
    pub mark_pending: bool,
    /// 有 TTY 时应向用户展示的提问文本。
    pub prompt: Option<String>,
}

/// 唯一的裁决入口。
///
/// - `has_tty`：是否有交互终端；
/// - `redeem`：平台注入的 token 兑换（Unix 用 `core::tokens::TokenStore`，Windows 用自己的）；
/// - `ask`：有 TTY 时的用户提问渠道（返回是否同意）。
pub fn decide_file<F, R>(
    policy: &Policy,
    req: &FileRequest<'_>,
    has_tty: bool,
    redeem: &mut R,
    ask: &mut F,
) -> Outcome
where
    F: FnMut(&str) -> bool,
    R: FnMut(&str, &str, &str) -> Result<TokenGrant, String>,
{
    let path = decision::real_path(req.path);
    let write = req.access.eq_ignore_ascii_case("write");
    let mut out = Outcome::default();

    // 1) 不可授权黑名单：fail-closed，token 也救不回
    if decision::is_prefix_hit(&policy.filesystem.deny_escalation, &path) {
        out.audits.push(serde_json::json!({
            "event": "escalation.deny", "op": "file", "path": path,
            "reason": "deny_escalation"
        }));
        out.decision = Decision::denied("路径在不可授权黑名单内");
        return out;
    }

    // 2) token 快速路径：一次性消费，重放必拒
    if !req.token.is_empty() {
        return match redeem(req.token, &path, req.access) {
            Ok(t) => {
                out.audits.push(serde_json::json!({
                    "event": "token.redeemed", "path": path, "access": req.access,
                    "acl_target": t.path
                }));
                out.grant_path = Some((t.path, write));
                out.decision = Decision::granted("已按授权 token 放宽下一次执行策略");
                out
            }
            Err(e) => {
                out.audits.push(serde_json::json!({
                    "event": "token.reject", "path": path, "reason": e
                }));
                out.decision = Decision::denied(&format!("授权 token 校验失败: {e}"));
                out
            }
        };
    }

    // 3) 模式裁决：Deny / Auto 未命中是终态，不邀请宿主
    let mode = policy.escalation_mode();
    let granted = match mode {
        EscalationMode::Deny => false,
        EscalationMode::Auto => decision::is_prefix_hit(&policy.filesystem.allow_escalation, &path),
        EscalationMode::Prompt => {
            if !has_tty {
                out.mark_pending = true;
                out.audits.push(serde_json::json!({
                    "event": "escalation.pending", "op": "file", "path": path,
                    "reason": "needs-approval"
                }));
                out.decision = Decision::approval_required("需要用户授权后重新执行");
                return out;
            }
            out.prompt = Some(format!(
                "沙箱请求{}:{}\n同意? [y/N] ",
                if write { "写入" } else { "读取" },
                path
            ));
            let msg = out.prompt.clone().unwrap_or_default();
            ask(&msg)
        }
    };

    if !granted {
        out.audits.push(serde_json::json!({
            "event": "escalation.deny", "op": "file", "path": path,
            "reason": format!("{mode:?}:user-or-policy")
        }));
        out.decision = Decision::denied("授权被拒绝");
        return out;
    }

    // 4) 放行：平台落地（加宽快照 / ACL）
    out.grant_path = Some((path.clone(), write));
    out.audits.push(serde_json::json!({
        "event": "escalation.grant", "op": "file", "path": path,
        "access": req.access
    }));
    out.decision = Decision::granted("已按具体路径授予访问权限");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::decision;

    fn reject_all(_: &str, _: &str, _: &str) -> Result<TokenGrant, String> {
        Err("token 无效".into())
    }

    fn good_token(tok: &str, _: &str, _: &str) -> Result<TokenGrant, String> {
        if tok == "good" {
            Ok(TokenGrant {
                path: "/tmp/x".into(),
                access: "write".into(),
            })
        } else {
            Err("token 无效".into())
        }
    }

    fn policy(mode: &str) -> Policy {
        Policy::parse(&format!(
            r#"{{"task":"t","filesystem":{{"escalation":"{mode}","deny_escalation":["/secret"],"allow_escalation":["/allow"]}}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn deny_list_wins_over_token() {
        let req = FileRequest {
            path: "/secret/a.txt",
            access: "write",
            token: "good",
        };
        let mut ask = |_: &str| true;
        let out = decide_file(&policy("prompt"), &req, true, &mut good_token, &mut ask);
        assert!(out.decision.denied_like());
        assert!(out.audits.iter().any(|v| v["event"] == "escalation.deny"));
        assert!(out.grant_path.is_none());
    }

    #[test]
    fn token_fast_path_bypasses_deny_mode() {
        let req = FileRequest {
            path: "/tmp/x",
            access: "write",
            token: "good",
        };
        let mut ask = |_: &str| false;
        let out = decide_file(&policy("deny"), &req, false, &mut good_token, &mut ask);
        assert!(out.decision.granted);
        assert!(out.audits.iter().any(|v| v["event"] == "token.redeemed"));
        assert!(out.grant_path.is_some());
    }

    #[test]
    fn bad_token_is_rejected() {
        let req = FileRequest {
            path: "/tmp/x",
            access: "write",
            token: "bad",
        };
        let mut ask = |_: &str| true;
        let out = decide_file(&policy("prompt"), &req, true, &mut good_token, &mut ask);
        assert!(out.decision.denied_like());
        assert!(out.audits.iter().any(|v| v["event"] == "token.reject"));
    }

    #[test]
    fn deny_mode_is_terminal_not_needs_approval() {
        let req = FileRequest {
            path: "/tmp/x",
            access: "write",
            token: "",
        };
        let mut ask = |_: &str| true;
        let out = decide_file(&policy("deny"), &req, false, &mut reject_all, &mut ask);
        assert!(!out.decision.granted && !out.decision.needs_approval());
        assert_eq!(out.decision.effect, "none");
        assert!(!out.mark_pending);
    }

    #[test]
    fn auto_hit_grants_miss_denies() {
        let mut ask = |_: &str| true;
        let hit = FileRequest {
            path: "/allow/x",
            access: "read",
            token: "",
        };
        assert!(
            decide_file(&policy("auto"), &hit, false, &mut reject_all, &mut ask)
                .decision
                .granted
        );
        let miss = FileRequest {
            path: "/tmp/x",
            access: "read",
            token: "",
        };
        let out = decide_file(&policy("auto"), &miss, false, &mut reject_all, &mut ask);
        assert!(!out.decision.granted && !out.decision.needs_approval());
    }

    #[test]
    fn prompt_without_tty_invites_approval() {
        let req = FileRequest {
            path: "/tmp/x",
            access: "write",
            token: "",
        };
        let mut ask = |_: &str| false;
        let out = decide_file(&policy("prompt"), &req, false, &mut reject_all, &mut ask);
        assert!(out.decision.needs_approval());
        assert!(out.mark_pending);
        assert!(out
            .audits
            .iter()
            .any(|v| v["event"] == "escalation.pending"));
    }

    #[test]
    fn prompt_with_tty_user_says_no_is_terminal() {
        let req = FileRequest {
            path: "/tmp/x",
            access: "write",
            token: "",
        };
        let mut ask = |_: &str| false;
        let out = decide_file(&policy("prompt"), &req, true, &mut reject_all, &mut ask);
        assert!(!out.decision.granted && !out.decision.needs_approval());
        assert!(!out.mark_pending);
        assert!(out.prompt.is_some());
    }

    #[test]
    fn token_binding_uses_platform_real_path() {
        // 确认引擎与平台共用同一套路径规范化（macOS /tmp → /private/tmp）。
        let p = decision::real_path("/tmp");
        assert!(!p.is_empty());
        let req = FileRequest {
            path: "/tmp/x",
            access: "write",
            token: "good",
        };
        let mut ask = |_: &str| false;
        let out = decide_file(&policy("prompt"), &req, false, &mut good_token, &mut ask);
        assert!(out.decision.granted);
    }
}
