//! 平台无关的闭环核心:协议 / 一次性 token / 审计 / 裁决 / 运行状态。
//! 方案 B 契约:策略配置 → 拒绝感知 → 用户授权 → 重新执行命令。

pub mod audit;
pub mod decision;
pub mod protocol;
pub mod state;
pub mod tokens;
