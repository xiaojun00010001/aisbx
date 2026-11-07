//! macOS 后端(方案 B):Seatbelt 静态 profile + 授权后重执行。

mod seatbelt;
pub mod violations;

use aisbx_policy::Policy;

pub fn run_macos(policy: &Policy, policy_file: &str, cmd: &[String], json: bool) -> Result<i32, String> {
    crate::unix::run::run_loop(policy, policy_file, cmd, json, |p, c, ctx| seatbelt::argv(p, c, ctx))
}
