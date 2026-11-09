//! Linux 后端(方案 B):bubblewrap + 独立 netns + 反逃逸 + 授权后重执行。

pub mod bwrap;
pub mod helper;

use aisbx_policy::Policy;

pub fn run_linux(
    policy: &Policy,
    policy_file: &str,
    cmd: &[String],
    json: bool,
) -> Result<i32, String> {
    crate::unix::run::run_loop(policy, policy_file, cmd, json, |p, c, ctx| {
        bwrap::argv(p, c, ctx)
    })
}
