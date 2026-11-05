//! Linux multicall helper:在 bwrap 建立的命名空间内把 lo 置 up,再 exec 目标命令。
//! 这样 `--unshare-net` 断外网的同时仍保留回环能力。

use std::os::unix::process::CommandExt;

pub fn linux_helper(args: &[String]) -> Result<i32, String> {
    let raw = args.first().ok_or("__linux_helper 缺少命令 JSON")?;
    let cmd: Vec<String> = serde_json::from_str(raw).map_err(|e| format!("命令 JSON 解析失败: {e}"))?;
    if cmd.is_empty() {
        return Err("空命令".into());
    }

    // netns 内 lo 可能 down;借用 userns 内 CAP_NET_ADMIN 置 up。
    // 某些 runner 没有 ip 或 lo 本就 up,此时静默跳过(冒烟 T4a 会真实验证回环)。
    for bin in ["ip", "/sbin/ip", "/usr/sbin/ip"] {
        if let Ok(s) = std::process::Command::new(bin)
            .args(["link", "set", "lo", "up"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            if s.success() {
                break;
            }
        }
    }

    let err = std::process::Command::new(&cmd[0]).args(&cmd[1..]).exec();
    Err(format!("exec {} 失败: {err}", cmd[0]))
}
