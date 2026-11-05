//! 回环放行:按 package SID 调用 CheckNetIsolation 加 Loopback 例外。
//! 不开 internet capability 时,这是沙箱获得"仅回环可达"的唯一路径。

pub fn exempt_loopback(package_sid: &str) -> Result<(), String> {
    let out = std::process::Command::new("CheckNetIsolation.exe")
        .args(["LoopbackExempt", "-a", &format!("-p={package_sid}")])
        .output()
        .map_err(|e| format!("CheckNetIsolation 启动失败: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "LoopbackExempt 失败: {}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
