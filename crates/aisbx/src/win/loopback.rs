//! 回环放行:按 package SID 调用 CheckNetIsolation 加 Loopback 例外。
//! 不开 internet capability 时,这是沙箱获得"仅回环可达"的唯一路径。
//!
//! 注意:CheckNetIsolation 的例外表是系统级、有容量上限的(约 100 条),
//! 且 `-a` 对同一 SID 重复调用会不断追加条目。因此这里统一按
//! "先删后加" 的幂等语义写入,并在任务结束时回收,避免长跑/多次运行后
//! 触发 `Maximum number of SIDs have already been added`。

fn invoke(flag: &str, package_sid: &str) -> Result<std::process::Output, String> {
    std::process::Command::new("CheckNetIsolation.exe")
        .args(["LoopbackExempt", flag, &format!("-p={package_sid}")])
        .output()
        .map_err(|e| format!("CheckNetIsolation 启动失败: {e}"))
}

/// 幂等写入回环例外:先按 SID 删除(清掉历史重复条目),再添加一条。
pub fn exempt_loopback(package_sid: &str) -> Result<(), String> {
    let _ = invoke("-d", package_sid); // 不存在时 CheckNetIsolation 返回非 0,忽略
    let out = invoke("-a", package_sid)?;
    if !out.status.success() {
        return Err(format!(
            "LoopbackExempt 失败: {}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// 任务结束回收例外,保证系统例外表不被历史任务占满。
pub fn revoke_loopback(package_sid: &str) {
    let _ = invoke("-d", package_sid);
}
