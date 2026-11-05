//! 文件 ACL:白名单授予 / 提权授予 / 清理撤销。
//!
//! MVP 通过 icacls 实现(`icacls <path> /grant *<SID>:(OI)(CI)M`),稳定且免手写
//! SECURITY_DESCRIPTOR;生产化可替换为 SetNamedSecurityInfoW 直接构造 ACE。

use std::process::Command;

/// 授予目录(含继承):write=Modify,read=Read+Execute
pub fn grant_dir(sid: &str, path: &str, write: bool) -> Result<(), String> {
    let perms = if write { "(OI)(CI)M" } else { "(OI)(CI)RX" };
    icacls(&["/grant", &format!("*{sid}:{perms}")], path)
}

/// 授予单文件(提权场景,无继承)
pub fn grant_file(sid: &str, path: &str, write: bool) -> Result<(), String> {
    let perms = if write { "M" } else { "R" };
    icacls(&["/grant", &format!("*{sid}:{perms}")], path)
}

/// 撤销该 SID 在路径上的 ACE(任务结束时调用)
pub fn revoke(sid: &str, path: &str) {
    let _ = icacls(&["/remove", &format!("*{sid}")], path);
}

fn icacls(ops: &[&str], path: &str) -> Result<(), String> {
    let status = Command::new("icacls")
        .arg(path)
        .args(ops)
        .output()
        .map_err(|e| format!("icacls 启动失败: {e}"))?;
    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        let stdout = String::from_utf8_lossy(&status.stdout);
        return Err(format!("icacls {path} {:?} 失败: {}{}", ops, stdout.trim(), stderr.trim()));
    }
    Ok(())
}
