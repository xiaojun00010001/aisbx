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

/// 按指定权限串授予目录(含继承)。
pub fn grant_dir_perm(sid: &str, path: &str, perm: &str) -> Result<(), String> {
    icacls(&["/grant", &format!("*{sid}:{perm}")], path)
}

/// 授予单文件(提权场景,无继承)
pub fn grant_file(sid: &str, path: &str, write: bool) -> Result<(), String> {
    let perms = if write { "M" } else { "R" };
    icacls(&["/grant", &format!("*{sid}:{perms}")], path)
}

/// 父目录上「仅可新建文件」的最小权限。
///
/// (AD) = Add Files/Add subdirectories:只能**新建**,不能修改/删除已有内容。
/// 比 Modify 窄得多——Modify 会让被授权范围悄悄扩大到整个目录。
const PERM_ADD_FILE: &str = "(OI)(CI)(AD)";

/// 对任意路径落 ACL,返回实际被授权的路径(**授权粒度最小**)。
///
/// 提权常发生在「文件尚不存在、沙箱随后要创建」的场景,而 icacls 对不存在的
/// 文件会直接报 "The system cannot find the file specified"。此时对**父目录**
/// 授予权限——但**不能**用 Modify:
///
/// - 用户在审批框里看到并同意的是「创建这一个文件」;
/// - 授 Modify 实际给出的是「改/删该目录下所有文件」→ **授权范围大于用户所见**,
///   这是一个真实的越权面(Unix 侧不存在:bwrap 只 `--bind` 目标路径本身)。
///
/// 故这里只授 (AD):允许在该目录新建文件,已有内容一律不可读写/删除。
/// 权衡:若要做到「只允许创建、不允许创建子目录」,需用 SDDL 的 FILE_ADD_FILE
/// (0x2) 且不继承,代价是新建的文件不再继承 ACE(「先建后写」的少见写法会失败)。
pub fn grant_path_precise(sid: &str, path: &str, write: bool) -> Result<String, String> {
    let p = std::path::Path::new(path);
    if p.is_dir() {
        grant_dir(sid, path, write)?;
        return Ok(path.to_string());
    }
    if p.exists() {
        grant_file(sid, path, write)?;
        return Ok(path.to_string());
    }
    let parent = p.parent().ok_or_else(|| format!("路径无父目录: {path}"))?;
    let parent_s = parent.to_string_lossy().to_string();
    if write {
        grant_dir_perm(sid, &parent_s, PERM_ADD_FILE)?;
    } else {
        grant_dir_perm(sid, &parent_s, "(OI)(CI)(RX)")?;
    }
    Ok(parent_s)
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
        return Err(format!(
            "icacls {path} {:?} 失败: {}{}",
            ops,
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(())
}
