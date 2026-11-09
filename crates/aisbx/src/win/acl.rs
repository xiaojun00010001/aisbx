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

/// 授权占位文件的前缀标记(记在 granted_acl 里,任务结束时据此回收文件)。
/// 以控制字符开头,不会与真实路径冲突。
pub const PLACEHOLDER_MARK: &str = "\u{1}ph:";

/// 对任意路径落 ACL,返回 (实际被授权的路径, 该路径是否为宿主预创建的占位文件)。
///
/// 提权常发生在「文件尚不存在、沙箱随后要创建」的场景,而 icacls 对不存在的
/// 文件会直接报 "The system cannot find the file specified"。可选的两条路都有问题:
///
/// - 授父目录 Modify:能写,但**授权范围大于用户所见**——用户在审批框里同意的
///   是「创建这一个文件」,实际给出的是「改/删该目录下所有文件」,这是真实的
///   越权面(Unix 侧不存在:bwrap 只 `--bind` 目标路径本身)。
/// - 授父目录 (AD)(Add Files):范围收窄了,但新建文件继承的是「只能创建、
///   不能写」的 ACE → **「先建后写」必然失败**(实测 Windows CI 的 T2d/T13a
///   就是这样挂的:授权成功、文件却写不进去)。
///
/// 故取第三条路:由宿主**预创建空占位文件**,再对该文件授 Modify。
/// 既能写(占位文件已存在,沙箱只需写权限),授权范围又精确到这一个文件。
/// 占位文件在任务结束时回收(仅当它仍是空文件,避免删掉沙箱写入的内容)。
pub fn grant_path_precise(sid: &str, path: &str, write: bool) -> Result<(String, bool), String> {
    let p = std::path::Path::new(path);
    if p.is_dir() {
        grant_dir(sid, path, write)?;
        return Ok((path.to_string(), false));
    }
    if p.exists() {
        grant_file(sid, path, write)?;
        return Ok((path.to_string(), false));
    }
    let parent = p.parent().ok_or_else(|| format!("路径无父目录: {path}"))?;
    let parent_s = parent.to_string_lossy().to_string();
    if !write {
        // 只读授权:目标文件还不存在,读权限需要随目录继承,否则后续读不到。
        grant_dir_perm(sid, &parent_s, "(OI)(CI)(RX)")?;
        return Ok((parent_s, false));
    }
    std::fs::File::create(p).map_err(|e| format!("预创建占位文件失败 {path}: {e}"))?;
    grant_file(sid, path, true)?;
    Ok((path.to_string(), true))
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
