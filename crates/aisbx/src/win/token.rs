//! LowBox(AppContainer)令牌创建:package SID 生成 + NtCreateLowBoxToken + 低完整性。
//!
//! 走 NtCreateLowBoxToken 而非 CreateAppContainerProfile:
//! 不写注册表、零残留、亚毫秒级创建,令牌随任务一次性生成与销毁(会话级资产)。

use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree, NTSTATUS, PSID,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SetTokenInformation, SID_AND_ATTRIBUTES, TokenIntegrityLevel,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 0x02000000(本地定义,避免跨模块引 SYMBOLIC 常量)
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateLowBoxToken(
        token_handle: *mut HANDLE,
        existing_token_handle: HANDLE,
        desired_access: u32,
        object_attributes: *mut std::ffi::c_void, // MVP 传空,满足 _in_ 可空约定
        package_sid: PSID,
        capability_count: u32,
        capabilities: *const SID_AND_ATTRIBUTES,
        handle_count: u32,
        handles: *mut HANDLE,
    ) -> NTSTATUS;
}

/// 生成任务级 package SID:S-1-15-3-4096-<4 个随机子授权>
/// 随机源 = 时间纳秒 + pid + task 混合(MVP 足够;生产可换 CSPRNG)
pub fn generate_package_sid(task: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let mut state = nanos ^ (pid << 32) ^ task_hash(task);
    let mut sub = [0u32; 4];
    for s in sub.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *s = (state >> 16) as u32;
    }
    format!("S-1-15-3-4096-{}-{}-{}-{}", sub[0], sub[1], sub[2], sub[3])
}

fn task_hash(t: &str) -> u64 {
    t.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

/// SID 字符串 -> PSID(返回 (PSID, 待 LocalFree 的指针))
pub unsafe fn sid_from_string(s: &str) -> Result<(PSID, *mut std::ffi::c_void), String> {
    let mut w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid: PSID = std::ptr::null_mut();
    if ConvertStringSidToSidW(w.as_mut_ptr(), &mut sid) == 0 || sid.is_null() {
        return Err(format!("ConvertStringSidToSidW 失败: {s}"));
    }
    Ok((sid, sid as *mut std::ffi::c_void))
}

pub unsafe fn local_free_sid(p: *mut std::ffi::c_void) {
    if !p.is_null() {
        LocalFree(p as _);
    }
}

/// 由当前进程令牌派生 LowBox token:
/// 1) DuplicateTokenEx -> 主令牌
/// 2) NtCreateLowBoxToken 注入 package SID + capability 列表(空 = 无任何网络)
/// 3) 降到低完整性(S-1-16-4096)
pub unsafe fn create_lowbox_token(
    package_sid: &str,
    capability_sids: &[&str],
) -> Result<HANDLE, String> {
    let mut h_current: HANDLE = 0;
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
        &mut h_current,
    ) == 0
    {
        return Err("OpenProcessToken 失败".into());
    }
    let mut h_dup: HANDLE = 0;
    let ok = DuplicateTokenEx(
        h_current,
        MAXIMUM_ALLOWED,
        std::ptr::null(),
        2, // SecurityImpersonation
        1, // TokenPrimary
        &mut h_dup,
    );
    CloseHandle(h_current);
    if ok == 0 {
        return Err("DuplicateTokenEx 失败".into());
    }

    let (pkg_sid, pkg_free) = sid_from_string(package_sid)?;
    let mut caps: Vec<SID_AND_ATTRIBUTES> = Vec::new();
    let mut frees: Vec<*mut std::ffi::c_void> = Vec::new();
    for cs in capability_sids {
        let (s, f) = sid_from_string(cs)?;
        frees.push(f);
        caps.push(SID_AND_ATTRIBUTES { Sid: s, Attributes: 0 });
    }

    let mut h_lowbox: HANDLE = 0;
    let nt = NtCreateLowBoxToken(
        &mut h_lowbox,
        h_dup,
        MAXIMUM_ALLOWED | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
        std::ptr::null_mut(),
        pkg_sid,
        caps.len() as u32,
        if caps.is_empty() { std::ptr::null() } else { caps.as_ptr() },
        0,
        std::ptr::null_mut(),
    );
    local_free_sid(pkg_free);
    for f in &frees {
        local_free_sid(*f);
    }
    CloseHandle(h_dup);
    if nt != 0 || h_lowbox == 0 || h_lowbox == INVALID_HANDLE_VALUE {
        return Err(format!("NtCreateLowBoxToken 失败 NTSTATUS=0x{nt:08X}"));
    }

    set_low_integrity(h_lowbox)?;
    Ok(h_lowbox)
}

/// TokenIntegrityLevel -> 低完整性 S-1-16-4096(TOKEN_MANDATORY_LABEL)
unsafe fn set_low_integrity(token: HANDLE) -> Result<(), String> {
    #[repr(C)]
    struct TokenMandatoryLabel {
        label: SID_AND_ATTRIBUTES,
    }
    let (sid, free) = sid_from_string("S-1-16-4096")?;
    let buf = TokenMandatoryLabel { label: SID_AND_ATTRIBUTES { Sid: sid, Attributes: 0 } };
    let ok = SetTokenInformation(
        token,
        TokenIntegrityLevel,
        &buf as *const TokenMandatoryLabel as *const std::ffi::c_void,
        std::mem::size_of::<TokenMandatoryLabel>() as u32,
    );
    local_free_sid(free);
    if ok == 0 {
        return Err("SetTokenInformation(TokenIntegrityLevel) 失败".into());
    }
    Ok(())
}

pub unsafe fn drop_token(h: HANDLE) {
    if h != 0 && h != INVALID_HANDLE_VALUE {
        CloseHandle(h);
    }
}
