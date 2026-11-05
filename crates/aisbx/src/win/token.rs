//! LowBox(AppContainer)令牌创建:package SID 生成 + NtCreateLowBoxToken + 低完整性。
//!
//! 走 NtCreateLowBoxToken 而非 CreateAppContainerProfile:
//! 不写注册表、零残留、亚毫秒级创建,令牌随任务一次性生成与销毁(会话级资产)。

use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree, NTSTATUS, PSID,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::core::PWSTR;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::{
    DuplicateTokenEx, FreeSid, SetTokenInformation, SID_AND_ATTRIBUTES, TokenIntegrityLevel,
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

/// 任务级 package SID。
///
/// AppContainer 的 package SID 必须是 `S-1-15-2-*` 形态;`S-1-15-3-*` 是
/// capability SID,直接传给 NtCreateLowBoxToken 会被判 STATUS_INVALID_PARAMETER
/// (0xC000000D)。这里用系统派生函数从名称推导,保证结构合法。
///
/// 名称由 task 稳定派生(同一任务多次 run 得到同一 SID),这样回环例外表
/// 可以"先删后加",不会随运行次数累积到系统上限。
pub fn generate_package_sid(task: &str) -> Result<String, String> {
    let name = format!("aisbx.{}", sanitize_name(task));
    unsafe {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid: PSID = std::ptr::null_mut();
        let hr = DeriveAppContainerSidFromAppContainerName(w.as_ptr(), &mut sid);
        if hr < 0 || sid.is_null() {
            return Err(format!("DeriveAppContainerSidFromAppContainerName 失败 HRESULT=0x{hr:08X}"));
        }
        let mut raw: PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut raw) == 0 || raw.is_null() {
            FreeSid(sid);
            return Err("ConvertSidToStringSidW 失败".into());
        }
        let len = (0..512).take_while(|&i| *raw.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
        LocalFree(raw as *mut std::ffi::c_void);
        FreeSid(sid);
        Ok(s)
    }
}

/// AppContainer 名称限 ASCII 且长度有上限(64),非法字符统一替换为 `-`。
fn sanitize_name(t: &str) -> String {
    let s: String = t
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' })
        .collect();
    s.chars().take(48).collect()
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
