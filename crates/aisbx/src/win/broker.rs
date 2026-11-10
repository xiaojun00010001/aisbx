//! 授权 broker(PEP 的宿主侧):
//! - 沙箱内唯一可达的命名管道(DACL 仅含 package SID)
//! - 接收提权请求(file/net),按策略裁决 -> 授权落 ACL / 拒绝,全量审计
//! - 沙箱内配套客户端 `aisbx escalate`

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use aisbx_policy::{EscalationMode, Policy};

use crate::common::pending::PendingViolation;

use super::acl;
use super::audit::Audit;
use super::netproxy::NetState;
use crate::common::expand_path;

// ── 服务端 ────────────────────────────────────────────────────────────

/// 已签发未消费的授权 token:token -> (路径, 访问级别, 过期时刻)。
pub type TokenStore = Arc<Mutex<HashMap<String, IssuedToken>>>;

#[derive(Clone)]
pub struct IssuedToken {
    pub path: String,
    pub access: String,
    pub expires_at: Instant,
}

/// 宿主 broker 的句柄:除停止标志外,还把 P0 网络状态与审计器交给 launcher。
pub struct BrokerHandle {
    pub stop: Arc<AtomicBool>,
    pub net_state: Arc<Mutex<NetState>>,
    pub audit: Arc<Audit>,
    /// C20:运行中提权新落的 ACL 目标,任务结束由 launcher 一并撤销。
    pub granted_acl: Arc<Mutex<Vec<String>>>,
    /// 宿主已授权的路径(B 契约:只影响本次任务的策略快照,不写回基线策略文件)。
    /// launcher 轮询它的长度变化,判断「用户是否已同意」,据此扩大白名单并重跑。
    pub granted_paths: Arc<Mutex<Vec<String>>>,
    /// 是否存在「需要用户授权」的拒绝。launcher 只为此等待(有上限),
    /// 其它失败(黑名单、策略拒绝)不等待,直接退出。
    pub needs_approval: Arc<AtomicBool>,
    /// 待用户授权的越界列表(供 `aisbx status` 查询;agent 据此问用户)。
    pub pending: Arc<Mutex<Vec<PendingViolation>>>,
    /// 当前执行轮次 / 重试次数(供 status 查询)。
    /// 当前执行轮次(供 status 查询)。Windows 侧暂未接入 launcher 的等待逻辑,
    /// 字段先留着与 Unix 侧对齐——故显式豁免 dead_code。
    #[allow(dead_code)]
    pub attempt: Arc<AtomicU32>,
    /// 重试次数(供 status 查询)。同上:与 Unix 侧对齐,暂未使用。
    #[allow(dead_code)]
    pub retries: Arc<AtomicU32>,
}

impl Drop for BrokerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn start_server(policy: &Policy, package_sid: &str) -> BrokerHandle {
    // SACL(强制完整性标签)要写进管道 SD,ConvertStringSD 要求 SeSecurityPrivilege
    // 处于启用态,否则 SACL 会被【静默丢弃】-> 管道保持默认 Medium IL + NO_WRITE_UP,
    // 低完整性的 AppContainer 子进程一律 ACCESS_DENIED。先提权再建管道。
    if !enable_security_privilege() {
        eprintln!("aisbx: 警告: SeSecurityPrivilege 启用失败,沙箱管道可能保持默认完整性策略");
    }
    let stop = Arc::new(AtomicBool::new(false));
    let tokens: TokenStore = Arc::new(Mutex::new(HashMap::new()));
    // C20:记录运行中提权实际落 ACL 的路径(可能是父目录),供 stage10 撤销。
    let granted_acl: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // B 契约:宿主授权到达的路径 + 「需要用户授权」标志,供 launcher 等授权并重跑。
    let granted_paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let needs_approval: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let pending: Arc<Mutex<Vec<PendingViolation>>> = Arc::new(Mutex::new(Vec::new()));
    let attempt: Arc<AtomicU32> = Arc::new(AtomicU32::new(1));
    let retries: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
    let sid = package_sid.to_string();
    let stop2 = stop.clone();
    let tokens2 = tokens.clone();
    let acl2 = granted_acl.clone();
    let needs2 = needs_approval.clone();
    let policy2 = policy.clone();
    std::thread::spawn(move || unsafe {
        if let Err(e) = server_loop(&policy2, &sid, &stop2, &tokens2, &acl2, &needs2) {
            eprintln!("aisbx: broker 授权管道异常: {e}");
        }
    });
    // 宿主控制通道:agent 在运行中签发授权 token 的入口(见 docs/03 §1.5)
    // 同时承载 P0 的 --host 网络放行,P0 代理与它共享同一份 NetState。
    let net_state: Arc<Mutex<NetState>> = Arc::new(Mutex::new(NetState::default()));
    let audit = Arc::new(Audit::new(policy.broker.audit_log.as_deref()));
    let policy3 = policy.clone();
    let stop3 = stop.clone();
    let tokens3 = tokens.clone();
    let net_state3 = net_state.clone();
    let audit3 = audit.clone();
    let granted3 = granted_paths.clone();
    let pending3 = pending.clone();
    let attempt3 = attempt.clone();
    let retries3 = retries.clone();
    std::thread::spawn(move || unsafe {
        if let Err(e) = control_server_loop(
            &policy3,
            &stop3,
            &tokens3,
            &net_state3,
            &audit3,
            &granted3,
            &pending3,
            &attempt3,
            &retries3,
        ) {
            eprintln!("aisbx: broker 控制管道异常: {e}");
        }
    });
    BrokerHandle {
        stop,
        net_state,
        audit,
        granted_acl,
        granted_paths,
        needs_approval,
        pending,
        attempt,
        retries,
    }
}

unsafe fn server_loop(
    policy: &Policy,
    package_sid: &str,
    stop: &AtomicBool,
    tokens: &TokenStore,
    granted_acl: &Arc<Mutex<Vec<String>>>,
    needs_approval: &Arc<AtomicBool>,
) -> Result<(), String> {
    let pipe_name = format!(r"\\.\pipe\{}", policy.pipe_name());
    let h = create_pipe(&pipe_name, package_sid)?;
    let audit = Audit::new(policy.broker.audit_log.as_deref());

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if ConnectNamedPipe(h, std::ptr::null_mut()) == 0 {
            // 已有客户端在等待(ERROR_PIPE_CONNECTED)时继续,其余错误重试
        }
        if let Some(line) = read_line(h) {
            let reply = handle_request(
                policy,
                &line,
                &audit,
                package_sid,
                tokens,
                granted_acl,
                needs_approval,
            );
            write_all(h, (reply + "\n").as_bytes());
        }
        DisconnectNamedPipe(h);
    }
    CloseHandle(h);
    Ok(())
}

/// 宿主控制通道:DACL 只含 SYSTEM/Administrators/属主(S-1-3-4)。
/// 沙箱内进程(AppContainer)即使与宿主同属一个用户,也过不了 AppContainer
/// 附加检查(SD 未授予 package SID),无法自行签发 token——授权决策权在宿主。
#[allow(clippy::too_many_arguments)]
unsafe fn control_server_loop(
    policy: &Policy,
    stop: &AtomicBool,
    tokens: &TokenStore,
    net_state: &Arc<Mutex<NetState>>,
    audit: &Arc<Audit>,
    granted_paths: &Arc<Mutex<Vec<String>>>,
    pending: &Arc<Mutex<Vec<PendingViolation>>>,
    attempt: &Arc<AtomicU32>,
    retries: &Arc<AtomicU32>,
) -> Result<(), String> {
    let pipe_name = format!(r"\\.\pipe\{}-ctl", policy.pipe_name());
    let h = create_pipe_sddl(&pipe_name, "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-3-4)")?;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // ConnectNamedPipe 在「客户端已先连上」时返回 0(ERROR_PIPE_CONNECTED),属正常;
        // 其余失败情形下 read_line 返回 None,继续循环即可。
        let _ = ConnectNamedPipe(h, std::ptr::null_mut());
        if let Some(line) = read_line(h) {
            let reply = handle_control(
                &line,
                tokens,
                net_state,
                audit,
                granted_paths,
                pending,
                attempt,
                retries,
            );
            write_all(h, (reply + "\n").as_bytes());
        }
        DisconnectNamedPipe(h);
    }
    CloseHandle(h);
    Ok(())
}

unsafe fn create_pipe(name: &str, package_sid: &str) -> Result<HANDLE, String> {
    // DACL = 用户 SID(标准检查) + package SID(AppContainer 校验),缺一不可。
    // SACL Low 强制标签必需:否则默认 Medium IL + NO_WRITE_UP 会拒低完整性子进程。
    // SDDL 的 S: 段可能被静默丢弃,故在下方用 SetSecurityInfo 显式写标签。
    // 常规 DACL 检查看 token 的 user/groups,AppContainer 校验另看 package SID,
    // 两者都要有 ACE:文件侧 icacls 是"追加"(原用户 ACE 仍在),管道 SD 是全新的,
    // 只写 package SID 会让标准 DACL 检查直接失败(GetLastError=5)。
    let user_sid = super::token::current_user_sid()?;
    let h = create_pipe_sddl(
        name,
        &format!("D:(A;;GA;;;{user_sid})(A;;GA;;;{package_sid})"),
    )?;
    // SDDL 的 S: 段在部分环境下会被静默丢弃,这里直接写标签兜底
    if let Err(e) = apply_low_label(h) {
        eprintln!("aisbx: 警告: 管道 Low 完整性标签设置失败: {e}");
    }
    Ok(h)
}

/// 给管道句柄显式打 Low 完整性标签(S-1-16-4096 + NO_WRITE_UP)。
/// 命名管道在无标签时按 Medium+NO_WRITE_UP 强制校验,低完整性的 AppContainer
/// 子进程写入会被拒(ERROR_ACCESS_DENIED);对象自身为 Low 后同级别即可读写。
unsafe fn apply_low_label(h: HANDLE) -> Result<(), String> {
    use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
    use windows_sys::Win32::Security::{
        GetLengthSid, InitializeSecurityDescriptor, SetSecurityDescriptorSacl,
        LABEL_SECURITY_INFORMATION, SECURITY_DESCRIPTOR,
    };
    // 常量值来自 Win32 头文件(SYSTEM_MANDATORY_LABEL_ACE_TYPE=17 / NO_WRITE_UP=1)
    const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 17;
    const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 1;

    let (sid, free) = super::token::sid_from_string("S-1-16-4096")?;
    let sid_len = GetLengthSid(sid) as usize;
    // 自建 ACL:header(8) + ACE{header(4) + mask(4) + SID}
    let acl_size = 8 + 8 + sid_len;
    let mut buf = vec![0u8; acl_size + 8];
    let acl = buf.as_mut_ptr();
    *acl.add(0) = 2; // AclRevision = ACL_REVISION
    *acl.add(1) = 0; // Sbz1
    (acl.add(2) as *mut u16).write_unaligned(acl_size as u16);
    (acl.add(4) as *mut u16).write_unaligned(1); // AceCount
    (acl.add(6) as *mut u16).write_unaligned(0); // Sbz2
    let ace = acl.add(8);
    *ace.add(0) = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    *ace.add(1) = 0;
    (ace.add(2) as *mut u16).write_unaligned((8 + sid_len) as u16);
    (ace.add(4) as *mut u32).write_unaligned(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
    std::ptr::copy_nonoverlapping(sid as *const u8, ace.add(8), sid_len);

    let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
    if InitializeSecurityDescriptor(&mut sd as *mut _ as *mut std::ffi::c_void, 1) == 0 {
        super::token::local_free_sid(free);
        return Err("InitializeSecurityDescriptor 失败".into());
    }
    if SetSecurityDescriptorSacl(
        &mut sd as *mut _ as *mut std::ffi::c_void,
        1,
        acl as *const _,
        0,
    ) == 0
    {
        super::token::local_free_sid(free);
        return Err("SetSecurityDescriptorSacl 失败".into());
    }
    // SE_KERNEL_OBJECT = 6
    let rc = SetSecurityInfo(
        h,
        6,
        LABEL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null(),
        acl as *const _,
    );
    super::token::local_free_sid(free);
    if rc != 0 {
        return Err(format!("SetSecurityInfo(label) 失败 win32={rc}"));
    }
    Ok(())
}

/// 启用 SeSecurityPrivilege(管理员的该特权默认处于禁用态)。
fn enable_security_privilege() -> bool {
    use windows_sys::Win32::Foundation::LUID;
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut h: HANDLE = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut h,
        ) == 0
        {
            return false;
        }
        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0] = LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 0,
                HighPart: 0,
            },
            Attributes: SE_PRIVILEGE_ENABLED,
        };
        if LookupPrivilegeValueW(
            std::ptr::null(),
            SE_SECURITY_NAME,
            &mut tp.Privileges[0].Luid,
        ) == 0
        {
            CloseHandle(h);
            return false;
        }
        let ok = AdjustTokenPrivileges(h, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
        CloseHandle(h);
        // AdjustTokenPrivileges 对"令牌未持有该特权"也返回 TRUE,需用 GetLastError 区分
        ok != 0 && windows_sys::Win32::Foundation::GetLastError() != 1300
    }
}

unsafe fn create_pipe_sddl(name: &str, sddl: &str) -> Result<HANDLE, String> {
    let mut sddl_w: Vec<u16> = format!("{sddl}\0")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    sddl_w.pop(); // SDDL 串自带结尾 NUL
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl_w.as_ptr(),
        SDDL_REVISION_1,
        &mut sd,
        std::ptr::null_mut(),
    ) == 0
    {
        return Err("ConvertStringSecurityDescriptorToSecurityDescriptorW 失败".into());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let h = CreateNamedPipeW(
        name_w.as_ptr(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        65536,
        65536,
        0,
        &sa,
    );
    if h == INVALID_HANDLE_VALUE {
        return Err(format!("CreateNamedPipeW 失败: {name}"));
    }
    Ok(h)
}

unsafe fn read_line(h: HANDLE) -> Option<String> {
    let mut buf = [0u8; 4096];
    let mut line: Vec<u8> = Vec::new();
    loop {
        let mut n: u32 = 0;
        if windows_sys::Win32::Storage::FileSystem::ReadFile(
            h,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut n,
            std::ptr::null_mut(),
        ) == 0
            || n == 0
        {
            return if line.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&line).into_owned())
            };
        }
        if let Some(pos) = buf[..n as usize].iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..pos]);
            return Some(String::from_utf8_lossy(&line).into_owned());
        }
        line.extend_from_slice(&buf[..n as usize]);
        if line.len() > 1 << 20 {
            return None; // 防御超长
        }
    }
}

unsafe fn write_all(h: HANDLE, data: &[u8]) {
    let mut written: u32 = 0;
    let _ = windows_sys::Win32::Storage::FileSystem::WriteFile(
        h,
        data.as_ptr(),
        data.len() as u32,
        &mut written,
        std::ptr::null_mut(),
    );
}

// ── 裁决 ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct EscRequest {
    op: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    port: u16,
    /// 宿主侧 `aisbx authorize` 签发的一次性授权 token(无头 agent 的授权闭环)
    #[serde(default)]
    token: String,
    #[serde(default)]
    requested_by: serde_json::Value,
}

fn handle_request(
    policy: &Policy,
    line: &str,
    audit: &Audit,
    package_sid: &str,
    tokens: &TokenStore,
    granted_acl: &Arc<Mutex<Vec<String>>>,
    needs_approval: &Arc<AtomicBool>,
) -> String {
    let reply = match serde_json::from_str::<EscRequest>(line) {
        Ok(req) => match req.op.as_str() {
            "file" => decide_file(
                policy,
                &req,
                audit,
                package_sid,
                tokens,
                granted_acl,
                needs_approval,
            ),
            "net" => decide_net(policy, &req, audit),
            other => json_reply(false, &format!("未知操作 {other}")),
        },
        Err(e) => json_reply(false, &format!("请求解析失败: {e}")),
    };
    reply
}

fn decide_file(
    policy: &Policy,
    req: &EscRequest,
    audit: &Audit,
    package_sid: &str,
    tokens: &TokenStore,
    granted_acl: &Arc<Mutex<Vec<String>>>,
    needs_approval: &Arc<AtomicBool>,
) -> String {
    let path = expand_path(&req.path);
    let write = req.access.eq_ignore_ascii_case("write");

    // 1) 不可授权黑名单:fail-closed,token 也不能越过(黑名单语义=不可授权)
    if is_prefix_hit(&policy.filesystem.deny_escalation, &path) {
        audit.log(&serde_json::json!({
            "event": "escalation.deny", "op": "file", "path": path,
            "reason": "deny_escalation", "requested_by": req.requested_by
        }));
        return json_reply(false, "路径在不可授权黑名单内");
    }

    // 2) token 快速路径:agent 已在宿主侧取得用户同意并签发,跳过 prompt/auto
    if !req.token.is_empty() {
        return redeem_token(
            &req.token,
            &path,
            &req.access,
            package_sid,
            tokens,
            audit,
            granted_acl,
        );
    }

    // 3) 按模式裁决
    let mode = policy.escalation_mode();
    let granted = match mode {
        EscalationMode::Deny => false,
        EscalationMode::Auto => is_prefix_hit(&policy.filesystem.allow_escalation, &path),
        EscalationMode::Prompt => {
            // 无头环境(agent / CI)没法就地问人 → 交给宿主授权通道:
            // 置 needs_approval,launcher 会等用户同意、并以更宽的策略快照重跑
            // (B 契约,与 Unix 侧语义一致)。
            if !is_tty() {
                needs_approval.store(true, Ordering::Relaxed);
                audit.log(&serde_json::json!({
                    "event": "escalation.pending", "op": "file", "path": path,
                    "reason": "needs-approval", "requested_by": req.requested_by
                }));
                return json_reply(false, "需要用户授权后重新执行");
            }

            prompt_user(&format!(
                "沙箱请求{}:{} ({})\n同意? [y/N] ",
                if write { "写入" } else { "读取" },
                path,
                req.access
            ))
        }
    };

    if !granted {
        audit.log(&serde_json::json!({
            "event": "escalation.deny", "op": "file", "path": path,
            "reason": format!("{mode:?}:user-or-policy"), "requested_by": req.requested_by
        }));
        return json_reply(false, "授权被拒绝");
    }

    // 3) 授权落 ACL(目标文件不存在时授权其父目录继承),后续真实 syscall 直接放行
    match acl::grant_path_precise(package_sid, &path, write) {
        Ok((acl_target, is_placeholder)) => {
            record_acl(granted_acl, &acl_target, is_placeholder);
            audit.log(&serde_json::json!({
                "event": "escalation.grant", "op": "file", "path": path,
                "acl_target": acl_target,
                "access": req.access, "requested_by": req.requested_by
            }));
            json_reply(true, "已按具体路径授予 ACL")
        }
        Err(e) => json_reply(false, &format!("授权落 ACL 失败: {e}")),
    }
}

fn decide_net(policy: &Policy, req: &EscRequest, audit: &Audit) -> String {
    if policy.network.internet {
        return json_reply(true, "策略已放开外网");
    }
    // MVP:无 WFP(需管理员)时无法对运行中的沙箱补按主机的放行;fail-closed 并给出路径
    audit.log(&serde_json::json!({
        "event": "escalation.deny", "op": "net",
        "host": req.host, "ip": req.ip, "port": req.port, "reason": "network-escalation-unsupported"
    }));
    json_reply(
        false,
        "外网默认拒绝;按主机放行需 WFP 规则(见设计文档路线图),可改策略 network.internet 或改用代理",
    )
}

// ── 宿主控制通道:token 签发 ──────────────────────────────────────────

#[derive(serde::Deserialize)]
struct IssueRequest {
    op: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: Option<u16>,
}

#[allow(clippy::too_many_arguments)]
fn handle_control(
    line: &str,
    tokens: &TokenStore,
    net_state: &Arc<Mutex<NetState>>,
    audit: &Arc<Audit>,
    granted_paths: &Arc<Mutex<Vec<String>>>,
    pending: &Arc<Mutex<Vec<PendingViolation>>>,
    attempt: &Arc<AtomicU32>,
    retries: &Arc<AtomicU32>,
) -> String {
    let req = match serde_json::from_str::<IssueRequest>(line) {
        Ok(r) => r,
        Err(e) => return json_reply(false, &format!("请求解析失败: {e}")),
    };

    // 宿主侧查询状态:给出**具体**待授权路径(agent 据此问用户),而不是只给数量。
    // 字段与 Unix 侧 status 保持一致,agent 一套代码吃两个平台。
    if req.op == "status" {
        let pend = pending.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let gp = granted_paths
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        return serde_json::json!({
            "backend": "windows",
            "attempt": attempt.load(Ordering::Relaxed),
            "retries": retries.load(Ordering::Relaxed),
            "needs_approval": !pend.is_empty(),
            "pending": pend,
            "granted_paths": gp,
            "granted_nets": Vec::<String>::new(),
        })
        .to_string();
    }

    // P0:放行代理真实观察过的网络目标。运行中即时生效,不写回策略文件、不需重跑。
    if req.op == "net-issue" {
        let port = req.port.unwrap_or(443);
        if req.host.is_empty() || port == 0 {
            return json_reply(false, "host/port 非法");
        }
        let key = NetState::key(&req.host, port);
        {
            let mut ns = net_state.lock().unwrap_or_else(|p| p.into_inner());
            if !ns.observed.contains(&key) {
                audit.log(&serde_json::json!({
                    "event": "authorize.reject", "op": "net", "host": req.host,
                    "port": port, "reason": "no-real-violation"
                }));
                return json_reply(false, "无真实网络拒绝记录,拒绝放行");
            }
            if !ns.granted.contains(&key) {
                ns.granted.push(key.clone());
            }
        }
        audit.log(&serde_json::json!({
            "event": "net.grant", "host": req.host, "port": port,
            "target": key, "scope": "task"
        }));
        return serde_json::json!({"granted": true, "host": req.host, "port": port, "scope": "task"}).to_string();
    }

    if req.op != "issue" {
        return json_reply(false, &format!("未知控制操作 {}", req.op));
    }
    let path = expand_path(&req.path);
    if path.is_empty() {
        return json_reply(false, "path 不能为空");
    }
    if !matches!(req.access.as_str(), "read" | "write") {
        return json_reply(false, "access 只允许 read|write");
    }
    let ttl = req.ttl_seconds.unwrap_or(300).clamp(1, 3600);

    let token = random_token();
    let mut store = match tokens.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    store.retain(|_, t| t.expires_at > Instant::now()); // 顺手清过期
    store.insert(
        token.clone(),
        IssuedToken {
            path: path.clone(),
            access: req.access.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        },
    );
    drop(store);
    // B 契约:宿主已授权 → 记入本次任务的授权清单。launcher 轮询它的长度变化,
    // 判断「用户是否已同意」,据此把该路径并入白名单(落 ACL)并重跑。
    // 授权本身仍由 token 承载(一次性、可过期),这里只记「已同意的路径」。
    {
        let mut g = granted_paths.lock().unwrap_or_else(|p| p.into_inner());
        if !g.iter().any(|x| x.eq_ignore_ascii_case(&path)) {
            g.push(path.clone());
        }
    }
    audit.log(&serde_json::json!({
        "event": "token.issued", "path": path, "access": req.access, "ttl_seconds": ttl
    }));
    serde_json::json!({ "granted": true, "token": token, "path": path, "access": req.access, "expires_in": ttl }).to_string()
}

/// token 消费:校验存在/未过期/路径匹配/访问级别满足,一次性,用后即删。
fn redeem_token(
    token: &str,
    path: &str,
    access: &str,
    package_sid: &str,
    tokens: &TokenStore,
    audit: &Audit,
    granted_acl: &Arc<Mutex<Vec<String>>>,
) -> String {
    let now = Instant::now();
    let hit = {
        let mut store = match tokens.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let ok = store.get(token).filter(|t| {
            t.expires_at > now
                && access_satisfied(&t.access, access)
                && is_prefix_hit(std::slice::from_ref(&t.path), path)
        });
        let issued = ok.cloned();
        if issued.is_some() {
            store.remove(token);
        }
        issued
    };
    let Some(t) = hit else {
        audit.log(&serde_json::json!({
            "event": "token.reject", "path": path, "access": access
        }));
        return json_reply(
            false,
            "授权 token 无效、已过期、已消费或与路径/访问级别不匹配",
        );
    };
    // 按 token 覆盖的具体路径落 ACL;文件尚不存在时授权父目录继承
    let write = t.access.eq_ignore_ascii_case("write");
    match acl::grant_path_precise(package_sid, path, write) {
        Ok((acl_target, is_placeholder)) => {
            record_acl(granted_acl, &acl_target, is_placeholder);
            audit.log(&serde_json::json!({
                "event": "token.redeemed", "path": path, "acl_target": acl_target,
                "access": access
            }));
            json_reply(true, "已按授权 token 授予 ACL(具体路径)")
        }
        Err(e) => json_reply(false, &format!("授权落 ACL 失败: {e}")),
    }
}

/// 登记运行中提权落下的 ACL 目标,供任务结束统一撤销(C20)。
fn record_acl(list: &Arc<Mutex<Vec<String>>>, target: &str, is_placeholder: bool) {
    let mut g = list.lock().unwrap_or_else(|p| p.into_inner());
    let entry = acl::acl_entry(target, is_placeholder);
    if !g.iter().any(|p| p.eq_ignore_ascii_case(&entry)) {
        g.push(entry);
    }
}

/// write token 可满足 read 请求(Modify 蕴含读);read token 只满足 read。
fn access_satisfied(granted: &str, requested: &str) -> bool {
    granted.eq_ignore_ascii_case("write") || granted.eq_ignore_ascii_case(requested)
}

/// 128 位随机 token。SipHash 实例种子来自 OS 熵,通道为本机同宿主命名管道,
/// 此强度足够;若未来开放跨机,应换 BCryptGenRandom。
fn random_token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = Vec::with_capacity(4);
    for _ in 0..4 {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_usize(std::process::id() as usize);
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        h.push(hasher.finish());
    }
    format!("{:016x}{:016x}{:016x}{:016x}", h[0], h[1], h[2], h[3])
}

fn is_prefix_hit(list: &[String], path: &str) -> bool {
    let p = path
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    list.iter()
        .map(|x| {
            expand_path(x)
                .replace('/', "\\")
                .trim_end_matches('\\')
                .to_ascii_lowercase()
        })
        .any(|base| p == base || p.starts_with(&format!("{base}\\")))
}

fn prompt_user(msg: &str) -> bool {
    use std::io::Write;
    eprint!("{msg}");
    let _ = std::io::stderr().flush();
    // 非 TTY(agent 接管 stdin)时 fail-closed
    if !is_tty() {
        eprintln!("[aisbx] stdin 非 TTY,按 fail-closed 拒绝");
        return false;
    }
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "是")
}

fn is_tty() -> bool {
    // MVP 判定:环境变量探测(Windows Services / CI 常见无 TTY 特征)
    std::env::var("TERM").is_ok() || std::env::var("SESSIONNAME").is_ok()
}

fn json_reply(granted: bool, reason: &str) -> String {
    serde_json::json!({ "granted": granted, "reason": reason }).to_string()
}

// ── 客户端(沙箱内执行 `aisbx escalate`) ─────────────────────────────

pub fn escalate_client(
    policy: &Policy,
    path: &str,
    access: &str,
    token: &str,
) -> Result<i32, String> {
    let name = format!(r"\\.\pipe\{}", policy.pipe_name());
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h = CreateFileW(
            name_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_NONE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        );
        if h == INVALID_HANDLE_VALUE {
            let err = windows_sys::Win32::Foundation::GetLastError();
            return Err(format!(
                "无法连接授权管道 {name}(不在沙箱内或 broker 未运行) GetLastError={err}"
            ));
        }
        let req = serde_json::json!({
            "op": "file", "path": path, "access": access, "token": token,
            "requested_by": { "pid": std::process::id(), "exe": std::env::current_exe().map(|e| e.display().to_string()).unwrap_or_default() }
        });
        write_all(h, format!("{req}\n").as_bytes());
        let reply = read_line(h).unwrap_or_default();
        CloseHandle(h);
        let v: serde_json::Value =
            serde_json::from_str(&reply).map_err(|e| format!("应答解析失败: {e}: {reply}"))?;
        println!("{reply}");
        Ok(
            if v.get("granted").and_then(|g| g.as_bool()).unwrap_or(false) {
                0
            } else {
                1
            },
        )
    }
}

/// 宿主侧 `aisbx authorize`:向运行中 broker 的控制通道签发一次性授权 token。
/// 这是 agent 框架在无头环境下把「用户同意」传入沙箱的唯一通道。
pub fn authorize_client(
    policy: &Policy,
    path: &str,
    access: &str,
    ttl: u64,
) -> Result<i32, String> {
    let name = format!(r"\\.\pipe\{}-ctl", policy.pipe_name());
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h = CreateFileW(
            name_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_NONE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        );
        if h == INVALID_HANDLE_VALUE {
            return Err(format!(
                "无法连接控制管道 {name}(任务未运行或不在宿主侧执行)"
            ));
        }
        let req = serde_json::json!({ "op": "issue", "path": path, "access": access, "ttl_seconds": ttl });
        write_all(h, format!("{req}\n").as_bytes());
        let reply = read_line(h).unwrap_or_default();
        CloseHandle(h);
        let v: serde_json::Value =
            serde_json::from_str(&reply).map_err(|e| format!("应答解析失败: {e}: {reply}"))?;
        println!("{reply}");
        Ok(
            if v.get("granted").and_then(|g| g.as_bool()).unwrap_or(false) {
                0
            } else {
                1
            },
        )
    }
}

/// 宿主侧 `aisbx status`:查询当前任务的待授权项与进度。
///
/// 与 Unix 侧 `aisbx status` 返回**同一套字段**,agent 一套代码吃两个平台。
pub fn status_client(policy: &Policy) -> Result<String, String> {
    let name = format!(r"\\.\pipe\{}-ctl", policy.pipe_name());
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h = CreateFileW(
            name_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_NONE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        );
        if h == INVALID_HANDLE_VALUE {
            return Err(format!(
                "无法连接控制管道 {name}(任务未运行或不在宿主侧执行)"
            ));
        }
        write_all(h, b"{\"op\":\"status\"}\n");
        let reply = read_line(h).unwrap_or_default();
        CloseHandle(h);
        if reply.trim().is_empty() {
            return Err("broker 无应答".into());
        }
        Ok(reply)
    }
}
