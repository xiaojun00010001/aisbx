//! 沙箱内进程创建:CreateProcessAsUserW 用 LowBox 主令牌启动命令。
//! 子进程链(bash -> gcc -> ...)自动继承该 token,隔离随之传递。
//!
//! L1(stderr 自报路径)需要捕获子进程 stderr:用匿名管道把 stderr 接出来,
//! 父进程边读边转发(用户可见性不变)边扫描被拒路径。

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, SetHandleInformation, DUPLICATE_SAME_ACCESS,
    GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, ResumeThread, WaitForSingleObject,
    CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use crate::common::quote_arg;

pub struct Child {
    pub process: HANDLE,
    pub thread: HANDLE,
    pub pi: PROCESS_INFORMATION,
}

pub fn spawn_suspended(token: HANDLE, cmd: &[String], cwd: Option<&str>) -> Result<Child, String> {
    spawn_inner(token, cmd, cwd, None)
}

/// 与 `spawn_suspended` 相同,但把子进程的 stderr 接到管道写端(供 L1 采集)。
///
/// **安全说明**:`bInheritHandles=TRUE` 会让子进程继承父进程所有**可继承**句柄。
/// 已核查:broker 命名管道用 `bInheritHandle=0` 创建(不可继承),Job / LowBox
/// token / 代理 socket 也都不可继承,故宿主控制通道不会泄漏给沙箱内程序。
pub fn spawn_suspended_with_stderr(
    token: HANDLE,
    cmd: &[String],
    cwd: Option<&str>,
    stderr_write: HANDLE,
) -> Result<Child, String> {
    spawn_inner(token, cmd, cwd, Some(stderr_write))
}

fn spawn_inner(
    token: HANDLE,
    cmd: &[String],
    cwd: Option<&str>,
    stderr_write: Option<HANDLE>,
) -> Result<Child, String> {
    let cmdline = cmd
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmdline_w: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd_w: Option<Vec<u16>> = cwd.map(|c| c.encode_utf16().chain(std::iter::once(0)).collect());

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 指针必须绑定到存活变量:cwd_w 是 Vec,直接 .map(as_ptr) 会产生悬垂指针
    let cwd_ptr = cwd_w
        .as_ref()
        .map(|c| c.as_ptr())
        .unwrap_or(std::ptr::null());

    // 用 STARTF_USESTDHANDLES 时,stdin/stdout/stderr 三个都要显式给,
    // 且 bInheritHandles 必须为 TRUE(句柄需可继承)。
    let mut extra_handles: Vec<HANDLE> = Vec::new();
    let mut inherit_handles = 0i32;
    if let Some(w) = stderr_write {
        si.dwFlags |= STARTF_USESTDHANDLES;
        let nul = open_nul_for_read()?;
        let stdout_src = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let h_stdin = duplicate_inheritable(nul)?;
        let h_stdout = duplicate_inheritable(stdout_src)?;
        si.hStdInput = h_stdin;
        si.hStdOutput = h_stdout;
        si.hStdError = w;
        extra_handles.push(nul);
        extra_handles.push(h_stdin);
        extra_handles.push(h_stdout);
        inherit_handles = 1;
    }

    let ok = unsafe {
        CreateProcessAsUserW(
            token,
            std::ptr::null(),
            cmdline_w.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            inherit_handles,
            CREATE_SUSPENDED,
            std::ptr::null(),
            cwd_ptr,
            &si,
            &mut pi,
        )
    };
    // 父进程侧的副本用完即关(子进程已获得自己的拷贝)
    for h in extra_handles {
        unsafe { CloseHandle(h) };
    }
    if ok == 0 {
        return Err(format!("CreateProcessAsUserW 失败,错误码 {}", unsafe {
            GetLastError()
        }));
    }
    Ok(Child {
        process: pi.hProcess,
        thread: pi.hThread,
        pi,
    })
}

/// 创建 stderr 捕获管道:返回 (读端, 写端)。
/// 写端可继承(子进程要用),读端**必须不可继承**(否则子进程也能读同一份数据)。
pub fn create_stderr_pipe() -> Result<(HANDLE, HANDLE), String> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read: HANDLE = 0;
    let mut write: HANDLE = 0;
    let ok = unsafe { CreatePipe(&mut read, &mut write, &sa, 0) };
    if ok == 0 {
        return Err(format!("CreatePipe 失败,错误码 {}", unsafe {
            GetLastError()
        }));
    }
    unsafe { SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0) };
    Ok((read, write))
}

/// 读取管道直到 EOF,原样转发到父进程 stderr,并扫描被拒路径。
pub fn read_stderr_scan(read: HANDLE) -> Vec<(String, String)> {
    use std::io::Write;
    let mut found: Vec<(String, String)> = Vec::new();
    let mut pending = String::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut n: u32 = 0;
        let ok = unsafe {
            ReadFile(
                read,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut n,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || n == 0 {
            break;
        }
        let chunk = String::from_utf8_lossy(&buf[..n as usize]).to_string();
        let _ = std::io::stderr().write_all(chunk.as_bytes());
        pending.push_str(&chunk);
        // 管道是字节流,一次读到的块可能不含完整行 → 自己按行切
        while let Some(pos) = pending.find('\n') {
            let line: String = pending.drain(..=pos).collect();
            let l = line.trim_end_matches(['\n', '\r']);
            push_denied(&mut found, l);
        }
    }
    // 最后一行可能没有换行符
    let tail = pending.trim().to_string();
    if !tail.is_empty() {
        push_denied(&mut found, &tail);
    }
    unsafe { CloseHandle(read) };
    found
}

fn push_denied(found: &mut Vec<(String, String)>, line: &str) {
    if let Some((p, a)) = crate::common::stderr_scan::extract_denied(line) {
        if !found.iter().any(|(x, _): &(String, String)| *x == p) {
            found.push((p, a.to_string()));
        }
    }
}

/// 打开 NUL 设备作 stdin(不可继承;需要可继承时用 duplicate_inheritable 复制)。
fn open_nul_for_read() -> Result<HANDLE, String> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
    };
    let name: Vec<u16> = "NUL\0".encode_utf16().collect();
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            0,
            0, // hTemplateFile:不适用
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(format!("打开 NUL 失败,错误码 {}", unsafe {
            GetLastError()
        }));
    }
    Ok(h)
}

/// 复制句柄并标记为可继承(STARTF_USESTDHANDLES 要求)。
fn duplicate_inheritable(src: HANDLE) -> Result<HANDLE, String> {
    let mut out: HANDLE = 0;
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            src,
            GetCurrentProcess(),
            &mut out,
            0,
            1, // bInheritHandle = TRUE
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(format!("DuplicateHandle 失败,错误码 {}", unsafe {
            GetLastError()
        }));
    }
    Ok(out)
}

impl Child {
    pub fn resume(&self) -> Result<(), String> {
        unsafe { ResumeThread(self.thread) };
        Ok(())
    }

    pub fn wait_exit_code(&self) -> Result<u32, String> {
        unsafe { WaitForSingleObject(self.process, INFINITE) };
        let mut code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(self.process, &mut code) };
        if ok == 0 {
            return Err("GetExitCodeProcess 失败".into());
        }
        Ok(code)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.thread);
            windows_sys::Win32::Foundation::CloseHandle(self.process);
        }
    }
}
