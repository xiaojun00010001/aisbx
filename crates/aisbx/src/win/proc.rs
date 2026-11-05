//! 沙箱内进程创建:CreateProcessAsUserW 用 LowBox 主令牌启动命令。
//! 子进程链(bash -> gcc -> ...)自动继承该 token,隔离随之传递。

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, ResumeThread, WaitForSingleObject,
    CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW, INFINITE,
};

use crate::common::quote_arg;

pub struct Child {
    pub process: HANDLE,
    pub thread: HANDLE,
    pub pi: PROCESS_INFORMATION,
}

pub fn spawn_suspended(
    token: HANDLE,
    cmd: &[String],
    cwd: Option<&str>,
) -> Result<Child, String> {
    let cmdline = cmd.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ");
    let mut cmdline_w: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd_w: Option<Vec<u16>> = cwd.map(|c| c.encode_utf16().chain(std::iter::once(0)).collect());

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // CREATE_SUSPENDED:先挂起,Assign 进 Job 之后再恢复,保证无"漏网瞬间"
    let ok = unsafe {
        CreateProcessAsUserW(
            token,
            std::ptr::null(),
            cmdline_w.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            cwd_w.map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(format!("CreateProcessAsUserW 失败,错误码 {}", unsafe { windows_sys::Win32::Foundation::GetLastError() }));
    }
    Ok(Child { process: pi.hProcess, thread: pi.hThread, pi })
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
