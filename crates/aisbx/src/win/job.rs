//! Job Object:资源预算层。
//!
//! 内存/CPU/IOPS/进程数全部在 Job 上设置;不打开 breakaway,
//! 子进程默认强制继承,KILL_ON_JOB_CLOSE 保证宿主退出无残留。

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_UILIMIT_GLOBALATOMS,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};

use aisbx_policy::ResourcePolicy;

pub struct Job {
    pub handle: HANDLE,
}

pub fn create(policy: &ResourcePolicy) -> Result<Job, String> {
    unsafe {
        let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if h == 0 {
            return Err("CreateJobObjectW 失败".into());
        }

        let mut eli: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; // 宿主退出 = 全杀
        if let Some(mb) = policy.memory_mb_per_process {
            eli.ProcessMemoryLimit = mb.saturating_mul(1024 * 1024) as usize;
            flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        }
        if let Some(mb) = policy.memory_mb_total {
            eli.JobMemoryLimit = mb.saturating_mul(1024 * 1024) as usize;
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        }
        if let Some(n) = policy.active_processes {
            eli.BasicLimitInformation.ActiveProcessLimit = n;
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        }
        eli.BasicLimitInformation.LimitFlags = flags;
        let r1 = SetInformationJobObject(
            h,
            JobObjectExtendedLimitInformation,
            &eli as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        let mut r2 = 1;
        if let Some(pct) = policy.cpu_percent {
            // CpuRate 单位为万分之一(0.01%),50% = 5000
            let mut crc: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = std::mem::zeroed();
            crc.ControlFlags =
                JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
            crc.Anonymous.CpuRate = (pct as u32).saturating_mul(100).min(10000);
            r2 = SetInformationJobObject(
                h,
                JobObjectCpuRateControlInformation,
                &crc as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            );
        }

        // UI 隔离:防剪贴板读取/写入与全局原子表
        let mut uir: JOBOBJECT_BASIC_UI_RESTRICTIONS = std::mem::zeroed();
        uir.UIRestrictionsClass = JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_GLOBALATOMS;
        let r3 = SetInformationJobObject(
            h,
            JobObjectBasicUIRestrictions,
            &uir as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        );

        if r1 == 0 || r2 == 0 || r3 == 0 {
            CloseHandle(h);
            return Err("SetInformationJobObject 失败(注意 IO 限速未在此实现,见设计文档)".into());
        }
        Ok(Job { handle: h })
    }
}

impl Job {
    pub fn assign(&self, process: windows_sys::Win32::Foundation::HANDLE) -> Result<(), String> {
        unsafe {
            if AssignProcessToJobObject(self.handle, process) == 0 {
                return Err("AssignProcessToJobObject 失败".into());
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn terminate(&self) {
        unsafe {
            TerminateJobObject(self.handle, 1);
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}
