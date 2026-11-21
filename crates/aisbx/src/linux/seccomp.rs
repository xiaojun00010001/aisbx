//! Linux seccomp-BPF 加固（docs/12 A2）。
//!
//! 在 helper 内、relay 子进程已启动之后、目标命令 exec 之前安装。
//! 过滤器**随 exec 继承、不可逆**，只作用于主进程链 —— relay 子进程
//! 在 spawn 前就已创建，不受影响（它需要 AF_INET 监听回环）。
//!
//! 拒绝清单（其余全部 ALLOW，避免误伤正常程序）：
//!   - unshare / setns / mount / umount2 / pivot_root：与 `--disable-userns`
//!     形成双层，防沙箱内自建 namespace 拆掉只读 bind；
//!   - io_uring_setup / io_uring_enter / io_uring_register：绕过 socket 的网络 I/O；
//!   - socket(AF_VSOCK)：绕过 AF_INET/AF_INET6 的旁路。
//!
//! 安装失败 **fail-closed**：返回 Err，helper 不 exec 目标命令。

use libc::{c_int, sock_filter, sock_fprog};

// BPF 指令编码（与 samples/seccomp/bpf-direct.c 一致）
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_SET_MODE_FILTER: c_int = 1;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const PR_SET_NO_NEW_PRIVS: c_int = 38;

// seccomp_data 布局：nr@0, arch@4, ip@8, args[0]@16
const OFFSET_NR: u32 = 0;
const OFFSET_ARG0: u32 = 16;
const AF_VSOCK: u32 = 40;

fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jeq(k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter {
        code: BPF_JMP_JEQ_K,
        jt,
        jf,
        k,
    }
}

fn nr_of(name: &str) -> Option<u32> {
    // 常用 syscall 号（x86_64 与 aarch64 一致的核心集合）。
    // 缺失时用 None 跳过该项，不误伤其它架构。
    match name {
        "unshare" => Some(libc::SYS_unshare as u32),
        "setns" => Some(libc::SYS_setns as u32),
        "mount" => Some(libc::SYS_mount as u32),
        "umount2" => Some(libc::SYS_umount2 as u32),
        "pivot_root" => Some(libc::SYS_pivot_root as u32),
        "socket" => Some(libc::SYS_socket as u32),
        // io_uring 在 libc 中并非所有版本都导出，用条件常量兜底。
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        "io_uring_setup" => Some(425),
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        "io_uring_enter" => Some(426),
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        "io_uring_register" => Some(427),
        _ => None,
    }
}

/// 安装 seccomp 过滤器。成功返回 Ok，失败返回 Err（调用方必须 fail-closed）。
pub fn install() -> Result<(), String> {
    let mut filter: Vec<sock_filter> = Vec::new();

    // 入口：加载 syscall number
    filter.push(stmt(BPF_LD_W_ABS, OFFSET_NR));

    // 对每个禁用的 syscall 生成 JEQ。命中则跳到 DENY 指令（相对偏移在末尾补齐）。
    // 先用一个占位，稍后回填 jt：策略是「命中 → 跳到 DENY」，jf=继续下一条。
    let deny_names = [
        "unshare",
        "setns",
        "mount",
        "umount2",
        "pivot_root",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
    ];
    let mut jeq_slots: Vec<usize> = Vec::new();
    for name in deny_names {
        if let Some(n) = nr_of(name) {
            jeq_slots.push(filter.len());
            filter.push(jeq(n, 0, 0)); // 回填见下
        }
    }

    // socket() 特判：先比对 nr=SYS_socket，命中则加载 args[0] 比对 AF_VSOCK
    let socket_idx = filter.len();
    filter.push(jeq(nr_of("socket").unwrap_or(9999), 0, 0));
    let vsock_check_idx = filter.len();
    filter.push(stmt(BPF_LD_W_ABS, OFFSET_ARG0));
    filter.push(jeq(AF_VSOCK, 0, 0));
    // socket 非 AF_VSOCK：回到 nr 继续（后续全是 ALLOW 分支），这里直接 ALLOW
    let sock_allow_idx = filter.len();
    filter.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    // 走到这里说明所有 JEQ 都未命中 → ALLOW
    filter.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    // DENY：返回 EPERM（进程行为可预期；比 KILL 更利于诊断与契约断言）
    let deny_idx = filter.len();
    filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));

    // 回填 JEQ 的 jt = 目标 DENY 的相对距离
    // BPF 相对跳转从「下一条指令」开始计数，故 offset = deny_idx - slot - 1
    for &slot in &jeq_slots {
        filter[slot].jt = (deny_idx - slot - 1) as u8;
    }
    // socket JEQ 命中 → 跳到 vsock_check_idx
    filter[socket_idx].jt = (vsock_check_idx - socket_idx - 1) as u8;
    // AF_VSOCK JEQ 命中 → 跳到 DENY；未命中 → 跳到 sock_allow
    filter[vsock_check_idx + 1].jt = (deny_idx - (vsock_check_idx + 1) - 1) as u8;
    filter[vsock_check_idx + 1].jf = (sock_allow_idx - (vsock_check_idx + 1) - 1) as u8;

    let mut prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut sock_filter,
    };

    // no_new_privs 是安装过滤器的前提（非 root 时），并顺带封死 setuid 提权。
    unsafe {
        if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!(
                "prctl(NO_NEW_PRIVS) 失败: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &mut prog as *mut sock_fprog,
        ) != 0
        {
            return Err(format!(
                "seccomp(SET_MODE_FILTER) 失败: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn syscall_numbers_are_defined() {
        // 确保核心 syscall 号在所有 Linux 目标可解析（编译期检查）
        assert!(super::nr_of("unshare").is_some());
        assert!(super::nr_of("mount").is_some());
        assert!(super::nr_of("socket").is_some());
    }
}
