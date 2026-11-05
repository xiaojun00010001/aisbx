//! 沙箱内冒烟测试载荷:验证资源限制与网络拒绝的确定性工具。
//! 用法: burn mem <mb> | spin <sec> | fork <n> | conn <host> <port>

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("mem") => mem(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(64)),
        Some("spin") => spin(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(5)),
        Some("fork") => fork(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(10)),
        Some("write") => write(args.get(1).map(|s| s.as_str()).unwrap_or("")),
        Some("flow") => flow(&args[1..]),
        Some("servepipe") => servepipe(&args[1..]),
        Some("openpipe") => openpipe(args.get(1).map(|s| s.as_str()).unwrap_or("")),
        Some("tokeninfo") => tokeninfo(),
        Some("conn") => conn(
            args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1"),
            args.get(2).and_then(|v| v.parse().ok()).unwrap_or(80),
        ),
        _ => {
            eprintln!("usage: burn mem <mb> | spin <sec> | fork <n> | write <path> | conn <host> <port> | flow <policy> <tokenFile> <target> <grant|deny>");
            2
        }
    };
    std::process::exit(code);
}

/// 分配并触碰 mb MB 内存。超过 Job 内存上限时分配失败(进程 abort,退出码非 0)。
fn mem(mb: usize) -> i32 {
    let n = mb * 1024 * 1024;
    // 必须用 vec![0; n] 使 len=n(with_capacity 只有 capacity,按下标写会越界 panic)
    let mut v: Vec<u8> = vec![0u8; n];
    for i in (0..n).step_by(4096) {
        v[i] = 1;
    }
    println!("allocated {mb} MB, sum={}", v.iter().map(|&b| b as u64).sum::<u64>());
    0
}

/// 空转 sec 秒(CPU 节流测试用,只打印迭代数供人工对照)。
fn spin(sec: u64) -> i32 {
    let t = std::time::Instant::now();
    let mut x: u64 = 0;
    while t.elapsed().as_secs() < sec {
        x = x.wrapping_add(1);
    }
    println!("{x} iterations in {sec}s");
    0
}

/// 并发拉起 n 个子进程后再统一等待。超过 Job 进程数上限时 spawn 失败,退出码 2。
fn fork(n: u32) -> i32 {
    use std::process::{Command, Stdio};
    let mut children = Vec::new();
    let mut ok = 0u32;
    for _ in 0..n {
        match Command::new("cmd")
            .args(["/c", "exit"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => {
                children.push(c);
                ok += 1;
            }
            Err(_) => break,
        }
    }
    for mut c in children {
        let _ = c.wait();
    }
    println!("spawned {ok}/{n}");
    if ok == n { 0 } else { 2 }
}

/// 打印当前进程令牌的 User / 组 SID / 完整性级别(诊断:核对 AppContainer 身份)。
fn tokeninfo() -> i32 {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree, PSID};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenGroups, TokenIntegrityLevel, TokenUser, TOKEN_GROUPS,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe fn sid_str(psid: PSID) -> String {
        let mut out: windows_sys::core::PWSTR = std::ptr::null_mut();
        unsafe {
            if ConvertSidToStringSidW(psid, &mut out) == 0 || out.is_null() {
                return "?".into();
            }
            let n = (0..256).take_while(|&i| *out.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, n));
            LocalFree(out as _);
            s
        }
    }

    unsafe fn query(h: HANDLE, class: i32) -> Option<Vec<u8>> {
        let mut need: u32 = 0;
        GetTokenInformation(h, class, std::ptr::null_mut(), 0, &mut need);
        if need == 0 {
            return None;
        }
        let mut buf = vec![0u8; need as usize];
        if GetTokenInformation(h, class, buf.as_mut_ptr() as *mut _, need, &mut need) == 0 {
            return None;
        }
        Some(buf)
    }

    unsafe {
        let mut h: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) == 0 {
            eprintln!("tokeninfo: OpenProcessToken 失败");
            return 1;
        }
        if let Some(b) = query(h, TokenUser) {
            let tu = &*(b.as_ptr() as *const TOKEN_USER);
            println!("user={}", sid_str(tu.User.Sid));
        }
        if let Some(b) = query(h, TokenGroups) {
            let tg = &*(b.as_ptr() as *const TOKEN_GROUPS);
            let n = tg.GroupCount as usize;
            let arr = std::slice::from_raw_parts(tg.Groups.as_ptr(), n);
            let sids: Vec<String> = arr.iter().map(|g| format!("{}(0x{:x})", sid_str(g.Sid), g.Attributes)).collect();
            println!("groups({n})={}", sids.join(","));
        }
        if let Some(b) = query(h, TokenIntegrityLevel) {
            let ml = &*(b.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            println!("il={}", sid_str(ml.Label.Sid));
        }
        CloseHandle(h);
    }
    0
}

/// 宿主机侧:建一根命名管道(可指定 SDDL),等待一次连接。用于冒烟探针。
/// 用法: servepipe <name> [sddl]
fn servepipe(args: &[String]) -> i32 {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    let name = args.first().cloned().unwrap_or_default();
    if name.is_empty() {
        eprintln!("servepipe 需要管道名");
        return 2;
    }
    let full = format!(r"\\.\pipe\{name}");
    let name_w: Vec<u16> = full.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if let Some(sddl) = args.get(1) {
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                eprintln!("servepipe: SDDL 解析失败: {sddl}");
                return 2;
            }
        }
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    unsafe {
        let h = CreateNamedPipeW(
            name_w.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            if sd.is_null() { std::ptr::null() } else { &sa },
        );
        if h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            eprintln!("servepipe: CreateNamedPipeW 失败 err={}", windows_sys::Win32::Foundation::GetLastError());
            return 1;
        }
        println!("servepipe ready {name}");
        ConnectNamedPipe(h, std::ptr::null_mut());
        println!("servepipe connected {name}");
    }
    // 保持实例存活,由冒烟脚本负责结束进程
    std::thread::sleep(std::time::Duration::from_secs(20));
    0
}

/// 沙箱内:尝试以读写方式打开管道,打印结果。成功 0 / 失败 1。
fn openpipe(name: &str) -> i32 {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING};
    let full = format!(r"\\.\pipe\{name}");
    let name_w: Vec<u16> = full.encode_utf16().chain(std::iter::once(0)).collect();
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
            println!("openpipe={name} err={}", GetLastError());
            return 1;
        }
        CloseHandle(h);
        println!("openpipe={name} ok");
        0
    }
}

/// 授权闭环载荷(运行在沙箱内):等待宿主写入 token 文件 → 消费 token →
/// 真实写入 → 用同一 token 重放。
/// 参数: flow <policy> <tokenFile> <targetPath> <grant|deny>
/// grace: 期望 escalate 成功并写入;deny: 期望 escalate 被拒(黑名单优先)。
fn flow(args: &[String]) -> i32 {
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    let policy = args.first().cloned().unwrap_or_default();
    let token_file = args.get(1).cloned().unwrap_or_default();
    let target = args.get(2).cloned().unwrap_or_default();
    let expect = args.get(3).cloned().unwrap_or_else(|| "grant".into());
    // current_exe 在 Windows 上可能返回 \\?\C:\... 前缀,CreateProcessW 不接受,需剥离
    let exe_raw = std::env::current_exe().unwrap_or_default();
    let exe_str = {
        let s = exe_raw.to_string_lossy().to_string();
        s.strip_prefix(r"\\?\").map(|x| x.to_string()).unwrap_or(s)
    };
    let exe: PathBuf = PathBuf::from(&exe_str)
        .parent()
        .map(|d| d.join("aisbx.exe"))
        .unwrap_or_else(|| PathBuf::from("aisbx.exe"));

    let escalate = |token: &str| -> i32 {
        // 不能用 Stdio::null():AppContainer 内打开 NUL 设备被拒(os error 5),
        // 默认继承父进程句柄即可,输出随 flow 一起落盘,反而便于取证。
        match Command::new(&exe)
            .args(["escalate", "-p", &policy, "--path", &target, "--access", "write", "--token", token])
            .status()
        {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("flow: spawn {exe:?} 失败: {e}");
                99
            }
        }
    };

    // 等宿主 authorize 写入 token(run 存活期间)
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut token = String::new();
    while Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(&token_file) {
            let t = s.trim().to_string();
            if !t.is_empty() {
                token = t;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if token.is_empty() {
        eprintln!("flow: 等待 token 超时");
        return 3;
    }

    let first = escalate(&token);
    println!("escalate={first}");

    if expect.eq_ignore_ascii_case("deny") {
        return if first != 0 { 0 } else { 1 };
    }
    if first != 0 {
        return 1;
    }

    let wrote = std::fs::write(&target, b"x").is_ok();
    println!("write={}", if wrote { "ok" } else { "fail" });

    // 一次性 token:重放必须被拒
    let replay = escalate(&token);
    println!("replay={replay}");

    if !wrote || replay == 0 {
        1
    } else {
        0
    }
}

/// 向 path 写入一个字节。成功 0 / 失败(ACL 拒绝等)1 / 参数缺失 2。
/// 用于替换 `cmd /c echo >` —— 避免 Windows 命令行引号解析带来的不确定性。
fn write(path: &str) -> i32 {
    if path.is_empty() {
        eprintln!("write 需要目标路径");
        return 2;
    }
    match std::fs::write(path, b"x") {
        Ok(_) => {
            println!("wrote {path}");
            0
        }
        Err(e) => {
            eprintln!("write failed: {e}");
            1
        }
    }
}

/// 连接 host:port(带 3s 超时,避免无 capability 时挂死)。成功 0 / 失败 1。
fn conn(host: &str, port: u16) -> i32 {
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => {
            eprintln!("resolve failed: {e}");
            return 1;
        }
    };
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            Ok(_) => {
                println!("connected {host}:{port}");
                return 0;
            }
            Err(e) => eprintln!("connect {addr} failed: {e}"),
        }
    }
    1
}
