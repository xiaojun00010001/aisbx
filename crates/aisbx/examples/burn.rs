//! 沙箱内冒烟测试载荷:验证资源限制与网络拒绝的确定性工具。
//! 用法: burn mem <mb> | spin <sec> | fork <n> | conn <host> <port>

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("mem") => mem(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(64)),
        Some("spin") => spin(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(5)),
        Some("fork") => fork(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(10)),
        Some("write") => write(args.get(1).map(|s| s.as_str()).unwrap_or("")),
        Some("stderrdeny") => stderrdeny(args.get(1).map(|s| s.as_str()).unwrap_or("")),
        Some("spoof") => spoof(
            args.get(1).map(|s| s.as_str()).unwrap_or(""),
            args.get(2).map(|s| s.as_str()).unwrap_or(""),
        ),
        Some("probe2") => probe2(
            args.get(1).map(|s| s.as_str()).unwrap_or(""),
            args.get(2).map(|s| s.as_str()).unwrap_or(""),
        ),
        Some("flow") => flow(&args[1..]),
        Some("retryflow") => retryflow(&args[1..]),
        Some("proxy") => proxy(
            args.get(1).map(|s| s.as_str()).unwrap_or(""),
            args.get(2).and_then(|v| v.parse().ok()).unwrap_or(443),
        ),
        Some("socks") => socks(
            args.get(1).map(|s| s.as_str()).unwrap_or(""),
            args.get(2).and_then(|v| v.parse().ok()).unwrap_or(443),
        ),
        Some("loopback") => loopback(),
        Some("conn") => conn(
            args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1"),
            args.get(2).and_then(|v| v.parse().ok()).unwrap_or(80),
        ),
        _ => {
            eprintln!("usage: burn mem <mb> | spin <sec> | fork <n> | write <path> | stderrdeny <path> | conn <host> <port> | proxy|socks <host> <port> | flow <policy> <tokenFile> <target> <grant|deny>");
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
    println!(
        "allocated {mb} MB, sum={}",
        v.iter().map(|&b| b as u64).sum::<u64>()
    );
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
    if ok == n {
        0
    } else {
        2
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
            .args([
                "escalate", "-p", &policy, "--path", &target, "--access", "write", "--token", token,
            ])
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

/// P0 验证载荷:模拟「遵守代理环境变量的程序」,发一次 HTTP CONNECT。
/// 不解析命令、不主动上报——目标 host:port 由代理从 CONNECT 报文中自己读到。
/// 退出码:200=0(已放行),403=3(等待授权超时/拒绝),其它=1,无代理=2。
fn proxy(host: &str, port: u16) -> i32 {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let p = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .unwrap_or_default();
    if p.is_empty() || host.is_empty() {
        eprintln!("proxy: 缺少 HTTPS_PROXY 或 host(不在沙箱内?)");
        return 2;
    }
    let addr = p
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let mut s = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("proxy: 连接 {addr} 失败: {e}");
            return 1;
        }
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(25)));
    if let Err(e) = write!(
        s,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    ) {
        eprintln!("proxy: 发送 CONNECT 失败: {e}");
        return 1;
    }
    let _ = s.flush();
    let mut line = String::new();
    if BufReader::new(&s).read_line(&mut line).is_err() {
        eprintln!("proxy: 读取应答失败");
        return 1;
    }
    let code: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    println!("proxy_status={code} target={host}:{port}");
    match code {
        200 => 0,
        403 => 3,
        _ => 1,
    }
}

/// P0 验证载荷:模拟遵守 ALL_PROXY 的程序,发一次 SOCKS5 CONNECT。
/// 目标 host:port 由代理从 SOCKS5 握手报文中自己读到,程序零配合。
/// 退出码:REP=0 -> 0(已放行),REP=2 -> 3(拒绝),其它 -> 1,无代理 -> 2。
fn socks(host: &str, port: u16) -> i32 {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let p = std::env::var("ALL_PROXY")
        .or_else(|_| std::env::var("all_proxy"))
        .unwrap_or_default();
    if p.is_empty() || host.is_empty() {
        eprintln!("socks: 缺少 ALL_PROXY 或 host(不在沙箱内?)");
        return 2;
    }
    let addr = p
        .trim_start_matches("socks5h://")
        .trim_start_matches("socks5://")
        .trim_end_matches('/');
    let mut s = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("socks: 连接 {addr} 失败: {e}");
            return 1;
        }
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(25)));
    if s.write_all(&[5, 1, 0]).is_err() {
        return 1;
    }
    let mut greeting = [0u8; 2];
    if s.read_exact(&mut greeting).is_err() || greeting[1] != 0 {
        eprintln!("socks: 代理方法协商失败");
        return 1;
    }
    let hb = host.as_bytes();
    let mut req = vec![5, 1, 0, 3, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    if s.write_all(&req).is_err() {
        return 1;
    }
    let mut reply = [0u8; 10];
    if s.read_exact(&mut reply).is_err() {
        eprintln!("socks: 读取应答失败");
        return 1;
    }
    println!("socks_status={} target={host}:{port}", reply[1]);
    match reply[1] {
        0 => 0,
        2 => 3,
        _ => 1,
    }
}

/// 回环自检:在同一沙箱进程内起监听并连接,不依赖宿主网络(Linux netns 独立)。
fn loopback() -> i32 {
    use std::net::{TcpListener, TcpStream};
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            eprintln!("loopback bind failed: {e}");
            return 1;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let handle = std::thread::spawn(move || listener.accept().is_ok());
    std::thread::sleep(std::time::Duration::from_millis(50));
    let ok = TcpStream::connect(("127.0.0.1", port)).is_ok();
    let _ = handle.join();
    println!("loopback={}", if ok { "ok" } else { "fail" });
    if ok {
        0
    } else {
        1
    }
}

/// 方案 B 的端到端载荷:第一次执行被拒并上报,授权后由 launcher 重跑(attempt=2)。
/// 用法: burn retryflow <target> [grant|deny]
fn retryflow(args: &[String]) -> i32 {
    use std::process::Command;

    let target = args.first().cloned().unwrap_or_default();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("grant");
    let attempt: u32 = std::env::var("AISBX_ATTEMPT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let policy = std::env::var("AISBX_POLICY_FILE").unwrap_or_default();
    let token = std::env::var("AISBX_TOKEN").unwrap_or_default();
    let cli = std::env::var("AISBX_CLI").unwrap_or_else(|_| "aisbx".into());

    eprintln!(
        "retryflow env: cli={cli} policy={policy} broker={}",
        std::env::var("AISBX_BROKER_DIR").unwrap_or_default()
    );
    let escalate = |extra: &[&str]| -> i32 {
        let mut a: Vec<String> = vec!["escalate".into(), "-p".into(), policy.clone()];
        a.extend(extra.iter().map(|s| s.to_string()));
        match Command::new(&cli).args(&a).status() {
            Ok(s) => s.code().unwrap_or(99),
            Err(e) => {
                eprintln!("retryflow spawn {cli} 失败: {e}");
                99
            }
        }
    };

    if attempt <= 1 {
        // 第一次:预期真实写被拒
        let leaked = std::fs::write(&target, b"x").is_ok();
        println!("first_write={}", if leaked { "LEAK" } else { "denied" });
        let e = escalate(&["--path", &target, "--access", "write"]);
        println!("escalate={e}");
        // 网络越界的拒绝感知与上报
        let n = escalate(&[
            "--op",
            "net",
            "--host",
            "example.com",
            "--ip",
            "1.1.1.1",
            "--port",
            "443",
        ]);
        println!("net_escalate={n}");
        // 非零退出触发 launcher 以新策略快照重跑(leaked 已打印,不影响返回)
        let _ = leaked;
        return 1;
    }

    // 第二次:授权路径已进入新的策略快照
    let wrote = std::fs::write(&target, b"x").is_ok();
    println!("wrote={}", if wrote { "ok" } else { "fail" });
    let e1 = escalate(&["--path", &target, "--access", "write", "--token", &token]);
    let e2 = escalate(&["--path", &target, "--access", "write", "--token", &token]);
    println!("redeem={e1} replay={e2}");
    if mode == "deny" {
        return 1; // 黑名单用例不应走到成功重跑
    }
    if wrote && e1 == 0 && e2 != 0 {
        0
    } else {
        1
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

/// 输出 .NET / PowerShell 形态的拒绝消息,用于验证 L1 采集链路。
///
/// 真实形态由 .NET 的 `UnauthorizedAccessException` 产生:
///   `Write-Error: Access to the path 'C:\ws\out.txt' is denied.`
/// Rust 标准库的 `io::Error` **不带路径**(实测 `Permission denied (os error 5)`),
/// 所以 Windows 上要验证 L1 必须用这个形态的载荷。
fn stderrdeny(path: &str) -> i32 {
    // 真的尝试写:被拒 → 打印带路径的 .NET 形态消息(供 L1 采集);被授权 → 写成功。
    // 这样「拒绝 → 授权 → 重跑成功」是真实链路,不是演出来的。
    match std::fs::write(path, b"x") {
        Ok(_) => {
            println!("wrote {path}");
            0
        }
        Err(_) => {
            eprintln!("Write-Error: Access to the path '{path}' is denied.");
            1
        }
    }
}

/// 一次 run 内验证「授权粒度不外溢」。
///
/// 1) 先尝试创建 `newp`(白名单外 → 被拒 → 打印带路径的 .NET 形态消息供 L1 采集);
/// 2) **不退出**,再尝试写 `oldp`(同目录下的既有文件)。
///    若授权外溢(父目录被授了 Modify),第 2 步会成功 → 打印 `EXISTING_WRITEABLE`。
///
/// 返回值位标志:bit0 = newp 创建成功,bit1 = oldp 写成功。
fn probe2(newp: &str, oldp: &str) -> i32 {
    let mut flags = 0;
    match std::fs::write(newp, b"x") {
        Ok(_) => {
            println!("NEW_CREATED {newp}");
            flags |= 1;
        }
        Err(_) => {
            eprintln!("Write-Error: Access to the path '{newp}' is denied.");
        }
    }
    match std::fs::write(oldp, b"x") {
        Ok(_) => {
            println!("EXISTING_WRITEABLE {oldp}");
            flags |= 2;
        }
        Err(_) => println!("EXISTING_DENIED {oldp}"),
    }
    // 返回码只反映「目标文件能否创建」:被拒 → 非 0(launcher 才会等授权并重跑);
    // 「既有文件是否可写」通过输出标记表达,不影响退出码。
    if flags & 1 != 0 {
        0
    } else {
        1
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

/// 对抗用例:**自称**一个无害路径,却**真实访问**另一个路径。
///
/// 用来检验两个感知通道的可信度差异,以及「L1 路径可伪造」是否构成越权:
/// - L2(内核日志,macOS):采到的应是**真实被拒的路径**(内核不受欺骗);
/// - L1(stderr 自报):只能采到**自称的路径**(程序想报什么就报什么);
/// - 授权自称路径后,真实路径**仍应被内核拒绝** → 伪造换不来越权。
fn spoof(claimed: &str, actual: &str) -> i32 {
    // 先真的尝试访问 actual(被拒 → 内核日志会记下真实路径)
    let denied = std::fs::write(actual, b"x").is_err();
    if denied {
        println!("ACTUAL_DENIED {actual}");
    } else {
        println!("ACTUAL_WRITABLE {actual}");
    }
    // 再自称一个「被拒」的路径(内核从未拒绝过它 → 只有 stderr 里有)
    eprintln!("sh: {claimed}: Operation not permitted");
    println!("CLAIMED_REPORTED {claimed}");
    if denied {
        1
    } else {
        0
    }
}
