//! 沙箱内冒烟测试载荷:验证资源限制与网络拒绝的确定性工具。
//! 用法: burn mem <mb> | spin <sec> | fork <n> | conn <host> <port>

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("mem") => mem(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(64)),
        Some("spin") => spin(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(5)),
        Some("fork") => fork(args.get(1).and_then(|v| v.parse().ok()).unwrap_or(10)),
        Some("conn") => conn(
            args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1"),
            args.get(2).and_then(|v| v.parse().ok()).unwrap_or(80),
        ),
        _ => {
            eprintln!("usage: burn mem <mb> | spin <sec> | fork <n> | conn <host> <port>");
            2
        }
    };
    std::process::exit(code);
}

/// 分配并触碰 mb MB 内存。超过 Job 内存上限时分配失败(进程 abort,退出码非 0)。
fn mem(mb: usize) -> i32 {
    let n = mb * 1024 * 1024;
    let mut v: Vec<u8> = Vec::with_capacity(n);
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
