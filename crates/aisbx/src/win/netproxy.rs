//! P0 · Windows 侧网络代理。
//!
//! Windows 的 AppContainer 已有回环例外,沙箱内程序可直接连宿主的回环代理端口,
//! 因此不需要 Unix 那层的沙箱内 relay:launcher 在宿主监听 127.0.0.1:<随机端口>,
//! 注入 HTTP(S)_PROXY,解析 HTTP CONNECT 即可拿到**真实 host:port**。
//! 与 Unix 侧输出同一套事件(violation / proxy.deny / net.grant),外层接口统一。

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING};

use aisbx_policy::Policy;

use super::audit::Audit;

const WAIT_AUTH_SECS: u64 = 12;

/// 代理与宿主控制通道共享:observed 是真实观察过的拒绝,granted 是用户放行清单。
#[derive(Default)]
pub struct NetState {
    pub observed: Vec<String>,
    pub granted: Vec<String>,
}

impl NetState {
    pub fn key(host: &str, port: u16) -> String {
        format!("{}:{}", host.to_ascii_lowercase(), port)
    }
}

pub struct NetProxy {
    pub port: u16,
    stop: Arc<AtomicBool>,
}

impl Drop for NetProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn start(net_state: Arc<Mutex<NetState>>, audit: Arc<Audit>) -> Result<NetProxy, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Windows 网络代理监听失败: {e}"))?;
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let _ = listener.set_nonblocking(true);
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    std::thread::spawn(move || {
        while !stop2.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let s = net_state.clone();
                    let a = audit.clone();
                    std::thread::spawn(move || {
                        let _ = handle_client(stream, &s, &a);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    Ok(NetProxy { port, stop })
}

fn handle_client(mut stream: TcpStream, state: &Arc<Mutex<NetState>>, audit: &Arc<Audit>) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    // 首字节 0x05 = SOCKS5;其余按 HTTP CONNECT。peek 不消耗数据。
    let mut probe = [0u8; 1];
    if stream.peek(&mut probe).unwrap_or(0) == 1 && probe[0] == 0x05 {
        return handle_socks5(stream, state, audit);
    }

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut first = String::new();
    reader.read_line(&mut first).map_err(|e| e.to_string())?;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" || h == "\n" {
            break;
        }
    }
    let mut parts = first.trim().split_whitespace();
    if !parts.next().unwrap_or("").eq_ignore_ascii_case("CONNECT") {
        return write_http(&mut stream, 405, "only CONNECT/SOCKS5 are supported");
    }
    let target = parts.next().unwrap_or("");
    let (host, port) = parse_authority(target).ok_or_else(|| format!("非法 CONNECT 目标 {target}"))?;

    if !decide(state, audit, &host, port) {
        return write_http(&mut stream, 403, "aisbx: user approval not granted");
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| e.to_string())?;
    tunnel(stream, reader.into_inner(), &host, port, audit)
}

/// SOCKS5(NO-AUTH + CONNECT):与 HTTP CONNECT 复用同一套裁决与授权清单,
/// 目标由 ATYP/DST.ADDR 自带,覆盖 `ALL_PROXY=socks5h://` 的客户端。
fn handle_socks5(mut stream: TcpStream, state: &Arc<Mutex<NetState>>, audit: &Arc<Audit>) -> Result<(), String> {
    use std::io::Read;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).map_err(|e| e.to_string())?;
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).map_err(|e| e.to_string())?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).map_err(|e| e.to_string())?;
        return Ok(());
    }
    stream.write_all(&[5, 0]).map_err(|e| e.to_string())?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(|e| e.to_string())?;
    let (host, port) = match head[3] {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).map_err(|e| e.to_string())?;
            (format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), win_read_port(&mut stream)?)
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(|e| e.to_string())?;
            let mut b = vec![0u8; len[0] as usize];
            stream.read_exact(&mut b).map_err(|e| e.to_string())?;
            (String::from_utf8_lossy(&b).to_string(), win_read_port(&mut stream)?)
        }
        _ => {
            let _ = stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]);
            return Ok(());
        }
    };
    if !decide(state, audit, &host, port) {
        stream.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).map_err(|e| e.to_string())?;
        return Ok(());
    }
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).map_err(|e| e.to_string())?;
    let src = stream.try_clone().map_err(|e| e.to_string())?;
    tunnel(stream, src, &host, port, audit)
}

fn win_read_port(stream: &mut TcpStream) -> Result<u16, String> {
    use std::io::Read;
    let mut b = [0u8; 2];
    stream.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u16::from_be_bytes(b))
}

/// 记一次真实越界并等待用户授权(运行中放行,命令不用重跑)。
fn decide(state: &Arc<Mutex<NetState>>, audit: &Arc<Audit>, host: &str, port: u16) -> bool {
    if let Some(addr) = forbidden_target(host, port) {
        audit.log(&json!({
            "event": "proxy.deny", "host": host, "port": port,
            "reason": format!("forbidden address {addr}")
        }));
        return false;
    }
    let key = NetState::key(host, port);
    {
        let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
        if !s.observed.contains(&key) {
            s.observed.push(key.clone());
            audit.log(&json!({
                "event": "violation", "kind": "net", "host": host, "ip": "", "port": port,
                "reason": "needs-approval", "source": "proxy", "command_id": ""
            }));
            audit.log(&json!({
                "event": "proxy.deny", "host": host, "port": port, "reason": "needs-approval"
            }));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(WAIT_AUTH_SECS);
    loop {
        {
            let s = state.lock().unwrap_or_else(|p| p.into_inner());
            if s.granted.contains(&key) {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn tunnel(stream: TcpStream, mut src: TcpStream, host: &str, port: u16, audit: &Arc<Audit>) -> Result<(), String> {
    stream.set_read_timeout(None).ok();
    // 策略已放行即回成功:CI 常无外网,不应让「上游不可达」掩盖「授权已生效」。
    let mut upstream = match TcpStream::connect((host, port)) {
        Ok(s) => s,
        Err(_) => {
            audit.log(&json!({"event": "proxy.upstream_unreachable", "host": host, "port": port}));
            return Ok(());
        }
    };
    let mut down = stream.try_clone().map_err(|e| e.to_string())?;
    let mut up_read = upstream.try_clone().map_err(|e| e.to_string())?;
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut up_read, &mut down);
        let _ = down.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut src, &mut upstream);
    let _ = upstream.flush();
    let _ = t.join();
    Ok(())
}

fn parse_authority(target: &str) -> Option<(String, u16)> {
    let (h, p) = target.rsplit_once(':')?;
    let port: u16 = p.parse().ok()?;
    if h.is_empty() || port == 0 {
        return None;
    }
    Some((h.to_string(), port))
}

fn write_http(stream: &mut TcpStream, code: u16, body: &str) -> Result<(), String> {
    let reason = if code == 403 { "Forbidden" } else { "Error" };
    let msg = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(msg.as_bytes()).map_err(|e| e.to_string())?;
    let _ = stream.flush();
    Ok(())
}

fn forbidden_target(host: &str, port: u16) -> Option<String> {
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return None;
    };
    for a in addrs {
        let ip = a.ip();
        if ip.is_loopback() || ip.is_unspecified() || is_forbidden_ip(&ip) {
            return Some(ip.to_string());
        }
    }
    None
}

fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || o[0] == 0
                || (o[0] == 100 && o[1] == 100 && o[2] == 100 && o[3] == 200)
                || (o[0] == 168 && o[1] == 63 && o[2] == 129 && o[3] == 16)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback() || v.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// 宿主侧 `aisbx authorize --host <host> --port <port>`(Windows)。
/// 走既有控制管道,DACL 不含 package SID,沙箱内无法自行签发。
pub fn authorize_net_client(policy: &Policy, host: &str, port: u16) -> Result<i32, String> {
    let name = format!(r"\\.\pipe\{}-ctl", policy.pipe_name());
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let body = json!({"op":"net-issue","host":host,"port":port}).to_string();
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
            return Err(format!("无法连接控制管道 {name}(任务未运行?)"));
        }
        let line = format!("{body}\n");
        let mut written: u32 = 0;
        let _ = windows_sys::Win32::Storage::FileSystem::WriteFile(
            h,
            line.as_ptr(),
            line.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        );
        let mut buf = [0u8; 4096];
        let mut n: u32 = 0;
        let _ = windows_sys::Win32::Storage::FileSystem::ReadFile(
            h,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut n,
            std::ptr::null_mut(),
        );
        CloseHandle(h);
        let reply = String::from_utf8_lossy(&buf[..n as usize]).trim().to_string();
        println!("{reply}");
        let v: Value = serde_json::from_str(&reply).unwrap_or_default();
        Ok(if v.get("granted").and_then(|x| x.as_bool()).unwrap_or(false) { 0 } else { 1 })
    }
}
