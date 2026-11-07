//! P0 · 宿主侧网络代理(net.sock)。
//!
//! 沙箱内所有 HTTP/HTTPS 出口被收敛到本机 relay,relay 把 CONNECT 里的
//! **真实 host:port** 送进这条 UDS。目标信息来自协议本身:
//! 不解析命令行、不猜测 stderr、不需要被跑的程序配合。
//!
//! 未授权目标 -> 结构化 violation + 等待用户授权(运行中即可放行,不用重跑命令);
//! 已授权目标 -> 宿主代连并双向转发。授权清单只在本次任务内存里,不写回策略文件。

use std::io::Write;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::core::state::State;

/// 等待用户授权的最长时间。超时即 403,不影响命令本身继续执行。
const WAIT_AUTH_SECS: u64 = 12;

pub fn spawn_server(listener: UnixListener, state: Arc<Mutex<State>>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let s = state.clone();
                    std::thread::spawn(move || {
                        let _ = handle(stream, &s);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
}

fn handle(stream: UnixStream, state: &Arc<Mutex<State>>) -> Result<(), String> {
    // 逐字节读:BufReader 会预读并吞掉 relay 在同一条 UDS 上随后写入的隧道数据。
    let mut req_line = String::new();
    super::relay::read_line_unbuffered(&stream, &mut req_line)
        .map_err(|e| format!("读取代理请求失败: {e}"))?;
    let req: Value = serde_json::from_str(req_line.trim()).unwrap_or_default();
    let host = req.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let port = req.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let ip = req.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let command_id = req.get("command_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let mut out = stream.try_clone().map_err(|e| format!("clone UDS 失败: {e}"))?;

    if host.is_empty() || port == 0 {
        let _ = writeln!(out, "{}", json!({"allow": false, "reason": "empty target"}));
        return Ok(());
    }
    {
        let s = state.lock().unwrap_or_else(|p| p.into_inner());
        if !command_id.is_empty() && command_id != s.command_id {
            let _ = writeln!(out, "{}", json!({"allow": false, "reason": "command_id mismatch"}));
            return Ok(());
        }
    }

    // 防 SSRF:代理不能成为打通宿主本机服务 / 云元数据的通道。
    if let Some(addr) = forbidden_target(&host, port) {
        let _ = writeln!(out, "{}", json!({"allow": false, "reason": format!("forbidden address {addr}")}));
        return Ok(());
    }

    // 记一次真实越界(同一目标只记一次,避免重连刷屏)。
    {
        let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
        let seen = s
            .violations
            .iter()
            .any(|v| v.kind == "net" && v.host == host && v.port == port);
        if !seen {
            let cid = s.command_id.clone();
            s.net_violation(&host, &ip, port, "needs-approval");
            s.emit_event(json!({
                "event": "proxy.deny", "host": host, "ip": ip, "port": port,
                "reason": "needs-approval", "command_id": cid
            }));
        }
    }

    // 运行中等待用户授权;授权到达即放行【本次连接】,命令不需要重跑。
    let deadline = Instant::now() + Duration::from_secs(WAIT_AUTH_SECS);
    let allowed = loop {
        {
            let s = state.lock().unwrap_or_else(|p| p.into_inner());
            if s.net_allowed(&host, port) {
                break true;
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    if !allowed {
        let _ = writeln!(out, "{}", json!({"allow": false, "reason": "user approval not granted"}));
        return Ok(());
    }
    writeln!(out, "{}", json!({"allow": true, "host": host, "port": port}))
        .map_err(|e| format!("写代理应答失败: {e}"))?;

    // 宿主代连(沙箱内 netns / Seatbelt 均无外网),然后 UDS <-> TCP 双向搬运。
    let mut upstream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => {
            // 策略已放行,只是宿主侧上游不可达(CI 常无外网)。relay 仍会回 200,
            // 命令因此能验证「授权已生效」;如实记一条事件,不假装连上了。
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            let cid = s.command_id.clone();
            s.emit_event(json!({
                "event": "proxy.upstream_unreachable", "host": host, "port": port,
                "command_id": cid
            }));
            return Ok(());
        }
    };
    let mut to_up = stream.try_clone().map_err(|e| format!("clone UDS 失败: {e}"))?;
    let mut from_up = upstream.try_clone().map_err(|e| format!("clone TCP 失败: {e}"))?;
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut to_up, &mut upstream);
        let _ = upstream.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut from_up, &mut out);
    let _ = out.flush();
    let _ = t.join();
    Ok(())
}

/// 解析目标并拒绝本机/私网/链路本地/云元数据地址。解析失败交给后续 connect 处理。
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
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 168 && o[1] == 63 && o[2] == 129 && o[3] == 16)
                || (o[0] == 100 && o[1] == 100 && o[2] == 100 && o[3] == 200)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback()
                || v.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x100 && s[1] == 0)
        }
    }
}
