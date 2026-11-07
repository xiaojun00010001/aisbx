//! P0 · 沙箱内入口 + HTTP CONNECT relay。
//!
//! `aisbx __unix_entry '<cmd-json>'` 是 Linux/macOS 沙箱里的第一个进程:
//!   1. (Linux) 把独立 netns 里的 lo 置 up;
//!   2. 在沙箱内回环监听一个随机端口,起 HTTP CONNECT relay;
//!   3. 注入 HTTP(S)_PROXY 指向该 relay;
//!   4. spawn 目标命令,透传退出码。
//!
//! 于是「遵守代理环境变量的程序」无需任何改造:它的每一次出站都会
//! 经过 relay,relay 从 CONNECT 报文里读到真实 host:port 并交给宿主裁决。
//! 裸 socket 程序不走代理,仍由内核默认拒绝(如实标注为 partial)。

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;

use serde_json::json;

pub fn entry(args: &[String]) -> Result<i32, String> {
    use std::os::unix::process::CommandExt;

    let raw = args.first().ok_or("__unix_entry 缺少命令 JSON")?;
    let cmd: Vec<String> = serde_json::from_str(raw).map_err(|e| format!("命令 JSON 解析失败: {e}"))?;
    if cmd.is_empty() {
        return Err("空命令".into());
    }

    #[cfg(target_os = "linux")]
    bring_loopback_up();

    let broker_dir = std::env::var("AISBX_BROKER_DIR").unwrap_or_default();
    let command_id = std::env::var("AISBX_COMMAND_ID").unwrap_or_default();
    let port: u16 = std::env::var("AISBX_RELAY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or("缺少 AISBX_RELAY_PORT(launcher 未分配 relay 端口)")?;

    // relay 跑在独立进程里,入口随后 exec 目标命令,保持 PID 不变。
    // 实测:Seatbelt 只为由 sandbox-exec 直接 exec 的进程上报 violation 日志,
    // 再 spawn 一层会导致内核不上报,P1 的按 PID 归属因此失效。
    let exe = std::env::current_exe().map_err(|e| format!("取当前 exe 失败: {e}"))?;
    let _relay = Command::new(&exe)
        .args(["__relay_only", &port.to_string(), &broker_dir, &command_id])
        .spawn()
        .map_err(|e| format!("启动沙箱内 relay 失败: {e}"))?;
    for _ in 0..40 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let proxy = format!("http://127.0.0.1:{port}");
    for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(k, &proxy);
    }
    std::env::set_var("NO_PROXY", "localhost,127.0.0.1,::1");
    std::env::set_var("no_proxy", "localhost,127.0.0.1,::1");

    // exec 后 PID 不变,内核日志里的 PID 就是沙箱入口 PID。
    report_pid(&broker_dir, &command_id, std::process::id());
    let err = Command::new(&cmd[0]).args(&cmd[1..]).exec();
    Err(format!("exec {} 失败: {err}", cmd[0]))
}

/// `__relay_only <port> <broker_dir> <command_id>`:沙箱内独立 relay 进程。
/// 由 launcher 在进程组兜底 kill 时一并回收。
pub fn relay_only(args: &[String]) -> Result<i32, String> {
    let port: u16 = args
        .first()
        .and_then(|v| v.parse().ok())
        .ok_or("__relay_only 缺少端口")?;
    let dir = args.get(1).cloned().unwrap_or_default();
    let command_id = args.get(2).cloned().unwrap_or_default();
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("沙箱内 relay 监听 {port} 失败: {e}"))?;
    serve(listener, PathBuf::from(dir).join("net.sock"), command_id);
    Ok(0)
}

fn report_pid(broker_dir: &str, command_id: &str, pid: u32) {
    let sock = PathBuf::from(broker_dir).join("esc.sock");
    let Ok(mut s) = UnixStream::connect(sock) else {
        return; // best-effort:broker 不可达时 P1 退化为无归属,能力报告已标 partial
    };
    let _ = writeln!(s, "{}", json!({"op":"pid","pid":pid,"command_id":command_id}));
    let mut line = String::new();
    let _ = BufReader::new(&s).read_line(&mut line);
}

#[cfg(target_os = "linux")]
fn bring_loopback_up() {
    for bin in ["ip", "/sbin/ip", "/usr/sbin/ip"] {
        if let Ok(s) = Command::new(bin)
            .args(["link", "set", "lo", "up"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            if s.success() {
                break;
            }
        }
    }
}

fn serve(listener: TcpListener, net_sock: PathBuf, command_id: String) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { break };
        let sock = net_sock.clone();
        let cid = command_id.clone();
        std::thread::spawn(move || {
            let _ = handle_client(stream, sock, cid);
        });
    }
}

fn handle_client(mut stream: TcpStream, net_sock: PathBuf, command_id: String) -> Result<(), String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut first = String::new();
    reader.read_line(&mut first).map_err(|e| e.to_string())?;
    // 读完剩余请求头,否则会被当成隧道数据
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" || h == "\n" {
            break;
        }
    }

    let mut parts = first.trim().split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (host, port) = if method.eq_ignore_ascii_case("CONNECT") {
        parse_authority(target).ok_or_else(|| format!("非法 CONNECT 目标 {target}"))?
    } else {
        return write_http(&mut stream, 405, "only CONNECT is supported by this prototype");
    };

    let mut uds = match UnixStream::connect(&net_sock) {
        Ok(s) => s,
        Err(_) => return write_http(&mut stream, 502, "host net proxy unavailable"),
    };
    let req = json!({
        "op": "connect", "host": host, "port": port,
        "ip": "", "command_id": command_id
    });
    writeln!(uds, "{req}").map_err(|e| e.to_string())?;

    let mut line = String::new();
    {
        let mut r = BufReader::new(&uds);
        r.read_line(&mut line).map_err(|e| e.to_string())?;
    }
    let reply: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_default();
    if !reply.get("allow").and_then(|v| v.as_bool()).unwrap_or(false) {
        let reason = reply.get("reason").and_then(|v| v.as_str()).unwrap_or("denied");
        return write_http(&mut stream, 403, &format!("aisbx: {reason}"));
    }

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| e.to_string())?;
    stream.set_read_timeout(None).ok();
    let _ = uds.set_read_timeout(None);

    let mut up = uds.try_clone().map_err(|e| e.to_string())?;
    let mut down = stream.try_clone().map_err(|e| e.to_string())?;
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut up, &mut down);
        let _ = down.shutdown(std::net::Shutdown::Write);
    });
    let mut src = reader.into_inner();
    let _ = std::io::copy(&mut src, &mut uds);
    let _ = uds.flush();
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
