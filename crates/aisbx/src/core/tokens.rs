//! 一次性授权 token:TTL、路径前缀、access 绑定、单次消费。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct IssuedToken {
    pub path: String,
    pub access: String,
    pub expires_at: Instant,
    pub command_id: String,
}

#[derive(Default)]
pub struct TokenStore {
    map: HashMap<String, IssuedToken>,
}

impl TokenStore {
    pub fn issue(&mut self, path: &str, access: &str, ttl: u64, command_id: &str) -> String {
        self.map.retain(|_, t| t.expires_at > Instant::now());
        let token = random_token();
        self.map.insert(
            token.clone(),
            IssuedToken {
                path: path.to_string(),
                access: access.to_string(),
                expires_at: Instant::now() + Duration::from_secs(ttl.clamp(1, 3600)),
                command_id: command_id.to_string(),
            },
        );
        token
    }

    /// 校验并消费。重放、过期、路径不匹配、access 不满足一律失败。
    ///
    /// `command_id` 校验是纵深防御:token 必须属于**当前这条命令**。
    /// 即便 token 从别处泄漏到手,也无法在另一条命令上消费。
    pub fn redeem(
        &mut self,
        token: &str,
        path: &str,
        access: &str,
        command_id: &str,
    ) -> Result<IssuedToken, String> {
        self.map.retain(|_, t| t.expires_at > Instant::now());
        let hit = self.map.get(token).cloned();
        let Some(t) = hit else {
            return Err("token 无效、已过期或已消费".into());
        };
        if t.command_id != command_id {
            return Err("token 不属于当前命令".into());
        }
        if !crate::core::decision::is_prefix_hit(std::slice::from_ref(&t.path), path) {
            return Err("token 与请求路径不匹配".into());
        }
        if !crate::core::decision::access_satisfied(&t.access, access) {
            return Err("token 访问级别不足".into());
        }
        self.map.remove(token);
        Ok(t)
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// 128bit 随机:优先 /dev/urandom,失败时退化为时间+pid+计数器(仅开发降级)。
pub fn random_token() -> String {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut b = [0u8; 16];
        if f.read_exact(&mut b).is_ok() {
            use std::fmt::Write;
            let mut s = String::with_capacity(b.len() * 2);
            for x in b {
                let _ = write!(s, "{x:02x}");
            }
            return s;
        }
    }
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("dev-{ts:x}-{:x}-{:x}", std::process::id(), n)
}
