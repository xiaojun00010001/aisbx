//! 审计 JSONL:三平台事件名一致。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

pub struct Audit {
    path: Option<PathBuf>,
}

impl Audit {
    pub fn new(path: Option<&std::path::Path>) -> Self {
        Self {
            path: path.map(|p| p.to_path_buf()),
        }
    }

    pub fn log(&self, event: &serde_json::Value) {
        let Some(p) = &self.path else { return };
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
            let _ = writeln!(f, "{}", serde_json::to_string(event).unwrap_or_default());
        }
    }
}
