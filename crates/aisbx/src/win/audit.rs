//! 提权审计:JSONL 追加写,每次授权/拒绝一行。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct Audit {
    path: Option<PathBuf>,
}

impl Audit {
    pub fn new(path: Option<&Path>) -> Audit {
        Audit { path: path.map(|p| p.to_path_buf()) }
    }

    pub fn log(&self, event: &serde_json::Value) {
        let Some(p) = &self.path else { return };
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
            let line = serde_json::to_string(event).unwrap_or_default();
            let _ = writeln!(f, "{line}");
        }
    }
}
