//! 平台后端分发骨架(阶段 0,见 `docs/04-跨平台实现方案.md` §5)。
//!
//! 约定:平台判断只在这一层出现一次。当前 `main.rs` 仍按 `cfg(windows)` 调用
//! 既有 Windows 流水线;Linux/macOS 后端在阶段 2/3 接入本层的 `run` 入口。
//! 非三平台 target 由 `backend_name()` 给出清晰降级,保证 `cargo check` 全绿。

/// 当前编译目标对应的后端名称(用于 `--help` 与能力报告)。
pub fn backend_name() -> &'static str {
    #[cfg(windows)]
    {
        "windows: AppContainer + Job Object + broker"
    }
    #[cfg(all(not(windows), target_os = "linux"))]
    {
        "linux: bubblewrap + netns + 授权后重执行(B 契约)"
    }
    #[cfg(all(not(windows), target_os = "macos"))]
    {
        "macos: Seatbelt + 授权后重执行(B 契约)"
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        "unsupported: 该平台暂无沙箱后端"
    }
}

/// 三平台后端均已接入。
#[allow(dead_code)]
pub fn run_supported() -> bool {
    cfg!(any(windows, target_os = "linux", target_os = "macos"))
}
