//! Linux multicall helper:在 bwrap 建立的命名空间内启动统一 Unix 入口。
//! lo up 与网络 relay 由 `unix::relay::entry` 统一处理(见 P0)。

pub fn linux_helper(args: &[String]) -> Result<i32, String> {
    crate::unix::relay::entry(args)
}
