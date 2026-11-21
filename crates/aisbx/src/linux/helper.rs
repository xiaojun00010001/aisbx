//! Linux multicall helper:在 bwrap 建立的命名空间内启动统一 Unix 入口。
//! lo up 与网络 relay 由 `unix::relay::entry` 统一处理(见 P0)。

pub fn linux_helper(args: &[String]) -> Result<i32, String> {
    // docs/12 A2:在 relay spawn 之前安装 seccomp —— 过滤器随 exec 继承到目标，
    // 但 relay 子进程尚未创建,它也需要 socket() 监听回环 →
    // 因此这里**不能**安装,改由 entry 在 spawn relay 之后、exec 目标之前安装。
    // 见 unix::relay::entry 中的 install_seccomp_before_exec 调用。
    crate::unix::relay::entry(args)
}
