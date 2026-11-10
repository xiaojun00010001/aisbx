# CI run 42739287628 (ubuntu-latest)

- commit: 2574f74740fc506fa94cf03d51fbda7e4cfee361
- workflow: cross-platform-smoke
- job status: failure

```text
[01:56:55] == 0. 构建 ==
224 |     pub tree: Vec<u32>,
    |         ^^^^

[01:56:55] == T0 策略 ==
  PASS  T0 策略解析与校验
[01:56:55] == T1 文件默认隔离 ==
  PASS  T1a 白名单外写入被拒
  PASS  T1b 白名单外文件未落盘
  PASS  T1c 白名单内写入成功
[01:56:55] == T2 拒绝感知 → 授权 → 重执行 ==
  PASS  T2a deny_escalation 黑名单前置
  PASS  T2b 拒绝感知(violation 含具体路径)
  PASS  T2c authorize 签发一次性 token
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.b0yEGf/outside/f2.txt","grant"],"event":"spawned"}
retryflow env: cli=/home/runner/work/aisbx/aisbx/target/debug/aisbx policy=/tmp/aisbx-smoke.b0yEGf/policy.json broker=/tmp/aisbx-smoke-2730
first_write=denied
{"granted":false,"reason":"需要用户授权后重新执行","effect":"retry","retry_required":true}
escalate=1
{"granted":false,"reason":"外网默认拒绝;按主机放行需代理(见 docs/05)","effect":"none","retry_required":false}
net_escalate=1
{"attempt":1,"code":1,"event":"exit"}
{"command_id":"7c18793ac98c351b0656a27773ded3f7","event":"retry","from":1,"reason":"user-approved","to":2}
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.b0yEGf/outside/f2.txt","grant"],"event":"spawned"}
retryflow env: cli=/home/runner/work/aisbx/aisbx/target/debug/aisbx policy=/tmp/aisbx-smoke.b0yEGf/policy.json broker=/tmp/aisbx-smoke-2730
wrote=ok
{"granted":true,"reason":"已按授权 token 放宽下一次执行策略","effect":"retry","retry_required":true}
{"granted":false,"reason":"授权 token 校验失败: token 无效、已过期或已消费","effect":"none","retry_required":false}
redeem=0 replay=1
{"attempt":2,"code":0,"event":"exit"}
retryflow exit=0
  PASS  T2d 授权后重新执行成功
  PASS  T2e retry 事件已落审计
  PASS  T2f 授权后真实写入落盘
  PASS  T2g token 一次性(消费成功+重放被拒)
  PASS  T2h token 重放被审计
  PASS  T2i 网络拒绝上报(host/ip/port)
[01:56:56] == T3 资源限制(按能力报告判定) ==
capabilities: memory_per_process=partial process_limit=unavailable
  PASS  T3a 配额内分配成功
  PASS  T3b 单进程内存超限被发现
  WARN  T3c 进程数上限:该平台无每任务内核配额(RLIMIT_NPROC 按用户计数,不可用),不计失败
[01:56:56] == T4 网络 ==
  PASS  T4a 回环放行
  PASS  T4b 外网被内核拒绝
[01:56:57] == T5 审计与能力报告 ==
  PASS  T5a token.issued 已落审计
  PASS  T5b escalation.deny 已落审计
  PASS  T5c spawned 事件已落审计
  PASS  T5d 能力报告声明 B 契约
[01:56:57] == T6 网络代理:精确目标自动采集 / 运行中授权 ==
  PASS  T6a 代理自动拿到精确 host:port(零解析/零改造)
  PASS  T6b 授权后运行中放行
  PASS  T6c net.grant 已落审计
  PASS  T6d 全程只执行一次(网络授权不需重跑)
[01:56:57] == T7 内核违规日志自动采集(按能力报告判定) ==
  PASS  T7a 无内核通道时能力报告如实标注该通道不可用
  WARN  T7b 内核违规日志自动采集:该平台不可用,不计失败(见 docs/06)
[01:56:57] == T8 SOCKS5:同一端口按首字节分流 ==
  PASS  T8a SOCKS5 自动拿到精确 host:port(零解析/零改造)
  PASS  T8b SOCKS5 授权后运行中放行
  PASS  T8c net.grant 已落审计
  PASS  T8d 全程只执行一次
[01:56:57] == T9 契约边界与安全断言 ==
  PASS  T9a --require-full 按能力报告判定(deny)
  PASS  T9b 无真实越界时拒绝签发网络授权(fail-closed)
  PASS  T9c 并发任务审计不串台
  PASS  T9d 代理拒绝 loopback 目标(SSRF fail-closed)
  PASS  T9e 能力报告含采集能力与代理协议字段
[01:57:02] == T10 能力契约组(C07/C19/C20/C22) ==
  PASS  T10a C07 auto 模式按 allow_escalation 授权
  PASS  T10b C22 --json 事件流含 spawned/exit
  WARN  T10c C19 宿主被杀进程树终止:该平台标 partial,未验证(已知缺口)
  WARN  T10d C20 ACL 清理:该后端不使用 ACL,由 Windows 冒烟实断言
  PASS  T10e 能力报告逐项状态明确
  PASS  T10f 越界路径精度字段取值合法(exact/reported/none)

[01:57:02] == T11 L1:程序自报路径(stderr)==
  PASS  T11a 越界路径被采集(内核日志或 stderr 自报)
  PASS  T11b 越界路径精度已标注(reported)
  PASS  T11c 无内核通道时精度如实为 reported
[01:57:02] == T14 status 给出待授权的具体路径 ==
  PASS  T14a status 给出待授权的具体路径
  PASS  T14b status 标注路径精度与归属
  PASS  T14c status 报告 needs_approval 标志
[01:57:03] == T15 对抗:自称路径 vs 真实路径 ==
  PASS  T15a 无内核通道时只采到自称路径
  PASS  T15b 无内核通道时采不到从未被拒的真实路径
  PASS  T15c 授权自称路径后真实路径仍被拒(伪造不构成越权)

SMOKE_DONE fail=0
冒烟验证全部通过
    Checking serde_core v1.0.229
    Checking zmij v1.0.23
    Checking memchr v2.8.3
    Checking itoa v1.0.18
    Checking libc v0.2.191
    Checking serde v1.0.229
    Checking serde_json v1.0.154
    Checking aisbx-policy v0.1.0 (/home/runner/work/aisbx/aisbx/crates/aisbx-policy)
    Checking aisbx v0.1.0 (/home/runner/work/aisbx/aisbx/crates/aisbx)
error: function `merge_pids` is never used
  --> crates/aisbx/src/unix/proctree.rs:87:8
   |
87 | pub fn merge_pids(groups: &[&[u32]]) -> Vec<u32> {
   |        ^^^^^^^^^^
   |
   = note: `-D dead-code` implied by `-D warnings`
   = help: to override `-D warnings` add `#[expect(dead_code)]` or `#[allow(dead_code)]`

error: function `pgid_table` is never used
   --> crates/aisbx/src/unix/proctree.rs:121:8
    |
121 | pub fn pgid_table() -> std::collections::HashMap<u32, u32> {
    |        ^^^^^^^^^^

error: field `tree` is never read
   --> crates/aisbx/src/unix/run.rs:224:9
    |
215 | pub struct SpawnOutcome {
    |            ------------ field in this struct
...
224 |     pub tree: Vec<u32>,
    |         ^^^^

error: unneeded `return` statement
  --> crates/aisbx/src/main.rs:56:17
   |
56 |                 return linux::helper::linux_helper(rest_after(args, 1));
   |                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.99.0/index.html#needless_return
   = note: `-D clippy::needless-return` implied by `-D warnings`
   = help: to override `-D warnings` add `#[allow(clippy::needless_return)]`
help: remove `return`
   |
56 -                 return linux::helper::linux_helper(rest_after(args, 1));
56 +                 linux::helper::linux_helper(rest_after(args, 1))
   |

error: unneeded `return` statement
   --> crates/aisbx/src/main.rs:146:9
    |
146 |         return linux::run_linux(&policy, &policy_file, &cmd, json);
    |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.99.0/index.html#needless_return
help: remove `return`
    |
146 -         return linux::run_linux(&policy, &policy_file, &cmd, json);
146 +         linux::run_linux(&policy, &policy_file, &cmd, json)
    |

error: function `pgid_table` is never used
   --> crates/aisbx/src/unix/proctree.rs:121:8
    |
121 | pub fn pgid_table() -> std::collections::HashMap<u32, u32> {
    |        ^^^^^^^^^^
    |
    = note: `-D dead-code` implied by `-D warnings`
    = help: to override `-D warnings` add `#[expect(dead_code)]` or `#[allow(dead_code)]`

error: could not compile `aisbx` (bin "aisbx") due to 5 previous errors
warning: build failed, waiting for other jobs to finish...
error: could not compile `aisbx` (bin "aisbx" test) due to 4 previous errors
```
