# CI run 44860297879 (ubuntu-latest)

- commit: 4e4a1bc4beb389fcfea6414b1a038cb65defd8bf
- workflow: cross-platform-smoke
- job status: success

```text
===== smoke.log =====
[03:17:23] == 0. 构建 ==
[03:17:23] == T0 策略 ==
  PASS  T0 策略解析与校验
[03:17:23] == T1 文件默认隔离 ==
  PASS  T1a 白名单外写入被拒
  PASS  T1b 白名单外文件未落盘
  PASS  T1c 白名单内写入成功
[03:17:23] == T2 拒绝感知 → 授权 → 重执行 ==
  PASS  T2a deny_escalation 黑名单前置
  PASS  T2b 拒绝感知(violation 含具体路径)
  PASS  T2c authorize 签发一次性 token
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.wQogMp/outside/f2.txt","grant"],"event":"spawned"}
retryflow env: cli=/home/runner/work/aisbx/aisbx/target/debug/aisbx policy=/tmp/aisbx-smoke.wQogMp/policy.json broker=/tmp/aisbx-smoke-2913
first_write=denied
{"granted":false,"reason":"需要用户授权后重新执行","effect":"retry","retry_required":true}
escalate=1
{"granted":false,"reason":"外网默认拒绝;按主机放行需代理(见 docs/05)","effect":"none","retry_required":false}
net_escalate=1
{"attempt":1,"code":1,"event":"exit"}
{"command_id":"42c32c7ad591789712dc352de38c9f3b","event":"retry","from":1,"granted":[],"placeholders":[],"reason":"user-approved","to":2}
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.wQogMp/outside/f2.txt","grant"],"event":"spawned"}
retryflow env: cli=/home/runner/work/aisbx/aisbx/target/debug/aisbx policy=/tmp/aisbx-smoke.wQogMp/policy.json broker=/tmp/aisbx-smoke-2913
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
[03:17:24] == T2x deny 模式行为契约 ==
T2x 应答: {"granted":false,"reason":"授权被拒绝","effect":"none","retry_required":false}
T2x status: {"attempt":1,"backend":"unix","granted_nets":[],"granted_paths":[],"needs_approval":false,"pending":[],"retries":0,"violations_total":1}
  PASS  T2xa deny 模式提权被拒
  PASS  T2xb deny 不邀请宿主授权(retry_required=false)
  PASS  T2xc deny 模式 status 不标 needs_approval
  PASS  T2xd deny 模式不产生 escalation.pending
  PASS  T2xe deny 的审计不带 retry_required
  PASS  T2xf deny 模式秒回(未空等授权超时,8s)
  PASS  T2xg deny 模式行为纳入同一份契约检查
[03:17:32] == T3 资源限制(按能力报告判定) ==
capabilities: memory_per_process=partial process_limit=unavailable
  PASS  T3a 配额内分配成功
  PASS  T3b 单进程内存超限被发现
  WARN  T3c 进程数上限:该平台无每任务内核配额(RLIMIT_NPROC 按用户计数,不可用),不计失败
[03:17:33] == T4 网络 ==
  PASS  T4a 回环放行
  PASS  T4b 外网被内核拒绝
[03:17:33] == T5 审计与能力报告 ==
  PASS  T5a token.issued 已落审计
  PASS  T5b escalation.deny 已落审计
  PASS  T5c spawned 事件已落审计
  PASS  T5d 能力报告声明 B 契约
[03:17:33] == T6 网络代理:精确目标自动采集 / 运行中授权 ==
  PASS  T6a 代理自动拿到精确 host:port(零解析/零改造)
  PASS  T6b 授权后运行中放行
  PASS  T6c net.grant 已落审计
  PASS  T6d 全程只执行一次(网络授权不需重跑)
[03:17:33] == T7 内核违规日志自动采集(按能力报告判定) ==
  PASS  T7a 无内核通道时能力报告如实标注该通道不可用
  WARN  T7b 内核违规日志自动采集:该平台不可用,不计失败(见 docs/06)
[03:17:33] == T8 SOCKS5:同一端口按首字节分流 ==
  PASS  T8a SOCKS5 自动拿到精确 host:port(零解析/零改造)
  PASS  T8b SOCKS5 授权后运行中放行
  PASS  T8c net.grant 已落审计
  PASS  T8d 全程只执行一次
[03:17:34] == T9 契约边界与安全断言 ==
  PASS  T9a --require-full 按能力报告判定(deny)
  PASS  T9b 无真实越界时拒绝签发网络授权(fail-closed)
  PASS  T9c 并发任务审计不串台
  PASS  T9d 代理拒绝 loopback 目标(SSRF fail-closed)
  PASS  T9e 能力报告含采集能力与代理协议字段
[03:17:38] == T10 能力契约组(C07/C19/C20/C22) ==
  PASS  T10a C07 auto 模式按 allow_escalation 授权
  PASS  T10b C22 --json 事件流含 spawned/exit
  WARN  T10c C19 宿主被杀进程树终止:该平台标 partial,未验证(已知缺口)
  WARN  T10d C20 ACL 清理:该后端不使用 ACL,由 Windows 冒烟实断言
  PASS  T10e 能力报告逐项状态明确
  PASS  T10f 越界路径精度字段取值合法(exact/reported/none)

[03:17:38] == T11 L1:程序自报路径(stderr)==
  PASS  T11a 越界路径被采集(内核日志或 stderr 自报)
  PASS  T11b 越界路径精度已标注(reported)
  PASS  T11c 无内核通道时精度如实为 reported
  PASS  T11d 采集到的路径正确
[03:17:39] == T14 status 给出待授权的具体路径 ==
  PASS  T14a status 给出待授权的具体路径
  PASS  T14b status 标注路径精度与归属
  PASS  T14c status 报告 needs_approval 标志
  PASS  T16a status.pending[] 带稳定 id
  PASS  T16b status.pending[] 带可回填 grant
  PASS  T16c approve --pending 按 id 授权成功
  PASS  T16d approve 授予的是 pending 声明的路径
  PASS  T16e approve 拒绝不存在的 id(fail-closed)
[03:17:39] == T17 guard 自动授权闭环 ==
  PASS  T17a guard 一条命令完成闭环(exit=0)
  PASS  T17b guard 授权后文件真实落盘
  PASS  T17c guard 触发了 retry 事件
  PASS  T17d guard 无审批回调不自动放行
[03:18:00] == T15 对抗:自称路径 vs 真实路径 ==
  PASS  T15a 无内核通道时只采到自称路径
  PASS  T15b 无内核通道时采不到从未被拒的真实路径
  PASS  T15c 授权自称路径后真实路径仍被拒(伪造不构成越权)
[03:18:20] == T12 B 契约:授权后重跑 ==
  PASS  T12a 授权后重跑成功
  PASS  T12b 文件真实落盘
  PASS  T12c retry 事件已落审计
[03:18:21] == T13 授权粒度不外溢 ==
  PASS  T13a 授权后新文件创建成功
  PASS  T13b 授权粒度不外溢(同目录既有文件仍不可写)
  PASS  T13c 既有文件内容未被改动
[03:18:21] == 跨平台契约检查 ==
  PASS  契约检查:能力/事件/审计/退出码 三平台同一份契约

SMOKE_DONE fail=0
冒烟验证全部通过
===== 0. 前置 =====
===== 1. 构造策略 =====
===== 2. 沙箱内采集内核证据 =====
== status ==
CapEff:	0000000000000000
NoNewPrivs:	1
Seccomp:	2
Seccomp_filters:	1
== mnt-ns ==
mnt:[4026532864]
== pid-ns ==
pid:[4026532866]
== proc-count ==
5
== unshare ==
unshare: unshare failed: Operation not permitted
== mount ==
mount: /tmp: must be superuser to use mount.
宿主 mnt-ns=mnt:[4026531832]
===== 3. 断言内核证据 =====
  PASS  NoNewPrivs=1（setuid 提权封死）
  PASS  CapEff 全 0（--cap-drop ALL 生效）
  PASS  Seccomp=2（BPF filter 已生效且不可逆）
  PASS  mnt namespace 与宿主不同（文件系统视图隔离）
  PASS  PID namespace 已建立（pid:[4026532866]）
  PASS  /proc 只含沙箱进程（count=5，未泄漏宿主）
  PASS  unshare 被 seccomp 拒绝（防自我换 namespace）
  PASS  mount 被拒绝（防拆只读 bind）
===== 汇总 =====
PASS=8 FAIL=0 NOTE=0
===== fmt.log =====
===== clippy.log =====
    Checking serde_core v1.0.229
    Checking zmij v1.0.23
    Checking memchr v2.8.3
    Checking itoa v1.0.18
    Checking libc v0.2.191
    Checking serde v1.0.229
    Checking serde_json v1.0.154
    Checking aisbx-policy v0.1.0 (/home/runner/work/aisbx/aisbx/crates/aisbx-policy)
    Checking aisbx-protocol v0.1.0 (/home/runner/work/aisbx/aisbx/crates/aisbx-protocol)
    Checking aisbx v0.1.0 (/home/runner/work/aisbx/aisbx/crates/aisbx)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.77s
===== test.log =====
   Compiling aisbx-policy v0.1.0 (/home/runner/work/aisbx/aisbx/crates/aisbx-policy)
   Compiling aisbx v0.1.0 (/home/runner/work/aisbx/aisbx/crates/aisbx)
   Compiling aisbx-protocol v0.1.0 (/home/runner/work/aisbx/aisbx/crates/aisbx-protocol)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.63s
     Running unittests src/main.rs (target/debug/deps/aisbx-544b611ea59bc607)

running 31 tests
test backend::tests::backend_name_is_stable ... ok
test backend::tests::net_escalation_capability_is_explicit ... ok
test capabilities::tests::status_capability_values_are_legal ... ok
test capabilities::tests::capability_keys_match_the_shared_contract ... ok
test capabilities::tests::top_level_shape_is_identical ... ok
test common::stderr_scan::tests::extracts_dotnet_unauthorized_path ... ok
test common::stderr_scan::tests::distinguishes_access_kind_by_heuristic ... ok
test common::stderr_scan::tests::extracts_powershell_denied_path ... ok
test common::stderr_scan::tests::extracts_python_quoted_path ... ok
test common::stderr_scan::tests::extracts_shell_style_path ... ok
test common::stderr_scan::tests::extracts_touch_style_path ... ok
test common::stderr_scan::tests::filters_system_noise ... ok
test common::stderr_scan::tests::extracts_windows_python_denied_path ... ok
test common::stderr_scan::tests::filters_windows_system_noise ... ok
test common::stderr_scan::tests::keeps_user_paths_under_var_folders ... ok
test common::stderr_scan::tests::recognizes_readonly_filesystem_denial ... ok
test common::stderr_scan::tests::recognises_windows_absolute_paths ... ok
test common::stderr_scan::tests::rust_style_error_has_no_path ... ok
test common::stderr_scan::tests::still_filters_toolchain_cache_under_var_folders ... ok
test core::decision_engine::tests::auto_hit_grants_miss_denies ... ok
test core::decision_engine::tests::bad_token_is_rejected ... ok
test core::decision_engine::tests::deny_list_wins_over_token ... ok
test core::decision_engine::tests::prompt_with_tty_user_says_no_is_terminal ... ok
test core::decision_engine::tests::deny_mode_is_terminal_not_needs_approval ... ok
test core::decision_engine::tests::prompt_without_tty_invites_approval ... ok
test linux::seccomp::tests::syscall_numbers_are_defined ... ok
test core::decision_engine::tests::token_binding_uses_platform_real_path ... ok
test core::decision_engine::tests::token_fast_path_bypasses_deny_mode ... ok
test unix::proctree::tests::merges_and_dedups ... ok
test unix::proctree::tests::parses_stat_pgrp ... ok
test common::stderr_scan::tests::ignores_lines_without_denial_semantics ... ok

test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/lib.rs (target/debug/deps/aisbx_policy-60e2c4b60c4fe477)

running 8 tests
test tests::escalation_modes ... ok
test tests::pipe_name_override ... ok
test tests::parse_full_contract ... ok
test tests::parse_minimal ... ok
test tests::reject_bad_task ... ok
test tests::violation_capture_defaults_off ... ok
test tests::reject_bad_cpu_and_zero_procs ... ok
test tests::reject_unknown_fields ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/lib.rs (target/debug/deps/aisbx_protocol-1162745bd9bce136)

running 10 tests
test tests::decision_semantics ... ok
test tests::capabilities_level_and_require_full ... ok
test tests::capability_groups_from_flat_keys ... ok
test tests::escalation_request_roundtrip ... ok
test tests::capability_groups_missing_keys_are_unavailable ... ok
test tests::grant_from_pending_file_and_net ... ok
test tests::status_roundtrip_file_pending ... ok
test tests::status_roundtrip_net_pending ... ok
test tests::unattributed_pending_is_not_actionable ... ok
test tests::unknown_kind_is_not_actionable ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aisbx_policy

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests aisbx_protocol

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

```
