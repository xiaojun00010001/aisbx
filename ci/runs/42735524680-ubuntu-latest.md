# CI run 42735524680 (ubuntu-latest)

- commit: da2f39f30b7db133f7d456d7cce3f26b858d77c1
- workflow: cross-platform-smoke
- job status: failure

```text
[01:24:32] == 0. 构建 ==
224 |     pub tree: Vec<u32>,
    |         ^^^^

[01:24:32] == T0 策略 ==
  PASS  T0 策略解析与校验
[01:24:32] == T1 文件默认隔离 ==
  PASS  T1a 白名单外写入被拒
  PASS  T1b 白名单外文件未落盘
  PASS  T1c 白名单内写入成功
[01:24:32] == T2 拒绝感知 → 授权 → 重执行 ==
  PASS  T2a deny_escalation 黑名单前置
  PASS  T2b 拒绝感知(violation 含具体路径)
  PASS  T2c authorize 签发一次性 token
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","grant"],"event":"spawned"}
retryflow env: cli=/home/runner/work/aisbx/aisbx/target/debug/aisbx policy=/tmp/aisbx-smoke.gkVe4n/policy.json broker=/tmp/aisbx-smoke-3000
first_write=denied
{"granted":false,"reason":"需要用户授权后重新执行","effect":"retry","retry_required":true}
escalate=1
{"granted":false,"reason":"外网默认拒绝;按主机放行需代理(见 docs/05)","effect":"none","retry_required":false}
net_escalate=1
{"attempt":1,"code":1,"event":"exit"}
{"command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"retry","from":1,"reason":"user-approved","to":2}
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","grant"],"event":"spawned"}
retryflow env: cli=/home/runner/work/aisbx/aisbx/target/debug/aisbx policy=/tmp/aisbx-smoke.gkVe4n/policy.json broker=/tmp/aisbx-smoke-3000
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
[01:24:33] == T3 资源限制(按能力报告判定) ==
capabilities: memory_per_process=partial process_limit=unavailable
  PASS  T3a 配额内分配成功
  PASS  T3b 单进程内存超限被发现
  WARN  T3c 进程数上限:该平台无每任务内核配额(RLIMIT_NPROC 按用户计数,不可用),不计失败
[01:24:34] == T4 网络 ==
  PASS  T4a 回环放行
  PASS  T4b 外网被内核拒绝
[01:24:34] == T5 审计与能力报告 ==
  PASS  T5a token.issued 已落审计
  PASS  T5b escalation.deny 已落审计
  PASS  T5c spawned 事件已落审计
  PASS  T5d 能力报告声明 B 契约
[01:24:34] == T6 网络代理:精确目标自动采集 / 运行中授权 ==
  PASS  T6a 代理自动拿到精确 host:port(零解析/零改造)
  PASS  T6b 授权后运行中放行
  PASS  T6c net.grant 已落审计
  PASS  T6d 全程只执行一次(网络授权不需重跑)
[01:24:34] == T7 内核违规日志自动采集(按能力报告判定) ==
  FAIL  T7a 内核日志自动给出精确路径(程序零配合)
  FAIL  T7b violation 标记为内核日志来源
  FAIL  T7c 授权后重执行成功 (rc=1)
  FAIL  T7d 授权后文件真实落盘
  FAIL  T7e retry 事件已落审计
  PASS  T7f 内核日志未归属的条目不作为越界上报(仅审计)
  FAIL  T7g 未归属条目仍留审计记录(路径可见)
  PASS  T7l 未归属条目不得用于申请授权
  FAIL  T7i 存活的深层进程按进程组精确归属(attributed=)
--- 诊断:审计里含 t7h 的行:
{"attempt":1,"cmd":["/bin/sh","-c","((echo hi > /tmp/aisbx-smoke.gkVe4n/outside/t7h.txt; sleep 15) &) & sleep 6"],"event":"spawned"}
--- 诊断:t7h.out 前 5 行:
{"attempt":1,"cmd":["/bin/sh","-c","((echo hi > /tmp/aisbx-smoke.gkVe4n/outside/t7h.txt; sleep 15) &) & sleep 6"],"event":"spawned"}
/bin/sh: 1: cannot create /tmp/aisbx-smoke.gkVe4n/outside/t7h.txt: Read-only file system
{"attempt":1,"code":0,"event":"exit"}
  FAIL  T7j 越界路径标注为内核来源且精确
  PASS  T7k 可归属的越界不重复出现在未归属列表
[01:26:37] == T8 SOCKS5:同一端口按首字节分流 ==
  PASS  T8a SOCKS5 自动拿到精确 host:port(零解析/零改造)
  PASS  T8b SOCKS5 授权后运行中放行
  PASS  T8c net.grant 已落审计
  PASS  T8d 全程只执行一次
[01:26:37] == T9 契约边界与安全断言 ==
  PASS  T9a --require-full 按能力报告判定(deny)
  PASS  T9b 无真实越界时拒绝签发网络授权(fail-closed)
  PASS  T9c 并发任务审计不串台
  PASS  T9d 代理拒绝 loopback 目标(SSRF fail-closed)
  PASS  T9e 能力报告含采集能力与代理协议字段
[01:26:42] == T10 能力契约组(C07/C19/C20/C22) ==
  PASS  T10a C07 auto 模式按 allow_escalation 授权
  PASS  T10b C22 --json 事件流含 spawned/exit
  WARN  T10c C19 宿主被杀进程树终止:该平台标 partial,未验证(已知缺口)
  WARN  T10d C20 ACL 清理:该后端不使用 ACL,由 Windows 冒烟实断言
  PASS  T10e 能力报告逐项状态明确
  PASS  T10f 越界路径精度字段取值合法(exact/reported/none)

[01:26:42] == T11 L1:程序自报路径(stderr)==
  FAIL  T11a 越界路径被采集(内核日志或 stderr 自报)
  FAIL  T11b 越界路径精度应标注 exact/reported(实际=)
  FAIL  T11c 无内核通道时精度应为 reported(实际=)
[01:27:13] == T14 status 给出待授权的具体路径 ==
  PASS  T14a status 给出待授权的具体路径
  PASS  T14b status 标注路径精度与归属
  PASS  T14c status 报告 needs_approval 标志
[01:27:13] == T15 对抗:自称路径 vs 真实路径 ==
  PASS  T15a 无内核通道时只采到自称路径
  FAIL  T15b 无内核通道时采不到从未被拒的真实路径
  PASS  T15c 授权自称路径后真实路径仍被拒(伪造不构成越权)

SMOKE_DONE fail=12
冒烟验证失败 12 项
---- 审计日志 ----
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","write","/tmp/aisbx-smoke.gkVe4n/outside/f1.txt"],"event":"spawned"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","write","/tmp/aisbx-smoke.gkVe4n/ws/f1.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/deny/x.txt","deny"],"event":"spawned"}
{"access":"write","attempt":1,"attributed":true,"command_id":"5937a1f2a5d0157fac1d04e3136506e9","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.gkVe4n/deny/x.txt","port":0,"precision":"reported","reason":"deny_escalation","source":"explicit"}
{"event":"escalation.deny","op":"file","path":"/tmp/aisbx-smoke.gkVe4n/deny/x.txt","reason":"deny_escalation"}
{"access":"read","attempt":1,"attributed":true,"command_id":"5937a1f2a5d0157fac1d04e3136506e9","event":"violation","host":"example.com","ip":"1.1.1.1","kind":"net","path":"","port":443,"precision":"reported","reason":"network-egress-denied","source":"explicit"}
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","grant"],"event":"spawned"}
{"access":"write","attempt":1,"attributed":true,"command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","port":0,"precision":"reported","reason":"needs-approval","source":"explicit"}
{"event":"escalation.deny","op":"file","path":"/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","reason":"Deny:user-or-policy","retry_required":true}
{"access":"read","attempt":1,"attributed":true,"command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"violation","host":"example.com","ip":"1.1.1.1","kind":"net","path":"","port":443,"precision":"reported","reason":"network-egress-denied","source":"explicit"}
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"access":"write","event":"token.issued","path":"/tmp/aisbx-smoke.gkVe4n/outside","ttl_seconds":120}
{"command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"retry","from":1,"reason":"user-approved","to":2}
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","grant"],"event":"spawned"}
{"access":"write","command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"token.redeemed","path":"/tmp/aisbx-smoke.gkVe4n/outside/f2.txt"}
{"event":"token.reject","path":"/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","reason":"token 无效、已过期或已消费"}
{"attempt":2,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","mem","32"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","mem","512"],"event":"spawned"}
{"attempt":1,"code":134,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","fork","40"],"event":"spawned"}
{"attempt":1,"code":2,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","loopback"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","conn","1.1.1.1","53"],"event":"spawned"}
{"attempt":1,"code":1,"event":"exit"}
---- 运行日志尾部 ----
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/outside/t14.txt","grant"],"event":"spawned"}
retryflow env: cli=/home/runner/work/aisbx/aisbx/target/debug/aisbx policy=/tmp/aisbx-smoke.gkVe4n/p14.json broker=/tmp/aisbx-smoke14-3000
wrote=ok
{"granted":true,"reason":"已按授权 token 放宽下一次执行策略","effect":"retry","retry_required":true}
{"granted":false,"reason":"授权 token 校验失败: token 无效、已过期或已消费","effect":"none","retry_required":false}
redeem=0 replay=1
{"attempt":2,"code":0,"event":"exit"}
[01:27:13] == T15 对抗:自称路径 vs 真实路径 ==
  PASS  T15a 无内核通道时只采到自称路径
  FAIL  T15b 无内核通道时采不到从未被拒的真实路径
{"access":"write","expires_in":300,"granted":true,"path":"/tmp/aisbx-smoke.gkVe4n/outside/claimed.txt","token":"8af38164b486c94a1a2f0a708e5144d9"}
  PASS  T15c 授权自称路径后真实路径仍被拒(伪造不构成越权)
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","spoof","/tmp/aisbx-smoke.gkVe4n/outside/claimed.txt","/tmp/aisbx-smoke.gkVe4n/outside/actual.txt"],"event":"spawned"}
ACTUAL_DENIED /tmp/aisbx-smoke.gkVe4n/outside/actual.txt
CLAIMED_REPORTED /tmp/aisbx-smoke.gkVe4n/outside/claimed.txt
sh: /tmp/aisbx-smoke.gkVe4n/outside/claimed.txt: Operation not permitted
{"attempt":1,"code":1,"event":"exit"}
{"access":"write","attempt":1,"attributed":true,"command_id":"c09b3c1b40fae7a7d9e4d693a7c90f3e","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.gkVe4n/outside/claimed.txt","port":0,"precision":"reported","reason":"needs-approval","source":"stderr-selfreport"}
{"command_id":"c09b3c1b40fae7a7d9e4d693a7c90f3e","event":"retry","from":1,"reason":"user-approved","to":2}
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","spoof","/tmp/aisbx-smoke.gkVe4n/outside/claimed.txt","/tmp/aisbx-smoke.gkVe4n/outside/actual.txt"],"event":"spawned"}
ACTUAL_DENIED /tmp/aisbx-smoke.gkVe4n/outside/actual.txt
CLAIMED_REPORTED /tmp/aisbx-smoke.gkVe4n/outside/claimed.txt
sh: /tmp/aisbx-smoke.gkVe4n/outside/claimed.txt: Operation not permitted
{"attempt":2,"code":1,"event":"exit"}

SMOKE_DONE fail=12
冒烟验证失败 12 项
---- 审计日志 ----
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","write","/tmp/aisbx-smoke.gkVe4n/outside/f1.txt"],"event":"spawned"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","write","/tmp/aisbx-smoke.gkVe4n/ws/f1.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/deny/x.txt","deny"],"event":"spawned"}
{"access":"write","attempt":1,"attributed":true,"command_id":"5937a1f2a5d0157fac1d04e3136506e9","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.gkVe4n/deny/x.txt","port":0,"precision":"reported","reason":"deny_escalation","source":"explicit"}
{"event":"escalation.deny","op":"file","path":"/tmp/aisbx-smoke.gkVe4n/deny/x.txt","reason":"deny_escalation"}
{"access":"read","attempt":1,"attributed":true,"command_id":"5937a1f2a5d0157fac1d04e3136506e9","event":"violation","host":"example.com","ip":"1.1.1.1","kind":"net","path":"","port":443,"precision":"reported","reason":"network-egress-denied","source":"explicit"}
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","grant"],"event":"spawned"}
{"access":"write","attempt":1,"attributed":true,"command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","port":0,"precision":"reported","reason":"needs-approval","source":"explicit"}
{"event":"escalation.deny","op":"file","path":"/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","reason":"Deny:user-or-policy","retry_required":true}
{"access":"read","attempt":1,"attributed":true,"command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"violation","host":"example.com","ip":"1.1.1.1","kind":"net","path":"","port":443,"precision":"reported","reason":"network-egress-denied","source":"explicit"}
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"access":"write","event":"token.issued","path":"/tmp/aisbx-smoke.gkVe4n/outside","ttl_seconds":120}
{"command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"retry","from":1,"reason":"user-approved","to":2}
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","grant"],"event":"spawned"}
{"access":"write","command_id":"ec4818a7eafc9d002e4c5dde680ff80e","event":"token.redeemed","path":"/tmp/aisbx-smoke.gkVe4n/outside/f2.txt"}
{"event":"token.reject","path":"/tmp/aisbx-smoke.gkVe4n/outside/f2.txt","reason":"token 无效、已过期或已消费"}
{"attempt":2,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","mem","32"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","mem","512"],"event":"spawned"}
{"attempt":1,"code":134,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","fork","40"],"event":"spawned"}
{"attempt":1,"code":2,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","loopback"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","conn","1.1.1.1","53"],"event":"spawned"}
{"attempt":1,"code":1,"event":"exit"}
```
