# CI run 42771988080 (ubuntu-latest)

- commit: 8fc973590f28c69e121c39bc025da6f465c60957
- workflow: cross-platform-smoke
- job status: failure

```text
===== smoke.log =====
[06:58:12] == T11 L1:程序自报路径(stderr)==
  PASS  T11a 越界路径被采集(内核日志或 stderr 自报)
  PASS  T11b 越界路径精度已标注(reported)
  PASS  T11c 无内核通道时精度如实为 reported
  PASS  T11d 采集到的路径正确
[06:58:13] == T14 status 给出待授权的具体路径 ==
  PASS  T14a status 给出待授权的具体路径
  PASS  T14b status 标注路径精度与归属
  PASS  T14c status 报告 needs_approval 标志
[06:58:13] == T15 对抗:自称路径 vs 真实路径 ==
  PASS  T15a 无内核通道时只采到自称路径
  PASS  T15b 无内核通道时采不到从未被拒的真实路径
  PASS  T15c 授权自称路径后真实路径仍被拒(伪造不构成越权)
[06:58:34] == T12 B 契约:授权后重跑 ==
  FAIL  T12a 授权后重跑成功
  FAIL  T12b 文件真实落盘
  PASS  T12c retry 事件已落审计
[06:58:54] == T13 授权粒度不外溢 ==
  FAIL  T13a 授权后新文件创建成功
  PASS  T13b 授权粒度不外溢(同目录既有文件仍不可写)
  PASS  T13c 既有文件内容未被改动
[06:59:14] == 跨平台契约检查 ==
  PASS  契约检查:能力/事件/审计/退出码 三平台同一份契约

SMOKE_DONE fail=3
冒烟验证失败 3 项
---- 审计日志 ----
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","write","/tmp/aisbx-smoke.ZUCSa8/outside/f1.txt"],"event":"spawned"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","write","/tmp/aisbx-smoke.ZUCSa8/ws/f1.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.ZUCSa8/deny/x.txt","deny"],"event":"spawned"}
{"access":"write","attempt":1,"attributed":true,"command_id":"23dab01da57dc546458289f2720cc14e","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.ZUCSa8/deny/x.txt","port":0,"precision":"reported","reason":"deny_escalation","source":"explicit"}
{"event":"escalation.deny","op":"file","path":"/tmp/aisbx-smoke.ZUCSa8/deny/x.txt","reason":"deny_escalation"}
{"access":"read","attempt":1,"attributed":true,"command_id":"23dab01da57dc546458289f2720cc14e","event":"violation","host":"example.com","ip":"1.1.1.1","kind":"net","path":"","port":443,"precision":"reported","reason":"network-egress-denied","source":"explicit"}
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","grant"],"event":"spawned"}
{"access":"write","attempt":1,"attributed":true,"command_id":"640ea1c0dcda985709a96ea3dabf71cb","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","port":0,"precision":"reported","reason":"needs-approval","source":"explicit"}
{"event":"escalation.deny","op":"file","path":"/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","reason":"Deny:user-or-policy","retry_required":true}
{"access":"read","attempt":1,"attributed":true,"command_id":"640ea1c0dcda985709a96ea3dabf71cb","event":"violation","host":"example.com","ip":"1.1.1.1","kind":"net","path":"","port":443,"precision":"reported","reason":"network-egress-denied","source":"explicit"}
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"access":"write","event":"token.issued","path":"/tmp/aisbx-smoke.ZUCSa8/outside","ttl_seconds":120}
{"command_id":"640ea1c0dcda985709a96ea3dabf71cb","event":"retry","from":1,"reason":"user-approved","to":2}
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","grant"],"event":"spawned"}
{"access":"write","command_id":"640ea1c0dcda985709a96ea3dabf71cb","event":"token.redeemed","path":"/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt"}
{"event":"token.reject","path":"/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","reason":"token 无效、已过期或已消费"}
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
  PASS  [契约] 顶层键 capabilities 存在
  PASS  [契约] 顶层键 contract 存在
  PASS  [契约] 顶层键 effect 存在
  PASS  [契约] contract == B — 实际 'B'
  PASS  [契约] effect == retry — 实际 'retry'
  PASS  [契约] capabilities 是对象
  PASS  [契约] 能力键集合与基线**完全一致**(三平台同一份契约) — (共 21 个)
  PASS  [契约] 状态类能力值域合法(full/partial/unavailable)
  PASS  [契约] 描述类能力非空(除允许空串者)
  PASS  [契约] 平台期望 launcher_retry=full — 实际 'full'
  PASS  [契约] 平台期望 file_isolation=full — 实际 'full'
  PASS  [契约] 平台期望 violation_file_path_precision=reported — 实际 'reported'
  PASS  [契约] 平台期望 violation_log_probe=empty — 实际 ''
  PASS  [契约] 平台期望 violation_net_path_precision=exact — 实际 'exact'
== --json 事件流 ==
  PASS  [契约] 事件名都在允许集合内 — (共 2 种)
  PASS  [契约] 平台无关事件齐备 — (2 种)
== 审计记录 ==
  PASS  [契约] 审计事件类型都在允许集合内 — (共 2 种)
== 退出码 ==
  PASS  [契约] 退出码取值在约定集合内 — 实际 2,允许 [0, 1, 2, 3, 99]

契约检查全部通过(19 项)
  PASS  契约检查:能力/事件/审计/退出码 三平台同一份契约

SMOKE_DONE fail=3
冒烟验证失败 3 项
---- 审计日志 ----
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","write","/tmp/aisbx-smoke.ZUCSa8/outside/f1.txt"],"event":"spawned"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","write","/tmp/aisbx-smoke.ZUCSa8/ws/f1.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.ZUCSa8/deny/x.txt","deny"],"event":"spawned"}
{"access":"write","attempt":1,"attributed":true,"command_id":"23dab01da57dc546458289f2720cc14e","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.ZUCSa8/deny/x.txt","port":0,"precision":"reported","reason":"deny_escalation","source":"explicit"}
{"event":"escalation.deny","op":"file","path":"/tmp/aisbx-smoke.ZUCSa8/deny/x.txt","reason":"deny_escalation"}
{"access":"read","attempt":1,"attributed":true,"command_id":"23dab01da57dc546458289f2720cc14e","event":"violation","host":"example.com","ip":"1.1.1.1","kind":"net","path":"","port":443,"precision":"reported","reason":"network-egress-denied","source":"explicit"}
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","grant"],"event":"spawned"}
{"access":"write","attempt":1,"attributed":true,"command_id":"640ea1c0dcda985709a96ea3dabf71cb","event":"violation","host":"","ip":"","kind":"file","path":"/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","port":0,"precision":"reported","reason":"needs-approval","source":"explicit"}
{"event":"escalation.deny","op":"file","path":"/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","reason":"Deny:user-or-policy","retry_required":true}
{"access":"read","attempt":1,"attributed":true,"command_id":"640ea1c0dcda985709a96ea3dabf71cb","event":"violation","host":"example.com","ip":"1.1.1.1","kind":"net","path":"","port":443,"precision":"reported","reason":"network-egress-denied","source":"explicit"}
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"access":"write","event":"token.issued","path":"/tmp/aisbx-smoke.ZUCSa8/outside","ttl_seconds":120}
{"command_id":"640ea1c0dcda985709a96ea3dabf71cb","event":"retry","from":1,"reason":"user-approved","to":2}
{"attempt":2,"cmd":["/home/runner/work/aisbx/aisbx/target/debug/examples/burn","retryflow","/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","grant"],"event":"spawned"}
{"access":"write","command_id":"640ea1c0dcda985709a96ea3dabf71cb","event":"token.redeemed","path":"/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt"}
{"event":"token.reject","path":"/tmp/aisbx-smoke.ZUCSa8/outside/f2.txt","reason":"token 无效、已过期或已消费"}
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
===== fmt.log =====
===== clippy.log =====
===== test.log =====
```
