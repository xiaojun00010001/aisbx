# 09 · macOS 沙箱使用手册（所有命令块可直接复制执行）

> **使用规则**
> 1. 下面**每个 `bash` 代码块都是自包含的**——整块复制粘贴到终端即可运行，不依赖前面任何步骤。
> 2. 每块第一行 `cd /Users/xiaojun/Work/workspace/nomar/aisbx` 是本机仓库路径；若你的仓库在别处，**只需改这一行**。
> 3. 每块用 `mktemp -d` 建自己的临时目录，结束时**不删除**，方便你检查结果；末尾会打印目录路径，用 `rm -rf <打印的路径>` 清理。
> 4. `text` 块是**实跑采样的输出**，不要复制。路径里的 `/var/folders/.../tmp.XXXX` 每次不同。
> 5. 环境：macOS + Rust 1.99.1；沙箱用系统 `/usr/bin/sandbox-exec`，**无需管理员、无需额外安装**。

---

## 0. 构建与产物

整块复制执行：

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
cargo build --bins --example burn
echo "=== 产物 ==="
ls -lh target/debug/aisbx target/debug/examples/burn
echo "=== 工具链 ==="
rustc --version
cargo --version
echo "=== 沙箱后端 ==="
target/debug/aisbx --help
```

实测输出：

```text
=== 产物 ===
-rwxr-xr-x@ 1 xiaojun  staff   2.9M Nov 12 19:37 target/debug/aisbx
-rwxr-xr-x@ 1 xiaojun  staff   923K Nov 11 23:29 target/debug/examples/burn
=== 工具链 ===
rustc 1.99.1 (58cf8f9c3 2026-10-13)
cargo 1.99.1 (5f94df478 2026-08-27)
=== 沙箱后端 ===
aisbx - agent 本地沙箱 (后端: macos: Seatbelt + 授权后重执行(B 契约))
  契约 B: 策略配置 → 拒绝感知 → 用户授权 → 重新执行
  run / escalate / authorize / capabilities / policy-check
```

| 产物 | 用途 |
|---|---|
| `target/debug/aisbx` | 主二进制（本文所有场景只用这一个） |
| `target/debug/examples/burn` | 测试载荷，**仅**§7 授权闭环与 §6 deny 演示用到；日常跑自己的命令不需要它 |

---

## 1. 查看能力报告

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
target/debug/aisbx capabilities
```

实测输出：

```text
{
  "backend": "macos",
  "capabilities": {
    "authorized_retry": "full",
    "auto_violation_capture": "partial",
    "bubblewrap": "unavailable",
    "cpu": "unavailable",
    "denial_detection": "partial",
    "file_isolation": "full",
    "landlock": "unavailable",
    "launcher_retry": "full",
    "memory_per_process": "unavailable",
    "memory_total": "unavailable",
    "net_proxy": "http-connect+socks5",
    "net_violation_capture": "partial",
    "network_egress": "full",
    "process_limit": "unavailable",
    "process_tree_kill": "partial",
    "seatbelt": "full",
    "seccomp": "unavailable",
    "strategy": "full",
    "violation_file_path_precision": "exact",
    "violation_log_probe": "sandbox-reporting-violation",
    "violation_net_path_precision": "exact"
  },
  "contract": "B",
  "effect": "retry"
}
```

macOS 要点：`file_isolation=full`；`violation_file_path_precision=exact` + `violation_log_probe=sandbox-reporting-violation`（内核日志能给出**精确**路径）；但 `memory_per_process`/`process_limit`/`cpu` 是 `unavailable`（无内核等价机制，**不假装有限制**）。

---

## 2. 策略校验（含实测踩坑）

下面整块会先校验一份**合法**策略，再校验一份**非法**策略，展示校验能力：

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
D=$(mktemp -d)
printf '{"task":"demo-1","filesystem":{"write":["/tmp"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false}}' > "$D/ok.json"
printf '{"task":"bad$$name","filesystem":{}}' > "$D/bad.json"
echo "=== 合法策略 ==="
target/debug/aisbx policy-check -p "$D/ok.json"
echo "exit=$?"
echo "=== 非法策略(task 含 \$) ==="
target/debug/aisbx policy-check -p "$D/bad.json"
echo "exit=$?"
echo "临时目录: $D"
```

实测输出：

```text
=== 合法策略 ===
策略合法: task=demo-1 write=1 read=0 deny_escalation=0
exit=0
=== 非法策略(task 含 $) ===
aisbx: 错误: task 只允许字母数字与 - _
用法: aisbx run -p <policy.json> [--json] [--require-full] -- <命令> [参数...]
      aisbx escalate -p <policy.json> --path <路径> --access read|write [--token <tok>]
      aisbx escalate --op net --host <host> --ip <ip> --port <port>
      aisbx authorize -p <policy.json> --path <路径> --access read|write [--ttl-seconds 300]
      aisbx authorize -p <policy.json> --host <域名> [--port 443]  # 放行代理观察到的目标(仅本次任务)
      aisbx capabilities [--json]
      aisbx policy-check -p <policy.json>
exit=2
```

**策略字段速查**（后面每块都会现场生成策略，这里先对照）：

| 字段 | 含义 |
|---|---|
| `task` | 任务名，**只允许字母数字、`-`、`_`**；决定 broker 目录 `$TMPDIR/aisbx-<task>/` |
| `filesystem.write` / `.read` | 可写 / 只读白名单目录 |
| `deny_escalation` | **不可授权**黑名单（命中直接拒，token 也救不回） |
| `allow_escalation` | 仅 `escalation:"auto"` 时自动放行的前缀 |
| `escalation` | `prompt`（无 TTY 交宿主授权）/ `auto`（按 allow 前缀）/ `deny`（一律拒绝且不邀请） |
| `network.loopback` / `.internet` | 回环 / 外网 |
| `broker.audit_log` | 审计 JSONL 路径（不配则只有 `--json` 事件流） |

**退出码**：`0` 成功 / `1` 被拒 / `2` 用法或环境错误 / `3` 等待授权超时 / `99` 内部错误。

---

## 3. 默认隔离：白名单内成功 / 白名单外被拒

整块复制执行（两场景一次跑完）：

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
BIN="$PWD/target/debug/aisbx"
D=$(mktemp -d)
mkdir -p "$D/ws" "$D/out"
printf '{"task":"basic-demo","filesystem":{"write":["%s/ws"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false},"broker":{"audit_log":"%s/audit.jsonl"}}' "$D" "$D" > "$D/p.json"
echo "=== 场景 A:白名单内写(应成功) ==="
"$BIN" run -p "$D/p.json" -- /bin/sh -c "echo hello > $D/ws/ok.txt"
echo "exit=$? content=$(cat "$D/ws/ok.txt" 2>/dev/null)"
echo "=== 场景 B:白名单外写(应被内核拒绝) ==="
"$BIN" run -p "$D/p.json" -- /bin/sh -c "echo hi > $D/out/blocked.txt"
echo "exit=$? exists=$([ -f "$D/out/blocked.txt" ] && echo yes || echo no)"
echo "=== 审计 JSONL ==="
cat "$D/audit.jsonl"
echo "临时目录: $D"
```

实测输出：

```text
=== 场景 A:白名单内写(应成功) ===
exit=0 content=hello
=== 场景 B:白名单外写(应被内核拒绝) ===
/bin/sh: /var/folders/.../T/tmp.tNPURUzZt2/out/blocked.txt: Operation not permitted
exit=1 exists=no
=== 审计 JSONL ===
{"attempt":1,"cmd":["/bin/sh","-c","echo hello > .../ws/ok.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/bin/sh","-c","echo hi > .../out/blocked.txt"],"event":"spawned"}
{"attempt":1,"code":1,"event":"exit"}
```

判决在 **syscall 边界**（Seatbelt），无论路径来自参数、脚本拼接还是程序运行时算出都兜得住；错误原文 `Operation not permitted` 是内核给的，沙箱不改写。

---

## 4. `--json` 事件流（agent 消费这个）

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
BIN="$PWD/target/debug/aisbx"
D=$(mktemp -d)
mkdir -p "$D/ws"
printf '{"task":"json-demo","filesystem":{"write":["%s/ws"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false}}' "$D" > "$D/p.json"
"$BIN" run -p "$D/p.json" --json -- /bin/sh -c "echo hi > $D/ws/a.txt"
echo "临时目录: $D"
```

实测输出：

```text
{"attempt":1,"cmd":["/bin/sh","-c","echo hi > /var/folders/.../ws/a.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
```

事件名固定集合：`spawned`/`exit`/`violation`/`violation.captured`/`escalation.*`/`token.*`/`retry`/`proxy.*`/`sid`/`network`（三平台同形，由 `scripts/contract_check.py` 保证）。

---

## 5. `deny` 模式：拒绝是终态（不邀请授权）

> ⚠️ `escalate`/`status`/`authorize` **只能在 run 正在运行时调用**（broker 生命周期 = 一次 run）。
> 本块会后台起一个 `burn spin`，跑完自动清理，整块复制即可。

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
BIN="$PWD/target/debug/aisbx"
BURN="$PWD/target/debug/examples/burn"
D=$(mktemp -d)
mkdir -p "$D/ws" "$D/out"
printf '{"task":"deny-demo-%s","filesystem":{"write":["%s/ws"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false},"broker":{"audit_log":"%s/audit.jsonl"}}' "$(date +%s)" "$D" "$D" > "$D/p.json"
"$BIN" run -p "$D/p.json" -- "$BURN" spin 20 >"$D/spin.out" 2>&1 &
RUN_PID=$!
sleep 3
echo "=== escalate(deny 模式应答) ==="
"$BIN" escalate -p "$D/p.json" --path "$D/out/denied.txt" --access write
echo "=== status(不应标待授权) ==="
"$BIN" status -p "$D/p.json"
kill "$RUN_PID" 2>/dev/null
wait "$RUN_PID" 2>/dev/null
echo "临时目录: $D"
```

实测输出：

```text
=== escalate(deny 模式应答) ===
{"granted":false,"reason":"授权被拒绝","effect":"none","retry_required":false}
=== status(不应标待授权) ===
{"attempt":1,"backend":"unix","granted_nets":[],"granted_paths":[],"needs_approval":false,"pending":[],"retries":0,"violations_total":1}
```

关键：`retry_required:false` + `needs_approval:false` → 拒绝是终态，**不会邀请宿主去授权**。
对比：`prompt` + 无 TTY 时应答是 `{"granted":false,"reason":"需要用户授权后重新执行","effect":"retry","retry_required":true}`。

---

## 6. 核心场景：B 契约授权闭环（感知 → 授权 → 重跑）

整块复制执行——它会：后台起 run → 查 `status` → 宿主 `authorize` 签 token → launcher 自动重跑 → 打印结果。

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
BIN="$PWD/target/debug/aisbx"
BURN="$PWD/target/debug/examples/burn"
D=$(mktemp -d)
mkdir -p "$D/ws" "$D/out"
printf '{"task":"flow-demo-%s","filesystem":{"write":["%s/ws"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"prompt"},"network":{"loopback":true,"internet":false},"broker":{"audit_log":"%s/audit.jsonl"}}' "$(date +%s)" "$D" "$D" > "$D/p.json"
echo "=== 策略 ==="
cat "$D/p.json"
"$BIN" run -p "$D/p.json" --json -- "$BURN" retryflow "$D/out/granted.txt" grant >"$D/run.out" 2>&1 &
RUN_PID=$!
sleep 2
echo "=== status(待授权项) ==="
"$BIN" status -p "$D/p.json"
echo "=== authorize(宿主签发一次性 token) ==="
"$BIN" authorize -p "$D/p.json" --path "$D/out" --access write --ttl-seconds 120
wait "$RUN_PID"
echo "=== run 输出(注意 attempt 1→2) ==="
cat "$D/run.out"
echo "=== 结果文件 ==="
cat "$D/out/granted.txt"
echo "=== 审计尾部 ==="
tail -8 "$D/audit.jsonl"
echo "临时目录: $D"
```

实测输出（路径简化为 `...`）：

```text
=== status(待授权项) ===
{"attempt":1,"backend":"unix","granted_nets":[],"granted_paths":[],"needs_approval":true,
 "pending":[{"access":"write","attributed":true,"host":"","kind":"file",
             "path":".../out/granted.txt","port":0,"precision":"reported","source":"explicit"}],
 "retries":0,"violations_total":2}
=== authorize(宿主签发一次性 token) ===
{"access":"write","expires_in":120,"granted":true,"path":".../out",
 "token":"3c447e8cf64a592458fcabed0fd9b55c"}
=== run 输出(注意 attempt 1→2) ===
{"attempt":1,"cmd":[".../burn","retryflow",".../out/granted.txt","grant"],"event":"spawned"}
first_write=denied
{"granted":false,"reason":"需要用户授权后重新执行","effect":"retry","retry_required":true}
escalate=1
{"attempt":1,"code":1,"event":"exit"}
{"command_id":"3dcb95f9...","event":"retry","from":1,"granted":[],"placeholders":[],"reason":"user-approved","to":2}
{"attempt":2,"cmd":[".../burn","retryflow",".../out/granted.txt","grant"],"event":"spawned"}
wrote=ok
{"granted":true,"reason":"已按授权 token 放宽下一次执行策略","effect":"retry","retry_required":true}
{"granted":false,"reason":"授权 token 校验失败: token 无效、已过期或已消费","effect":"none","retry_required":false}
redeem=0 replay=1
{"attempt":2,"code":0,"event":"exit"}
=== 结果文件 ===
x
=== 审计尾部 ===
{"event":"escalation.deny","host":"example.com","ip":"1.1.1.1","op":"net","port":443,"reason":"network-escalation-unsupported"}
{"attempt":1,"code":1,"event":"exit"}
{"event":"token.issued","path":".../out","ttl_seconds":120}
{"event":"retry","from":1,"reason":"user-approved","to":2}
{"event":"token.redeemed","path":".../out/granted.txt"}
{"event":"token.reject","path":".../out/granted.txt","reason":"token 无效、已过期或已消费"}
{"attempt":2,"code":0,"event":"exit"}
```

**要点**：`attempt:1` 被拒 → `event:"retry"` → `attempt:2` 成功（≤3 轮）；第二次的 `token.reject` 证明 **token 一次性**。

自己的程序想主动申报越界，在沙箱内调用：
```bash
aisbx escalate -p <policy> --path <被拒路径> --access write
```
launcher 会自动把 token 注入并重跑，程序无需自己处理 token。

---

## 7. 网络默认拒绝

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
BIN="$PWD/target/debug/aisbx"
D=$(mktemp -d)
printf '{"task":"net-demo","filesystem":{"write":[],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false}}' > "$D/p.json"
echo "=== 外网连接(应失败) ==="
"$BIN" run -p "$D/p.json" -- /usr/bin/nc -z -G 2 1.1.1.1 53
echo "exit=$?"
echo "=== 回环连接(应成功) ==="
"$BIN" run -p "$D/p.json" -- /usr/bin/nc -z -G 2 127.0.0.1 1
echo "exit=$?"
echo "临时目录: $D"
```

实测输出：

```text
=== 外网连接(应失败) ===
exit=1
=== 回环连接(应成功) ===
exit=0
```

按主机放行（运行中即时生效、命令**不**重跑）：`aisbx authorize -p <policy> --host example.com --port 443`。
⚠️ 必须先有代理真实观察到的拒绝，否则返回 `authorize.reject{reason:"no-real-violation"}`（fail-closed）。

---

## 8. `--require-full` 严格门控（macOS 会拒绝）

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
BIN="$PWD/target/debug/aisbx"
D=$(mktemp -d)
printf '{"task":"strict-demo","filesystem":{"write":[],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false}}' > "$D/p.json"
"$BIN" run -p "$D/p.json" --require-full -- /bin/echo hi
echo "exit=$?"
echo "临时目录: $D"
```

实测输出：

```text
aisbx: 错误: 严格模式下以下能力不可用: memory_per_process, process_limit
（退出码 2）
```

说明 macOS 诚实上报 `unavailable`，不会假装有限制。**不要在 macOS 上用此开关做硬资源断言**；需要硬预算用 Linux（RLIMIT_AS）或 Windows（Job Object）。

---

## 9. 一键自检（全量冒烟）

```bash
cd /Users/xiaojun/Work/workspace/nomar/aisbx
bash scripts/smoke-unix.sh
```

成功尾部实测输出：

```text
  PASS  契约检查:能力/事件/审计/退出码 三平台同一份契约

SMOKE_DONE fail=0
冒烟验证全部通过
```

其中 §5/§6 的两组断言在 CI 与本地都全绿：

```text
T2x 应答: {"granted":false,"reason":"授权被拒绝","effect":"none","retry_required":false}
T2x status: {...,"needs_approval":false,"pending":[]}
  PASS  T2xa deny 模式提权被拒
  PASS  T2xb deny 不邀请宿主授权(retry_required=false)
  PASS  T2xc deny 模式 status 不标 needs_approval
  PASS  T2xd deny 模式不产生 escalation.pending
  PASS  T2xe deny 的审计不带 retry_required
  PASS  T2xf deny 模式秒回(未空等授权超时)
  PASS  T2xg deny 模式行为纳入同一份契约检查
```

---

## 10. 排错速查

| 现象 | 原因与处理 |
|---|---|
| `task 只允许字母数字与 - _`（退出码 2） | task 含 `$`/空格/中文；改成 `demo-1` 这种 |
| `连接 .../esc.sock 失败...(任务未运行?)` | `escalate` 需要 **run 正在运行**；按 §5 后台起 run 再调用 |
| `连接 .../ctl.sock 失败...(任务未运行?)` | `status`/`authorize` 同上 |
| `Operation not permitted` 但 `status.pending` 为空 | 被动越界走 L1/L2 感知通道；用 §6 的 `burn retryflow` 或主动 `escalate` 得到确定性链路 |
| `--require-full` 报能力不可用 | macOS 诚实边界（§8）；去掉开关或换平台 |
| `authorize.reject{reason:"no-real-violation"}` | 网络授权必须基于代理真实观察到的拒绝，不能凭空签发 |
| 想看三平台 CI 结果 | `git fetch origin '+refs/heads/ci-run/*:refs/remotes/origin/ci-run/*'`（**必须带 `+`**，远端被 force push 过），再 `git show origin/ci-run/unix-macos-latest:ci/runs/<run_id>-macos-latest.md` |

---

## 11. 相关文档

- `docs/03-场景使用指南.md`：网络代理、审计、agent 集成伪代码
- `docs/04-跨平台实现方案.md`：契约 C01–C22 与平台映射
- `docs/07-测试覆盖矩阵.md`：场景矩阵、CI 结果读取
- `docs/08-架构与实现原理.md`：逐系统实现原理（能力矩阵、场景→系统映射）
