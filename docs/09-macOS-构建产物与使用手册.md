# 09 · macOS 构建产物与使用手册（可直接照抄执行）

> 本文所有命令与输出示例均在 **macOS + Rust 1.99.1** 上**实跑采集**（不是推演）。
> 路径中的 `/var/folders/.../T/tmp.XXXXXXXX` 是 macOS 临时目录，你机器上会不同，用你自己的 `$D` 即可。
>
> 一句话定位：`aisbx` 把命令关进 **Seatbelt（`/usr/bin/sandbox-exec`）** 沙箱；越界的路径
> 经「**感知 → 授权 → 重跑**」闭环处理（契约 B）。策略是唯一契约，见 `examples/policy.example.json`。

---

## 0. 构建与产物

### 0.1 构建命令

```bash
cd /path/to/aisbx
cargo build                          # debug（本文示例都用这个）
cargo build --release                # release（产物在 target/release/）
```

实测环境：

```
$ rustc --version
rustc 1.99.1 (58cf8f9c3 2026-10-13)
$ cargo --version
cargo 1.99.1 (5f94df478 2026-08-27)
```

macOS 只用系统自带的 `/usr/bin/sandbox-exec`，**无需管理员、无需额外安装**。
（Linux 才需要 `bubblewrap`；Windows 走 AppContainer。）

### 0.2 产物清单与用途

| 路径 | 用途 | 实测大小 |
|---|---|---|
| `target/debug/aisbx` | **主二进制**：所有子命令 `run`/`status`/`authorize`/`escalate`/`capabilities`/`policy-check` | 2,970,632 B |
| `target/debug/examples/burn` | **测试载荷**：冒烟测试专用，模拟越界/资源超限/网络/授权闭环 | 945,176 B |
| `target/release/aisbx` | release 主二进制（`cargo build --release` 后） | — |

**`burn` 不是沙箱运行必需的**——日常只跑自己的命令时只需 `aisbx`。
本文「场景 4：授权闭环」用 `burn retryflow` 是因为它是**确定性触发 `escalate` 的最小载荷**；
你的程序若想主动申报越界，调用 `aisbx escalate`（见 §4.2）即可，不依赖 `burn`。

### 0.3 子命令总览（实测）

```
$ target/debug/aisbx --help
aisbx - agent 本地沙箱 (后端: macos: Seatbelt + 授权后重执行(B 契约))
  契约 B: 策略配置 → 拒绝感知 → 用户授权 → 重新执行
  run / escalate / authorize / capabilities / policy-check
```

| 子命令 | 用途 | 详细 |
|---|---|---|
| `run -p <policy> [--json] [--require-full] -- <cmd> [args...]` | 在沙箱里执行命令（主入口） | §2、§3 |
| `status -p <policy>` | 查本次任务的**待授权项**（需 run 正在运行） | §4 |
| `authorize -p <policy> --path X --access write [--ttl-seconds N]` | 宿主侧签发一次性 token | §4 |
| `authorize -p <policy> --host H --port P` | 运行中放行代理观察到的网络目标 | docs/03 §2 |
| `escalate -p <policy> --path X --access read\|write [--token T]` | 沙箱内主动上报越界 | §4.2 |
| `escalate --op net --host H --ip I --port P` | 网络越界上报（Unix） | docs/03 |
| `capabilities [--json]` | 能力报告（full/partial/unavailable） | §1.3 |
| `policy-check -p <policy>` | 校验策略合法性 | §1.2 |

**退出码**：`0` 成功 / `1` 被拒 / `2` 用法或环境错误 / `3` 等待授权超时 / `99` 内部错误。

---

## 1. 策略文件（先准备）

### 1.1 最小可用策略（macOS）

把下面内容存成 `~/aisbx-demo/policy.json`（先把 `WS` 替换成你的实际路径）：

```json
{
  "task": "demo-1",
  "filesystem": {
    "write":  ["/Users/you/aisbx-demo/ws"],
    "read":   [],
    "deny_escalation": [],
    "allow_escalation": [],
    "escalation": "prompt"
  },
  "network": { "loopback": true, "internet": false },
  "broker":  { "audit_log": "/Users/you/aisbx-demo/audit.jsonl" }
}
```

字段说明：

| 字段 | 含义 |
|---|---|
| `task` | 任务名，**只允许字母数字、`-`、`_`**（实测 `handbook-$$` 直接报错：`task 只允许字母数字与 - _`）。它决定 broker 通道名 `$TMPDIR/aisbx-<task>/` |
| `filesystem.write` | 可写白名单（目录） |
| `filesystem.read` | 只读白名单 |
| `deny_escalation` | **不可授权**黑名单：命中后直接拒，连问都不问（连 token 也救不回） |
| `allow_escalation` | `escalation:"auto"` 时自动放行的前缀表 |
| `escalation` | `prompt`（无 TTY 时交宿主授权）/ `auto`（按 allow 前缀）/ `deny`（一律拒绝，不邀请授权） |
| `network.loopback` | 放行回环 |
| `network.internet` | 放行外网（macOS 用 SBPL 禁 `network*`） |
| `broker.audit_log` | 审计 JSONL 路径；不配则只输出 `--json` 事件流 |

完整契约示例见 `examples/policy.example.json`（Windows 形态，字段通用）。

### 1.2 校验策略（实测）

```
$ target/debug/aisbx policy-check -p examples/policy.example.json
策略合法: task=task-42 write=2 read=1 deny_escalation=4
```

写错字段会被 `deny_unknown_fields` 抓住；task 含非法字符会报 `task 只允许字母数字与 - _` 并以退出码 2 结束。

### 1.3 查能力（实测，macOS）

```
$ target/debug/aisbx capabilities
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

要点：macOS 的 `violation_file_path_precision=exact`、`violation_log_probe=sandbox-reporting-violation`
——**内核日志通道可给出精确路径**；但 `memory_per_process`/`process_limit`/`cpu` 是 `unavailable`，
不会静默假装有限制。

`--require-full` 会让任何 `unavailable` 拒绝启动（实测）：

```
$ target/debug/aisbx run -p $D/p.json --require-full -- /bin/echo hi
aisbx: 错误: 严格模式下以下能力不可用: memory_per_process, process_limit
（退出码 2）
```

---

## 2. 基础场景：默认隔离（最常用）

```bash
BIN=$PWD/target/debug/aisbx
D=$(mktemp -d); mkdir -p "$D/ws" "$D/out"
cat > "$D/p.json" <<EOF
{"task":"basic-demo","filesystem":{"write":["$D/ws"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false},"broker":{"audit_log":"$D/audit.jsonl"}}
EOF
```

### 场景 2.1 白名单内写入 → 成功（实测）

```
$ $BIN run -p "$D/p.json" -- /bin/sh -c "echo hello > $D/ws/ok.txt"
$ echo "exit=$? content=$(cat $D/ws/ok.txt)"
exit=0 content=hello
```

无任何输出即成功（stdout 由被跑命令决定）。

### 场景 2.2 白名单外写入 → 内核拒绝（实测）

```
$ $BIN run -p "$D/p.json" -- /bin/sh -c "echo hi > $D/out/blocked.txt"
/bin/sh: /var/folders/.../T/tmp.tNPURUzZt2/out/blocked.txt: Operation not permitted
$ echo "exit=$? exists=$([ -f $D/out/blocked.txt ] && echo yes || echo no)"
exit=1 exists=no
```

**判决发生在 syscall 边界**：无论路径来自模型参数、脚本拼接还是程序运行时算出，都兜得住。
该错误的原文是内核给的 `Operation not permitted`（Seatbelt），沙箱不改写它。

### 场景 2.3 `--json` 事件流（agent 消费这个，实测）

```
$ $BIN run -p "$D/p.json" --json -- /bin/sh -c "echo hi > $D/ws/a.txt"
{"attempt":1,"cmd":["/bin/sh","-c","echo hi > /var/folders/.../ws/a.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
```

事件名固定为允许集合：`spawned` / `exit` / `violation` / `violation.captured` /
`escalation.*` / `token.*` / `retry` / `proxy.*` / `sid` / `network`。三平台同形。

### 场景 2.4 审计 JSONL（写了 `broker.audit_log` 时，实测）

```
$ cat "$D/audit.jsonl"
{"attempt":1,"cmd":["/bin/sh","-c","echo hello > .../ws/ok.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
{"attempt":1,"cmd":["/bin/sh","-c","echo hi > .../out/blocked.txt"],"event":"spawned"}
{"attempt":1,"code":1,"event":"exit"}
{"attempt":1,"cmd":["/bin/sh","-c","echo hi > .../ws/a.txt"],"event":"spawned"}
{"attempt":1,"code":0,"event":"exit"}
```

---

## 3. `deny` 模式：拒绝是终态（不邀请授权）

> ⚠️ **`escalate` / `status` / `authorize` 都必须有 run 正在运行**（broker 生命周期 = 一次 run）。
> 独立执行会报 `连接 .../esc.sock 失败...(任务未运行?)` 并以退出码 2 结束 —— 这是实测踩过的坑。
> 要单独验证本节，请先以后台方式起一个不会退出的 run：
>
> ```bash
> "$BIN" run -p "$D/p.json" -- "$BURN" spin 8 >"$D/spin.out" 2>&1 &
> RUN_PID=$!
> sleep 3        # 等 broker 就绪
> # ... 执行下面的 escalate / status ...
> kill "$RUN_PID" 2>/dev/null; wait "$RUN_PID" 2>/dev/null
> ```

实测应答（三平台逐字段同构）：

```
$ $BIN escalate -p "$D/p.json" --path "$D/out/denied.txt" --access write
{"granted":false,"reason":"授权被拒绝","effect":"none","retry_required":false}
```

- `retry_required:false` → **不会邀请宿主去申请授权**（`deny` 的严格语义）
- 对比：`prompt` + 无 TTY 时是 `{"granted":false,"reason":"需要用户授权后重新执行","effect":"retry","retry_required":true}`
- 对比：`escalation.grant` 时是 `{"granted":true,"reason":"...","effect":"retry","retry_required":true}`

`status` 也不会标待授权（实测）：

```
$ $BIN status -p "$D/p.json"
{"attempt":1,"backend":"unix","granted_nets":[],"granted_paths":[],"needs_approval":false,"pending":[],"retries":0,...}
```

---

## 4. 核心场景：B 契约授权闭环（感知 → 授权 → 重跑）

> 这是本沙箱最有价值的能力：程序越界后**无需改造**，宿主授权后自动以更宽策略**重跑**。

### 4.1 准备（用 `escalation:"prompt"`，无 TTY 时交宿主授权）

```bash
BIN=$PWD/target/debug/aisbx
BURN=$PWD/target/debug/examples/burn
D=$(mktemp -d); mkdir -p "$D/ws" "$D/out"
cat > "$D/p.json" <<EOF
{"task":"handbook-flow","filesystem":{"write":["$D/ws"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"prompt"},"network":{"loopback":true,"internet":false},"broker":{"audit_log":"$D/audit.jsonl"}}
EOF
```

### 4.2 起 run（后台）+ 查 status（实测原文）

```bash
$BIN run -p "$D/p.json" --json -- "$BURN" retryflow "$D/out/granted.txt" grant > "$D/run.out" 2>&1 &
PID=$!
sleep 2
$BIN status -p "$D/p.json"
```

```
{"attempt":1,"backend":"unix","granted_nets":[],"granted_paths":[],"needs_approval":true,
 "pending":[{"access":"write","attributed":true,"host":"","kind":"file",
             "path":"/var/folders/.../T/tmp.l3CyBQmjRH/out/granted.txt","port":0,
             "precision":"reported","source":"explicit"}],
 "retries":0,"violations_total":2}
```

`pending[]` 的字段就是给 agent 呈现给用户的依据：
- `path` / `access`：要授权的具体对象
- `precision`：`exact`（内核/协议自带）或 `reported`（程序自称，可伪造）
- `attributed`：能否证明来自本次执行；`false` 时**不要**据此授权

### 4.3 宿主授权（签发一次性 token，实测）

```
$ $BIN authorize -p "$D/p.json" --path "$D/out" --access write --ttl-seconds 120
{"access":"write","expires_in":120,"granted":true,
 "path":"/private/var/folders/.../T/tmp.l3CyBQmjRH/out",
 "token":"3c447e8cf64a592458fcabed0fd9b55c"}
```

### 4.4 等 run 结束，看重跑（实测原文）

```bash
wait "$PID"; cat "$D/run.out"
```

```
{"attempt":1,"cmd":[".../burn","retryflow",".../out/granted.txt","grant"],"event":"spawned"}
first_write=denied
{"granted":false,"reason":"需要用户授权后重新执行","effect":"retry","retry_required":true}
escalate=1
{"attempt":1,"code":1,"event":"exit"}
{"command_id":"3dcb95f9...","event":"retry","from":1,"granted":[],"placeholders":[],
 "reason":"user-approved","to":2}
{"attempt":2,"cmd":[".../burn","retryflow",".../out/granted.txt","grant"],"event":"spawned"}
wrote=ok
{"granted":true,"reason":"已按授权 token 放宽下一次执行策略","effect":"retry","retry_required":true}
{"granted":false,"reason":"授权 token 校验失败: token 无效、已过期或已消费","effect":"none","retry_required":false}
redeem=0 replay=1
{"attempt":2,"code":0,"event":"exit"}
```

关键点：
- `attempt:1` 被拒 → `event:"retry"` → `attempt:2` 成功 → **命令自动重跑，≤3 轮**
- 第二次 `token.reject` 证明 **token 一次性**（重放被拒）
- 审计尾部（实测）：
```
{"event":"token.issued","path":".../out","ttl_seconds":120}
{"event":"retry","from":1,"reason":"user-approved","to":2}
{"event":"token.redeemed","path":".../out/granted.txt"}
{"event":"token.reject","path":".../out/granted.txt","reason":"token 无效、已过期或已消费"}
```

### 4.5 自己的程序如何主动申报越界

沙箱内直接调用（与 `burn` 内部做法相同）：

```bash
aisbx escalate -p <policy> --path <被拒路径> --access write
# 输出：{"granted":false,"reason":"需要用户授权后重新执行","effect":"retry","retry_required":true}
```

宿主看到 `status.pending` 后签发 token，launcher 会自动注入并重跑（`AISBX_TOKEN`/`AISBX_ATTEMPT` 环境变量）。
**你不需要自己处理 token**——除非你想做「程序自持 token 运行中重试」这类高级集成（见 docs/03 §1.5）。

---

## 5. 网络场景

```bash
# 默认外网被内核拒绝（实测）
$ $BIN run -p "$D/p.json" -- /usr/bin/nc -z -G 2 1.1.1.1 53
$ echo $?
1
```

- 回环（`127.0.0.1`）放行；外网默认拒绝。
- 若需按主机放行（运行中即时生效，命令**不**重跑）：
  `aisbx authorize -p <policy> --host example.com --port 443`
  ——但必须**先有代理真实观察到的拒绝**，否则 `authorize.reject{reason:"no-real-violation"}`（fail-closed）。
- 精确 host:port 由**宿主代理读协议本身**得到（HTTP CONNECT / SOCKS5），不解析命令、不改造被跑程序。

---

## 6. 资源限制：macOS 的诚实边界

macOS 没有内核等价机制，能力报告如实标 `unavailable`：

| 维度 | macOS 表现 |
|---|---|
| 单进程内存 | `memory_per_process: unavailable` → 不限制、`WARN` 不计失败 |
| 每任务进程数 | `process_limit: unavailable` → 同上 |
| CPU 节流 | `cpu: unavailable` |
| 进程树终止 | `process_tree_kill: partial`（`setpgid` + `kill(-pgid)`，宿主被 SIGKILL 时无法清理） |

因此**不要用 `memory_mb_per_process` 在 macOS 上做硬断言**；需要硬资源预算请用 Linux（RLIMIT_AS）或 Windows（Job Object）。

---

## 7. 自检：一键跑全量冒烟（推荐首次使用）

```bash
bash scripts/smoke-unix.sh
```

这是仓库自带的全量验证（在 macOS 上覆盖 T0–T15 + 契约检查）。成功尾部：

```
  PASS  契约检查:能力/事件/审计/退出码 三平台同一份契约

SMOKE_DONE fail=0
冒烟验证全部通过
```

其中 `T2x deny 模式行为契约` 段的实测输出：

```
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

## 8. 排错速查

| 现象 | 原因与处理 |
|---|---|
| `task 只允许字母数字与 - _`（退出码 2） | task 名含 `$`/空格/中文等；改成 `demo-1` 这种 |
| `连接 .../ctl.sock 失败...(任务未运行?)` | `status`/`authorize` 需要 **run 正在运行**（broker 生命周期 = 一次 run）；先后台起 run 再查 |
| `Operation not permitted` 但没进 `pending` | 被动越界走 L1/L2 感知通道；确认策略里 `broker.violation_capture`（若用自动采集），或用 `burn retryflow`/主动 `escalate` 得到确定性链路 |
| `--require-full` 报 `memory_per_process, process_limit 不可用` | macOS 的诚实边界（§6）；去掉 `--require-full` 或改用 Linux/Windows |
| `authorize.reject{reason:"no-real-violation"}` | 网络授权必须基于代理真实观察到的拒绝，不能凭空签发（fail-closed） |
| 授权后仍写不进 | 见 docs/07 §4.5：Linux 的 `--bind` 源路径必须存在，三平台已统一为「占位文件 + 单文件授权」；macOS 用 Seatbelt 规则一般不受此影响 |
| 想看三平台 CI 的真机结果 | `git fetch origin '+refs/heads/ci-run/*:refs/remotes/origin/ci-run/*'`（**必须带 `+`**，远端被 force push 过），再 `git show origin/ci-run/unix-macos-latest:ci/runs/<run_id>-macos-latest.md` |

---

## 9. 相关文档

- `docs/01-调研报告.md`：同类沙箱调研
- `docs/03-场景使用指南.md`：网络代理、审计、agent 集成伪代码
- `docs/04-跨平台实现方案.md`：契约 C01–C22 与平台映射
- `docs/07-测试覆盖矩阵.md`：场景矩阵、断言规模、CI 结果读取
- `docs/08-架构与实现原理.md`：逐系统实现原理（能力矩阵、场景→系统映射）
