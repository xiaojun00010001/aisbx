#!/usr/bin/env bash
# aisbx Linux/macOS 冒烟验证(方案 B 契约)
#   策略配置 → 拒绝感知(violation) → 用户授权(authorize) → 重新执行(retry) → 成功
# 与 scripts/smoke.ps1 的能力语义对齐,但按 B 契约组织断言。
set -u

cd "$(dirname "$0")/.." || exit 2
REPO="$PWD"
BIN="$REPO/target/debug/aisbx"
BURN="$REPO/target/debug/examples/burn"
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/aisbx-smoke.XXXXXX") || exit 2
WS="$ROOT/ws"
OUT="$ROOT/outside"
DENY="$ROOT/deny"
POLICY="$ROOT/policy.json"
AUDIT="$ROOT/audit.jsonl"
LOG="$ROOT/smoke.log"
TASK="smoke-$$"

mkdir -p "$WS" "$OUT" "$DENY" || exit 2

python3 - "$POLICY" "$WS" "$DENY" "$AUDIT" "$TASK" <<'PY'
import json, sys
policy, ws, deny, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {
        "write": [ws],
        "read": [],
        "deny_escalation": [deny],
        "allow_escalation": [],
        "escalation": "deny",
    },
    "network": {"loopback": True, "internet": False},
    "resources": {"memory_mb_per_process": 64, "memory_mb_total": 256, "active_processes": 10},
    "broker": {"audit_log": audit},
}, open(policy, "w"), indent=2)
PY

fail=0
pass() { printf '  PASS  %s\n' "$1" | tee -a "$LOG"; }
bad()  { printf '  FAIL  %s\n' "$1" | tee -a "$LOG"; fail=$((fail + 1)); }
warn() { printf '  WARN  %s\n' "$1" | tee -a "$LOG"; }
assert() { local name="$1"; shift; if "$@" >>"$LOG" 2>&1; then pass "$name"; else bad "$name"; fi; }

echo "[$(date +%H:%M:%S)] == 0. 构建 ==" | tee -a "$LOG"
cargo build --quiet --bins --example burn 2>&1 | tail -3 | tee -a "$LOG"
if [[ ! -x "$BIN" || ! -x "$BURN" ]]; then
  bad "构建产物缺失 ($BIN / $BURN)"; echo "SMOKE_DONE fail=$fail"; exit 1
fi

echo "[$(date +%H:%M:%S)] == T0 策略 ==" | tee -a "$LOG"
assert "T0 策略解析与校验" "$BIN" policy-check -p "$POLICY"

echo "[$(date +%H:%M:%S)] == T1 文件默认隔离 ==" | tee -a "$LOG"
"$BIN" run -p "$POLICY" -- "$BURN" write "$OUT/f1.txt" >>"$LOG" 2>&1
RC=$?
if [[ $RC -ne 0 ]]; then pass "T1a 白名单外写入被拒"; else bad "T1a 白名单外写入被拒"; fi
assert "T1b 白名单外文件未落盘" test ! -f "$OUT/f1.txt"
"$BIN" run -p "$POLICY" -- "$BURN" write "$WS/f1.txt" >>"$LOG" 2>&1
RC=$?
if [[ $RC -eq 0 && -f "$WS/f1.txt" ]]; then pass "T1c 白名单内写入成功"; else bad "T1c 白名单内写入成功"; fi

echo "[$(date +%H:%M:%S)] == T2 拒绝感知 → 授权 → 重执行 ==" | tee -a "$LOG"
# 黑名单前置:token 也救不回(fail-closed,且不应触发等待授权)
"$BIN" run -p "$POLICY" -- "$BURN" retryflow "$DENY/x.txt" deny >>"$LOG" 2>&1
RC=$?
if [[ $RC -ne 0 ]]; then pass "T2a deny_escalation 黑名单前置"; else bad "T2a deny_escalation 黑名单前置"; fi

RETRY_OUT="$ROOT/retry.out"
"$BIN" run -p "$POLICY" --json -- "$BURN" retryflow "$OUT/f2.txt" grant >"$RETRY_OUT" 2>&1 &
RUN_PID=$!

# 必须等「本轮需要用户授权」的 violation:T2a 黑名单用例也会写 violation,不能命中它
for _ in $(seq 1 100); do
  grep -q '"event":"violation".*"reason":"needs-approval"' "$AUDIT" 2>/dev/null && break
  sleep 0.2
done
if grep -q '"event":"violation".*"reason":"needs-approval"' "$AUDIT" 2>/dev/null; then
  pass "T2b 拒绝感知(violation 含具体路径)"
else
  bad "T2b 拒绝感知(violation 含具体路径)"
fi

AUTH=$("$BIN" authorize -p "$POLICY" --path "$OUT" --access write --ttl-seconds 120 2>>"$LOG")
echo "$AUTH" >>"$LOG"
TOKEN=$(printf '%s' "$AUTH" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
if [[ -n "$TOKEN" ]]; then pass "T2c authorize 签发一次性 token"; else bad "T2c authorize 签发一次性 token"; fi

wait "$RUN_PID"
RC=$?
cat "$RETRY_OUT" | tee -a "$LOG"
echo "retryflow exit=$RC" | tee -a "$LOG"
if [[ $RC -eq 0 ]]; then pass "T2d 授权后重新执行成功"; else bad "T2d 授权后重新执行成功"; fi
assert "T2e retry 事件已落审计" grep -q '"event":"retry"' "$AUDIT"
assert "T2f 授权后真实写入落盘" test -f "$OUT/f2.txt"
assert "T2g token 一次性(消费成功+重放被拒)" grep -q '"event":"token.redeemed"' "$AUDIT"
assert "T2h token 重放被审计" grep -q '"event":"token.reject"' "$AUDIT"
assert "T2i 网络拒绝上报(host/ip/port)" grep -q '"op":"net"' "$AUDIT"

echo "[$(date +%H:%M:%S)] == T3 资源限制(按能力报告判定) ==" | tee -a "$LOG"
CAP_JSON=$("$BIN" capabilities 2>>"$LOG")
MEM_CAP=$(printf '%s' "$CAP_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capabilities"]["memory_per_process"])' 2>/dev/null)
PROC_CAP=$(printf '%s' "$CAP_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capabilities"]["process_limit"])' 2>/dev/null)
echo "capabilities: memory_per_process=$MEM_CAP process_limit=$PROC_CAP" | tee -a "$LOG"

"$BIN" run -p "$POLICY" -- "$BURN" mem 32 >>"$LOG" 2>&1
if [[ $? -eq 0 ]]; then pass "T3a 配额内分配成功"; else bad "T3a 配额内分配成功"; fi
"$BIN" run -p "$POLICY" -- "$BURN" mem 512 >>"$LOG" 2>&1
MEM_RC=$?
if [[ "$MEM_CAP" == "unavailable" ]]; then
  warn "T3b 内存硬上限:该平台无内核等价机制(见能力报告),不计失败"
elif [[ $MEM_RC -ne 0 ]]; then
  pass "T3b 单进程内存超限被发现"
else
  bad "T3b 单进程内存超限被发现"
fi
"$BIN" run -p "$POLICY" -- "$BURN" fork 40 >>"$LOG" 2>&1
PROC_RC=$?
if [[ "$PROC_CAP" == "unavailable" ]]; then
  warn "T3c 进程数上限:该平台无每任务内核配额(RLIMIT_NPROC 按用户计数,不可用),不计失败"
elif [[ $PROC_RC -ne 0 ]]; then
  pass "T3c 进程数上限生效"
else
  bad "T3c 进程数上限生效"
fi

echo "[$(date +%H:%M:%S)] == T4 网络 ==" | tee -a "$LOG"
"$BIN" run -p "$POLICY" -- "$BURN" loopback >>"$LOG" 2>&1
if [[ $? -eq 0 ]]; then pass "T4a 回环放行"; else bad "T4a 回环放行"; fi
"$BIN" run -p "$POLICY" -- "$BURN" conn 1.1.1.1 53 >>"$LOG" 2>&1
if [[ $? -ne 0 ]]; then pass "T4b 外网被内核拒绝"; else bad "T4b 外网被内核拒绝"; fi

echo "[$(date +%H:%M:%S)] == T5 审计与能力报告 ==" | tee -a "$LOG"
assert "T5a token.issued 已落审计" grep -q '"event":"token.issued"' "$AUDIT"
assert "T5b escalation.deny 已落审计" grep -q '"event":"escalation.deny"' "$AUDIT"
assert "T5c spawned 事件已落审计" grep -q '"event":"spawned"' "$AUDIT"
CAP=$("$BIN" capabilities 2>>"$LOG")
echo "$CAP" >>"$LOG"
if printf '%s' "$CAP" | grep -q '"contract": "B"'; then
  pass "T5d 能力报告声明 B 契约"
else
  bad "T5d 能力报告声明 B 契约"
fi

echo "[$(date +%H:%M:%S)] == T6 网络代理:精确目标自动采集 / 运行中授权 ==" | tee -a "$LOG"
# burn proxy 只是遵守 HTTPS_PROXY 发一次 CONNECT,不主动上报、不解析命令。
# 精确 host:port 必须由代理从协议里自己读到。
P6="$ROOT/p6.json"; A6="$ROOT/p6.audit.jsonl"; TASK6="smoke6-$$"
python3 - "$P6" "$WS" "$A6" "$TASK6" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit},
}, open(policy, "w"), indent=2)
PY
T6_OUT="$ROOT/t6.out"
"$BIN" run -p "$P6" --json -- "$BURN" proxy example.com 443 >"$T6_OUT" 2>&1 &
T6_PID=$!
for _ in $(seq 1 100); do
  grep -q '"event":"violation".*"kind":"net"' "$A6" 2>/dev/null && break
  sleep 0.2
done
assert "T6a 代理自动拿到精确 host:port(零解析/零改造)" grep -q '"host":"example.com".*"port":443' "$A6"
"$BIN" authorize -p "$P6" --host example.com --port 443 >>"$LOG" 2>&1
wait "$T6_PID"
T6_RC=$?
if [[ $T6_RC -eq 0 ]]; then pass "T6b 授权后运行中放行"; else bad "T6b 授权后运行中放行 (rc=$T6_RC)"; fi
assert "T6c net.grant 已落审计" grep -q '"event":"net.grant"' "$A6"
if [[ $(grep -c '"event":"spawned"' "$A6") -eq 1 ]]; then
  pass "T6d 全程只执行一次(网络授权不需重跑)"
else
  bad "T6d 全程只执行一次(网络授权不需重跑)"
fi
cat "$T6_OUT" >> "$LOG"

echo "[$(date +%H:%M:%S)] == T7 内核违规日志自动采集(按能力报告判定) ==" | tee -a "$LOG"
CAP_JSON=$("$BIN" capabilities 2>>"$LOG")
# ⚠️ 判据必须是「内核日志通道(L2)是否存在」,而不是 auto_violation_capture:
# 后者在只有 L1(stderr 自报)的平台上同样是 full/partial,而本段的断言
# 全是 L2 专属(violation.captured / source=sandbox-log)——判据与断言不匹配
# 就会在 Linux 上整段误跑并全红(实测 CI 如此)。
AUTO_CAP=$(printf '%s' "$CAP_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capabilities"]["auto_violation_capture"])' 2>/dev/null)
L2_PROBE=$(printf '%s' "$CAP_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capabilities"].get("violation_log_probe",""))' 2>/dev/null)
if [[ -n "$L2_PROBE" ]]; then
  # P1 完整闭环:burn write 不调 escalate、不解析命令,精确路径由内核日志自动给出。
  P7="$ROOT/p7.json"; A7="$ROOT/p7.audit.jsonl"; TASK7="smoke7-$$"
  python3 - "$P7" "$WS" "$A7" "$TASK7" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PY
  "$BIN" run -p "$P7" --json -- "$BURN" write "$OUT/t7.txt" >"$ROOT/t7.out" 2>&1 &
  T7_PID=$!
  for _ in $(seq 1 100); do
    grep -q '"event":"violation.captured"' "$A7" 2>/dev/null && break
    sleep 0.2
  done
  assert "T7a 内核日志自动给出精确路径(程序零配合)" grep -q '"event":"violation.captured".*t7.txt' "$A7"
  assert "T7b violation 标记为内核日志来源" grep -q '"source":"sandbox-log"' "$A7"
  "$BIN" authorize -p "$P7" --path "$OUT" --access write >>"$LOG" 2>&1
  wait "$T7_PID"
  T7_RC=$?
  if [[ $T7_RC -eq 0 ]]; then pass "T7c 授权后重执行成功"; else bad "T7c 授权后重执行成功 (rc=$T7_RC)"; fi
  assert "T7d 授权后文件真实落盘" test -f "$OUT/t7.txt"
  assert "T7e retry 事件已落审计" grep -q '"event":"retry"' "$A7"
  cat "$ROOT/t7.out" >> "$LOG"

  # T7f/T7g:回归——内核上报的是【真正执行违规的那个进程】的 PID。
  # 实测(2026-11-08):入口 PID=64904,而日志里是 64905=入口 fork 出的子 shell。
  # 旧实现按「入口 PID + 登记 PID」归属,必然漏掉所有 fork 出来的子孙进程。
  # 现改为:进程存活期间按 pgid 累积组成员 → 覆盖整棵进程树。
  P7F="$ROOT/p7f.json"; A7F="$ROOT/p7f.audit.jsonl"; TASK7F="smoke7f-$$"
  python3 - "$P7F" "$WS" "$A7F" "$TASK7F" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PY
  "$BIN" run -p "$P7F" --json -- /bin/sh -c "echo \"SANDBOX_PARENT_PID=\$\$\"; (echo hi > $OUT/t7f.txt)" >"$ROOT/t7f.out" 2>&1 &
  T7F_PID=$!
  # 等待 violation 事件(不能只等路径:`spawned` 事件的命令串里也含该路径,
  # 用路径做条件会立刻 break,断言在采集完成前就跑了)
  for _ in $(seq 1 150); do
    grep 't7f\.txt' "$A7F" 2>/dev/null | grep -q '"event":"violation' && break
    sleep 0.2
  done
  # T7f:短命深层进程 → 【无法归属】。实测违规进程可比入口深 3 层
  # (入口 84007 / 内核上报 84011),而 kqueue 的 fork 事件只在父子间投递,
  # 短命进程退出后又无法反查进程组,归属不可判定。
  # 关键安全约束:未能归属 ≠ 是我们的越界 —— 同机其它应用的违规(实测能捞到
  # Chrome、wifip2pd)会落进同一个日志流。所以这类条目只能进审计,
  # 绝不能进 violations 列表、绝不能驱动授权(否则等于让用户授权无关路径,
  # 还能被用来伪造「真实拒绝」骗过 token 签发)。
  # 注意:serde_json 的 Map 是 BTreeMap,输出按【字母序】(access, attributed,
  # command_id, event, path, pid, precision, reason, source)——所以不能假设
  # "event" 在 "path" 之前,匹配一律用管道 grep,不依赖字段顺序。
  if grep 't7f\.txt' "$A7F" 2>/dev/null | grep -q '"event":"violation.captured"'; then
    bad "T7f 内核日志未归属的条目不得作为越界上报(会误认同机其它进程的违规)"
  else
    pass "T7f 内核日志未归属的条目不作为越界上报(仅审计)"
  fi
  assert "T7g 未归属条目仍留审计记录(路径可见)" bash -c "grep 't7f\.txt' '$A7F' | grep -q '\"event\":\"violation.unattributed\"'"
  # T7l:只有「内核日志未归属」这一条来源时,不得用于申请授权。
  # ⚠️ 不能沿用 T7f 的载荷:`sh -c 'echo hi > path'` 的 stderr 带路径 →
  # 会被 L1 以 attributed=true 采到 → 归属确定 → 授权本就合法(这正是 L1 的价值)。
  # 这里显式关闭 stderr 采集(violation_capture=false):L2 照常采(macOS 固有),
  # L1 不采 → 只剩「未归属」这一条来源 → authorize 必须被拒。
  # 该用例与平台无关:Linux 无 L2,同样什么都没有 → 同样必须被拒。
  P7L="$ROOT/p7l.json"; A7L="$ROOT/p7l.audit.jsonl"; TASK7L="smoke7l-$$"
  python3 - "$P7L" "$WS" "$A7L" "$TASK7L" <<'PYL'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": False},
}, open(policy, "w"), indent=2)
PYL
  "$BIN" run -p "$P7L" --json -- /bin/sh -c "echo hi > $OUT/t7l.txt" >"$ROOT/t7l.out" 2>&1 &
  T7L_PID=$!
  for _ in $(seq 1 150); do
    grep 't7l\.txt' "$A7L" 2>/dev/null | grep -q '"event":"violation' && break
    sleep 0.2
  done
  if "$BIN" authorize -p "$P7L" --path "$OUT/t7l.txt" --access write >>"$LOG" 2>&1; then
    bad "T7l 未归属条目不得用于申请授权"
  else
    pass "T7l 未归属条目不得用于申请授权"
  fi
  wait "$T7L_PID"
  cat "$ROOT/t7l.out" >> "$LOG"
  wait "$T7F_PID"
  cat "$ROOT/t7f.out" >> "$LOG"

  # T7i:违规进程【仍存活】时,用 pid→pgid 反查精确归属(与层级深度无关,
  # 因为 fork 继承进程组)。这是深层次归属的主力判据。
  P7H="$ROOT/p7h.json"; A7H="$ROOT/p7h.audit.jsonl"; TASK7H="smoke7h-$$"
  python3 - "$P7H" "$WS" "$A7H" "$TASK7H" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PY
  # 用两层子 shell,让违规进程深到 kqueue 覆盖不到(它只投递父子事件),
  # 从而真正验证「pid→pgid 反查」这条与层级深度无关的兜底判据。
  "$BIN" run -p "$P7H" --json -- /bin/sh -c "((echo hi > $OUT/t7h.txt; sleep 15) &) & sleep 6" >"$ROOT/t7h.out" 2>&1 &
  T7H_PID=$!
  for _ in $(seq 1 200); do
    grep 't7h\.txt' "$A7H" 2>/dev/null | grep -q '"event":"violation' && break
    sleep 0.2
  done
  T7H_ATTR=$(python3 -c 'import json,sys
for ln in open(sys.argv[1]):
    try: d=json.loads(ln)
    except Exception: continue
    if d.get("event")=="violation.captured" and "t7h.txt" in d.get("path",""):
        print(json.dumps(d.get("attributed"))); break' "$A7H" 2>/dev/null)
  if [[ "$T7H_ATTR" == "true" ]]; then
    pass "T7i 存活的深层进程按进程组精确归属(attributed=true)"
  else
    bad "T7i 存活的深层进程按进程组精确归属(attributed=$T7H_ATTR)"
    echo "--- 诊断:审计里含 t7h 的行:" | tee -a "$LOG"
    grep 't7h' "$A7H" 2>/dev/null | head -3 | tee -a "$LOG"
    echo "--- 诊断:t7h.out 前 5 行:" | tee -a "$LOG"
    head -5 "$ROOT/t7h.out" 2>/dev/null | tee -a "$LOG"
  fi
  assert "T7j 越界路径标注为内核来源且精确" grep -q '"precision":"exact".*"source":"sandbox-log"' "$A7H"
  if grep 't7h\.txt' "$A7H" 2>/dev/null | grep -q '"event":"violation.unattributed"'; then
    bad "T7k 可归属的越界不应同时出现在未归属列表"
  else
    pass "T7k 可归属的越界不重复出现在未归属列表"
  fi
  "$BIN" authorize -p "$P7H" --path "$OUT" --access write >>"$LOG" 2>&1
  wait "$T7H_PID"
  cat "$ROOT/t7h.out" >> "$LOG"
else
  # ⚠️ 这里要断言的是**内核日志通道(L2)**不可用,不是「自动采集」不可用:
  # 只有 L1(stderr 自报)的平台上,auto_violation_capture 同样是 full/partial
  # (L1 确实在工作),拿它当判据会误判。
  assert "T7a 无内核通道时能力报告如实标注该通道不可用" test -z "$L2_PROBE"
  warn "T7b 内核违规日志自动采集:该平台不可用,不计失败(见 docs/06)"
fi

echo "[$(date +%H:%M:%S)] == T8 SOCKS5:同一端口按首字节分流 ==" | tee -a "$LOG"
P8="$ROOT/p8.json"; A8="$ROOT/p8.audit.jsonl"; TASK8="smoke8-$$"
python3 - "$P8" "$WS" "$A8" "$TASK8" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit},
}, open(policy, "w"), indent=2)
PY
"$BIN" run -p "$P8" --json -- "$BURN" socks example.com 443 >"$ROOT/t8.out" 2>&1 &
T8_PID=$!
for _ in $(seq 1 100); do
  grep -q '"event":"violation".*"kind":"net"' "$A8" 2>/dev/null && break
  sleep 0.2
done
assert "T8a SOCKS5 自动拿到精确 host:port(零解析/零改造)" grep -q '"host":"example.com".*"port":443' "$A8"
"$BIN" authorize -p "$P8" --host example.com --port 443 >>"$LOG" 2>&1
wait "$T8_PID"
T8_RC=$?
if [[ $T8_RC -eq 0 ]]; then pass "T8b SOCKS5 授权后运行中放行"; else bad "T8b SOCKS5 授权后运行中放行 (rc=$T8_RC)"; fi
assert "T8c net.grant 已落审计" grep -q '"event":"net.grant"' "$A8"
if [[ $(grep -c '"event":"spawned"' "$A8") -eq 1 ]]; then
  pass "T8d 全程只执行一次"
else
  bad "T8d 全程只执行一次"
fi
cat "$ROOT/t8.out" >> "$LOG"

echo "[$(date +%H:%M:%S)] == T9 契约边界与安全断言 ==" | tee -a "$LOG"
P9="$ROOT/p9.json"; A9="$ROOT/p9.audit.jsonl"; TASK9="smoke9-$$"
python3 - "$P9" "$WS" "$A9" "$TASK9" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit},
}, open(policy, "w"), indent=2)
PY

# T9a --require-full 必须按能力报告判定,不能硬编码平台结论
CAP_ALL=$("$BIN" capabilities 2>>"$LOG")
FULL_EXPECT=$(printf '%s' "$CAP_ALL" | python3 -c '
import json,sys
w={"auto_violation_capture","cpu","memory_total","landlock","bubblewrap","seatbelt","seccomp","launcher_retry"}
c=json.load(sys.stdin)["capabilities"]
print("deny" if any(v=="unavailable" and k not in w for k,v in c.items()) else "allow")
' 2>/dev/null)
"$BIN" run --require-full -p "$P9" -- "$BURN" write "$WS/full.txt" >>"$LOG" 2>&1
FULL_RC=$?
if { [[ "$FULL_EXPECT" == "deny" && $FULL_RC -ne 0 ]] || [[ "$FULL_EXPECT" == "allow" && $FULL_RC -eq 0 ]]; }; then
  pass "T9a --require-full 按能力报告判定($FULL_EXPECT)"
else
  bad "T9a --require-full 按能力报告判定(期望 $FULL_EXPECT, rc=$FULL_RC)"
fi

# T9b 没发生过真实越界时,宿主不能凭空签发网络授权(fail-closed)
"$BIN" run -p "$P9" -- "$BURN" spin 4 >"$ROOT/t9b.run" 2>&1 &
T9B_PID=$!
sleep 1
"$BIN" authorize -p "$P9" --host never-observed.invalid --port 443 >"$ROOT/t9b.auth" 2>&1
T9B_RC=$?
wait "$T9B_PID"
if [[ $T9B_RC -ne 0 ]]; then
  pass "T9b 无真实越界时拒绝签发网络授权(fail-closed)"
else
  bad "T9b 无真实越界时拒绝签发网络授权(fail-closed)"
fi
cat "$ROOT/t9b.auth" >> "$LOG"

# T9c 两个并发任务的审计不得串台
P9A="$ROOT/p9a.json"; A9A="$ROOT/p9a.audit.jsonl"
P9B="$ROOT/p9b.json"; A9B="$ROOT/p9b.audit.jsonl"
python3 - "$P9A" "$WS" "$A9A" "smoke9a-$$" "$P9B" "$A9B" "smoke9b-$$" <<'PY'
import json, sys
for p, a, t in [(sys.argv[1], sys.argv[3], sys.argv[4]), (sys.argv[5], sys.argv[6], sys.argv[7])]:
    ws = sys.argv[2]
    json.dump({
        "task": t,
        "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                       "allow_escalation": [], "escalation": "deny"},
        "network": {"loopback": True, "internet": False},
        "resources": {}, "broker": {"audit_log": a},
    }, open(p, "w"), indent=2)
PY
"$BIN" run -p "$P9A" --json -- "$BURN" write "$WS/a9.txt" >"$ROOT/a9.out" 2>&1 &
PA=$!
"$BIN" run -p "$P9B" --json -- "$BURN" write "$WS/b9.txt" >"$ROOT/b9.out" 2>&1 &
PB=$!
wait "$PA"; wait "$PB"
if grep -q 'a9.txt' "$A9A" && ! grep -q 'b9.txt' "$A9A" && grep -q 'b9.txt' "$A9B" && ! grep -q 'a9.txt' "$A9B"; then
  pass "T9c 并发任务审计不串台"
else
  bad "T9c 并发任务审计不串台"
fi

# T9d 代理拒绝 loopback/私网目标(防 SSRF),且不进入等待授权
"$BIN" run -p "$P9" -- "$BURN" proxy 127.0.0.1 443 >"$ROOT/t9d.out" 2>&1
T9D_RC=$?
if [[ $T9D_RC -eq 3 ]]; then
  pass "T9d 代理拒绝 loopback 目标(SSRF fail-closed)"
else
  bad "T9d 代理拒绝 loopback 目标(SSRF fail-closed) (rc=$T9D_RC)"
fi
cat "$ROOT/t9d.out" >> "$LOG"

# T9e 能力报告关键字段完整(避免静默降级)
if printf '%s' "$CAP_ALL" | grep -q '"net_proxy"' && printf '%s' "$CAP_ALL" | grep -q '"auto_violation_capture"'; then
  pass "T9e 能力报告含采集能力与代理协议字段"
else
  bad "T9e 能力报告含采集能力与代理协议字段"
fi

echo "[$(date +%H:%M:%S)] == T10 能力契约组(C07/C19/C20/C22) ==" | tee -a "$LOG"
P10="$ROOT/p10.json"; A10="$ROOT/p10.audit.jsonl"; TASK10="smoke10-$$"
python3 - "$P10" "$WS" "$OUT" "$A10" "$TASK10" <<'PY'
import json, sys
policy, ws, out, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [out], "escalation": "auto"},
    "network": {"loopback": True, "internet": False},
    "resources": {}, "broker": {"audit_log": audit},
}, open(policy, "w"), indent=2)
PY

# T10a C07:auto 模式命中 allow_escalation 前缀时授权(deny 模式已由 T2a 覆盖)
"$BIN" run -p "$P10" -- "$BIN" escalate -p "$P10" --path "$OUT/t10a.txt" --access write >"$ROOT/t10a.out" 2>&1
assert "T10a C07 auto 模式按 allow_escalation 授权" grep -q '"granted":true' "$ROOT/t10a.out"
cat "$ROOT/t10a.out" >> "$LOG"

# T10b C22:--json 事件流含 spawned / exit
"$BIN" run -p "$P10" --json -- "$BURN" write "$WS/t10b.txt" >"$ROOT/t10b.out" 2>&1
if grep -q '"event":"spawned"' "$ROOT/t10b.out" && grep -q '"event":"exit"' "$ROOT/t10b.out"; then
  pass "T10b C22 --json 事件流含 spawned/exit"
else
  bad "T10b C22 --json 事件流含 spawned/exit"
fi

# T10c C19:宿主被杀时进程树终止,按能力报告判定(Unix 标 partial,如实跳过)
CAP10=$("$BIN" capabilities 2>>"$LOG")
PTK=$(printf '%s' "$CAP10" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capabilities"]["process_tree_kill"])' 2>/dev/null)
if [[ "$PTK" == "full" ]]; then
  "$BIN" run -p "$P10" -- "$BURN" spin 20 >"$ROOT/t10c.out" 2>&1 &
  T10C_PID=$!
  sleep 2
  kill -9 "$T10C_PID" 2>/dev/null
  sleep 1
  if pgrep -f "$BURN spin 20" >/dev/null 2>&1; then
    bad "T10c C19 宿主被杀后无残留沙箱进程"
  else
    pass "T10c C19 宿主被杀后无残留沙箱进程"
  fi
else
  warn "T10c C19 宿主被杀进程树终止:该平台标 $PTK,未验证(已知缺口)"
fi

# T10d C20:任务结束无 ACL 残余。Unix 无 ACL 机制,如实跳过;Windows 由 smoke.ps1 实断言。
warn "T10d C20 ACL 清理:该后端不使用 ACL,由 Windows 冒烟实断言"

# T10e 能力报告每个能力都有明确状态值(不静默降级/不虚报)
CAP10_OK=$(printf '%s' "$CAP10" | python3 -c '
import json,sys
c=json.load(sys.stdin)["capabilities"]
skip={"net_proxy","violation_log_probe","violation_file_path_precision","violation_net_path_precision"}
bad=[k for k,v in c.items() if k not in skip and v not in ("full","partial","unavailable")]
print("ok" if not bad else "bad:"+",".join(bad))
' 2>/dev/null)
if [[ "$CAP10_OK" == "ok" ]]; then
  pass "T10e 能力报告逐项状态明确"
else
  bad "T10e 能力报告逐项状态明确 ($CAP10_OK)"
fi

# T10f 路径精度字段:取值必须是 exact/reported/none 之一(不虚报精度)
CAP_PREC=$(printf '%s' "$CAP10" | python3 -c '
import json,sys
c=json.load(sys.stdin)["capabilities"]
allowed={"exact","reported","none"}
keys=("violation_file_path_precision","violation_net_path_precision")
bad=[k+"="+str(c.get(k)) for k in keys if c.get(k) not in allowed]
print("ok" if not bad else "bad:"+",".join(bad))
' 2>/dev/null)
if [[ "$CAP_PREC" == "ok" ]]; then
  pass "T10f 越界路径精度字段取值合法(exact/reported/none)"
else
  bad "T10f 越界路径精度字段取值合法 ($CAP_PREC)"
fi

echo "" | tee -a "$LOG"

# T11 L1:程序自报路径(stderr)。内核日志给的是「谁」,stderr 给的是「程序自己
# 声称要什么」——归属确定但路径可伪造,故精度只能是 reported。
# 两者互补:L2 拿不到归属时(短命深层进程)由 L1 顶上,反之亦然。
echo "[$(date +%H:%M:%S)] == T11 L1:程序自报路径(stderr)==" | tee -a "$LOG"
P11="$ROOT/p11.json"; A11="$ROOT/p11.audit.jsonl"; TASK11="smoke11-$$"
python3 - "$P11" "$WS" "$A11" "$TASK11" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PY
# 目标文件**预先存在**:白名单外目录被 bind 成只读时,写「新文件」得到的是
# EROFS(Read-only file system),写「已存在文件」才是 EACCES(Permission denied)。
# 两种形态 L1 都要能识别,这里用后者(更贴近「越界写既有文件被拒」)。
: > "$OUT/t11.txt"
"$BIN" run -p "$P11" --json -- /bin/sh -c "echo hi > $OUT/t11.txt" >"$ROOT/t11.out" 2>&1 &
T11_PID=$!
for _ in $(seq 1 150); do
  grep 't11\.txt' "$A11" 2>/dev/null | grep -q '"event":"violation' && break
  sleep 0.2
done
cat "$ROOT/t11.out" >> "$LOG" 2>/dev/null || true
assert "T11a 越界路径被采集(内核日志或 stderr 自报)" bash -c "grep 't11\.txt' '$A11' | grep -q '\"event\":\"violation\"'"
T11_PREC=$(python3 -c 'import json,sys
for ln in open(sys.argv[1]):
    try: d=json.loads(ln)
    except Exception: continue
    if d.get("event")=="violation" and "t11.txt" in d.get("path",""):
        print(d.get("precision")); break' "$A11" 2>/dev/null)
if [[ "$T11_PREC" == "exact" || "$T11_PREC" == "reported" ]]; then
  pass "T11b 越界路径精度已标注($T11_PREC)"
else
  bad "T11b 越界路径精度应标注 exact/reported(实际=$T11_PREC)"
fi
# 无内核通道的平台(Linux)只能靠 L1,精度必须如实落到 reported
PROBE=$(printf '%s' "$CAP_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capabilities"].get("violation_log_probe",""))' 2>/dev/null)
if [[ -z "$PROBE" ]]; then
  if [[ "$T11_PREC" == "reported" ]]; then
    pass "T11c 无内核通道时精度如实为 reported"
  else
    bad "T11c 无内核通道时精度应为 reported(实际=$T11_PREC)"
  fi
else
  pass "T11c 该平台有内核通道,精度可为 exact"
fi
# T11d:采集到的路径正确。只比**尾部**(目录名+文件名):程序自报的是原样路径
# (CI 上可能是短路径),规范化后的是长路径,JSON 里还要再转义一层 ——
# 三种形态并存,只有尾部是稳定判据(与 Windows 侧同口径)。
T11LEAF=$(basename "$OUT/t11.txt")
T11DIR=$(basename "$OUT")
assert "T11d 采集到的路径正确" \
  bash -c "grep 't11\\.txt' '$A11' | grep -q '$T11DIR[\\\\/]*$T11LEAF'"
"$BIN" authorize -p "$P11" --path "$OUT" --access write >>"$LOG" 2>&1
wait "$T11_PID"
cat "$ROOT/t11.out" >> "$LOG"


# T14 status:agent 能拿到【具体】待授权路径(而不是只拿到数量)
# ——agent 要拿它去问用户「允许写 /x/y 吗」,只给个数没法问。
echo "[$(date +%H:%M:%S)] == T14 status 给出待授权的具体路径 ==" | tee -a "$LOG"
P14="$ROOT/p14.json"; A14="$ROOT/p14.audit.jsonl"; TASK14="smoke14-$$"
python3 - "$P14" "$WS" "$A14" "$TASK14" <<'PYJ'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PYJ
"$BIN" run -p "$P14" --json -- "$BURN" retryflow "$OUT/t14.txt" grant >"$ROOT/t14.out" 2>&1 &
T14_PID=$!
T14_STATUS=""
for _ in $(seq 1 100); do
  T14_STATUS=$("$BIN" status -p "$P14" 2>"$ROOT/t14.status.err" || true)
  # 必须判断 pending **非空**:字段名恒存在,只看字段名会第一次就 break
  printf '%s' "$T14_STATUS" | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
sys.exit(0 if d.get("pending") else 1)' && break
  sleep 0.2
done
printf '%s' "$T14_STATUS" > "$ROOT/t14.status"
assert "T14a status 给出待授权的具体路径" grep -q 't14.txt' "$ROOT/t14.status"
assert "T14b status 标注路径精度与归属" grep -q '"precision"' "$ROOT/t14.status"
assert "T14c status 报告 needs_approval 标志" grep -q '"needs_approval":true' "$ROOT/t14.status"
"$BIN" authorize -p "$P14" --path "$OUT" --access write >>"$LOG" 2>&1
wait "$T14_PID"
cat "$ROOT/t14.out" >> "$LOG"

# T15 对抗用例:程序【自称】一个无害路径,却【真实访问】另一个路径。
#   - L2(内核日志,仅 macOS):应采到**真实被拒路径**(内核不受欺骗)→ precision=exact
#   - L1(stderr 自报):只能采到**自称路径** → precision=reported
#   - 授权【自称】路径后,真实路径仍必须被内核拒绝 → 伪造换不来越权
echo "[$(date +%H:%M:%S)] == T15 对抗:自称路径 vs 真实路径 ==" | tee -a "$LOG"
P15="$ROOT/p15.json"; A15="$ROOT/p15.audit.jsonl"; TASK15="smoke15-$$"
python3 - "$P15" "$WS" "$A15" "$TASK15" <<'PYK'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PYK
CLAIMED="$OUT/claimed.txt"; ACTUAL="$OUT/actual.txt"
"$BIN" run -p "$P15" --json -- "$BURN" spoof "$CLAIMED" "$ACTUAL" >"$ROOT/t15.out" 2>&1 &
T15_PID=$!
for _ in $(seq 1 150); do
  grep 'claimed\.txt' "$A15" 2>/dev/null | grep -q '"event":"violation' && break
  sleep 0.2
done
# 有内核通道的平台(macOS):应同时采到两条,且精度不同
if [[ -n "$PROBE" ]]; then
  assert "T15a 内核通道采到真实被拒路径(precision=exact)" \
    bash -c "grep 'actual\.txt' '$A15' | grep -q '\"precision\":\"exact\"'"
  assert "T15b 自称路径仅由 stderr 自报(precision=reported)" \
    bash -c "grep 'claimed\.txt' '$A15' | grep -q '\"precision\":\"reported\"'"
else
  assert "T15a 无内核通道时只采到自称路径" \
    bash -c "grep 'claimed\.txt' '$A15' | grep -q '\"event\":\"violation\"'"
  # ⚠️ 只排除**内核通道**采到的条目:审计里出现 actual.txt 本身不算失败——
  # 策略感知(source=explicit)也会记下这个路径,那是正常行为。
  assert "T15b 无内核通道时采不到从未被拒的真实路径" \
    bash -c "! grep 'actual\.txt' '$A15' | grep -q '\"source\":\"sandbox-log\"'"
fi
# 只授权【自称】路径 → 重跑 → 真实路径仍必须写不动
"$BIN" authorize -p "$P15" --path "$CLAIMED" --access write >>"$LOG" 2>&1
wait "$T15_PID"
assert "T15c 授权自称路径后真实路径仍被拒(伪造不构成越权)" \
  bash -c "! test -f '$ACTUAL'"
cat "$ROOT/t15.out" >> "$LOG"

# ── T12 B 契约:授权后重跑(launcher retry)─────────────────────────
# 沙箱内程序写白名单外的路径 → 被拒(stderr 含路径)→ L1 采集 → 置 needs-approval
# → launcher 等宿主授权 → 把该路径并入策略快照 → **重跑** → 成功。
# 与 Windows 侧 T12 同语义(那边是 AppContainer + ACL)。
echo "[$(date +%H:%M:%S)] == T12 B 契约:授权后重跑 ==" | tee -a "$LOG"
P12="$ROOT/p12.json"; A12="$ROOT/p12.audit.jsonl"; TASK12="smoke12-$$"
python3 - "$P12" "$WS" "$A12" "$TASK12" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PY
T12TARGET="$OUT/t12.txt"
"$BIN" run -p "$P12" --json -- /bin/sh -c "echo hi > $T12TARGET" >"$ROOT/t12.out" 2>&1 &
T12_PID=$!
for _ in $(seq 1 150); do
  grep -q 'needs-approval' "$A12" 2>/dev/null && break
  sleep 0.2
done
"$BIN" authorize -p "$P12" --path "$T12TARGET" --access write >>"$LOG" 2>&1
wait "$T12_PID"; T12_RC=$?
cat "$ROOT/t12.out" >> "$LOG" 2>/dev/null || true
assert "T12a 授权后重跑成功" test "$T12_RC" -eq 0
assert "T12b 文件真实落盘" test -f "$T12TARGET"
assert "T12c retry 事件已落审计" grep -q '"event":"retry"' "$A12"

# ── T13 授权粒度:不外溢 ────────────────────────────────────────────
# 用户同意的是「创建这一个文件」;若实现对父目录授 Modify,授权范围就悄悄
# 扩大到整个目录 —— 这是真实的越权面。probe2 先试新建(被拒→采集→授权→
# 重跑),再试同目录既有文件:授权后新的能建,旧的必须仍写不动、内容不变。
echo "[$(date +%H:%M:%S)] == T13 授权粒度不外溢 ==" | tee -a "$LOG"
P13="$ROOT/p13.json"; A13="$ROOT/p13.audit.jsonl"; TASK13="smoke13-$$"
python3 - "$P13" "$WS" "$A13" "$TASK13" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PY
T13NEW="$OUT/t13new.txt"; T13OLD="$OUT/t13old.txt"
echo "orig" > "$T13OLD"
"$BIN" run -p "$P13" -- "$BURN" probe2 "$T13NEW" "$T13OLD" >"$ROOT/t13.out" 2>&1 &
T13_PID=$!
for _ in $(seq 1 150); do
  grep -q 'needs-approval' "$A13" 2>/dev/null && break
  sleep 0.2
done
"$BIN" authorize -p "$P13" --path "$T13NEW" --access write >>"$LOG" 2>&1
wait "$T13_PID"
cat "$ROOT/t13.out" >> "$LOG" 2>/dev/null || true
assert "T13a 授权后新文件创建成功" grep -q "NEW_CREATED" "$ROOT/t13.out"
assert "T13b 授权粒度不外溢(同目录既有文件仍不可写)" \
  bash -c "grep -q 'EXISTING_DENIED' '$ROOT/t13.out' && ! grep -q 'EXISTING_WRITEABLE' '$ROOT/t13.out'"
assert "T13c 既有文件内容未被改动" grep -q "orig" "$T13OLD"

# ── 跨平台契约检查(与 Windows **共用同一份** contract_check.py 与基线)──
# 目的是保证「三个环境的表现形式与交互一样」:能力报告的键集合、
# --json 事件流的事件名、审计事件类型、退出码语义,三平台必须一致。
echo "[$(date +%H:%M:%S)] == 跨平台契约检查 ==" | tee -a "$LOG"
CP="$ROOT/contract"; mkdir -p "$CP"
"$BIN" capabilities > "$CP/caps.json" 2>/dev/null
python3 - "$CP/policy.json" "$WS" "$CP/audit.jsonl" "contract-$$" <<'PY'
import json, sys
policy, ws, audit, task = sys.argv[1:]
json.dump({
    "task": task,
    "filesystem": {"write": [ws], "read": [], "deny_escalation": [],
                   "allow_escalation": [], "escalation": "deny"},
    "network": {"loopback": True, "internet": False},
    "resources": {},
    "broker": {"audit_log": audit, "violation_capture": True},
}, open(policy, "w"), indent=2)
PY
# 一次最小越界 run:收集 --json 事件流、审计与退出码
# ⚠️ 必须有界:契约检查是纯文件处理(秒级),卡住就是出了问题 ——
# 不能让它把整轮冒烟拖死(Windows 侧就踩过这个坑)。
timeout 60 "$BIN" run -p "$CP/policy.json" --json -- /bin/sh -c "echo hi > $OUT/contract.txt" \
  > "$CP/events.jsonl" 2>"$CP/run.err"
CP_RC=$?
# ⚠️ 平台名必须取自能力报告的 backend:同一个 Unix 脚本在 macOS 与 Linux
# 两个 runner 上跑,写死 linux 会让 macOS 拿 Linux 的期望去比 → 假失败。
CP_PLATFORM=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['backend'])" "$CP/caps.json")
if timeout 60 python3 scripts/contract_check.py \
     --caps "$CP/caps.json" \
     --baseline scripts/contract-baseline.json \
     --platform "$CP_PLATFORM" \
     --events "$CP/events.jsonl" \
     --audit "$CP/audit.jsonl" \
     --exit-code "$CP_RC" >>"$LOG" 2>&1; then
  pass "契约检查:能力/事件/审计/退出码 三平台同一份契约"
else
  bad "契约检查:能力/事件/审计/退出码 三平台同一份契约"
  cat "$CP/events.jsonl" >> "$LOG" 2>/dev/null || true
fi

echo "" | tee -a "$LOG"
echo "SMOKE_DONE fail=$fail" | tee -a "$LOG"
if [[ $fail -eq 0 ]]; then
  echo "冒烟验证全部通过" | tee -a "$LOG"
else
  echo "冒烟验证失败 $fail 项" | tee -a "$LOG"
  echo "---- 审计日志 ----" | tee -a "$LOG"
  cat "$AUDIT" 2>/dev/null | tee -a "$LOG"
  echo "---- 运行日志尾部 ----"
  tail -60 "$LOG"
fi
rm -rf "$ROOT"
exit "$fail"
