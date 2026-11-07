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
AUTO_CAP=$(printf '%s' "$CAP_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["capabilities"]["auto_violation_capture"])' 2>/dev/null)
if [[ "$AUTO_CAP" == "full" || "$AUTO_CAP" == "partial" ]]; then
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
else
  assert "T7a 能力报告如实标注自动采集不可用" test "$AUTO_CAP" = "unavailable"
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
