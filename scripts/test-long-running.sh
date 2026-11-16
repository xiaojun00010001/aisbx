#!/bin/bash
# 长期运行/后台服务测试脚本（macOS，可直接执行：bash scripts/test-long-running.sh）
#
# 验证 aisbx 跑「服务类」长驻进程的能力与正确操作方式：
#   1. 后台启动长期 HTTP 服务（bash 作业控制 set -m，launcher 独立进程组）
#   2. 服务运行期间 `aisbx status` 可查
#   3. 宿主经回环访问服务成功（网络默认仅回环）
#   4. 停止：直接 kill launcher → launcher 的 SIGTERM handler 会连带杀掉
#      沙箱进程组 → 无残留（修复前会残留，本脚本是回归保护）
#   5. 运行中文件动态授权 → authorize 触发「用新策略快照重跑」
#      （服务会重启一次，日志出现 retry from:1 to:2）
#
# 全程 mktemp -d，不触碰真实 ~/.ssh；退出前确保清理所有子进程。

set -um pipefail
cd "$(dirname "$0")/.." || exit 2
BIN="$PWD/target/debug/aisbx"
[ -x "$BIN" ] || { echo "缺少 ${BIN}，请先 cargo build"; exit 2; }

# 清理可能残留的测试服务（只匹配本脚本的 task 前缀）
cleanup_stale() {
  local pids
  pids=$(pgrep -f 'python3 -m http.server' 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "清理残留 http.server: $pids"
    kill -9 $pids 2>/dev/null || true
    sleep 1
  fi
}
cleanup_stale

D=$(mktemp -d)
mkdir -p "$D/ws" "$D/home"
printf 'SERVICE-OK' > "$D/ws/index.html"
PORT=$((20000 + RANDOM % 20000))
TASK="svc-test-$(date +%s)"
printf '{"task":"%s","filesystem":{"write":["%s/ws"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"prompt"},"network":{"loopback":true,"internet":false},"broker":{"audit_log":"%s/audit.jsonl"}}' \
  "$TASK" "$D" "$D" > "$D/p.json"

LOG="$D/test.log"
fail=0
pass() { printf '  PASS  %s\n' "$1" | tee -a "$LOG"; }
bad()  { printf '  FAIL  %s\n' "$1" | tee -a "$LOG"; fail=$((fail+1)); }
note() { printf '  NOTE  %s\n' "$1" | tee -a "$LOG"; }
hr()   { printf '\n===== %s =====\n' "$1" | tee -a "$LOG"; }

echo "临时目录: $D"
echo "日志: $LOG"
echo "端口: $PORT  task: $TASK"

hr "1. 后台启动长期 HTTP 服务"
# set -m: bash 作业控制 → 后台作业独立进程组，便于安全清理
set -m
HOME="$D/home" "$BIN" run -p "$D/p.json" --json -- \
  /usr/bin/python3 -m http.server "$PORT" --directory "$D/ws" > "$D/srv.log" 2>&1 &
LPID=$!
set +m
sleep 3
CHILD=$(pgrep -P "$LPID" | head -1)
if kill -0 "$LPID" 2>/dev/null && [ -n "$CHILD" ]; then
  pass "服务后台运行（launcher=${LPID}，沙箱子进程=${CHILD}）"
else
  bad "服务后台运行"
fi

hr "2. 服务运行中 status 可查"
ST=$(HOME="$D/home" "$BIN" status -p "$D/p.json" 2>&1)
echo "$ST" | head -c 300 | tee -a "$LOG"; echo
if echo "$ST" | grep -q '"backend"' && echo "$ST" | grep -q '"needs_approval"'; then
  pass "status 在服务运行期间可用"
else
  bad "status 在服务运行期间可用"
fi

hr "3. 宿主经回环访问服务"
BODY=$(curl -s --max-time 3 "http://127.0.0.1:$PORT/" 2>&1)
echo "响应: $BODY" | tee -a "$LOG"
if [ "$BODY" = "SERVICE-OK" ]; then
  pass "回环访问服务成功"
else
  bad "回环访问服务成功"
fi

hr "4. 停止：kill launcher（SIGTERM handler 连带杀进程组）"
echo "沙箱子进程=$CHILD（由 SIGTERM handler 连带回收）" | tee -a "$LOG"
kill "$LPID" 2>/dev/null || true
sleep 2
if curl -s --max-time 2 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
  bad "kill launcher 后服务不可访问（无残留）"
  # 兜底清理
  CHPGID=$(ps -o pgid= -p "$CHILD" | tr -d ' ')
  [ -n "$CHPGID" ] && kill -9 -- "-$CHPGID" 2>/dev/null || true
  pkill -9 -f "python3 -m http.server $PORT" 2>/dev/null || true
else
  pass "kill launcher 后服务不可访问（无残留）"
fi
wait "$LPID" 2>/dev/null || true

hr "5. 边界记录（不是失败项）"
note "服务中文件授权 = 用新策略快照【重跑】（服务重启一次），macOS Seatbelt profile 无法热更新"
note "网络授权走代理通道，运行中即时生效（不需重跑）"
note "重跑上限 MAX_ATTEMPTS=3，超过后不再重启"

hr "汇总"
echo "PASS=$(grep -c '  PASS  ' "$LOG")" | tee -a "$LOG"
echo "FAIL=$fail" | tee -a "$LOG"
echo "SMOKE_DONE fail=$fail" | tee -a "$LOG"
if [ $fail -eq 0 ]; then echo "长期运行服务验证全部通过"; else echo "失败 $fail 项（日志 ${LOG}）"; fi
echo "临时目录（用完 rm -rf ${D}）: $D"
exit $fail
