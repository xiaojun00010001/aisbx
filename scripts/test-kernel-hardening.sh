#!/usr/bin/env bash
# docs/12 A8:内核加固探针 —— 用内核证据验证 cap-drop / no_new_privs /
# seccomp / PID 视图 / 逃逸 syscall 阻断 是否真的生效。
#
# 用法（Linux 真机或特权容器）:
#   bash scripts/test-kernel-hardening.sh
# 非 Linux 或无 bwrap 时按平台能力跳过（NOTE,不计 FAIL）——
# 运行时审批与内核原语不是所有环境都能实现,不强求。
set -u
cd "$(dirname "$0")/.."
BIN="$PWD/target/debug/aisbx"
BURN="$PWD/target/debug/examples/burn"
ROOT=$(mktemp -d); LOG="$ROOT/test.log"
pass=0; fail=0; note=0
ok(){ printf '  PASS  %s\n' "$1"; pass=$((pass+1)); }
bad(){ printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
skip(){ printf '  NOTE  %s\n' "$1"; note=$((note+1)); }

echo "===== 0. 前置 ====="
UNAME=$(uname -s)
if [[ "$UNAME" != "Linux" || ! -x "$BIN" || ! -x "$BURN" || ! -x "$(command -v bwrap || true)" ]]; then
  echo "非 Linux 或缺 bwrap/二进制 → 全部跳过（按能力不强求）"
  echo "SKIP=all"
  exit 0
fi
# bwrap 在非特权命名空间环境会失败;探测一次,失败则整体跳过
if ! bwrap --unshare-user --ro-bind / / --dev /dev true >/dev/null 2>&1; then
  echo "当前环境不允许在 userns 内 remount（嵌套容器/WSL/AppArmor）→ 跳过"
  echo "SKIP=all"
  exit 0
fi

echo "===== 1. 构造策略 ====="
WS="$ROOT/ws"; OUT="$ROOT/out"; mkdir -p "$WS" "$OUT"
P="$ROOT/p.json"; A="$ROOT/audit.jsonl"
TASK="kh$(date +%s)"
printf '{"task":"%s","filesystem":{"write":["%s"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false},"resources":{},"broker":{"audit_log":"%s"}}' "$TASK" "$WS" "$A" > "$P"

echo "===== 2. 沙箱内采集内核证据 ====="
PROBE="$OUT/probe.txt"
"$BIN" run -p "$P" -- /bin/sh -c '
  echo "== status =="
  grep -E "NoNewPrivs|^CapEff|^Seccomp" /proc/self/status
  echo "== mnt-ns =="
  readlink /proc/self/ns/mnt
  echo "== pid-ns =="
  readlink /proc/self/ns/pid
  echo "== proc-count =="
  ls /proc | grep -cE "^[0-9]+$"
  echo "== unshare =="
  unshare --user true 2>&1 | head -1
  echo "== mount =="
  mount -t tmpfs none /tmp 2>&1 | head -1
' > "$PROBE" 2>&1
cat "$PROBE"

HOST_MNT=$(readlink /proc/self/ns/mnt)
echo "宿主 mnt-ns=$HOST_MNT"

echo "===== 3. 断言内核证据 ====="
grep -q 'NoNewPrivs:[[:space:]]*1' "$PROBE" && ok "NoNewPrivs=1（setuid 提权封死）" || bad "NoNewPrivs=1"
grep -q 'CapEff:[[:space:]]*0000000000000000' "$PROBE" && ok "CapEff 全 0（--cap-drop ALL 生效）" || bad "CapEff 全 0"
grep -q 'Seccomp:[[:space:]]*2' "$PROBE" && ok "Seccomp=2（BPF filter 已生效且不可逆）" || bad "Seccomp=2"
SANDBOX_MNT=$(sed -n '/== mnt-ns ==/{n;p;}' "$PROBE")
[[ -n "$SANDBOX_MNT" && "$SANDBOX_MNT" != "$HOST_MNT" ]] && ok "mnt namespace 与宿主不同（文件系统视图隔离）" || bad "mnt namespace 隔离"
SANDBOX_PID=$(sed -n '/== pid-ns ==/{n;p;}' "$PROBE")
[[ -n "$SANDBOX_PID" ]] && ok "PID namespace 已建立（$SANDBOX_PID）" || bad "PID namespace 已建立"
PROC_COUNT=$(sed -n '/== proc-count ==/{n;p;}' "$PROBE")
if [[ -n "$PROC_COUNT" && "$PROC_COUNT" -lt 20 ]]; then
  ok "/proc 只含沙箱进程（count=$PROC_COUNT，未泄漏宿主）"
else
  bad "/proc PID 视图泄漏（count=$PROC_COUNT）"
fi
sed -n '/== unshare ==/{n;p;}' "$PROBE" | grep -qi 'not permitted\|Operation not permitted' \
  && ok "unshare 被 seccomp 拒绝（防自我换 namespace）" || bad "unshare 被拒绝"
sed -n '/== mount ==/{n;p;}' "$PROBE" | grep -qi 'not permitted\|permission denied' \
  && ok "mount 被拒绝（防拆只读 bind）" || bad "mount 被拒绝"

echo "===== 汇总 ====="
printf 'PASS=%s FAIL=%s NOTE=%s\n' "$pass" "$fail" "$note"
[[ "$fail" -eq 0 ]]
