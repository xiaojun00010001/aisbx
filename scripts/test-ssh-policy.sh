#!/bin/bash
# SSH 默认策略测试脚本（macOS，可直接执行：bash scripts/test-ssh-policy.sh）
#
# 被测策略语义（SSH 默认策略）：
#   · 工作目录 + /tmp 可读写
#   · 其他目录只读（全局 file-read* 放行，但只有白名单目录可写）
#   · $HOME/.ssh 等敏感目录：Seatbelt 显式 (deny file-read*)
#       ⚠️ 当前实现的真实表现是 EPERM 完全拒绝（不可见/不可读/不可写）
#          **不是**「可见但读为空、写为空」——见下方 NOTE
#   · 网络默认仅回环（localhost:*），外网 EPERM
#
# 覆盖案例：
#   1. 工作目录写新增 case.txt，写入 case1
#   2. 修改 case.txt 为 case2，然后读取
#   3. 查看 .ssh 下的文件（记录真实表现 + 标注与期望语义的差异）
#   4. 访问 www.baidu.com（应被拒）
#   5. 脚本内对「非工作空间目录」和「工作目录」分别读写
#   6. 【失败 → 授权 → 成功访问】闭环（命中运行时审批能力）
#      ⚠️ 运行时审批不是所有环境都能提供；设置 AISBX_SKIP_AUTH_CASE=1 可跳过该案例。
#         跳过只记 NOTE，不计 FAIL —— 不强求全平台一致。
#
# 安全：所有测试都在 mktemp -d 的临时 HOME 中进行，**绝不触碰真实 ~/.ssh**。

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
BIN="$PWD/target/debug/aisbx"
BURN="$PWD/target/debug/examples/burn"

[ -x "$BIN" ] || { echo "缺少 $BIN，请先 cargo build --bins --example burn"; exit 2; }
[ -x "$BURN" ] || { echo "缺少 $BURN，请先 cargo build --bins --example burn"; exit 2; }

# ── 测试环境 ─────────────────────────────────────────────────────────────
D=$(mktemp -d)
WS="$D/workspace"        # 工作目录（可读写）
TMP="$D/tmp"             # /tmp 替代（可读写）
HOME_T="$D/home"         # 临时 HOME（避免触碰真实 ~/.ssh）
OUT="$D/other"           # 其他目录（只读）
mkdir -p "$WS" "$TMP" "$HOME_T/.ssh" "$OUT"

printf 'TOP-SECRET' > "$HOME_T/.ssh/id_rsa"
printf 'outside-original' > "$OUT/outside.txt"
printf 'existing' > "$WS/case.txt"

# 策略：工作目录 + tmp 可写；其他只读；deny 模式；仅回环
P="$D/policy.json"
printf '{"task":"ssh-policy-test","filesystem":{"write":["%s","%s"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"deny"},"network":{"loopback":true,"internet":false},"broker":{"audit_log":"%s/audit.jsonl"}}' \
  "$WS" "$TMP" "$D" > "$P"

LOG="$D/test.log"
fail=0
pass() { printf '  PASS  %s\n' "$1" | tee -a "$LOG"; }
bad()  { printf '  FAIL  %s\n' "$1" | tee -a "$LOG"; fail=$((fail+1)); }
note() { printf '  NOTE  %s\n' "$1" | tee -a "$LOG"; }
hr()   { printf '\n===== %s =====\n' "$1" | tee -a "$LOG"; }

echo "临时目录: $D"
echo "日志文件: $LOG"

hr "0. 策略校验"
"$BIN" policy-check -p "$P" 2>&1 | tee -a "$LOG"
if [[ ${PIPESTATUS[0]} -eq 0 ]]; then pass "策略合法"; else bad "策略合法"; fi

# 沙箱调用统一封装：注入临时 HOME / TMPDIR，使 Seatbelt 的 .ssh deny 规则指向临时目录
run_sandbox() {
  HOME="$HOME_T" TMPDIR="$TMP" "$BIN" run -p "$P" -- "$@"
}

hr "1. 工作目录写新增 case.txt，写入 case1"
# 先删掉预置文件，验证「新增」
rm -f "$WS/case.txt"
OUT1=$(run_sandbox /bin/sh -c "echo case1 > '$WS/case.txt' && cat '$WS/case.txt'" 2>&1)
RC1=$?
echo "沙箱输出: $OUT1" | tee -a "$LOG"
if [[ $RC1 -eq 0 && "$OUT1" == "case1" && "$(cat "$WS/case.txt" 2>/dev/null)" == "case1" ]]; then
  pass "工作目录新增并写入 case1"
else
  bad "工作目录新增并写入 case1"
fi

hr "2. 修改 case.txt 为 case2，然后读取"
OUT2=$(run_sandbox /bin/sh -c "echo case2 > '$WS/case.txt'; cat '$WS/case.txt'" 2>&1)
RC2=$?
echo "沙箱输出: $OUT2" | tee -a "$LOG"
if [[ $RC2 -eq 0 && "$OUT2" == "case2" && "$(cat "$WS/case.txt" 2>/dev/null)" == "case2" ]]; then
  pass "工作目录修改并读回 case2"
else
  bad "工作目录修改并读回 case2"
fi

hr "3. 查看 .ssh 下的文件（SSH 默认策略的敏感目录）"
OUT3=$(run_sandbox /bin/sh -c "ls -la '$HOME_T/.ssh' 2>&1; cat '$HOME_T/.ssh/id_rsa' 2>&1; echo HACK > '$HOME_T/.ssh/id_rsa' 2>&1" 2>&1)
echo "沙箱输出:" | tee -a "$LOG"
echo "$OUT3" | tee -a "$LOG"
if echo "$OUT3" | grep -q 'Operation not permitted' \
   && [[ "$(cat "$HOME_T/.ssh/id_rsa")" == "TOP-SECRET" ]]; then
  pass ".ssh 目录列举/读取/写入均被内核拒绝（EPERM），宿主文件未被改动"
else
  bad ".ssh 敏感目录保护"
fi
note "期望描述「可见、读为空、写为空」与当前实现不同：当前是 EPERM 完全拒绝"
note "理由：Seatbelt profile 用 (deny file-read* (subpath \"\$HOME/.ssh\")) + (deny default) 写"

hr "4. 访问 www.baidu.com（默认仅回环，外网应被拒）"
OUT4=$(run_sandbox /usr/bin/nc -z -G 2 www.baidu.com 443 2>&1)
RC4=$?
echo "沙箱输出: $OUT4 (exit=$RC4)" | tee -a "$LOG"
if [[ $RC4 -ne 0 ]]; then
  pass "外网 www.baidu.com 被拒绝"
else
  bad "外网 www.baidu.com 被拒绝"
fi
# 对照：回环应放行（用 burn loopback 自起 listener 自连；不要连没人监听的端口）
OUT4B=$(run_sandbox "$BURN" loopback 2>&1)
RC4B=$?
echo "回环对照: $OUT4B (exit=$RC4B)" | tee -a "$LOG"
if [[ $RC4B -eq 0 ]]; then pass "回环放行（burn loopback 自连）"; else bad "回环放行（burn loopback 自连）(rc=$RC4B)"; fi

hr "5. 脚本内对非工作空间目录与工作目录分别读写"
OPS="$WS/ops.sh"
cat > "$OPS" <<EOF
#!/bin/sh
echo "WS_READ=\$(cat '$WS/case.txt' 2>&1)"
echo "case3" > '$WS/from_script.txt' && echo "WS_WRITE=ok" || echo "WS_WRITE=denied"
echo "OTHER_READ=\$(cat '$OUT/outside.txt' 2>&1)"
echo "hacked" > '$OUT/outside.txt' 2>/dev/null && echo "OTHER_WRITE=ok" || echo "OTHER_WRITE=denied"
echo "TMP_WRITE=\$(echo tmpdata > '$TMP/tmp.txt' && echo ok || echo denied)"
EOF
chmod +x "$OPS"
OUT5=$(run_sandbox /bin/sh "$OPS" 2>&1)
RC5=$?
echo "沙箱输出:" | tee -a "$LOG"
echo "$OUT5" | tee -a "$LOG"
# 断言：工作目录读写成功；其他目录读成功但写被拒；tmp 写成功
if echo "$OUT5" | grep -q 'WS_READ=case2' \
   && echo "$OUT5" | grep -q 'WS_WRITE=ok' \
   && echo "$OUT5" | grep -q 'OTHER_READ=outside-original' \
   && echo "$OUT5" | grep -q 'OTHER_WRITE=denied' \
   && echo "$OUT5" | grep -q 'TMP_WRITE=ok' \
   && [[ "$(cat "$OUT/outside.txt")" == "outside-original" ]]; then
  pass "脚本内:工作目录可读写、其他目录只读、tmp 可写"
else
  bad "脚本内:工作目录可读写、其他目录只读、tmp 可写"
fi

hr "6. 失败 → 授权 → 成功访问（B 契约闭环）"
if [[ "${AISBX_SKIP_AUTH_CASE:-0}" == "1" ]]; then
  note "已按 AISBX_SKIP_AUTH_CASE=1 跳过：该环境不要求提供运行时审批能力"
else
  # 独立策略:prompt 模式(无 TTY → 交宿主授权闭环)
  P2="$D/policy-auth.json"
  printf '{"task":"ssh-auth-%s","filesystem":{"write":["%s","%s"],"read":[],"deny_escalation":[],"allow_escalation":[],"escalation":"prompt"},"network":{"loopback":true,"internet":false},"broker":{"audit_log":"%s/audit-auth.jsonl"}}' \
    "$(date +%s)" "$WS" "$TMP" "$D" > "$P2"
  TARGET="$OUT/after-auth.txt"
  rm -f "$TARGET"

  # 目标在只读目录 OUT 中 → 第一次写必然失败,程序主动 escalate 请求授权
  # ⚠️ TMPDIR 必须与 run 一致,否则 status/authorize 连不上 broker 的 ctl.sock
  HOME="$HOME_T" TMPDIR="$TMP" "$BIN" run -p "$P2" --json -- \
    "$BURN" retryflow "$TARGET" grant > "$D/auth-run.out" 2>&1 &
  RUN_PID=$!
  sleep 2

  EVID_FAIL=$(grep -E 'first_write=denied|"granted":false' "$D/auth-run.out" 2>/dev/null | head -2 | tr '\n' ' ')
  echo "阶段1 失败: ${EVID_FAIL}" | tee -a "$LOG"

  ST2=$(HOME="$HOME_T" TMPDIR="$TMP" "$BIN" status -p "$P2" 2>&1)
  echo "阶段2 待授权: $(printf '%s' "$ST2" | head -c 220)" | tee -a "$LOG"
  AUTH2=$(HOME="$HOME_T" TMPDIR="$TMP" "$BIN" authorize -p "$P2" --path "$OUT" --access write --ttl-seconds 120 2>&1)
  echo "阶段2 授权: $(printf '%s' "$AUTH2" | head -c 220)" | tee -a "$LOG"

  wait "$RUN_PID" 2>/dev/null
  RC6=$?

  EVID_OK=$(grep -E '"event":"retry"|wrote=ok|"attempt":2' "$D/auth-run.out" 2>/dev/null | head -4 | tr '\n' ' ')
  echo "阶段3 成功: ${EVID_OK}" | tee -a "$LOG"
  echo "阶段3 目标内容: $(cat "$TARGET" 2>/dev/null)" | tee -a "$LOG"

  if printf '%s' "$EVID_FAIL" | grep -q 'first_write=denied' \
     && printf '%s' "$ST2" | grep -q '"needs_approval":true' \
     && printf '%s' "$AUTH2" | grep -q '"token"' \
     && printf '%s' "$EVID_OK" | grep -q '"event":"retry"' \
     && printf '%s' "$EVID_OK" | grep -q 'wrote=ok' \
     && [[ -f "$TARGET" ]] && [[ "$(cat "$TARGET" 2>/dev/null)" == "x" ]]; then
    pass "失败→授权→成功访问（只读目录内文件，授权后写入并读回成功）"
  else
    bad "失败→授权→成功访问闭环（rc=${RC6}，日志 ${D}/auth-run.out）"
  fi
  note "此案例依赖运行时审批闭环；不支持的环境设 AISBX_SKIP_AUTH_CASE=1 跳过（不计 FAIL）"
fi

# ── 汇总 ─────────────────────────────────────────────────────────────────
hr "汇总"
echo "PASS=$(grep -c '  PASS  ' "$LOG")" | tee -a "$LOG"
echo "FAIL=$fail" | tee -a "$LOG"
echo "SMOKE_DONE fail=$fail" | tee -a "$LOG"
if [[ $fail -eq 0 ]]; then
  echo "SSH 默认策略验证全部通过"
else
  echo "SSH 默认策略验证失败 $fail 项（日志: ${LOG}）"
fi
echo "临时目录（用完 rm -rf ${D}）: $D"
exit "$fail"
