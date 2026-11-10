#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨平台契约检查:三平台**共用同一份**脚本与基线。

要保证的是「三个环境的表现形式与交互一样」——agent 是通过能力报告、
`--json` 事件流、审计记录、退出码这四样跟沙箱交互的,它们在三个平台上
必须长得一样(值可以不同,结构不能不同)。

本脚本检查:
  1. 能力报告:顶层结构、键集合(严格相等)、值域、平台期望;
  2. `--json` 事件流:事件名必须在允许集合内,平台无关事件必须齐;
  3. 审计记录:事件类型必须在允许集合内;
  4. 退出码:语义取值在约定集合内。

用法:
  python3 scripts/contract_check.py --caps caps.json --baseline scripts/contract-baseline.json \\
      --platform linux [--events events.jsonl] [--audit audit.jsonl] [--exit-code 0]
"""
import argparse
import json
import os
import sys

FAILURES = []
CHECKS = 0
REPORT_OUT = ""


REPORT = []


def check(name, ok, detail=""):
    global CHECKS
    CHECKS += 1
    line = "  %s  [契约] %s%s" % (
        "PASS" if ok else "FAIL",
        name,
        (" — " + detail) if detail else "",
    )
    REPORT.append(line)
    print(line)
    if not ok:
        FAILURES.append(name)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path):
    """逐行读 JSONL;坏行不算失败(那是日志噪声),但要能看出事件名。"""
    out = []
    if not path or not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def event_names(records):
    names = set()
    for r in records:
        e = r.get("event")
        if isinstance(e, str):
            names.add(e)
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--caps", required=True, help="能力报告 JSON")
    ap.add_argument("--baseline", required=True, help="契约基线 JSON")
    ap.add_argument("--platform", required=True, help="平台名(macos/linux/windows)")
    ap.add_argument("--events", default="", help="--json 事件流 JSONL")
    ap.add_argument("--audit", default="", help="审计 JSONL")
    ap.add_argument("--exit-code", type=int, default=None, help="被测命令的退出码")
    ap.add_argument("--out", default="", help="把报告另存到该文件(便于随 CI 结果回写)")
    args = ap.parse_args()
    global REPORT_OUT
    REPORT_OUT = (args.out or "").strip()

    base = load_json(args.baseline)
    caps_doc = load_json(args.caps)

    # ── 1. 能力报告 ────────────────────────────────────────────────────
    print("== 能力报告 ==")
    for k in base["top_level_keys"]:
        check("顶层键 %s 存在" % k, k in caps_doc)
    check(
        "contract == %s" % base["contract"],
        caps_doc.get("contract") == base["contract"],
        "实际 %r" % caps_doc.get("contract"),
    )
    check(
        "effect == %s" % base["effect"],
        caps_doc.get("effect") == base["effect"],
        "实际 %r" % caps_doc.get("effect"),
    )

    caps = caps_doc.get("capabilities")
    check("capabilities 是对象", isinstance(caps, dict))
    if not isinstance(caps, dict):
        return finish()

    want_keys = sorted(base["capability_keys"])
    got_keys = sorted(caps.keys())
    missing = [k for k in want_keys if k not in got_keys]
    extra = [k for k in got_keys if k not in want_keys]
    check(
        "能力键集合与基线**完全一致**(三平台同一份契约)",
        not missing and not extra,
        ("缺 %s " % missing if missing else "")
        + ("多 %s" % extra if extra else "")
        + "(共 %d 个)" % len(got_keys),
    )

    bad_values = []
    for k in base["status_keys"]:
        v = caps.get(k)
        if v not in ("full", "partial", "unavailable"):
            bad_values.append("%s=%r" % (k, v))
    check(
        "状态类能力值域合法(full/partial/unavailable)",
        not bad_values,
        ", ".join(bad_values),
    )

    empty_described = []
    for k in base["described_keys"]:
        v = caps.get(k)
        # violation_log_probe 允许空串(=该平台没有内核日志通道)
        if v in (None, "") and not (k in base["empty_allowed_keys"] and v == ""):
            empty_described.append("%s=%r" % (k, v))
    check(
        "描述类能力非空(除允许空串者)",
        not empty_described,
        ", ".join(empty_described),
    )

    # 平台期望:某些能力在三平台上的**值**必须符合预期
    expect = base.get("platform_expect", {}).get(args.platform, {})
    for key, want in expect.items():
        got = caps.get(key)
        if want == "nonempty":
            ok = isinstance(got, str) and got != ""
        elif want == "empty":
            ok = got == ""
        else:
            ok = got == want
        check(
            "平台期望 %s=%s" % (key, want),
            ok,
            "实际 %r" % (got,),
        )

    # ── 2. --json 事件流 ────────────────────────────────────────────────
    if args.events:
        print("== --json 事件流 ==")
        evs = event_names(load_jsonl(args.events))
        allowed = set(base["event_names_allowed"])
        unknown = sorted(evs - allowed)
        check(
            "事件名都在允许集合内",
            not unknown,
            "越界: %s" % unknown if unknown else "(共 %d 种)" % len(evs),
        )
        required = set(base["event_names_required"])
        absent = sorted(required - evs)
        check(
            "平台无关事件齐备",
            not absent,
            "缺 %s" % absent if absent else "(%d 种)" % len(evs),
        )

    # ── 3. 审计记录 ────────────────────────────────────────────────────
    if args.audit:
        print("== 审计记录 ==")
        auds = event_names(load_jsonl(args.audit))
        allowed = set(base["audit_events_allowed"])
        unknown = sorted(auds - allowed)
        check(
            "审计事件类型都在允许集合内",
            not unknown,
            "越界: %s" % unknown if unknown else "(共 %d 种)" % len(auds),
        )

    # ── 4. 退出码语义 ──────────────────────────────────────────────────
    if args.exit_code is not None:
        print("== 退出码 ==")
        allowed = set(base["exit_codes_allowed"])
        check(
            "退出码取值在约定集合内",
            args.exit_code in allowed,
            "实际 %d,允许 %s" % (args.exit_code, sorted(allowed)),
        )

    return finish()


def finish():
    tail = []
    if FAILURES:
        tail.append("")
        tail.append("契约检查失败 %d 项:%s" % (len(FAILURES), "; ".join(FAILURES)))
        rc = 1
    else:
        tail.append("")
        tail.append("契约检查全部通过(%d 项)" % CHECKS)
        rc = 0
    for t in tail:
        print(t)
        REPORT.append(t)
    # 报告落盘路径:环境变量优先(Unix 侧用),其次 --out(Windows 侧用)。
    # ⚠️ --out 之前是个**死参数**:声明了却从不生效 → Windows 侧契约报告
    # 一直没生成,失败详情只能靠猜。
    out = os.environ.get("CONTRACT_REPORT_OUT", "").strip() or REPORT_OUT
    if out:
        # 报告落文件:Windows 上契约检查的输出继承控制台,Issue 只带 smoke.log →
        # 失败详情会丢。落进回写目录就能随结果一起被读到。
        try:
            os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                f.write("\n".join(REPORT) + "\n")
        except Exception as e:
            print("契约报告写文件失败: %s" % e)
    return rc


if __name__ == "__main__":
    sys.exit(main())
