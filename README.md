# aisbx — agent 本地沙箱（Windows / Linux / macOS）

把 agent 的命令执行关进 OS 级沙箱，越界访问通过 **策略配置 → 拒绝感知 → 用户授权 → 重新执行**
的闭环处理（契约 B，见 `docs/04` §10）。单一二进制、Rust 实现、无需管理员。

```text
aisbx run -p task.policy.json -- <命令> [参数...]          # 沙箱内执行(授权后自动重跑)
aisbx escalate -p task.policy.json --path X --access write  # 沙箱内上报越界
aisbx escalate --op net --host H --ip I --port P            # 网络越界上报(Unix)
aisbx authorize -p task.policy.json --path X --access write # 宿主侧签发一次性 token
aisbx capabilities                                         # 能力报告 full/partial/unavailable
aisbx policy-check -p task.policy.json
```

| 能力 | Windows | Linux | macOS |
|---|---|---|---|
| 文件默认拒绝 + 白名单 | AppContainer ACL | bubblewrap 只读根 + bind | Seatbelt SBPL |
| 网络默认仅回环 | capability + 回环例外 | 独立 netns | SBPL 仅 localhost |
| 拒绝感知 / 授权后重执行 | ✅（in-place 保留为 legacy 加速路径） | ✅ | ✅ |
| launcher 重跑闭环 | ✅ `full` | ✅ `full` | ✅ `full` |
| 文件越界路径自动采集 | `partial`（stderr 自报路径） | `partial`（stderr 自报路径） | `partial`（内核日志，精确路径 + 两级归属） |
| 越界路径精度标注 | `file=reported` / `net=exact` | `file=reported` / `net=exact` | `file=exact` / `net=exact` |
| 资源预算 | Job（内存/CPU/进程数） | `RLIMIT_AS` 软限制 | 无等价机制（如实上报） |
| broker 通道 | 命名管道 | UDS | UDS |

三平台能力差异由 `capabilities --json` 逐项如实标注；`--require-full` 在关键能力不可用时拒绝启动。
完整能力矩阵、风险登记与实测踩坑见 `docs/04` §10。

## 构建

```bash
cargo build --release                       # 当前平台
cargo check --target x86_64-pc-windows-gnu --all-targets
cargo check --target x86_64-unknown-linux-gnu --all-targets
```

依赖按 target 分区（`Cargo.toml` 的 `[target.'cfg(...)'.dependencies]`）：Windows 用 `windows-sys`，
Unix 用 `libc`。Linux 运行需要 `bubblewrap`（Ubuntu：`apt-get install bubblewrap iproute2`）；
macOS 使用系统 `/usr/bin/sandbox-exec`。

## 验证

```bash
# Linux / macOS:B 契约冒烟(策略/拒绝感知/授权重执行/token 一次性/网络/审计/能力报告)
bash scripts/smoke-unix.sh

# Windows:46 项断言(管理员 PowerShell;GitHub Actions runner 天然满足)
.\scripts\smoke.ps1
```

CI：`.github/workflows/windows-smoke.yml`（Windows 18 项）与
`.github/workflows/cross-platform.yml`（ubuntu/macos B 契约冒烟 + Windows 编译检查）。
失败时工作流会把完整日志自动发布为 Issue，便于无鉴权诊断。

## 文档

- [docs/01-调研报告.md](docs/01-调研报告.md) — 同类产品调研与差距分析
- [docs/02-设计与实现.md](docs/02-设计与实现.md) — Windows v0.1 架构与机制映射
- [docs/03-场景使用指南.md](docs/03-场景使用指南.md) — 越界识别、授权回传、资源可观测性
- [docs/04-跨平台实现方案.md](docs/04-跨平台实现方案.md) — 跨平台方案（v1.2：方案 B 已实施）
- [docs/05-竞品沙箱实现调研.md](docs/05-竞品沙箱实现调研.md) — Claude Code / Codex / dsh 调研
- [docs/06-P0P1实施记录.md](docs/06-P0P1实施记录.md) — 网络强制代理 + macOS 内核违规日志采集
- [docs/08-运行时感知通道调研.md](docs/08-运行时感知通道调研.md) — 五层感知通道模型、竞品机制重读、归属精度改造（P0）
- [examples/policy.example.json](examples/policy.example.json) — 策略契约示例

## agent 集成

```bash
aisbx run -p task.policy.json --json -- <命令>        # 后台启动沙箱执行
aisbx status -p task.policy.json                     # 查待授权项(具体路径 + 精度标注)
aisbx authorize -p task.policy.json --path X --access write   # 用户同意后签发
# run 检测到授权 → 自动以更宽的策略快照重跑(≤3 轮)
```

`aisbx status` 在三平台返回**同一套字段**,其中 `pending[]` 给出可直接呈现给用户的
具体越界项,并带两个正交标注:`precision`(`exact`=内核/协议自带,`reported`=程序自称)
与 `attributed`(能否证明来自本次执行;为 false 时多半是同机其它进程,不应据此授权)。

## 状态

v0.5：三平台后端与 B 契约闭环已落地，主线统一为「**感知 → 授权 → 重跑**」：

- **感知**：macOS 用内核 Seatbelt violation 日志（**精确路径** + 「已知 PID 集合 /
  进程组反查」两级归属判定）；Linux / Windows 用 **stderr 自报路径**（归属确定，
  精度 `reported`——路径由程序自称，可被伪造）。
- **授权**：只有「需要用户授权」的拒绝才等待（上限 20s）；黑名单/策略拒绝直接退出。
- **重跑**：授权到达 → 把该路径并入本次任务的策略快照 → 重跑（≤3 轮）。
  Windows 侧原先 `launcher_retry: unavailable`（授权后 agent 重跑仍被拒 → 死循环），
  本轮补齐，`effect` 由 `in-place(legacy)+agent-retry` 改为 `retry`。

授权落地也收紧了粒度:用户批准「创建文件 X」时,Windows 侧只对父目录授
`(AD)`(仅可新建),不再授 Modify——否则授权范围会悄悄扩大到「改/删该目录下所有文件」。

两条感知通道都遵守「**未能归属 ≠ 是本次越界**」：未归属条目只进审计、不驱动授权，
也不能被用来申请授权。

本机 macOS 冒烟 **58 PASS / 0 FAIL / 4 WARN**（T0–T15；4 WARN 为平台不具备/不适用的能力）。
Windows 的 T11–T13 由 GitHub Actions windows-smoke 验证（本机无 Windows 内核，
**只做了交叉编译、未本地真机执行**）。已知边界（按域运行时放行、macOS 资源硬限制、
Linux 内核侧精确路径、Windows 精确路径采集需 minifilter）均如实登记在能力报告中，
未静默降级。
