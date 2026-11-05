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
| 拒绝感知 / 授权后重执行 | 既有 in-place 实现保留 | ✅ | ✅ |
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

# Windows:既有 18 项断言(管理员 PowerShell;GitHub Actions runner 天然满足)
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
- [examples/policy.example.json](examples/policy.example.json) — 策略契约示例

## 状态

v0.2：三平台后端与 B 契约闭环已落地；Windows 18 项、Linux/macOS B 契约冒烟由 GitHub Actions 验证。
已知边界（内核被动拒绝自动采集、按域运行时放行、macOS 资源硬限制、Linux 原生 Landlock/cgroups）
均如实登记在能力报告中，未静默降级。
