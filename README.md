# aisbx — agent 本地沙箱(Windows)

把 agent 的命令执行关进 **AppContainer(LowBox token)+ Job Object**,越界访问通过**授权 broker** 走用户授权。单一静态二进制,Rust 编写,无需管理员。

```text
aisbx run -p task.policy.json -- cmd /c build.bat    # 沙箱内执行
aisbx escalate -p task.policy.json --path C:\x --access write [--token <tok>]   # 沙箱内提权
aisbx authorize -p task.policy.json --path C:\x --access write   # 宿主侧签发一次性授权 token
aisbx policy-check -p task.policy.json
```

- 文件:默认拒绝,白名单(write/read),越界可经用户授权精确放行
- 资源:单进程/全任务内存、CPU 硬上限、进程数、KILL_ON_JOB_CLOSE、UI 限制
- 网络:默认仅回环;外网零 capability 内核级拒绝
- 子进程全自动继承(bash→gcc→curl 同一沙箱)

## 构建

```bash
# Windows 上(host 工具链)
cargo build --release

# macOS/Linux 交叉类型检查
rustup target add x86_64-pc-windows-gnu
cargo check --target x86_64-pc-windows-gnu
```

## 文档

- [docs/01-调研报告.md](docs/01-调研报告.md) — 同类产品调研(landstrip / Codex / Maka)与差距分析
- [docs/02-设计与实现.md](docs/02-设计与实现.md) — 架构、机制映射、agent 接入方式、路线图
- [docs/03-场景使用指南.md](docs/03-场景使用指南.md) — 文件/网络越界识别与授权回传、资源超限可观测性、agent 集成示例
- [examples/policy.example.json](examples/policy.example.json) — 策略契约示例

## 验证(Windows)

```powershell
# 管理员 PowerShell(回环例外写入需管理员;GitHub Actions runner 天然满足)
.\scripts\smoke.ps1              # 18 项断言:默认隔离/token 闭环/资源限制/网络/审计
.\scripts\smoke.ps1 -SkipNetwork # 无外网环境
```

三条验证路径,按推荐排序:

| 路径 | 前置成本 | 说明 |
|---|---|---|
| **GitHub Actions `windows-latest`** | 零本地磁盘 | `git init && git push` 后,workflow 一行 `powershell .\scripts\smoke.ps1`;runner 是管理员且预装 Rust |
| 本地 VM(UTM / VMware Fusion,Apple Silicon 用 Win11 ARM64) | ~25GB 磁盘 + 8GB RAM | M1 8GB 可跑但需先清磁盘;ARM64 上 x64 模拟运行冒烟脚本同样有效 |
| 云 Windows VM(Server 2022 按量付费) | 费用 | 适合长周期回归 |

## 状态

v0.1:Windows 目标 `cargo check` 通过;**尚未在真实 Windows 上回归**(冒烟脚本已就绪,见上)。
