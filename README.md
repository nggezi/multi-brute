# multi-brute · 内部授权安全审计工具

面向**自有/内部授权资产**的批量服务指纹识别与弱口令审计工具。  
对外部未授权目标使用属于违法行为，本项目仅供授权范围内使用。

核心流程由 Python 调度层（`src/xui.py`）+ 统一 Go 引擎（`src/engine.go`）组成：

```
目标列表 ──► masscan 端口扫描 ──► 指纹验证 ──► 统一引擎精准审计 ──► results/
```

## 功能特性

- **16 种审计模式**：X-UI、哪吒、H-UI、咸蛋、S-UI、SSH、Sub Store、OpenWrt/iStoreOS、AI Key 池、Alist、MiSub 登录/指纹、代理海选、全服务扫描、通用 Web 指纹。
- **统一引擎**：所有模式共用同一个 Go 引擎，按模式配置自动路由到 HTTP / SSH / TCP 审计逻辑，不再维护 13 份模板。
- **三阶段流水线**：masscan 端口扫描 → 指纹验证 → 精准审计，全程自动执行。
- **三态指纹探测**：`True` 匹配 / `False` 响应但不匹配 / `None` 超时失败，失败目标自动进入重试轮。
- **韧性设计**：
  - 指纹命中/已探测记录**增量落盘**（`work/fingerprint_hits.txt` / `work/fingerprint_done.txt`），支持断点续扫。
  - 审查结果**实时写入** `results/`，中断时抢救已产出结果。
  - 中断后可选择续扫（per-`(ip, port)` 粒度去重）。
- **实时可见**：审计阶段实时打印命中行 + 进度计数，结果同步落盘。
- **可调参数**：`config/settings.json` 集中管理超时、并发、速率等。

## 目录结构

```
scan/
├── main.py                  # 入口：切到项目根目录后执行 src/xui.py
├── yj.sh                    # 快捷脚本：bgp.py + main.py
├── prefixes.txt             # 目标列表（CIDR / 范围 / 单IP / IP:端口，每行一个）
├── username.txt             # 用户名字典
├── password.txt             # 密码字典
├── guide.md                 # 速查备注
├── src/
│   ├── xui.py               # Python 调度层（UI / masscan / 指纹 / 流水线 / 实时 tail）
│   ├── engine.go            # 统一 Go 引擎（HTTP / SSH / TCP 审计）
│   ├── bgp.py               # BGP 辅助脚本
│   ├── go.mod
│   └── go.sum
├── config/
│   ├── mode_01_xui.json     # 各模式端口 + 指纹规则
│   ├── ...
│   ├── mode_15_webfp.json
│   ├── web_keywords.json    # 未知端口通用 Web 指纹关键词表
│   └── settings.json        # 可调参数
├── work/                    # 中间/临时文件（引擎输入输出、进度文件、日志）
│   ├── outputs/
│   └── logs/
└── results/                 # 最终审计结果
```

## 模式一览

| 模式 | 名称 | 默认端口 |
|------|------|----------|
| 1 | X-UI 面板审查 | 2053, 54321 |
| 2 | 哪吒面板审查 | 8008 |
| 3 | H-UI 面板审查 | 8081 |
| 4 | 咸蛋面板审查 | 需输入 |
| 5 | S-UI 面板审查 | 2095 |
| 6 | SSH 审查 | 22 |
| 7 | Sub Store 审查 | 3000, 3001 |
| 8 | OpenWrt/iStoreOS | 80, 8443 |
| 9 | AI Key 池审查 | 需输入 |
| 10 | Alist 审查 | 5244 |
| 11 | MiSub 登录审查 | 25556 |
| 12 | MiSub 指纹海选 | 25556 |
| 13 | Socks5/HTTP 代理 | 需指定 |
| 14 | 全服务扫描 | 18 端口（含 SSH 22、80/443/8080/8443） |
| 15 | 通用 Web 指纹海选 | 80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000 |
| 16 | 全服务扫描（不含 SSH，推荐） | 13 端口（去掉 22/80/443/8080/8443） |

> 带端口的输入行（如 `1.2.3.4:8000`）会跳过指纹验证，直接按该服务逻辑审查；CIDR / 单 IP 走 masscan + 指纹验证。模式 14/16 由代码合成，无独立配置文件。

## 环境依赖

- Python 3 + `requests`、`openpyxl`
- Go 1.22+（引擎会在首次运行时自动 `go build`）
- masscan
- Linux（VPS / Kali）；Go 编译验证必须在目标机进行

## 使用方法

```bash
# 快捷方式（根目录）
./yj.sh

# 或直接运行
python3 main.py
```

交互流程（以模式 16 为例）：

1. 选择模式（1-16，默认 16）
2. 选择输入方式（1 = 手动输入 IP 范围，2 = 从文件读取，默认 2）
3. 输入文件路径（默认 `prefixes.txt`）
4. 选择字典来源（1 = 本地文件，2 = Kali 系统字典，3 = 默认凭证）

非交互（脚本化）示例：

```bash
printf '16\n2\n\n2\n' | python3 main.py
```

> 若 `work/` 下已有指纹进度文件，启动时会额外提示「是否续扫？(Y/n)」，需在 stdin 中额外补一行。

## 可调参数（config/settings.json）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `fingerprint_timeout` | 1.5 | 指纹探测单次超时（秒） |
| `fingerprint_retry_timeout` | 3.0 | 重试轮的超时（秒） |
| `fingerprint_workers` | 32 | 指纹并发 |
| `fingerprint_batch_size` | 2000 | 指纹分批提交大小 |
| `engine_workers` | 50 | 引擎并发（Go 端） |
| `mode_workers` | 4 | 审查阶段同时跑几种服务 |
| `masscan_rate` | 10000 | masscan 发包速率 |
| `masscan_wait` | 3 | masscan `--wait` |
| `masscan_timeout` | 600 | masscan 进程超时（秒） |
| `http_timeout` | 2 | 引擎 HTTP 请求超时（秒） |

## 输出

- 最终结果位于 `results/`，每个模式一份 `<模式名>-<时间戳>.txt`。
- 中间文件与进度位于 `work/`（`fingerprint_hits.txt` / `fingerprint_done.txt` / `fingerprint_retry.txt` 等）。

## 免责声明

本项目仅限**公司内部或已获书面授权的资产**安全审计使用。使用者须确保目标在授权范围内，任何未授权的使用行为由使用者自行承担全部法律责任。
