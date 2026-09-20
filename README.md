# multi-brute

多服务面板 / 服务的**授权安全审查**工具。统一引擎（Go）+ 调度层（Python）架构，
每个模式都自动执行完整流水线：

```
masscan 端口扫描 → 指纹验证 → 统一引擎审查 → 结果导出
```

> 仅限**自有资产**或**获得书面授权**的目标使用。使用者需自行确保合规。

## 特性

- **15 种服务模式 + 2 种聚合模式**：每种服务内置默认端口与指纹规则，自动筛选真实目标，避免无效请求。
- **统一 Go 引擎**：所有模式共用一个编译后的引擎二进制，并发受控、写入加锁、支持断点续扫。
- **指纹前置**：masscan 发现开放端口后，先用 HTTP/TCP 指纹确认真实服务，再进入审查阶段。
- **韧性设计**：
  - 指纹结果**分批落盘**（每 2000 个目标 fsync 一次），中途被杀不丢已扫结果；
  - 审查阶段**每个服务完成即写** `results/`，不必等全部跑完；
  - 支持**断点续扫**（以 `(IP, 端口)` 为粒度），重启后可选择继续或全新扫描；
  - 中断（Ctrl+C / 异常）时自动把已完成的服务输出抢救到 `results/`。
- **字典来源**：本地字典 / Kali 系统字典 (`/usr/share/wordlists`) / 内置默认凭证。
- **多格式导出**：TXT / JSON / CSV。

## 目录结构

```
.
├── main.py                # 入口：切到项目根目录后执行 src/xui.py
├── yj.sh                  # 快捷脚本（可选，先跑 bgp.py 再跑 main.py）
├── guide.md
├── config/                # 每个模式一份配置（端口 + 指纹规则）
│   ├── mode_01_xui.json
│   ├── ...
│   ├── mode_15_webfp.json
│   └── web_keywords.json  # 未知端口通用 Web 指纹关键词表
├── src/
│   ├── xui.py             # 调度层：菜单、masscan、指纹、流水线、导出
│   ├── engine.go          # 统一 Go 引擎
│   ├── go.mod / go.sum
│   └── bgp.py             # 按 ASN 拉取 IPv4 前缀（写入 prefixes.txt）
├── results/               # 最终产物
└── work/                  # 运行时中间目录（自动清理，不提交）
```

## 环境要求

| 依赖 | 说明 |
|------|------|
| Python 3 | `requests`、`openpyxl` |
| Go 1.21+ | 运行时会自动编译 `engine.go` |
| masscan | 端口扫描，需手动安装：`sudo apt install masscan -y` |

`check_environment()` 会在启动时检测缺失项并按需安装（Go / pip / requests / openpyxl）。

## 使用

```bash
git clone https://github.com/nggezi/multi-brute.git
cd multi-brute
python3 main.py
```

按提示选择模式与目标输入方式。**所有模式默认走聚合流程。**

### 目标输入格式

`prefixes.txt`（每行一个，支持混合格式，`#` 开头为注释）：

```
192.168.1.1:443        # IP:端口（直通，不做 masscan）
10.0.0.1               # 单 IP
10.0.0.0/24            # CIDR（masscan 扫描默认端口）
10.0.0.1-10.0.0.50     # 范围
172.16.0.1 8080        # IP + 空格 + 端口
```

也可在运行时直接输入 IP 段，无需文件。

### 模式列表

| 模式 | 服务 | 默认端口 | 指纹 |
|------|------|----------|------|
| 1 | X-UI | 2053, 54321 | GET `/login` → 含 `x-ui` |
| 2 | 哪吒 (Nezha) | 8008 | POST `/api/v1/login` → `success==true` |
| 3 | H-UI | 8081 | POST `/hui/auth/login` → 含 `accessToken` |
| 4 | 咸蛋 (xdpanel) | 需输入 | POST `/login` → `data.token` |
| 5 | S-UI | 2095 | POST `/app/api/login` → `success==true` |
| 6 | SSH | 22 | TCP banner `SSH-` |
| 7 | Sub Store | 3000, 3001 | GET `/{path}/api/utils/env` 或 `/` |
| 8 | OpenWrt / iStoreOS | 80, 8443 | POST `/cgi-bin/luci/` → title |
| 9 | AI Key 池 | 需输入 | POST `/api/auth/login` → `success==true` |
| 10 | Alist | 5244 | GET `/api/me` → `code==200` |
| 11 | MiSub 登录 | 25556 | POST `/api/login` → `success==true` |
| 12 | MiSub 指纹 | 25556 | GET `/` → title `MiSub` |
| 13 | Socks5 / HTTP 代理 | 需指定 | TCP 连接 + 协议识别 |
| 14 | **全服务扫描** | 全部（含 SSH） | 逐端口匹配全部服务指纹 |
| 15 | 通用 Web 指纹海选 | 80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000 | title 关键词 |
| 16 | **全服务扫描（不含 SSH）** | 全部（去掉 22/80/443/8080/8443） | 同上（推荐） |

### 字典来源

1. **本地文件** — `username.txt` / `password.txt`（模式 7、9 固定用户名，只读 `password.txt`）
2. **Kali 系统字典** — `/usr/share/wordlists`
3. **默认凭证** — 内置各服务的常见弱口令组合

## 输出

最终结果写入 `results/{服务名}-{YYYYMMDD-HHMMSS}.txt`，可选 JSON / CSV。

中断时已完成但未汇总的输出会抢救为 `results/{服务名}-rescue-{时间戳}-p{pid}.txt`。

运行时中间文件全部在 `work/`，正常结束会自动清空。

## 断点续扫

指纹阶段以 `(IP, 端口)` 为粒度记录进度。若上次运行被中断，进度会保留；
下次启动时会询问：

```
发现上次未完成的指纹进度，是否续扫？(Y/n)：
```

- 回车 / `Y` → 只处理剩余目标
- `n` → 清空旧进度，全新扫描

## 开发

```bash
python -m py_compile src/xui.py     # 语法检查
go vet ./src/...                    # 引擎检查（可选）
```

## 免责声明

本项目仅供安全研究与**授权范围内**的资产审查使用。请勿用于未授权目标。
因使用本工具产生的一切后果由使用者自行承担。
