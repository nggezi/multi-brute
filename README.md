# X-UI Brute

基于 Go + Python 的混合爆破工具，支持 8 种面板/SSH 爆破，CIDR 网段展开，Telegram 通知。

## 目录结构

```
x-ui/
├── main.py                  # 唯一入口
├── config.yaml              # 用户配置（改这里，保存即生效）
├── .gitignore
├── README.md
├── src/
│   ├── config.py            # 读取 config.yaml + 环境变量
│   ├── cli.py               # 命令行入口
│   ├── models.py            # 面板模式数据模型
│   ├── environment.py       # 环境检测 & 自动安装依赖
│   ├── generators.py        # Go 代码生成
│   ├── runner.py            # 分片 → 执行 → 合并
│   ├── normalizer.py        # CIDR 展开 + URL 归一化
│   ├── ip_query.py          # IP 地理查询 → Excel
│   └── telegram.py          # Telegram 通知
└── templates/               # Go 模板
    ├── common.go.tmpl       # 公共函数（所有模式共享）
    ├── runner_common.go.tmpl # 通用 runner（模式 1~5, 8）
    ├── runner_ssh.go.tmpl   # SSH runner（模式 6）
    ├── runner_substore.go.tmpl # Sub Store runner（模式 7）
    └── handler_mode*.go.tmpl # 各模式差异 handler
```

## 快速开始

### 1. 配置

编辑 `config.yaml`，最少设两项：

```yaml
XUI_MODE: 1          # 1=XUI 2=哪吒 3=HUI 4=咸蛋 5=SUI 6=SSH 7=SubStore 8=OpenWrt
XUI_INPUT_FILE: "ips.txt"
XUI_THREADS: 500
```

### 2. 准备目标文件

```
# ips.txt — 支持多种格式混写
192.168.1.1:443                # IP:Port
10.0.0.1                       # 无端口自动补 :443
10.0.0.0/30:8080               # CIDR 自动展开为 4 个
172.16.0.0/24                  # /24 展开 256 个
https://1.2.3.4:8443/login     # URL 格式，路径不丢
# 注释行会被跳过
```

### 3. 运行

```bash
python main.py
```

## 三种使用方式

### 方式一：config.yaml（推荐）

```bash
# 编辑 config.yaml 改好参数
vim config.yaml

# 直接跑，零交互
python main.py
```

### 方式二：环境变量（临时覆盖）

```bash
# 覆盖 config.yaml 中的值，适合临时调整
XUI_THREADS=1000 python main.py

# 敏感信息不写 yaml，用环境变量
TG_BOT_TOKEN=xxx TG_CHAT_ID=yyy python main.py
```

优先级：**环境变量 > config.yaml > 代码默认值**

### 方式三：命令行参数（一次性）

```bash
python main.py -m 1 -i ips.txt -t 500 -b 2000

# SSH 爆破 + 后门
python main.py -m 6 -i ssh.txt --backdoor
```

| 参数 | 简写 | 说明 |
|------|------|------|
| `--mode 1~8` | `-m` | 爆破模式 |
| `--input` | `-i` | 目标文件路径 |
| `--threads` | `-t` | 并发协程数 |
| `--batch` | `-b` | 每批数量 |
| `--lines` | `-L` | 分片行数 |
| `--sleep` | `-s` | 批次间冷却秒数 |
| `--username-file` | `-U` | 用户名字典 |
| `--password-file` | `-P` | 密码字典 |
| `--backdoor` | | SSH 后门（仅模式6） |
| `--no-excel` | | 跳过 Excel 生成 |

## 爆破模式

| -m | 名称 | 接口 | 默认凭据 |
|----|------|------|----------|
| 1 | XUI 面板 | POST /login (form) | admin / admin |
| 2 | 哪吒面板 | POST /api/v1/login (json) | admin / admin |
| 3 | HUI 面板 | POST /hui/auth/login | sysadmin / sysadmin |
| 4 | 咸蛋面板 | POST /login (json) | admin / admin |
| 5 | SUI 面板 | POST /app/api/login | admin / admin |
| 6 | SSH | SSH 直连 + 蜜罐检测 + 后门 | root / password |
| 7 | Sub Store | GET 路径探测 | 内置 key |
| 8 | OpenWrt | POST /cgi-bin/luci/ | root / password |

## 工作流程

```
config.yaml / 环境变量 / 命令行参数
        │
        ▼
  环境检测（自动安装 curl/pip3/Go/依赖）
        │
        ▼
  输入归一化（CIDR 展开 + URL 提取）
        │
        ▼
  生成 Go 爆破代码 → 分片 → go run 并发爆破
        │
        ▼
  合并结果 → IP 地理查询 → 生成 Excel
        │
        ▼
  Telegram 通知 → 清理临时文件
```

## 输出产物

```
XUI-20260718-2230.txt      # IP:Port 用户名 密码
XUI-20260718-2230.xlsx     # 含国家/城市/ISP 列
```

SSH 模式额外：
```
后门安装成功-20260718-2230.txt
后门安装失败-20260718-2230.txt
```

## 配置参考

详见 `config.yaml`，所有可配置项：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `XUI_MODE` | 0 (交互) | 爆破模式 1~8 |
| `XUI_INPUT_FILE` | 1.txt | 目标文件路径 |
| `XUI_THREADS` | 250 | 并发协程数 |
| `XUI_BATCH_SIZE` | 1000 | 每批处理数量 |
| `XUI_LINES_PER_FILE` | 5000 | 分片行数 |
| `XUI_SLEEP_SECONDS` | 2 | 批次间冷却 |
| `XUI_USERNAME_FILE` | — | 自定义用户字典 |
| `XUI_PASSWORD_FILE` | — | 自定义密码字典 |
| `XUI_BACKDOOR` | false | SSH 后门开关 |
| `XUI_BACKDOOR_CMD_FILE` | 后门命令.txt | 后门命令文件 |
| `XUI_NO_EXCEL` | false | 跳过 Excel |
| `TG_BOT_TOKEN` | — | Telegram Bot Token |
| `TG_CHAT_ID` | — | Telegram Chat ID |
| `GOPROXY` | 自动检测 | Go 代理地址 |
| `GOSUMDB` | 自动检测 | Go 校验数据库 |

## 环境要求

- Python 3.7+
- Linux（Windows 跳过环境检测，需自行安装 Go）
- SSH 模式额外需要 `golang.org/x/crypto/ssh`（自动安装）

## 添加新面板

1. 在 `templates/` 下创建 `handler_mode9.go.tmpl`（写 `postRequest` + `processIP`）
2. 在 `src/config.py` 的 `PANEL_MODES`、`DEFAULT_CREDENTIALS`、`OUTPUT_PREFIX` 各加一行
3. 在 `src/cli.py` 的 `build_parser()` 里把 `choices=range(1, 9)` 改成 `range(1, 10)`
