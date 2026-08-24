# About

**multi-brute** 是一个基于 Python + Go 的混合凭据安全测试工具，用于对常见面板与 SSH 服务进行批量登录检测，帮助安全审计人员快速发现弱口令目标。

## 核心特性

- 支持 8 种目标的爆破/探测：XUI、哪吒、HUI、咸蛋、SUI、SSH、Sub Store、OpenWrt/iStoreOS
- CIDR 网段自动展开（保留 URL 路径），输入格式灵活混写
- Python 生成 Go 代码 + 分片并发执行，高并发且内存可控
- SSH 模式内置蜜罐检测、超时保护与卡死自动重试
- 结果自动做 IP 地理定位（国家/地区/城市/ISP）并生成 Excel 报告
- 完成后可自动推送结果文件到 Telegram
- 配置三层覆盖：命令行参数 > 环境变量 > config.yaml，改配置即生效

## 架构

```
config.yaml / 环境变量 / CLI 参数
        │
        ▼
  环境检测与依赖安装（Linux 自动装 Go/curl/pip）
        │
        ▼
  输入归一化（CIDR 展开 + URL 提取）
        │
        ▼
  模板生成 Go 爆破代码 → 分片 → go run 并发执行
        │
        ▼
  合并结果 → IP 地理查询 → Excel → Telegram 通知
```

## 技术栈

- Python 3.7+：配置、输入归一化、代码生成、结果汇总
- Go 1.20+：并发爆破执行（模板动态生成，每次运行按需编译）
- openpyxl / requests：Excel 报告与 Telegram/IP 查询

## 快速开始

```bash
python main.py -m 1 -i ips.txt -t 500
```

详细用法、模式说明与配置项见 [README.md](README.md)。

## 免责声明

本工具仅用于授权范围内的安全测试与自研系统弱口令排查。请勿对未获得授权的系统使用；使用者需自行承担一切法律责任。
