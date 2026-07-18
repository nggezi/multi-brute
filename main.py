#!/usr/bin/env python3
"""X-UI 混合爆破工具 —— 入口文件.

直接运行:  python main.py
交互式运行:  python main.py
环境变量运行:  XUI_MODE=1 XUI_INPUT_FILE=ips.txt python main.py
"""

import sys
import os

# 确保项目根在 path 中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.cli import main

if __name__ == "__main__":
    main()
