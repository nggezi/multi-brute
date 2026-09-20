#!/bin/bash
# 项目根目录运行
cd /root/scan || exit 1
python3 src/bgp.py
python3 main.py
