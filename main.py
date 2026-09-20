#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""项目入口：切换到项目根目录后执行 src/xui.py。"""
import os
import runpy

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)

runpy.run_path(os.path.join(ROOT, "src", "xui.py"), run_name="__main__")
