"""环境检测与自动安装依赖（Linux 专用）.

检测网络环境（中国大陆/海外），自动安装 curl、pip3、Go、相关模块.
"""

import importlib.util
import os
import platform
import re
import shutil
import subprocess
import sys
from typing import List


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def check_china_network() -> bool:
    """通过 ping Google 判断是否在中国大陆网络."""
    system = platform.system()
    cmd = (
        ["ping", "-n", "1", "-w", "1000", "www.google.com"]
        if system == "Windows"
        else ["ping", "-c", "1", "-W", "1", "www.google.com"]
    )
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        ttl_match = re.search(r"ttl[=|=](\d+)", output)
        time_match = re.search(r"time[=|=]([\d.]+)", output)
        ttl = int(ttl_match.group(1)) if ttl_match else 0
        delay = float(time_match.group(1)) if time_match else 999
        return ttl <= 64 and delay < 20
    except Exception:
        return True


def setup_china_mirrors():
    """如果在中国大陆，切换到国内镜像源."""
    if not os.path.exists("/etc/apt/sources.list"):
        return
    with open("/etc/apt/sources.list", "r") as f:
        content = f.read()
    if "mirrors.aliyun.com" in content:
        print(">>> 已使用国内 apt 源，跳过源替换")
        return
    print(">>> 正在切换为阿里云 apt 源...")
    try:
        shutil.copy("/etc/apt/sources.list", "/etc/apt/sources.list.bak")
        with open("/etc/apt/sources.list", "w") as f:
            f.write(
                "deb http://mirrors.aliyun.com/debian stable main contrib non-free\n"
                "deb http://mirrors.aliyun.com/debian stable-updates main contrib non-free\n"
                "deb http://mirrors.aliyun.com/debian-security stable-security main contrib non-free\n"
            )
        subprocess.run(["apt", "update", "-y"], check=True)
        print("✅ 已成功切换为阿里 apt 源")
    except Exception as e:
        print(f"❌ 切换 apt 源失败: {e}")


def run_cmd(cmd: List[str], check: bool = True):
    """执行命令，静默输出."""
    try:
        subprocess.run(cmd, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        if check:
            raise e


def ensure_cmd_exists(cmd_name: str, install_cmd: List[str], apt_updated: bool) -> bool:
    """确保命令行工具存在，不存在则安装."""
    if shutil.which(cmd_name) is not None:
        print(f"✅ {cmd_name} 已存在，跳过安装")
        return apt_updated
    print(f"⚠️ {cmd_name} 未安装，准备通过 apt 安装...")
    try:
        if not apt_updated:
            run_cmd(["apt", "update", "-y"])
            apt_updated = True
        run_cmd(install_cmd)
        print(f"✅ {cmd_name} 安装成功")
    except Exception:
        print(f"❌ 安装 {cmd_name} 失败，请手动安装后重试！")
        sys.exit(1)
    return apt_updated


def ensure_python_module(module_name: str, in_china: bool):
    """确保 Python 模块已安装."""
    if importlib.util.find_spec(module_name) is not None:
        print(f"✅ 模块 {module_name} 已安装")
        return
    print(f"⚠️ 模块 {module_name} 未安装，准备安装...")
    cmd = ["pip3", "install", module_name, "--break-system-packages"]
    if in_china:
        cmd += ["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"]
    try:
        subprocess.run(cmd, check=True)
        print(f"✅ 模块 {module_name} 安装成功")
    except Exception:
        print(f"❌ 安装模块 {module_name} 失败，请手动安装！")
        sys.exit(1)


def get_go_version() -> tuple:
    """获取已安装的 Go 版本，未安装返回 None."""
    go_exec = "/usr/local/go/bin/go"
    if not os.path.exists(go_exec):
        go_exec = shutil.which("go")
        if not go_exec:
            return None
    try:
        out = subprocess.check_output([go_exec, "version"], stderr=subprocess.DEVNULL).decode()
        m = re.search(r"go(\d+)\.(\d+)", out)
        return (int(m.group(1)), int(m.group(2))) if m else None
    except Exception:
        return None


def ensure_go(in_china: bool):
    """确保 Go >= 1.20 已安装."""
    version = get_go_version()
    if version and version >= (1, 20):
        print(f"✅ Go {version[0]}.{version[1]} 已安装")
        os.environ["PATH"] = "/usr/local/go/bin:" + os.environ.get("PATH", "")
        return

    print("⚠️ Go 未安装或版本过低，准备安装 Go 1.22.1 ...")
    ensure_cmd_exists("curl", ["apt", "install", "-y", "curl"], False)

    url = (
        "https://studygolang.com/dl/golang/go1.22.1.linux-amd64.tar.gz"
        if in_china
        else "https://go.dev/dl/go1.22.1.linux-amd64.tar.gz"
    )
    try:
        subprocess.run(f"curl -Lo /tmp/go.tar.gz {url}", shell=True, check=True)
        subprocess.run("rm -rf /usr/local/go", shell=True, check=True)
        subprocess.run("tar -C /usr/local -xzf /tmp/go.tar.gz", shell=True, check=True)
    except Exception:
        print("❌ 下载或解压 Go 安装包失败，请检查网络或Go镜像源")
        sys.exit(1)

    # 写入 profile
    export_line = 'export PATH="/usr/local/go/bin:$PATH"'
    profile_path = "/etc/profile"
    with open(profile_path, "r") as f:
        if export_line not in f.read():
            with open(profile_path, "a") as f2:
                f2.write(f"\n{export_line}\n")
            print(f"✅ PATH 写入 {profile_path} 完成（系统级永久生效）")

    os.environ["PATH"] = "/usr/local/go/bin:" + os.environ.get("PATH", "")
    print("✅ Go 安装完成")


def ensure_go_package(pkg: str):
    """安装 Go 模块依赖."""
    go_exec = shutil.which("go") or "/usr/local/go/bin/go"
    print(f"检查 Go 包 {pkg} ...")
    try:
        subprocess.check_output([go_exec, "list", "-m", pkg], stderr=subprocess.DEVNULL)
        print(f"✅ Go 模块 {pkg} 已存在")
        return
    except Exception:
        pass

    if not os.path.exists("go.mod"):
        subprocess.run([go_exec, "mod", "init", "xui"], check=True)

    try:
        subprocess.run([go_exec, "get", pkg], check=True, env=os.environ.copy())
        print(f"✅ 成功安装 Go 模块 {pkg}")
    except subprocess.CalledProcessError:
        print(f"❌ 安装 {pkg} 失败，请检查网络或手动安装。")
        sys.exit(1)


def setup_environment(extra_go_packages: List[str] = None):
    """主入口：检测并安装所有依赖.

    Windows 下直接跳过.
    """
    if is_windows():
        print(">>> 检测到 Windows 系统，跳过环境检测和依赖安装...\n")
        return

    extra_go_packages = extra_go_packages or []

    print(">>> 正在检测网络位置...\n")
    in_china = check_china_network()
    print(
        f">>> 网络环境判断结果：{'中国大陆（使用国内镜像）' if in_china else '非中国大陆（使用官方源）'}\n"
    )

    # Go 代理：环境变量优先，否则根据网络自动选择
    from . import config as cfg
    if not cfg.GOPROXY:
        os.environ["GOPROXY"] = (
            "https://goproxy.cn,direct" if in_china else "https://proxy.golang.org,direct"
        )
    if not cfg.GOSUMDB:
        os.environ["GOSUMDB"] = (
            "sum.golang.google.cn" if in_china else "sum.golang.org"
        )

    if in_china:
        setup_china_mirrors()

    apt_updated = ensure_cmd_exists("curl", ["apt", "install", "-y", "curl"], False)
    apt_updated = ensure_cmd_exists("pip3", ["apt", "install", "-y", "python3-pip"], apt_updated)

    ensure_python_module("requests", in_china)
    ensure_python_module("openpyxl", in_china)

    ensure_go(in_china)

    for pkg in extra_go_packages:
        ensure_go_package(pkg)

    print(">>> 依赖环境检测完成 ✅\n")
