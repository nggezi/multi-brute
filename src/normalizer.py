"""输入文件预处理：CIDR 展开 + 补全默认端口.

绝不丢弃 URL 路径。Go handler 内部自行提取 host:port。

支持输入格式:
  1.2.3.4:443                              → 1.2.3.4:443          (不变)
  1.2.3.4                                  → 1.2.3.4:443          (补端口)
  10.0.0.0/30:8080                         → 10.0.0.0:8080 ~ .3   (CIDR 展开)
  192.168.1.0/24                           → 192.168.1.0:443 ~ .255
  https://1.2.3.4:8443/login               → https://1.2.3.4:8443/login  (路径保留!)
  http://10.0.0.1                           → http://10.0.0.1:443       (补端口)
  https://10.0.0.0/30:9090/admin           → 4个完整URL + 路径 (不丢/admin)
"""

import ipaddress
import re
from pathlib import Path
from typing import List, Iterator
from urllib.parse import urlparse


DEFAULT_PORT = "443"


def _expand_cidr(cidr_str: str) -> List[str]:
    """展开 CIDR 网段为所有 IP 列表（含网络地址和广播地址）."""
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        return [str(ip) for ip in network]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR: {cidr_str} ({e})")


def _has_cidr(text: str) -> bool:
    """检测文本是否包含 CIDR 标记."""
    cleaned = text.strip()
    if cleaned.startswith(("http://", "https://")):
        cleaned = re.sub(r"^https?://", "", cleaned)
    return bool(re.search(r"\d+\.\d+\.\d+\.\d+/\d+", cleaned))


def _has_url(text: str) -> bool:
    """检测文本是否为完整 URL."""
    return text.strip().startswith(("http://", "https://"))


def _ensure_port(host_port: str, default: str = DEFAULT_PORT) -> str:
    """确保 host 部分有端口."""
    if ":" in host_port:
        return host_port
    return f"{host_port}:{default}"


def normalize_line(line: str) -> Iterator[str]:
    """归一化一行输入：CIDR 展开 + 补端口，保留 URL 和路径.

    Yields:
        归一化后的字符串
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return

    # ── 完整 URL + CIDR ──
    if _has_url(line) and _has_cidr(line):
        # 解析: https://10.0.0.0/30:9090/admin → 展开 4 个
        match = re.match(
            r"^(https?://)"           # scheme
            r"(\d+\.\d+\.\d+\.\d+)"  # IP (group 2)
            r"(/\d+)"                 # CIDR mask (group 3)
            r"(?::(\d+))?"            # optional port (group 4)
            r"(/.*)?$",               # optional path (group 5)
            line
        )
        if match:
            scheme = match.group(1)
            cidr = match.group(2) + match.group(3)  # e.g. 10.0.0.0/30
            port = match.group(4) or DEFAULT_PORT
            path = match.group(5) or ""
            for ip in _expand_cidr(cidr):
                yield f"{scheme}{ip}:{port}{path}"
            return

        # 降级: 提取 CIDR 部分尝试展开
        no_scheme = re.sub(r"^https?://", "", line)
        cidr_match = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)(?::(\d+))?(.*)$", no_scheme)
        if cidr_match:
            cidr = cidr_match.group(1)
            port = cidr_match.group(2) or DEFAULT_PORT
            rest = cidr_match.group(3) or ""
            for ip in _expand_cidr(cidr):
                if rest:
                    yield f"{ip}:{port}{rest}"
                else:
                    yield f"{ip}:{port}"
            return

    # ── 纯 CIDR（无 URL）──
    if _has_cidr(line):
        # 10.0.0.0/30:8080 或 10.0.0.0/30
        match = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)(?::(\d+))?(.*)$", line)
        if match:
            cidr = match.group(1)
            port = match.group(2) or DEFAULT_PORT
            rest = match.group(3) or ""
            for ip in _expand_cidr(cidr):
                if rest:
                    yield f"{ip}:{port}{rest}"
                else:
                    yield f"{ip}:{port}"
            return

    # ── 完整 URL（无 CIDR）──
    if _has_url(line):
        parsed = urlparse(line)
        if parsed.hostname:
            port = str(parsed.port) if parsed.port else DEFAULT_PORT
            # 重构 URL，保留路径和 query
            path = parsed.path or ""
            query = "?" + parsed.query if parsed.query else ""
            fragment = "#" + parsed.fragment if parsed.fragment else ""
            yield f"{parsed.scheme}://{parsed.hostname}:{port}{path}{query}{fragment}"
            return
        # 无法解析，保留原样
        yield line
        return

    # ── 纯 IP（无端口）──
    if ":" not in line:
        yield f"{line}:{DEFAULT_PORT}"
        return

    # ── IP:Port（不动）──
    yield line


def normalize_file(input_path: str, output_path: str = None) -> str:
    """对一个输入文件做归一化处理.

    Returns:
        归一化后的内容字符串 (output_path=None) 或输出文件路径.
    """
    src = Path(input_path)
    if not src.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    normalized_lines: List[str] = []
    raw_lines = [l for l in src.read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.strip().startswith("#")]
    raw_count = len(raw_lines)

    for raw_line in raw_lines:
        for norm in normalize_line(raw_line):
            normalized_lines.append(norm)

    content = "\n".join(normalized_lines)

    if len(normalized_lines) > raw_count:
        print(f"  [CIDR] {raw_count} line(s) -> {len(normalized_lines)} target(s)")

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        return output_path

    return content
