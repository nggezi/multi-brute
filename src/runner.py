"""执行引擎 —— 归一化、分片、运行 Go 程序、合并结果."""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, List

from .config import (
    TEMP_PART_DIR,
    TEMP_XUI_DIR,
    TEMP_HMSUCCESS_DIR,
    TEMP_HMFAIL_DIR,
    RESULTS_FILE,
    GO_SOURCE_FILE,
    OUTPUT_FILE,
)
from .normalizer import normalize_line


def ensure_temp_dirs():
    """创建临时目录."""
    for d in [TEMP_PART_DIR, TEMP_XUI_DIR, TEMP_HMSUCCESS_DIR, TEMP_HMFAIL_DIR]:
        os.makedirs(d, exist_ok=True)


def prepare_and_split(input_file: str, lines_per_file: int) -> int:
    """归一化输入文件（CIDR展开 + URL提取）后拆分为多个小文件.

    返回归一化后的总目标数.
    """
    input_path = Path(input_file)
    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_file}")

    # 归一化：CIDR 展开 + URL → IP:Port
    raw_lines = [
        line for line in input_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    raw_count = len(raw_lines)

    normalized: List[str] = []
    for line in raw_lines:
        for normalized_line in normalize_line(line):
            normalized.append(normalized_line)

    total_count = len(normalized)
    if total_count > raw_count:
        print(f"  [CIDR] Expanded: {raw_count} line(s) → {total_count} target(s)")
    print(f"  [Norm] Input: {raw_count} raw → {total_count} normalized IP:Port")

    # 分片写入
    for idx, start in enumerate(range(0, total_count, lines_per_file), 1):
        chunk = normalized[start:start + lines_per_file]
        part_path = Path(TEMP_PART_DIR) / f"part_{idx}.txt"
        part_path.write_text("\n".join(chunk), encoding="utf-8")

    return total_count


def split_input_file(input_file: str, lines_per_file: int):
    """将输入文件按行数拆分为多个小文件（不做归一化，兼容旧版）."""
    input_path = Path(input_file)
    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_file}")

    lines = input_path.read_text(encoding="utf-8").splitlines()
    for idx, start in enumerate(range(0, len(lines), lines_per_file), 1):
        chunk = lines[start:start + lines_per_file]
        part_path = Path(TEMP_PART_DIR) / f"part_{idx}.txt"
        part_path.write_text("\n".join(chunk), encoding="utf-8")


def run_go_for_parts(sleep_seconds: int):
    """对每个分片文件依次执行 Go 爆破程序."""
    part_dir = Path(TEMP_PART_DIR)
    part_files = sorted(part_dir.glob("part_*.txt"))
    total_parts = len(part_files)

    if total_parts == 0:
        print("⚠️ 没有找到分片文件，请检查输入文件")
        return

    start_time = time.time()

    for idx, part in enumerate(part_files, 1):
        elapsed = time.time() - start_time
        avg_time = elapsed / idx if idx > 0 else 0
        remaining = avg_time * (total_parts - idx)
        est_min = int(remaining) // 60
        est_sec = int(remaining) % 60

        print(f"爆破 {part.name} ({idx}/{total_parts}) 预计剩余时间: {est_min} 分 {est_sec} 秒")

        # 拷贝当前分片到 results.txt
        shutil.copy(str(part), RESULTS_FILE)

        # 运行 go run xui.go
        try:
            subprocess.run(["go", "run", GO_SOURCE_FILE], check=True)
        except subprocess.CalledProcessError:
            print("❌ go 运行失败，请检查环境")
            sys.exit(1)

        # 移动输出文件到临时目录
        output_part = Path(TEMP_XUI_DIR) / f"xui{idx}.txt"
        if os.path.exists(OUTPUT_FILE):
            shutil.move(OUTPUT_FILE, str(output_part))
        else:
            print(f"第 {idx} 批无爆破成功结果（未生成 {OUTPUT_FILE}）")

        # 移动 SSH 后门结果文件
        if os.path.exists("hmsuccess.txt"):
            shutil.move("hmsuccess.txt", str(Path(TEMP_HMSUCCESS_DIR) / f"hmsuccess{idx}.txt"))
        if os.path.exists("hmfail.txt"):
            shutil.move("hmfail.txt", str(Path(TEMP_HMFAIL_DIR) / f"hmfail{idx}.txt"))

        time.sleep(sleep_seconds)


def merge_result_files(prefix: str, output_name: str, source_dir: str):
    """合并指定前缀的结果文件."""
    source_path = Path(source_dir)
    output_path = source_path / output_name

    if output_path.exists():
        output_path.unlink()

    files = sorted(source_path.glob(f"{prefix}*.txt"))
    with output_path.open("w", encoding="utf-8") as out:
        for f in files:
            if f.name == output_name:
                continue
            with f.open("r", encoding="utf-8") as inf:
                shutil.copyfileobj(inf, out)

    # 拷贝一份到工作目录
    if output_path.exists():
        shutil.copy(str(output_path), output_name)


def merge_xui_files():
    """合并所有 xuiN.txt 到 xui.txt."""
    xui_dir = Path(TEMP_XUI_DIR)
    merged = xui_dir / OUTPUT_FILE
    if merged.exists():
        merged.unlink()

    files = sorted(xui_dir.glob("xui*.txt"))
    with merged.open("w", encoding="utf-8") as out:
        for f in files:
            if f.name == OUTPUT_FILE:
                continue
            with f.open("r", encoding="utf-8") as inf:
                shutil.copyfileobj(inf, out)

    if merged.exists():
        shutil.copy(str(merged), OUTPUT_FILE)


def run_ipcx_script():
    """执行 ipcx.py 生成 Excel."""
    if not os.path.exists("ipcx.py"):
        from .ip_query import generate_ipcx_script
        generate_ipcx_script()

    subprocess.run([sys.executable, "ipcx.py"])


def cleanup_temp_files():
    """清理所有临时文件和目录."""
    for d in [TEMP_PART_DIR, TEMP_XUI_DIR, TEMP_HMSUCCESS_DIR, TEMP_HMFAIL_DIR]:
        shutil.rmtree(d, ignore_errors=True)

    for f in [RESULTS_FILE, GO_SOURCE_FILE, "ipcx.py", OUTPUT_FILE]:
        if os.path.exists(f):
            os.remove(f)
