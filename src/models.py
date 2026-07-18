"""面板模式数据模型."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class PanelMode:
    """单个面板爆破模式的定义."""

    mode_id: int
    name: str
    output_prefix: str
    default_usernames: List[str]
    default_passwords: List[str]

    # 需要安装的额外 Go 包
    extra_go_packages: List[str] = field(default_factory=list)

    # 是否启用 Excel 输出 (ipcx)
    enable_excel: bool = True

    # SSH 相关
    is_ssh_mode: bool = False
    enable_backdoor: bool = False
    custom_backdoor_cmds: List[str] = field(default_factory=list)

    @property
    def handler_name(self) -> str:
        """Go handler 模板文件名 (不含扩展名)."""
        return f"handler_mode{self.mode_id}"


def build_panel_modes(
    mode_id: int,
    custom_usernames: Optional[List[str]] = None,
    custom_passwords: Optional[List[str]] = None,
    install_backdoor: bool = False,
    backdoor_cmds: Optional[List[str]] = None,
) -> PanelMode:
    """根据模式 ID 构建 PanelMode 实例."""
    from .config import DEFAULT_CREDENTIALS, PANEL_MODES, OUTPUT_PREFIX

    default_user, default_pass = DEFAULT_CREDENTIALS[mode_id]
    name = PANEL_MODES[mode_id]
    prefix = OUTPUT_PREFIX[mode_id]

    usernames = custom_usernames if custom_usernames else default_user
    passwords = custom_passwords if custom_passwords else default_pass

    extra_packages = []
    if mode_id == 6:
        extra_packages.append("golang.org/x/crypto/ssh")

    return PanelMode(
        mode_id=mode_id,
        name=name,
        output_prefix=prefix,
        default_usernames=usernames,
        default_passwords=passwords,
        extra_go_packages=extra_packages,
        enable_excel=(mode_id != 7),  # Sub Store 不生成 Excel
        is_ssh_mode=(mode_id == 6),
        enable_backdoor=install_backdoor,
        custom_backdoor_cmds=backdoor_cmds or [],
    )
