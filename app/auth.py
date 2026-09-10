"""服务间共享的认证逻辑。

HTTP 与 WebDAV 共用 HTTP Basic；两者都从同一份 SQLite 用户库校验，
保证口径一致。口令在库中以 scrypt 散列存储，不落明文。
"""

from __future__ import annotations

import base64
import binascii

from .config import AppConfig


def parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    """解析 Authorization: Basic xxx，返回 (user, password)。"""
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        raw = base64.b64decode(parts[1]).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    if ":" not in raw:
        return None
    username, password = raw.split(":", 1)
    return username, password


class Authenticator:
    """把 AppConfig 包装成各服务可用的校验器（后端为 SQLite）。"""

    def __init__(self, config: AppConfig):
        self.config = config

    @property
    def anonymous_allowed(self) -> bool:
        return self.config.auth_enabled and self.config.anonymous_readonly

    # ---------- 校验 ----------

    def check(self, username: str | None, password: str | None):
        """返回用户对象（含 can_read/can_write）或 None。"""
        if not self.config.auth_enabled:
            return None
        from .models import authenticate

        return authenticate(username, password)

    def check_basic_header(self, header: str | None):
        creds = parse_basic_auth(header)
        if not creds:
            return None
        return self.check(*creds)

    def can_write(self, user) -> bool:
        """匿名(未认证)只能写当且仅当未开启认证。"""
        if not self.config.auth_enabled:
            return True
        if user is None:
            return False
        return user.can_write

    def can_read(self, user) -> bool:
        """匿名可读当且仅当未开启认证，或开启了匿名只读。"""
        if not self.config.auth_enabled:
            return True
        if user is None:
            return self.config.anonymous_readonly
        return user.can_read
