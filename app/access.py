"""统一准入控制：IP 黑白名单 + 热重载。

三个协议（HTTP / WebDAV / FTP）都通过 AccessController 判定来源 IP，
保证规则只有一份、行为一致。

热重载：管理界面保存后调用 reload()，重新读取 config.json，
后续请求立即使用新规则（用户表与 IP 规则都即时生效）。
"""

from __future__ import annotations

import threading

from .config import AppConfig, AuthUser, load_config
from .iprules import IPMatcher, build_matcher, is_allowed
from .logging_setup import get_logger

log = get_logger("staticfileserver.access")


class AccessController:
    """持有当前生效的配置，并提供 IP 判定；支持热重载。"""

    def __init__(self, config: AppConfig):
        self._lock = threading.RLock()
        self._config = config
        self._load_matchers(config)

    # ---------- 内部 ----------

    def _load_matchers(self, config: AppConfig) -> None:
        self._white = build_matcher(config.access_whitelist)
        self._black = build_matcher(config.access_blacklist)

    # ---------- 配置访问 ----------

    @property
    def config(self) -> AppConfig:
        with self._lock:
            return self._config

    @property
    def enabled(self) -> bool:
        return self.config.access_enabled

    def reload(self, config: AppConfig | None = None) -> AppConfig:
        """重新载入配置（默认从磁盘读）。返回新配置。"""
        with self._lock:
            new_config = config if config is not None else load_config(self._config.config_path or None)
            self._config = new_config
            self._load_matchers(new_config)
        # 通知 FTP 等模块刷新各自的派生缓存
        try:
            from . import ftp_server

            ftp_server.bump_authz_generation()
        except Exception:  # noqa: BLE001
            pass
        log.info(
            "配置热重载完成：用户=%d 白名单=%d 黑名单=%d 启用=%s",
            len(new_config.users),
            len(new_config.access_whitelist),
            len(new_config.access_blacklist),
            new_config.access_enabled,
        )
        return new_config

    # ---------- IP 判定 ----------

    def check_ip(self, ip: str | None) -> tuple[bool, str]:
        """返回 (是否放行, 原因)。未启用 IP 限制时一律放行。"""
        if not ip or ip == "-":
            # 无法识别来源时，若配了白名单则保守拒绝
            if self.enabled and (self._white):
                return False, "无法识别来源 IP"
            return True, "来源未知，默认放行"
        if not self.enabled:
            return True, "IP 限制未启用"
        return is_allowed(ip, self._black, self._white)

    def is_allowed(self, ip: str | None) -> bool:
        return self.check_ip(ip)[0]

    # ---------- 用户管理 ----------

    def find_user(self, username: str) -> AuthUser | None:
        return self.config.users.get(username)

    def verify(self, username: str | None, password: str | None) -> AuthUser | None:
        return self.config.authenticate(username, password)


# 进程内单例：三个服务模块共享同一个控制器
_controller: AccessController | None = None
_controller_lock = threading.Lock()


def set_controller(controller: AccessController) -> AccessController:
    global _controller
    with _controller_lock:
        _controller = controller
    return controller


def get_controller() -> AccessController | None:
    return _controller


def init_controller(config: AppConfig) -> AccessController:
    return set_controller(AccessController(config))
