"""FTP 服务，基于 pyftpdlib。

- 支持匿名只读（anonymous / 空密码）
- 认证账号与 HTTP/WebDAV 共用配置
"""

from __future__ import annotations

import threading

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from .access import get_controller
from .auth import Authenticator
from .config import AppConfig
from .logging_setup import get_logger

log = get_logger("staticfileserver.ftp")


def _ip_allowed(ip: str) -> tuple[bool, str]:
    """经统一准入控制器判定 FTP 来源 IP。"""
    controller = get_controller()
    if controller is None:
        return True, ""
    return controller.check_ip(ip)


def build_authorizer(config: AppConfig) -> DummyAuthorizer:
    """从给定配置构建 FTP 授权器。"""
    authz = DummyAuthorizer()

    for name, user in config.users.items():
        perm = "elradfmwMT" if user.can_write else "elr"
        authz.add_user(name, user.password, config.root, perm=perm, msg_login=f"欢迎 {name}")

    if config.anonymous_readonly or not config.auth_enabled:
        authz.add_anonymous(config.root, perm="elr", msg_login="匿名只读登录成功")

    return authz


# 授权器缓存：由 bump_authz_generation() 显式失效（配置热重载时调用）
_authz_lock = threading.Lock()
_authz_cache: tuple[int, DummyAuthorizer] | None = None
_authz_generation = 0


def bump_authz_generation() -> None:
    """通知 FTP 授权器缓存失效（配置变更后调用）。"""
    global _authz_generation, _authz_cache
    with _authz_lock:
        _authz_generation += 1
        _authz_cache = None


def _live_authorizer() -> DummyAuthorizer:
    """基于当前生效配置构建授权器；代际未变时复用缓存。"""
    global _authz_cache
    controller = get_controller()
    cfg = controller.config if controller is not None else None
    if cfg is None:
        raise RuntimeError("access controller 未初始化")
    with _authz_lock:
        if _authz_cache is None or _authz_cache[0] != _authz_generation:
            _authz_cache = (_authz_generation, build_authorizer(cfg))
        return _authz_cache[1]


def build_handler(config: AppConfig) -> type[FTPHandler]:
    class Handler(FTPHandler):
        passive_ports = None
        banner = config.ftp.extra.get("banner", "StaticFileServer FTP")

        def on_connect(self):
            ip = self.remote_ip
            allowed, reason = _ip_allowed(ip)
            if not allowed:
                log.warning("FTP 拒绝连接 %s -> %s", ip, reason)
                self.respond("530 您的 IP 不允许访问。")
                self.close_when_done()

        def process_command(self, cmd, *args, **kwargs):
            # 每次命令前刷新授权器，保证热重载后的用户表立即生效
            self.authorizer = _live_authorizer()
            return super().process_command(cmd, *args, **kwargs)

    return Handler


def create_server(config: AppConfig) -> FTPServer:
    handler = build_handler(config)
    return FTPServer((config.ftp.host, config.ftp.port), handler)


def run(config: AppConfig, block: bool = True, server_holder: list | None = None) -> FTPServer:
    server = create_server(config)
    log.info("FTP 服务启动: ftp://%s:%s  根目录=%s", config.ftp.host, config.ftp.port, config.root)

    if server_holder is not None:
        server_holder.append(server)

    if block:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.close_all()
    else:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    return server
