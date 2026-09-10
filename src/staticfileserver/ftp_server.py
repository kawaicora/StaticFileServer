"""FTP 服务，基于 pyftpdlib。

- 支持匿名只读（anonymous / 空密码）
- 认证账号与 HTTP/WebDAV 共用配置
"""

from __future__ import annotations

import threading

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from .auth import Authenticator
from .config import AppConfig
from .logging_setup import get_logger

log = get_logger("staticfileserver.ftp")


def build_authorizer(config: AppConfig) -> DummyAuthorizer:
    authz = DummyAuthorizer()

    for name, user in config.users.items():
        perm = "elradfmwMT" if user.can_write else "elr"
        authz.add_user(name, user.password, config.root, perm=perm, msg_login=f"欢迎 {name}")

    if config.anonymous_readonly or not config.auth_enabled:
        authz.add_anonymous(config.root, perm="elr", msg_login="匿名只读登录成功")

    return authz


def build_handler(config: AppConfig) -> type[FTPHandler]:
    authz = build_authorizer(config)

    class Handler(FTPHandler):
        authorizer = authz
        passive_ports = None
        banner = config.ftp.extra.get("banner", "StaticFileServer FTP")

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
