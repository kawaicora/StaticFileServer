"""WebDAV 服务，基于 wsgidav + cheroot。

- 账号与 HTTP/FTP 共用同一份配置（Linux 风格 r/w 权限）
- 匿名只读：匿名可读，写操作一律 403；带凭据按账号权限
- 必须认证（anonymous_readonly=False）：未认证一律 401
"""

from __future__ import annotations

import threading

from cheroot import wsgi
from wsgidav.dc.simple_dc import SimpleDomainController
from wsgidav.wsgidav_app import WsgiDAVApp

from .auth import Authenticator
from .config import AppConfig
from .logging_setup import get_logger

log = get_logger("staticfileserver.webdav")

# 匿名可用的安全（读）方法
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "PROPFIND", "REPORT"}


def make_domain_controller_class(anonymous_readonly: bool):
    """生成带匿名只读策略的 DomainController 类。

    wsgidav 以 cls(wsgidav_app, config) 两参实例化，故策略通过闭包注入。
    """

    class SfsDomainController(SimpleDomainController):
        def require_authentication(self, realm, environ):
            if anonymous_readonly:
                env = environ or {}
                method = env.get("REQUEST_METHOD", "GET").upper()
                # 带了凭据就交给认证流程处理（也能让目录页显示真实用户）；
                # 没带凭据的读请求直接放行。
                if method in _SAFE_METHODS and not env.get("HTTP_AUTHORIZATION"):
                    return False
                return True
            return super().require_authentication(realm, environ)

        def basic_auth_user(self, realm, user_name, password, environ):
            ok = super().basic_auth_user(realm, user_name, password, environ)
            if ok and environ is not None:
                # 目录页显示真实登录用户
                environ["wsgidav.auth.user_name"] = user_name
            return ok

    return SfsDomainController


class WriteGuardMiddleware:
    """匿名只读 / 只读账号的写操作拦截（认证之后的最后一道闸）。"""

    def __init__(self, app, auth: Authenticator, anonymous_readonly: bool, realm: str):
        self.app = app
        self.auth = auth
        self.anonymous_readonly = anonymous_readonly
        self.realm = realm

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        header = environ.get("HTTP_AUTHORIZATION")
        user = self.auth.check_basic_header(header)

        # 关键：开启认证但没有凭据时，必须回 401 + WWW-Authenticate 挑战。
        # 否则客户端（WinSCP / 资源管理器 / 映射驱动器）看到 200 就以为不需要登录，
        # 后续写请求不会带上账号密码，从而永远 403。
        if self.auth.config.auth_enabled and not header:
            return self._deny_401(environ, start_response)

        if method not in _SAFE_METHODS:
            if user is None:
                return self._deny_401(environ, start_response)
            if not user.can_write:
                return self._deny_403(environ, start_response)

        # 把已认证身份告知 wsgidav，使目录页正确显示当前用户与权限
        if user is not None:
            environ["wsgidav.auth.user_name"] = user.username
            environ["wsgidav.auth.roles"] = list(environ.get("wsgidav.auth.roles") or [])
            perms = ["read"]
            if user.can_write:
                perms.append("write")
            environ["wsgidav.auth.permissions"] = perms
            environ.setdefault("wsgidav.auth.realm", self.realm)

        return self.app(environ, start_response)

    def _deny_401(self, environ, start_response, _body=b"401 Not Authorized"):
        start_response(
            "401 Not Authorized",
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("WWW-Authenticate", f'Basic realm="{self.realm}"'),
                ("Content-Length", str(len(_body))),
            ],
        )
        return [_body]

    def _deny_403(self, environ, start_response, _body=b"403 Forbidden: read-only"):
        start_response(
            "403 Forbidden",
            [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(_body)))],
        )
        return [_body]


class MountMiddleware:
    """把 WebDAV 挂载在指定路径前缀下（对应配置里的 webdav.mount）。

    - 位于 mount 之下的请求：剥掉前缀后交给 wsgidav
    - 恰好请求 mount 根（无尾斜杠）：重定向补斜杠
    - 不在 mount 下的请求：404
    """

    def __init__(self, app, mount: str):
        self.app = app
        self.mount = "/" + (mount or "").strip("/")
        if self.mount == "/":
            self.mount = ""

    def __call__(self, environ, start_response):
        if not self.mount:
            return self.app(environ, start_response)

        path = environ.get("PATH_INFO", "/")
        if path == self.mount:
            location = path + "/"
            if environ.get("QUERY_STRING"):
                location += "?" + environ["QUERY_STRING"]
            start_response("301 Moved Permanently", [("Location", location), ("Content-Length", "0")])
            return [b""]

        if path.startswith(self.mount + "/"):
            environ["PATH_INFO"] = path[len(self.mount):]
            return self.app(environ, start_response)

        body = b"404 Not Found: WebDAV is mounted at " + self.mount.encode()
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]


def build_wsgi_app(config: AppConfig):
    auth = Authenticator(config)

    users = {name: {"password": u.password} for name, u in config.users.items()}

    # 挂载前缀（默认 "/"，即直接挂在根路径）。
    # 若配了前缀，MountMiddleware 会先把前缀剥掉，
    # 所以 wsgidav 内部看到的始终是 "/"，provider/realm 都用 "/"。
    mount = "/" + str(config.webdav.extra.get("mount", "/") or "").strip("/")
    if mount == "/":
        mount = ""

    # realm 指向真实用户表，保证 Basic 认证始终可用；
    # 匿名只读策略由自定义 DomainController + WriteGuardMiddleware 实现。
    user_mapping: dict = {
        "/": dict(users),
        "*": dict(users),
        "/:dir_browser": True,
    }

    dav_config = {
        "provider_mapping": {"/": config.root},
        "http_authenticator": {
            "domain_controller": make_domain_controller_class(config.anonymous_readonly),
            "accept_basic": config.auth_enabled,
            "accept_digest": False,
            "default_to_digest": False,
        },
        "simple_dc": {"user_mapping": user_mapping},
        "verbose": 1,
        "logging": {"enable_loggers": []},
        "allow_anonymous": config.anonymous_readonly,
        "dir_browser": {
            "enable": True,
            "davmount": True,
            "ms_sharepoint_support": True,
            "response_trailer": "",
        },
    }

    app = WsgiDAVApp(dav_config)

    # 先按挂载前缀剥路径，再做写权限拦截
    if mount:
        app = MountMiddleware(app, mount)
    if config.anonymous_readonly:
        return WriteGuardMiddleware(app, auth, config.anonymous_readonly, config.realm)
    return app


def run(config: AppConfig, block: bool = True, server_holder: list | None = None) -> wsgi.Server:
    app = build_wsgi_app(config)
    server = wsgi.Server(
        (config.webdav.host, config.webdav.port),
        app,
        numthreads=8,
    )

    if server_holder is not None:
        server_holder.append(server)

    log.info(
        "WebDAV 服务启动: http://%s:%s/  根目录=%s",
        config.webdav.host,
        config.webdav.port,
        config.root,
    )
    if block:
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()
    else:
        threading.Thread(target=server.start, daemon=True).start()
    return server
