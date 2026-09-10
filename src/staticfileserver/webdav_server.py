"""WebDAV 服务，基于 wsgidav + cheroot。

- 通过 simple_dc 提供账号认证，账号与 HTTP/FTP 共用同一份配置
- 匿名只读：匿名请求放行读方法，写方法一律拒绝
"""

from __future__ import annotations

from cheroot import wsgi
from wsgidav.wsgidav_app import WsgiDAVApp

from .auth import Authenticator
from .config import AppConfig
from .logging_setup import get_logger

log = get_logger("staticfileserver.webdav")

# 匿名可用的安全方法
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "PROPFIND", "REPORT"}


class ManageRealmMiddleware:
    """按“匿名只读/必须认证”策略控制 WebDAV 访问。

    wsgidav 的 simple_dc 只在 realm 映射为 True 时放行匿名。这里统一接管：
    - anonymous_readonly=True：匿名放行读，写返回 403；带凭据则按账号权限
    - anonymous_readonly=False：一律要求凭据，由 wsgidav 自身返回 401
    """

    def __init__(self, app, auth: Authenticator, anonymous_readonly: bool, realm: str):
        self.app = app
        self.auth = auth
        self.anonymous_readonly = anonymous_readonly
        self.realm = realm

    def __call__(self, environ, start_response):
        user = self.auth.check_basic_header(environ.get("HTTP_AUTHORIZATION"))
        method = environ.get("REQUEST_METHOD", "GET").upper()

        if user is None:
            if not self.anonymous_readonly:
                return self._deny_401(environ, start_response)
            if method not in _SAFE_METHODS:
                return self._deny_403(environ, start_response)

        environ["wsgidav.auth.user_name"] = user.username if user else "anonymous"
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

    def _deny_403(self, environ, start_response, _body=b"403 Forbidden: anonymous is read-only"):
        start_response(
            "403 Forbidden",
            [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(_body)))],
        )
        return [_body]


def build_wsgi_app(config: AppConfig) -> WsgiDAVApp:
    auth = Authenticator(config)

    # realm 为 True 时 wsgidav 放行匿名；其余走 "*" 用户表做 Basic 认证
    user_mapping: dict = {}
    users = {name: {"password": u.password} for name, u in config.users.items()}

    if config.auth_enabled:
        user_mapping["*"] = users
        # realm 映射为 True 时 wsgidav 放行匿名；写权限由中间件控制
        if config.anonymous_readonly:
            user_mapping["/"] = True
            user_mapping["/:dir_browser"] = True

    dav_config = {
        "provider_mapping": {"/": config.root},
        "http_authenticator": {
            "domain_controller": "wsgidav.dc.simple_dc.SimpleDomainController",
            "accept_basic": config.auth_enabled,
            "accept_digest": False,
            "default_to_digest": False,
        },
        "simple_dc": {"user_mapping": user_mapping},
        "verbose": 1,
        "logging": {"enable_loggers": []},
        "allow_anonymous": not config.auth_required,
        # 目录浏览页面
        "dir_browser": {
            "enable": True,
            "davmount": True,
            "ms_sharepoint_support": True,
            "response_trailer": "",
        },
    }

    app = WsgiDAVApp(dav_config)

    # 用一个薄中间件统一覆盖匿名策略
    if config.anonymous_readonly or config.auth_required:
        return ManageRealmMiddleware(app, auth, config.anonymous_readonly, config.realm)
    return app


def run(config: AppConfig, block: bool = True) -> wsgi.Server:
    app = build_wsgi_app(config)
    server = wsgi.Server(
        (config.webdav.host, config.webdav.port),
        app,
        numthreads=8,
    )
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
        server.prepare()
    return server
