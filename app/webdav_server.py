"""WebDAV 服务，基于 wsgidav。

- 账号与 HTTP 共用同一份 SQLite 用户库（Linux 风格 r/w 权限）
- 匿名只读：匿名可读，写操作一律 403；带凭据按账号权限
- 必须认证（anonymous_readonly=False）：未认证一律 401
- 由 app/server.py 挂在单端口的 `webdav.mount` 前缀下（默认 /dav）

/provider_mapping 的 "/" 指向配置里的 root（即 HTTP 浏览的同一个目录），
而不是字面量的 ./dav 目录。
挂载前缀由 MountMiddleware 剥离，wsgidav 内部始终按根 "/" 处理。
"""

from __future__ import annotations

from wsgidav.dc.base_dc import BaseDomainController
from wsgidav.wsgidav_app import WsgiDAVApp

from .access import get_controller
from .auth import Authenticator, parse_basic_auth
from .config import AppConfig
from .logging_setup import get_logger
from .realip import get_real_ip as resolve_real_ip

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


def _app_context():
    """为 WebDAV（不经过 Flask 请求栈）提供数据库所需的应用上下文。"""
    from .server import get_flask_app

    flask_app = get_flask_app()
    if flask_app is None:
        raise RuntimeError("Flask 应用未初始化")
    return flask_app.app_context()


class SqliteDomainController(BaseDomainController):
    """把 wsgidav 的 Basic 认证接到 SQLite 用户库上。

    wsgidav 以 cls(wsgidav_app, config) 两参实例化，
    故匿名只读策略从类属性读取（见 _make_domain_controller_class）。
    """

    # 由 build_wsgi_app 在实例化前注入
    anonymous_readonly: bool = True

    def __init__(self, wsgidav_app, config):
        super().__init__(wsgidav_app, config)
        self.realm = "/"

    def get_domain_realm(self, path_info, environ):  # noqa: ARG002
        return self.realm

    def require_authentication(self, realm, environ):  # noqa: ARG002
        if type(self).anonymous_readonly:
            env = environ or {}
            method = env.get("REQUEST_METHOD", "GET").upper()
            if method in _SAFE_METHODS and not env.get("HTTP_AUTHORIZATION"):
                return False
        return True

    def basic_auth_user(self, realm, user_name, password, environ):  # noqa: ARG002
        from .models import authenticate

        # WebDAV 不经过 Flask 请求栈，需自建应用上下文才能用 db.session
        with _app_context():
            user = authenticate(user_name, password)
        if user is None:
            return False
        if environ is not None:
            environ["wsgidav.auth.user_name"] = user_name
        return True

    def supports_http_digest_auth(self) -> bool:
        return False

    def get_roles(self, realm, user_name, environ):  # noqa: ARG002
        return ["reader", "writer"]

    def get_realm(self) -> str:
        return self.realm

    def auth_failed(self, realm, user_name, environ):  # noqa: ARG002
        log.warning("WebDAV 认证失败: user=%s", user_name)


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
        # WebDAV 不经过 Flask 请求栈，认证需自建应用上下文（db.session）
        with _app_context():
            user = self.auth.check_basic_header(header)

        # 提供了凭据但校验失败：一律 401。
        # 绝不能降级为匿名，否则错口令在 anonymous_readonly 下会被放行读。
        if header and user is None:
            return self._deny_401(environ, start_response)

        # 关键：开启认证但没有凭据时，必须回 401 + WWW-Authenticate 挑战。
        # 否则客户端（WinSCP / 资源管理器 / 映射驱动器）看到 200 就以为不需要登录，
        # 后续写请求不会带上账号密码，从而永远 403。
        #
        # 这里对 WebDAV 不做匿名豁免：只要开启了认证，任何无凭据请求都先挑战，
        # 以兼容 Windows 映射驱动器 / WinSCP 的凭据协商。
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


class IPGateMiddleware:
    """最先执行的 IP 准入闸：命中黑名单或不在白名单时直接 403。"""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        controller = get_controller()
        if controller is None or not controller.enabled:
            return self.app(environ, start_response)
        ip = resolve_real_ip(environ, trust_headers=controller.config.trust_proxy_headers)
        allowed, reason = controller.check_ip(ip)
        if not allowed:
            log.warning("WebDAV 拒绝 %s -> %s", ip, reason)
            body = b"403 Forbidden: IP not allowed"
            start_response(
                "403 Forbidden",
                [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))],
            )
            return [body]
        return self.app(environ, start_response)


class MountMiddleware:
    """把 WebDAV 挂载在指定路径前缀下，并修正 Destination 头。

    自带路由：位于挂载前缀下的请求剥掉前缀后交给 dav_app；
    其余路径原样交给 fallback（Flask）。

    Destination 头里的挂载前缀也一并剥掉，否则 MOVE/COPY 会把
    /dav/b.txt 传给已剥前缀的 wsgidav 而失败。
    """

    def __init__(self, fallback, mount: str, dav_app=None):
        self.fallback = fallback
        self.dav_app = dav_app if dav_app is not None else fallback
        self.mount = "/" + (mount or "").strip("/")
        if self.mount == "/":
            self.mount = ""

    def __call__(self, environ, start_response):
        if not self.mount:
            return self.dav_app(environ, start_response)

        path = environ.get("PATH_INFO", "/")
        if path == self.mount:
            location = path + "/"
            if environ.get("QUERY_STRING"):
                location += "?" + environ["QUERY_STRING"]
            start_response("301 Moved Permanently", [("Location", location), ("Content-Length", "0")])
            return [b""]

        if path.startswith(self.mount + "/"):
            # 剥离挂载前缀：PATH_INFO 去前缀，SCRIPT_NAME 置为前缀。
            # Destination 头不在此处处理：wsgidav 会按 provider 的
            # mount_path 自行剥前缀（见 request_server.py），
            # 我们提前剥反而会被当成跨 realm 而报 502。
            environ["SCRIPT_NAME"] = environ.get("SCRIPT_NAME", "") + self.mount
            environ["PATH_INFO"] = path[len(self.mount):]
            return self.dav_app(environ, start_response)

        # 非挂载路径交给 Flask
        return self.fallback(environ, start_response)

    def _strip_destination(self, environ) -> None:
        """已废弃：挂载前缀由 wsgidav 的 provider.mount_path 处理。

        保留空实现以避免外部引用报错；不再修改 Destination 头。
        """
        return


def _make_domain_controller_class(anonymous_readonly: bool):
    """生成绑定了匿名策略的 DomainController 子类（wsgidav 需要类，不是工厂）。"""

    class _Bound(SqliteDomainController):
        pass

    _Bound.anonymous_readonly = anonymous_readonly
    return _Bound


def build_wsgi_app(config: AppConfig, mount: str = ""):
    """构建 WebDAV 的 WSGI 应用（认证走 SQLite）。

    mount: 挂载前缀（如 "/dav"）。wsgidav 内部始终按根 "/" 处理路径，
    但目录页会用它拼接静态资源链接（/:dir_browser/... -> /dav/:dir_browser/...），
    否则挂在子路径下时样式/脚本会 404。
    """
    auth = Authenticator(config)
    mount = "/" + (mount or "").strip("/")
    if mount == "/":
        mount = ""

    dav_config = {
        "provider_mapping": {"/": config.root},
        # 目录页静态资源链接前缀，并让 wsgidav 知道
        # 自己挂在子路径下（MOVE/COPY 会据此剥 Destination 前缀）：
        # /:dir_browser/... -> /dav/:dir_browser/...
        "mount_path": mount,
        "http_authenticator": {
            "domain_controller": _make_domain_controller_class(config.anonymous_readonly),
            "accept_basic": config.auth_enabled,
            "accept_digest": False,
            "default_to_digest": False,
        },
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

    # 把挂载前缀告诉每个 provider：wsgidav 的 MOVE/COPY 依赖它
    # 删掉 Destination 里的前缀，否则报 "Inter-realm copy/move"。
    if mount:
        for provider in getattr(app, "provider_map", {}).values():
            try:
                provider.mount_path = mount
            except Exception:  # noqa: BLE001
                pass

    if config.auth_enabled:
        # 开启认证时统一走写权限闸（无凭据 -> 401 挑战）
        app = WriteGuardMiddleware(app, auth, config.anonymous_readonly, config.realm)
    # IP 准入闸放最外层：未过闸的请求不进入任何认证/业务逻辑
    app = IPGateMiddleware(app)
    return app


def run(config: AppConfig, block: bool = True, server_holder: list | None = None):
    """独立启动 WebDAV（不合并到 HTTP 时使用，保留兼容）。"""
    from cheroot import wsgi

    mount = config.webdav_mount
    app = build_wsgi_app(config, mount=mount)
    if mount:
        app = MountMiddleware(app, mount)

    port = config.webdav_server.extra.get("port", config.server.port)
    server = wsgi.Server((config.server.host, int(port)), app, numthreads=8)
    if server_holder is not None:
        server_holder.append(server)

    log.info("WebDAV 服务启动: http://%s:%s%s/", config.server.host, port, mount)
    if block:
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()
    else:
        import threading

        threading.Thread(target=server.start, daemon=True).start()
    return server
