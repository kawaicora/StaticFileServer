"""统一服务：单端口同时提供 HTTP 浏览与 WebDAV。

架构（进程内合并，无 sock/管道，无额外故障点）：

    单端口（cheroot + gevent 兼容）
    ├─ /dav/*   → wsgidav（WebDAV）
    └─ 其它     → Flask（目录浏览 / 下载 / 上传 / 管理界面）

共享同一份：
    - 真实 IP 解析（Cloudflare / 代理 / 直连）
    - SQLite 用户库（scrypt）
    - IP 黑白名单

WebDAV 挂载前缀由 `webdav.mount` 决定（默认 `/dav`）。
"""

from __future__ import annotations

import threading

from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response as WerkzeugResponse

from .access import get_controller
from .config import AppConfig
from .logging_setup import get_logger
from .webdav_server import MountMiddleware
from .webdav_server import build_wsgi_app as build_webdav_wsgi

log = get_logger("staticfileserver.server")

# 进程内保管 Flask 应用引用，供 WebDAV 侧建立应用上下文（db.session）
_flask_app = None


def set_flask_app(app) -> None:
    global _flask_app
    _flask_app = app


def get_flask_app():
    return _flask_app


def _webdav_disabled_app(mount: str):
    """WebDAV 关闭时，访问挂载点给出明确提示。"""

    def app(environ, start_response):
        body = f"WebDAV 已关闭（挂载点 {mount}）".encode("utf-8")
        start_response(
            "503 Service Unavailable",
            [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))],
        )
        return [body]

    return app


def build_app(config: AppConfig):
    """构建合并后的 WSGI 应用（复用已注册数据库的 Flask 应用）。"""
    from .http_server import create_flask_app

    flask_app = get_flask_app()
    if flask_app is None:
        # 未预先初始化：自建并绑定数据库
        from .models import db

        flask_app = create_flask_app(config)
        flask_app.config["SQLALCHEMY_DATABASE_URI"] = config.database_url
        flask_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        db.init_app(flask_app)
        set_flask_app(flask_app)

    mount = config.webdav_mount  # 如 "/dav"；根挂载时为空串

    if config.webdav_server.enabled:
        dav_app = build_webdav_wsgi(config, mount=mount)
        log.info("WebDAV 已挂载于 %s/", mount or "/")
    else:
        dav_app = _webdav_disabled_app(mount or "/")

    # 路由结构：MountMiddleware 负责前缀剥离 + Destination 修正，
    # 剥完后自接路由：位于挂载前缀下的交给 wsgidav，其余交给 Flask。
    if mount and config.webdav_server.enabled:
        return MountMiddleware(flask_app, mount, dav_app=dav_app)

    app = DispatcherMiddleware(flask_app, {})

    if not mount:
        # WebDAV 挂根：无法与 Flask 共存于同一前缀，故仅在
        # 请求显式声明 DAV 方法/头部时才交给 WebDAV，否则用 Flask。
        webdav_fallback = dav_app

        def root_app(environ, start_response):
            method = (environ.get("REQUEST_METHOD") or "GET").upper()
            depth = environ.get("HTTP_DEPTH")
            ua = (environ.get("HTTP_USER_AGENT") or "").lower()
            wants_dav = (
                method in {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
                or (method == "OPTIONS" and depth is not None)
                or "dav" in ua
                or "winscp" in ua
                or "microsoft-webdav" in ua
            )
            if wants_dav:
                return webdav_fallback(environ, start_response)
            return app(environ, start_response)

        return root_app

    return app


def run(config: AppConfig, block: bool = True, server_holder: list | None = None):
    """启动统一服务（HTTP + WebDAV 同端口）。"""
    from cheroot import wsgi

    app = build_app(config)
    server = wsgi.Server(
        (config.server.host, config.server.port),
        app,
        numthreads=16,
        timeout=120,
    )

    if server_holder is not None:
        server_holder.append(server)

    mount = config.webdav_mount or "/"
    log.info(
        "统一服务启动: http://%s:%s/  浏览=/  WebDAV=%s/  根目录=%s",
        config.server.host,
        config.server.port,
        mount,
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
