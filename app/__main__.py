"""命令行入口与启动引导。

用法：
    python -m staticfileserver                  # 按配置启动（HTTP + WebDAV 同端口）
    python -m staticfileserver --no-webdav      # 只提供 HTTP 浏览

首次运行时会自动在程序目录生成 config.json 与 ./root，并初始化 SQLite 用户库，
然后直接启动，无需额外初始化命令。
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading

from . import __version__
from .access import init_controller
from .config import (
    DEFAULT_CONFIG_NAME,
    ensure_config_file,
    ensure_root_dir,
    get_base_dir,
    load_config,
)
from .logging_setup import setup_logging
from .models import db, init_db, normalize_db_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="staticfileserver",
        description="静态文件服务：HTTP 浏览 + WebDAV（同端口）",
    )
    parser.add_argument("--config", help="配置文件路径（默认程序目录下 config.json）")
    parser.add_argument("--root", help="覆盖服务根目录")
    parser.add_argument("--port", type=int, help="覆盖监听端口")
    parser.add_argument("--no-webdav", action="store_true", help="禁用 WebDAV（仅提供 HTTP 浏览）")
    parser.add_argument("--log-level", help="覆盖日志级别")
    parser.add_argument("--version", action="version", version=f"StaticFileServer {__version__}")
    return parser


def create_application(config):
    """构建 Flask 应用并绑定数据库（供 server 与初始化共用）。"""
    from .http_server import create_flask_app
    from .server import set_flask_app

    app = create_flask_app(config)
    app.config["SQLALCHEMY_DATABASE_URI"] = config.database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    set_flask_app(app)
    return app


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 启动前确保程序目录下存在 config.json；不存在则用默认模板创建
    config_path = args.config or os.path.join(get_base_dir(), DEFAULT_CONFIG_NAME)
    created_config = ensure_config_file(config_path)

    config = load_config(config_path)

    if args.root:
        config.root = os.path.abspath(args.root)
    if args.port:
        config.server.port = int(args.port)
    if args.log_level:
        config.log_level = args.log_level.upper()
    if args.no_webdav:
        config.webdav_server.enabled = False

    # SQLite 相对路径锚定到配置文件所在目录（与 root 同一锚点），
    # 避免配置与数据库分家。
    _anchor = os.path.dirname(os.path.abspath(config.config_path)) if config.config_path else get_base_dir()
    config.database_url = normalize_db_url(config.database_url, base_dir=_anchor)

    log = setup_logging(config.log_level, config.log_file, base_dir=get_base_dir())

    if created_config:
        log.info("未找到配置，已生成默认配置: %s", created_config)

    if not os.path.isdir(config.root):
        ensure_root_dir(config.root)
        log.info("根目录不存在，已自动创建: %s", config.root)

    log.info("StaticFileServer %s 启动，配置文件=%s", __version__, config.config_path or "(默认)")
    log.info("服务根目录: %s", config.root)

    # 初始化全局准入控制器（两协议共享，支持管理界面热重载）
    init_controller(config)
    log.info(
        "IP 访问控制: %s（白名单 %d 条 / 黑名单 %d 条）",
        "已启用" if config.access_enabled else "未启用",
        len(config.access_whitelist),
        len(config.access_blacklist),
    )

    # ---------- 数据库初始化（Flask-SQLAlchemy） ----------
    app = create_application(config)
    try:
        init_db(app, initial_user=config.initial_user)
        log.info("数据库: %s", config.database_url)
    except Exception as e:  # noqa: BLE001
        log.error("数据库初始化失败，无法继续: %s", e)
        return 1

    stop_event = threading.Event()

    def _shutdown(signum, frame):  # noqa: ARG001
        log.info("收到退出信号 %s，正在停止...", signum)
        stop_event.set()

    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is not None:
            try:
                signal.signal(sig, _shutdown)
            except (ValueError, OSError):
                pass

    servers: dict[str, object] = {}

    try:
        # 单端口统一服务：Flask(HTTP) 与 WebDAV 合并到一个 WSGI 应用
        from . import server as unified

        srv = unified.run(config, block=True, server_holder=[servers.setdefault("main", None)])
        servers["main"] = srv
        return 0
    except KeyboardInterrupt:
        log.info("Ctrl+C，正在停止...")
    finally:
        for srv in servers.values():
            if srv is None:
                continue
            try:
                srv.stop()
            except Exception:  # noqa: BLE001
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
