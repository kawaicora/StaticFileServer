"""命令行入口与多服务编排。

用法：
    python -m staticfileserver                 # 按配置启动全部启用服务
    python -m staticfileserver --only http     # 只启动 HTTP

首次运行时会自动在程序目录生成 config.json 与 ./root 后直接启动。
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading

from . import __version__
from .access import init_controller
from .config import DEFAULT_CONFIG_NAME, ensure_config_file, ensure_root_dir, get_base_dir, load_config
from .logging_setup import get_logger, setup_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="staticfileserver",
        description="静态文件服务：HTTP / WebDAV / FTP",
    )
    parser.add_argument("--config", help="配置文件路径（默认程序目录下 config.json）")
    parser.add_argument("--root", help="覆盖服务根目录")
    parser.add_argument("--only", choices=["http", "webdav", "ftp"], help="只启动指定服务")
    parser.add_argument("--no-http", action="store_true", help="禁用 HTTP")
    parser.add_argument("--no-webdav", action="store_true", help="禁用 WebDAV")
    parser.add_argument("--no-ftp", action="store_true", help="禁用 FTP")
    parser.add_argument("--log-level", help="覆盖日志级别")
    parser.add_argument("--version", action="version", version=f"StaticFileServer {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 启动前确保程序目录下存在 config.json；不存在则用默认模板创建
    config_path = args.config or os.path.join(get_base_dir(), DEFAULT_CONFIG_NAME)
    created_config = ensure_config_file(config_path)

    config = load_config(config_path)

    if args.root:
        config.root = os.path.abspath(args.root)
    if args.log_level:
        config.log_level = args.log_level.upper()

    if args.only:
        config.http.enabled = args.only == "http"
        config.webdav.enabled = args.only == "webdav"
        config.ftp.enabled = args.only == "ftp"
    else:
        if args.no_http:
            config.http.enabled = False
        if args.no_webdav:
            config.webdav.enabled = False
        if args.no_ftp:
            config.ftp.enabled = False

    log = setup_logging(config.log_level, config.log_file, base_dir=get_base_dir())

    if created_config:
        log.info("未找到配置，已生成默认配置: %s", created_config)

    if not os.path.isdir(config.root):
        ensure_root_dir(config.root)
        log.info("根目录不存在，已自动创建: %s", config.root)

    log.info("StaticFileServer %s 启动，配置文件=%s", __version__, config.config_path or "(默认)")
    log.info("服务根目录: %s", config.root)

    # 初始化全局准入控制器（三协议共享，支持管理界面热重载）
    init_controller(config)
    log.info(
        "IP 访问控制: %s（白名单 %d 条 / 黑名单 %d 条）",
        "已启用" if config.access_enabled else "未启用",
        len(config.access_whitelist),
        len(config.access_blacklist),
    )

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

    threads: list[threading.Thread] = []
    servers: dict[str, object] = {}

    if config.ftp.enabled:
        from . import ftp_server

        ftp = ftp_server.create_server(config)
        servers["ftp"] = ftp
        t = threading.Thread(target=ftp.serve_forever, name="ftp", daemon=True)
        t.start()
        threads.append(t)
        log.info("FTP 监听 %s:%s", config.ftp.host, config.ftp.port)

    if config.webdav.enabled:
        from . import webdav_server

        # run(block=False) 已在内部启动服务线程
        dav_server = webdav_server.run(config, block=False)
        servers["webdav"] = dav_server
        log.info("WebDAV 监听 %s:%s", config.webdav.host, config.webdav.port)

    try:
        if config.http.enabled:
            from . import http_server

            log.info("HTTP 监听 %s:%s", config.http.host, config.http.port)
            http_server.run(config)  # Flask 阻塞在此
            return 0
        # 没有 HTTP 时主线程等待
        stop_event.wait()
    except KeyboardInterrupt:
        log.info("Ctrl+C，正在停止...")
    finally:
        for name, srv in servers.items():
            try:
                if name == "ftp":
                    srv.close_all()
            except Exception:  # noqa: BLE001
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
