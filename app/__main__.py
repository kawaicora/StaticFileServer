"""命令行入口与多服务编排。

用法：
    python -m staticfileserver                 # 按配置启动全部启用服务
    python -m staticfileserver --only http     # 只启动 HTTP
    python -m staticfileserver --init-config   # 生成默认 config.json
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading

from . import __version__
from .config import candidate_path_pending, get_base_dir, load_config, write_default_config
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
    parser.add_argument("--init-config", action="store_true", help="生成默认配置文件后退出")
    parser.add_argument("--version", action="version", version=f"StaticFileServer {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.init_config:
        target = args.config or candidate_path_pending(get_base_dir())
        path = write_default_config(target)
        print(f"已生成默认配置: {path}")
        # 确保默认根目录存在
        from .config import ensure_root_dir

        cfg = load_config(path)
        created = ensure_root_dir(cfg.root)
        if created:
            print(f"已创建根目录: {created}")
        return 0

    config = load_config(args.config)

    if args.root:
        import os

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

    import os

    if not os.path.isdir(config.root):
        from .config import ensure_root_dir

        ensure_root_dir(config.root)
        log.info("根目录不存在，已自动创建: %s", config.root)

    log.info("StaticFileServer %s 启动，配置文件=%s", __version__, config.config_path or "(默认)")
    log.info("服务根目录: %s", config.root)

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
