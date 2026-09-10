"""HTTP 静态文件服务（Flask + Jinja2 模板）。

功能：目录浏览、文件下载、上传接口、上传页面。
认证：可选的 HTTP Basic；未认证时按配置决定是否只读。
模板：app/templates/*.html
"""

from __future__ import annotations

import os
import posixpath
import random
import string

from flask import Flask, Response, redirect, render_template, request, send_file

from .auth import Authenticator
from .config import AppConfig, resolve_safe_path
from .filters import register_filters
from .logging_setup import get_logger

log = get_logger("staticfileserver.http")


def get_real_ip() -> str:
    """获取客户端真实 IP，兼容 Cloudflare / FRP / Nginx / 直连。"""
    for header in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
        value = request.headers.get(header)
        if value:
            return value.split(",")[0].strip()
    return request.remote_addr or "-"


def unique_upload_name(base_dir: str, user_filename: str) -> str | None:
    """防御路径穿越并生成不冲突的文件名。"""
    pure_name = os.path.basename(user_filename or "").strip() or "unnamed"
    if not os.path.exists(os.path.join(base_dir, pure_name)):
        return pure_name

    name_no_ext, ext = os.path.splitext(pure_name)
    for _ in range(200):
        suffix = "".join(random.choices(string.ascii_lowercase, k=3))
        candidate = f"{name_no_ext}_{suffix}{ext}"
        if not os.path.exists(os.path.join(base_dir, candidate)):
            return candidate
    return None


def _build_entries(subpath: str, full_path: str, url_base: str) -> list[dict]:
    """扫描目录，构造模板需要的条目列表。"""
    subpath = subpath.strip("/")
    try:
        names = sorted(
            os.listdir(full_path),
            key=lambda e: (not os.path.isdir(os.path.join(full_path, e)), e.lower()),
        )
    except OSError:
        names = []

    entries = []
    for name in names:
        entry_full = os.path.join(full_path, name)
        is_dir = os.path.isdir(entry_full)
        entry_rel = f"{subpath}/{name}" if subpath else name
        href = posixpath.join(url_base.rstrip("/") or "/", entry_rel)
        if is_dir and not href.endswith("/"):
            href += "/"
        size = ""
        if not is_dir:
            try:
                size = os.path.getsize(entry_full)
            except OSError:
                size = 0
        entries.append({"name": name, "is_dir": is_dir, "href": href, "size": size})
    return entries


def create_app(config: AppConfig) -> Flask:
    # static_folder=None：本项目把静态文件服务与 Flask 自身静态资源分开
    app = Flask(__name__, static_folder=None)
    register_filters(app)
    auth = Authenticator(config)
    app.config["SFS_CONFIG"] = config

    @app.before_request
    def _log_request():
        user = auth.check_basic_header(request.headers.get("Authorization"))
        who = user.username if user else "anonymous"
        log.info("%s %s %s -> user=%s", request.method, get_real_ip(), request.path, who)

    def _require_write() -> Response | None:
        """写操作鉴权；返回非 None 表示应直接返回该响应。"""
        user = auth.check_basic_header(request.headers.get("Authorization"))
        if auth.can_write(user):
            return None
        return Response("需要写入权限", 401, {"WWW-Authenticate": f'Basic realm="{config.realm}"'})

    def _require_read() -> Response | None:
        user = auth.check_basic_header(request.headers.get("Authorization"))
        if auth.can_read(user):
            return None
        return Response("需要认证", 401, {"WWW-Authenticate": f'Basic realm="{config.realm}"'})

    @app.route("/api/upload", methods=["POST"])
    def upload_file():
        denied = _require_write()
        if denied:
            return denied
        if "file" not in request.files:
            return "未选择文件", 400
        file = request.files["file"]
        if not file.filename:
            return "文件名为空", 400

        safe_name = unique_upload_name(config.root, file.filename)
        if not safe_name:
            return "文件名冲突过多，无法生成安全文件名", 500
        file.save(os.path.join(config.root, safe_name))
        log.info("上传成功: %s", safe_name)
        return f"上传成功，文件名：{safe_name}"

    @app.route("/view/upload", methods=["GET"])
    def upload_page():
        denied = _require_read()
        if denied:
            return denied
        return render_template("upload.html", url_base="/", upload_action="/api/upload")

    @app.route("/", defaults={"subpath": ""})
    @app.route("/<path:subpath>")
    def list_dir(subpath: str):
        denied = _require_read()
        if denied:
            return denied

        full_path = resolve_safe_path(config.root, subpath, config.allow_access_base_dir_up_level)
        if full_path is None:
            return render_template("error.html", code=403, message="禁止访问：路径越界", url_base="/"), 403

        if os.path.isdir(full_path) and not request.path.endswith("/"):
            return redirect(request.path + "/", code=301)

        if os.path.isfile(full_path):
            log.info("下载: %s", full_path)
            return send_file(full_path)

        if os.path.isdir(full_path):
            stripped = subpath.strip("/")
            parent_sub = posixpath.dirname(stripped)
            parent_link = f"/{parent_sub}/" if parent_sub else "/"
            return render_template(
                "directory.html",
                subpath=stripped,
                parent_link=parent_link,
                entries=_build_entries(subpath, full_path, "/"),
            )

        return render_template("error.html", code=404, message="Not Found", url_base="/"), 404

    return app


def run(config: AppConfig) -> None:
    app = create_app(config)
    log.info("HTTP 服务启动: http://%s:%s  根目录=%s", config.http.host, config.http.port, config.root)
    app.run(
        host=config.http.host,
        port=config.http.port,
        debug=config.http.extra.get("debug", False),
        threaded=True,
    )
