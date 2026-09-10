"""管理界面与 API。

入口：/view/admin
鉴权：必须是拥有写权限（rw）的已认证用户（账号存于 SQLite）。

API（均需写权限）：
    GET    /api/admin/state           读取当前状态（用户来自 SQLite）
    POST   /api/admin/users           新增或修改用户（口令 scrypt 散列）
    DELETE /api/admin/users/<name>    删除用户
    POST   /api/admin/access          保存 IP 黑白名单与开关
    POST   /api/admin/reload          重新从磁盘载入配置
"""

from __future__ import annotations

from flask import Flask, Response, jsonify, render_template, request

from .access import AccessController
from .auth import Authenticator
from .iprules import validate_entries
from .logging_setup import get_logger

log = get_logger("staticfileserver.admin")


def _unauthorized(realm: str) -> Response:
    return Response(
        "需要管理员权限",
        401,
        {"WWW-Authenticate": f'Basic realm="{realm}"', "Content-Type": "text/plain; charset=utf-8"},
    )


def register_admin(app: Flask, controller: AccessController) -> None:
    """把管理页面与 API 注册到 Flask app 上。"""
    auth = Authenticator(controller.config)

    def _current_user():
        return auth.check_basic_header(request.headers.get("Authorization"))

    def _require_admin() -> Response | None:
        user = _current_user()
        if user is None or not user.can_write:
            return _unauthorized(controller.config.realm)
        return None

    def _persist_access() -> None:
        """把 IP 黑白名单与开关写入数据库（不再写 config.json）。"""
        from .models import save_access_config

        cfg = controller.config
        save_access_config(
            enabled=cfg.access_enabled,
            whitelist=list(cfg.access_whitelist),
            blacklist=list(cfg.access_blacklist),
            trust_proxy_headers=cfg.trust_proxy_headers,
        )

    # ---------- 页面 ----------

    @app.route("/view/admin", methods=["GET"])
    def admin_page():
        denied = _require_admin()
        if denied:
            return denied
        user = _current_user()
        return render_template("admin.html", admin_user=user.username)

    # ---------- API ----------

    @app.route("/api/admin/state", methods=["GET"])
    def admin_state():
        denied = _require_admin()
        if denied:
            return denied
        from .models import list_users

        cfg = controller.config
        users = [u.to_dict() for u in list_users()]
        return jsonify(
            {
                "users": users,
                "access": {
                    "enabled": cfg.access_enabled,
                    "whitelist": list(cfg.access_whitelist),
                    "blacklist": list(cfg.access_blacklist),
                    "trust_proxy_headers": cfg.trust_proxy_headers,
                },
                "config_path": cfg.config_path,
                "database_url": cfg.database_url,
                "root": cfg.root,
                "webdav_mount": cfg.webdav_mount or "/",
            }
        )

    @app.route("/api/admin/users", methods=["POST"])
    def admin_save_user():
        denied = _require_admin()
        if denied:
            return denied
        from .models import upsert_user

        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", "")).strip()
        if not username:
            return jsonify({"ok": False, "error": "用户名不能为空"}), 400

        permissions = str(payload.get("permissions", "rw")).strip().lower()
        if permissions not in ("r", "rw", "ro", "readonly", "read", "read_only", "read-only"):
            return jsonify({"ok": False, "error": "权限只能是 r 或 rw"}), 400

        password = payload.get("password")
        password = str(password) if password else None

        try:
            # hash 参数仅为界面兼容：无论是否勾选，都只存 scrypt 散列
            upsert_user(username, password, permissions)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        log.info("用户已保存: %s (%s)", username, permissions)
        return jsonify({"ok": True, "username": username})

    @app.route("/api/admin/users/<name>", methods=["DELETE"])
    def admin_delete_user(name: str):
        denied = _require_admin()
        if denied:
            return denied
        from .models import count_users, delete_user

        if count_users() <= 1:
            return jsonify({"ok": False, "error": "至少需要保留一个用户"}), 400
        if not delete_user(name):
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        log.info("用户已删除: %s", name)
        return jsonify({"ok": True})

    @app.route("/api/admin/access", methods=["POST"])
    def admin_save_access():
        denied = _require_admin()
        if denied:
            return denied
        payload = request.get_json(silent=True) or {}
        whitelist = [str(x).strip() for x in (payload.get("whitelist") or []) if str(x).strip()]
        blacklist = [str(x).strip() for x in (payload.get("blacklist") or []) if str(x).strip()]
        enabled = bool(payload.get("enabled", False))
        trust = bool(payload.get("trust_proxy_headers", True))

        errors = validate_entries(whitelist) + validate_entries(blacklist)
        if errors:
            return jsonify({"ok": False, "error": "规则格式错误：" + "；".join(errors)}), 400

        cfg = controller.config
        cfg.raw.setdefault("access", {})
        cfg.access_enabled = enabled
        cfg.access_whitelist = whitelist
        cfg.access_blacklist = blacklist
        cfg.trust_proxy_headers = trust
        _persist_access()
        controller.reload(cfg)
        log.info("访问规则已保存到数据库: 启用=%s 白%d 黑%d", enabled, len(whitelist), len(blacklist))
        return jsonify({"ok": True})

    @app.route("/api/admin/reload", methods=["POST"])
    def admin_reload():
        denied = _require_admin()
        if denied:
            return denied
        controller.reload()
        return jsonify({"ok": True})
