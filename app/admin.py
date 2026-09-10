"""管理界面与 API。

入口：/view/admin
鉴权：必须是拥有写权限（rw）的已认证用户。

API（均需写权限）：
    GET    /api/admin/state           读取当前配置（口令只回传是否设置）
    POST   /api/admin/users           新增或修改用户
    DELETE /api/admin/users/<name>    删除用户
    POST   /api/admin/access          保存 IP 黑白名单与开关
    POST   /api/admin/reload          重新从磁盘载入配置
"""

from __future__ import annotations

from flask import Flask, Response, jsonify, render_template, request

from .access import AccessController
from .auth import Authenticator, parse_basic_auth
from .config import hash_password, save_config
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

    def _persist() -> str:
        """把当前内存配置写回磁盘。"""
        cfg = controller.config
        data = dict(cfg.raw)
        data.setdefault("access", {})
        data["access"] = {
            "enabled": cfg.access_enabled,
            "whitelist": list(cfg.access_whitelist),
            "blacklist": list(cfg.access_blacklist),
        }
        data.setdefault("auth", {})
        data["auth"]["users"] = {
            name: {"password": u.password, "permissions": u.permissions}
            for name, u in cfg.users.items()
        }
        return save_config(cfg.config_path, data)

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
        cfg = controller.config
        users = [
            {
                "username": u.username,
                "permissions": u.permissions,
                "has_password": bool(u.password),
                "password_hashed": u.password.startswith("sha256:"),
            }
            for u in sorted(cfg.users.values(), key=lambda x: x.username)
        ]
        return jsonify(
            {
                "users": users,
                "access": {
                    "enabled": cfg.access_enabled,
                    "whitelist": list(cfg.access_whitelist),
                    "blacklist": list(cfg.access_blacklist),
                },
                "config_path": cfg.config_path,
                "root": cfg.root,
            }
        )

    @app.route("/api/admin/users", methods=["POST"])
    def admin_save_user():
        denied = _require_admin()
        if denied:
            return denied
        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", "")).strip()
        if not username:
            return jsonify({"ok": False, "error": "用户名不能为空"}), 400

        permissions = str(payload.get("permissions", "rw")).strip().lower()
        if permissions not in ("r", "rw", "ro", "readonly", "read", "read_only", "read-only"):
            return jsonify({"ok": False, "error": "权限只能是 r 或 rw"}), 400

        cfg = controller.config
        existing = cfg.users.get(username)
        password = payload.get("password")
        hashed = bool(payload.get("hash", False))

        if existing is None:
            if not password:
                return jsonify({"ok": False, "error": "新用户必须设置密码"}), 400
        elif not password:
            # 未填密码 -> 沿用旧口令
            password = existing.password
            hashed = existing.password.startswith("sha256:")

        new_pw = password
        if password and hashed and not str(password).startswith("sha256:"):
            new_pw = hash_password(str(password))

        raw_users = dict(cfg.raw.get("auth", {}).get("users", {}) or {})
        raw_users[username] = {"password": new_pw, "permissions": permissions}
        cfg.raw.setdefault("auth", {})["users"] = raw_users

        from .config import AuthUser

        cfg.users[username] = AuthUser(username=username, password=new_pw, permissions=permissions)
        _persist()
        controller.reload(cfg)
        log.info("用户已保存: %s (%s)", username, permissions)
        return jsonify({"ok": True, "username": username})

    @app.route("/api/admin/users/<name>", methods=["DELETE"])
    def admin_delete_user(name: str):
        denied = _require_admin()
        if denied:
            return denied
        cfg = controller.config
        if name not in cfg.users:
            return jsonify({"ok": False, "error": "用户不存在"}), 404
        if len(cfg.users) <= 1:
            return jsonify({"ok": False, "error": "至少需要保留一个用户"}), 400

        del cfg.users[name]
        raw_users = cfg.raw.get("auth", {}).get("users", {}) or {}
        raw_users.pop(name, None)
        cfg.raw.setdefault("auth", {})["users"] = raw_users
        _persist()
        controller.reload(cfg)
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

        errors = validate_entries(whitelist) + validate_entries(blacklist)
        if errors:
            return jsonify({"ok": False, "error": "规则格式错误：" + "；".join(errors)}), 400

        cfg = controller.config
        cfg.access_enabled = enabled
        cfg.access_whitelist = whitelist
        cfg.access_blacklist = blacklist
        _persist()
        controller.reload(cfg)
        log.info("访问规则已保存: 启用=%s 白%d 黑%d", enabled, len(whitelist), len(blacklist))
        return jsonify({"ok": True})

    @app.route("/api/admin/reload", methods=["POST"])
    def admin_reload():
        denied = _require_admin()
        if denied:
            return denied
        controller.reload()
        return jsonify({"ok": True})
