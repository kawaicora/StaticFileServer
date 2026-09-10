"""SQLAlchemy 模型与初始化（写法参照项目惯例）。

    db: SQLAlchemy = SQLAlchemy()

配合 create_app 使用：

    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {str(e)}")
            logger.error(traceback.format_exc())

口令用 scrypt 散列存储，**不落明文**。
"""

from __future__ import annotations

import os
import traceback

from flask_sqlalchemy import SQLAlchemy

from .logging_setup import get_logger
from .users_db import hash_password, needs_rehash, verify_password

log = get_logger("staticfileserver.models")

db: SQLAlchemy = SQLAlchemy()


class User(db.Model):  # type: ignore[name-defined]
    """用户表。"""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    permissions = db.Column(db.String(16), nullable=False, default="rw")
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    # ---------- 权限 ----------

    @property
    def perms(self) -> set[str]:
        value = (self.permissions or "").strip().lower()
        if value in ("readonly", "ro", "read_only", "read-only", "read"):
            return {"r"}
        return {ch for ch in value if ch in ("r", "w")}

    @property
    def can_read(self) -> bool:
        return "r" in self.perms

    @property
    def can_write(self) -> bool:
        return "w" in self.perms

    @property
    def password_hashed(self) -> bool:
        return (self.password_hash or "").startswith("scrypt$")

    # ---------- 口令 ----------

    def check(self, plain: str) -> bool:
        return verify_password(self.password_hash, plain)

    def set_password(self, plain: str) -> None:
        self.password_hash = hash_password(plain)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "permissions": self.permissions,
            "has_password": bool(self.password_hash),
            "password_hashed": self.password_hashed,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.username} {self.permissions}>"


def normalize_db_url(url: str, base_dir: str = "") -> str:
    """把相对 sqlite 路径锚定到基准目录，避免受工作目录影响。

    锚点优先级与 root 一致：配置文件所在目录。
    """
    if not url.startswith("sqlite:"):
        return url
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return url
    rel = url[len(prefix):]
    if os.path.isabs(rel) or rel == ":memory:":
        return url
    anchor = base_dir or os.getcwd()
    return prefix + os.path.normpath(os.path.join(anchor, rel))


def init_db(app, initial_user: dict | None = None) -> None:
    """建表 + 首次填充初始账号。

    写法与项目其他地方一致：create_all 包在 app_context + try/except 里，
    失败时打印完整堆栈，便于定位。
    """
    with app.app_context():
        try:
            db.create_all()
            log.info("Database tables created successfully")
        except Exception as e:  # noqa: BLE001
            log.error(f"Failed to create database tables: {str(e)}")
            log.error(traceback.format_exc())
            raise

        # 库为空时写入初始账号（默认 admin/admin），哈希存储
        if not db.session.query(User.id).first():
            seed = initial_user or {}
            username = str(seed.get("username") or "admin")
            password = str(seed.get("password") or "admin")
            permissions = str(seed.get("permissions") or "rw")
            user = User(username=username, permissions=permissions)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            log.info("用户表为空，已创建初始账号: %s（口令已散列存储）", username)


def authenticate(username: str | None, password: str | None) -> User | None:
    """校验账号口令；命中旧格式（明文/sha256）时自动升级为 scrypt。"""
    if not username or password is None:
        return None
    user = db.session.query(User).filter_by(username=username).first()
    if user is None or not user.check(password):
        return None
    if needs_rehash(user.password_hash):
        try:
            user.set_password(password)
            db.session.commit()
            log.info("已升级口令散列算法: %s", username)
        except Exception:  # noqa: BLE001
            db.session.rollback()
    return user


def list_users() -> list[User]:
    return db.session.query(User).order_by(User.username).all()


def get_user(username: str) -> User | None:
    return db.session.query(User).filter_by(username=username).first()


def upsert_user(username: str, password: str | None, permissions: str) -> User:
    """新增或修改用户。password 为 None 时保留原口令。"""
    user = get_user(username)
    if user is None:
        user = User(username=username, permissions=permissions)
        if password:
            user.set_password(password)
        else:
            raise ValueError("新用户必须设置密码")
        db.session.add(user)
    else:
        user.permissions = permissions
        if password:
            user.set_password(password)
    db.session.commit()
    return user


def delete_user(username: str) -> bool:
    user = get_user(username)
    if user is None:
        return False
    db.session.delete(user)
    db.session.commit()
    return True


def count_users() -> int:
    return int(db.session.query(User.id).count())
