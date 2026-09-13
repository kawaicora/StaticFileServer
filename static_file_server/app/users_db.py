"""用户库：SQLite + scrypt 密码散列。

- 用户与口令存在 SQLite（默认 users.db），**不落明文**
- 口令用标准库 hashlib.scrypt 加盐散列，格式：
      scrypt$<n>$<r>$<p>$<salt_hex>$<hash_hex>
- 兼容旧的 sha256:<hex> 与明文（仅用于首次从 config.json 迁移/校验，
  校验通过后会被重写为 scrypt）
- 提供 authenticate / verify，供 HTTP / WebDAV 共用
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass

from .logging_setup import get_logger

log = get_logger("staticfileserver.usersdb")

# scrypt 参数（约 16MB 内存 / 次，单机小服务足够且不拖慢登录）
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16

SCHEME = "scrypt"


def hash_password(plain: str) -> str:
    """生成 scrypt 散列串。"""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        plain.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"{SCHEME}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(stored: str, plain: str) -> bool:
    """校验口令。支持 scrypt / sha256:<hex> / 明文（迁移期兼容）。"""
    if not stored:
        return False

    if stored.startswith(SCHEME + "$"):
        try:
            _, n, r, p, salt_hex, hash_hex = stored.split("$")
            digest = hashlib.scrypt(
                plain.encode("utf-8"),
                salt=bytes.fromhex(salt_hex),
                n=int(n),
                r=int(r),
                p=int(p),
                dklen=len(bytes.fromhex(hash_hex)),
            )
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(digest.hex(), hash_hex)

    if stored.startswith("sha256:"):
        return hmac.compare_digest(
            hashlib.sha256(plain.encode("utf-8")).hexdigest(), stored[7:]
        )

    # 明文（旧配置遗留）：常数时间比较
    return hmac.compare_digest(stored, plain)


def needs_rehash(stored: str) -> bool:
    """是否应升级为 scrypt（明文或 sha256）。"""
    return not (stored or "").startswith(SCHEME + "$")


@dataclass
class DbUser:
    username: str
    password_hash: str
    permissions: str = "rw"

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

    def check(self, plain: str) -> bool:
        return verify_password(self.password_hash, plain)


class UserDatabase:
    """SQLite 用户库（线程安全）。"""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._lock = threading.RLock()
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username      TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    permissions   TEXT NOT NULL DEFAULT 'rw',
                    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )

    # ---------- 查询 ----------

    def list_users(self) -> list[DbUser]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT username, password_hash, permissions FROM users ORDER BY username"
            ).fetchall()
        return [DbUser(r["username"], r["password_hash"], r["permissions"]) for r in rows]

    def get(self, username: str) -> DbUser | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT username, password_hash, permissions FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None:
            return None
        return DbUser(row["username"], row["password_hash"], row["permissions"])

    def count(self) -> int:
        with self._lock, self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    # ---------- 写入 ----------

    def upsert(self, username: str, password_hash: str, permissions: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, permissions)
                VALUES (?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    permissions   = excluded.permissions,
                    updated_at    = datetime('now')
                """,
                (username, password_hash, permissions),
            )

    def delete(self, username: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            return cur.rowcount > 0

    # ---------- 认证 ----------

    def authenticate(self, username: str | None, password: str | None) -> DbUser | None:
        if not username or password is None:
            return None
        user = self.get(username)
        if user is None or not user.check(password):
            return None
        # 旧格式（明文 / sha256）校验通过后自动升级为 scrypt
        if needs_rehash(user.password_hash):
            try:
                self.upsert(username, hash_password(password), user.permissions)
                log.info("已升级口令散列算法: %s", username)
            except Exception:  # noqa: BLE001
                pass
        return user

    def seed_if_empty(self, username: str, password: str, permissions: str = "rw") -> bool:
        """库为空时写入初始账号。返回是否写入。"""
        if self.count() > 0:
            return False
        self.upsert(username, hash_password(password), permissions)
        log.info("用户库为空，已创建初始账号: %s", username)
        return True
