"""配置加载与基础工具。

优先级：命令行参数 > 环境变量 > 配置文件 > 内置默认值。

配置文件为 JSON，默认读取程序目录下的 config.json（可用 --config 指定）。
所有服务共用同一份认证账号，口令支持明文或 sha256:<hex>，避免把明文写进仓库。
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

DEFAULT_CONFIG_NAME = "config.json"

CONFIG_TEMPLATE = {
    "root": "./root",
    "allow_access_base_dir_up_level": False,
    "http": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 80,
        "debug": False,
    },
    "webdav": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 8081,
        "mount": "/dav",
    },
    "ftp": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 21,
        "banner": "StaticFileServer FTP",
    },
    "auth": {
        "enabled": True,
        "realm": "StaticFileServer",
        "anonymous_readonly": True,
        "users": {
            "admin": {
                "password": "admin",
                "permissions": "rw",
            }
        },
    },
    "log": {
        "level": "INFO",
        "file": "",
    },
}


def get_base_dir() -> str:
    """返回程序基准目录：打包后为 exe 所在目录，源码运行为项目根目录。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    # app/config.py -> 项目根
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, os.pardir))


def ensure_root_dir(root: str) -> str | None:
    """确保服务根目录存在；已存在返回 None，新建则返回路径。"""
    path = os.path.abspath(root)
    if os.path.isdir(path):
        return None
    os.makedirs(path, exist_ok=True)
    return path


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def hash_password(plain: str) -> str:
    return "sha256:" + hashlib.sha256(plain.encode("utf-8")).hexdigest()


def verify_password(stored: str, plain: str) -> bool:
    if stored.startswith("sha256:"):
        return hashlib.sha256(plain.encode("utf-8")).hexdigest() == stored[7:]
    return stored == plain


@dataclass
class AuthUser:
    username: str
    password: str
    permissions: str = "rw"

    @property
    def perms(self) -> set[str]:
        """Linux 风格权限集合，支持 r / w / rw / ro(readonly)。"""
        value = (self.permissions or "").strip().lower()
        if value in ("readonly", "ro", "read_only", "read-only", "read"):
            return {"r"}
        flags: set[str] = set()
        for ch in value:
            if ch in ("r", "w"):
                flags.add(ch)
        return flags

    @property
    def can_read(self) -> bool:
        return "r" in self.perms

    @property
    def can_write(self) -> bool:
        return "w" in self.perms

    def check(self, plain: str) -> bool:
        return verify_password(self.password, plain)


@dataclass
class ServerConfig:
    host: str
    port: int
    enabled: bool = True
    extra: dict = field(default_factory=dict)


@dataclass
class AppConfig:
    root: str
    allow_access_base_dir_up_level: bool
    http: ServerConfig
    webdav: ServerConfig
    ftp: ServerConfig
    auth_enabled: bool
    realm: str
    anonymous_readonly: bool
    users: dict[str, AuthUser]
    log_level: str
    log_file: str
    config_path: str
    raw: dict = field(default_factory=dict)

    @property
    def auth_required(self) -> bool:
        """是否强制认证（关闭匿名只读时需要）。"""
        return self.auth_enabled and not self.anonymous_readonly

    def authenticate(self, username: str | None, password: str | None) -> AuthUser | None:
        if not username:
            return None
        user = self.users.get(username)
        if user and password is not None and user.check(password):
            return user
        return None

    @staticmethod
    def from_dict(data: dict, config_path: str = "", base_dir: str = "") -> "AppConfig":
        merged = _deep_merge(CONFIG_TEMPLATE, data or {})

        raw_root = str(merged["root"])
        if os.path.isabs(raw_root):
            root = os.path.abspath(raw_root)
        else:
            # 相对路径以配置文件所在目录为基准（无配置文件时用程序目录），
            # 保证“配置与 root 目录一起放置”时行为一致。
            anchor = os.path.dirname(os.path.abspath(config_path)) if config_path else (base_dir or os.getcwd())
            root = os.path.normpath(os.path.join(anchor, raw_root))
        http = merged["http"]
        webdav = merged["webdav"]
        ftp = merged["ftp"]
        auth = merged["auth"]
        log = merged["log"]

        users = {
            name: AuthUser(
                username=name,
                password=str(info.get("password", "")),
                permissions=str(info.get("permissions", "rw")),
            )
            for name, info in (auth.get("users") or {}).items()
        }

        return AppConfig(
            root=root,
            allow_access_base_dir_up_level=bool(merged["allow_access_base_dir_up_level"]),
            http=ServerConfig(host=str(http["host"]), port=int(http["port"]), enabled=bool(http["enabled"])),
            webdav=ServerConfig(
                host=str(webdav["host"]),
                port=int(webdav["port"]),
                enabled=bool(webdav["enabled"]),
                extra={"mount": str(webdav.get("mount", "/dav"))},
            ),
            ftp=ServerConfig(
                host=str(ftp["host"]),
                port=int(ftp["port"]),
                enabled=bool(ftp["enabled"]),
                extra={"banner": str(ftp.get("banner", "StaticFileServer FTP"))},
            ),
            auth_enabled=bool(auth["enabled"]),
            realm=str(auth["realm"]),
            anonymous_readonly=bool(auth["anonymous_readonly"]),
            users=users,
            log_level=str(log["level"]).upper(),
            log_file=str(log.get("file", "") or ""),
            config_path=config_path,
            raw=merged,
        )


def _env_overrides(cfg: AppConfig) -> AppConfig:
    """允许用环境变量覆盖关键项（容器/CI 友好）。"""
    env = os.environ
    if env.get("SFS_ROOT"):
        cfg.root = os.path.abspath(env["SFS_ROOT"])
    if env.get("SFS_HTTP_PORT"):
        cfg.http.port = int(env["SFS_HTTP_PORT"])
    if env.get("SFS_WEBDAV_PORT"):
        cfg.webdav.port = int(env["SFS_WEBDAV_PORT"])
    if env.get("SFS_FTP_PORT"):
        cfg.ftp.port = int(env["SFS_FTP_PORT"])
    if env.get("SFS_LOG_LEVEL"):
        cfg.log_level = env["SFS_LOG_LEVEL"].upper()
    return cfg


def load_config(path: str | None = None) -> AppConfig:
    """加载配置；文件不存在时返回默认配置（不落盘）。"""
    base_dir = get_base_dir()
    candidates = [path] if path else [
        os.path.join(base_dir, DEFAULT_CONFIG_NAME),
        os.path.join(os.getcwd(), DEFAULT_CONFIG_NAME),
    ]

    data: dict[str, Any] = {}
    used_path = ""
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            # 兼容 Windows 下带 BOM 的 UTF-8 配置文件
            data = _load_json_file(candidate)
            used_path = os.path.abspath(candidate)
            break

    cfg = AppConfig.from_dict(data, used_path, base_dir=base_dir)
    cfg = _env_overrides(cfg)

    if not cfg.config_path:
        cfg.config_path = str(candidate_path_pending(base_dir))
    return cfg


def candidate_path_pending(base_dir: str) -> str:
    return os.path.join(base_dir, DEFAULT_CONFIG_NAME)


def write_default_config(path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(CONFIG_TEMPLATE, fh, ensure_ascii=False, indent=2)
    return os.path.abspath(path)


def _load_json_file(path: str) -> dict:
    """读 JSON，容忍 UTF-8 BOM。"""
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def resolve_safe_path(root: str, subpath: str, allow_up_level: bool) -> str | None:
    """把请求子路径解析为磁盘路径，越界返回 None。"""
    subpath = (subpath or "").replace("\\", "/").lstrip("/")
    subpath = subpath.replace("/", os.sep)

    full_path = os.path.normpath(os.path.join(root, subpath))
    root_norm = os.path.normpath(root)

    if allow_up_level:
        if os.name == "nt" and os.path.splitdrive(full_path)[0] != os.path.splitdrive(root_norm)[0]:
            return None
        return full_path

    if full_path == root_norm:
        return full_path
    if not full_path.startswith(root_norm + os.sep):
        return None
    return full_path
