"""统一真实 IP 解析。

HTTP 可能经由 Cloudflare、Nginx、FRP 等代理，`REMOTE_ADDR` 往往不是真实来源。
按可信度依次读取常见头部：

    CF-Connecting-IP       Cloudflare
    X-Forwarded-For        通用（取最左，即最初客户端）
    X-Real-IP              Nginx
    True-Client-IP         Cloudflare Enterprise / Akamai
    X-Client-IP
    Forwarded              RFC 7239

HTTP / WebDAV 共用同一份逻辑，保证 IP 黑白名单看到的是同一个地址。
"""

from __future__ import annotations

import ipaddress
import re

# 头部按优先级排列
_HEADERS = (
    "HTTP_CF_CONNECTING_IP",
    "HTTP_TRUE_CLIENT_IP",
    "HTTP_X_REAL_IP",
    "HTTP_X_CLIENT_IP",
    "HTTP_X_FORWARDED_FOR",
    "HTTP_FORWARDED",
)

_FORWARDED_RE = re.compile(r"for=(?:\"?)(\[[0-9a-fA-F:]+\]|[^;,\s\"]+)")


def normalize_ip(value: str | None) -> str | None:
    """把各种写法规整为纯 IP 字符串；失败返回 None。

    处理：端口后缀（1.2.3.4:5678）、IPv6 方括号（[::1]:80）、
    引号与 for= 前缀、RFC7239 的 quoted-string。
    """
    if not value:
        return None
    text = value.strip().strip('"').strip()

    m = _FORWARDED_RE.search(text)
    if m:
        text = m.group(1)

    text = text.strip('"').strip()
    if not text:
        return None

    # [::1]:80 / [::1]
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            text = text[1:end]

    # IPv4:port（注意不要误伤 IPv6 的冒号）
    if text.count(":") == 1 and "." in text:
        host, _, port = text.partition(":")
        if port.isdigit():
            text = host

    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def get_real_ip(environ: dict, trust_headers: bool = True) -> str:
    """从 WSGI environ 解析客户端真实 IP。"""
    if trust_headers:
        for header in _HEADERS:
            raw = environ.get(header)
            if not raw:
                continue
            # X-Forwarded-For 可能是 "client, proxy1, proxy2"
            candidate = raw.split(",")[0]
            ip = normalize_ip(candidate)
            if ip:
                return ip

    return normalize_ip(environ.get("REMOTE_ADDR")) or (environ.get("REMOTE_ADDR") or "-")


def is_private(ip: str | None) -> bool:
    """是否内网/回环地址（用于诊断与日志）。"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local
