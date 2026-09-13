"""Jinja2 模板过滤器。"""

from __future__ import annotations


def format_size(size: int) -> str:
    """把字节数格式化为可读字符串。"""
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def register_filters(app) -> None:
    app.jinja_env.filters["filesize"] = format_size
