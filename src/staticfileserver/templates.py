"""共享模板与目录渲染工具。"""

from __future__ import annotations

import html
import os
import posixpath

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 820px; padding: 0 1rem; color: #222; }}
  h2 {{ border-bottom: 1px solid #e3e3e3; padding-bottom: .4rem; }}
  ul {{ list-style: none; padding: 0; }}
  li {{ padding: .35rem .5rem; border-radius: 6px; }}
  li:hover {{ background: #f5f5f5; }}
  a {{ color: #0b6bcb; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .meta {{ color: #888; font-size: .85rem; margin-left: .6rem; }}
  form {{ margin-top: 1rem; }}
  input[type=file] {{ margin-right: .5rem; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def render_page(title: str, body: str) -> str:
    return PAGE_TEMPLATE.format(title=html.escape(title), body=body)


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def render_directory(subpath: str, full_path: str, url_base: str = "/") -> str:
    """渲染目录浏览页；url_base 为路由前缀（如 / 或 /dav/）。"""
    subpath = subpath.strip("/")
    items: list[str] = []

    parent_sub = posixpath.dirname(subpath)
    parent_path = f"{url_base.rstrip('/')}/{parent_sub}" if parent_sub else url_base
    if not parent_path.endswith("/"):
        parent_path += "/"
    items.append(f'<li><a href="{html.escape(parent_path)}">.. 返回上级</a></li>')

    try:
        entries = sorted(os.listdir(full_path), key=lambda e: (not os.path.isdir(os.path.join(full_path, e)), e.lower()))
    except OSError:
        entries = []

    for entry in entries:
        entry_full = os.path.join(full_path, entry)
        entry_rel = f"{subpath}/{entry}" if subpath else entry
        href = posixpath.join(url_base.rstrip("/") or "/", entry_rel)
        if os.path.isdir(entry_full):
            if not href.endswith("/"):
                href += "/"
            items.append(f'<li>[文件夹] <a href="{html.escape(href)}">{html.escape(entry)}/</a></li>')
        else:
            try:
                size = format_size(os.path.getsize(entry_full))
            except OSError:
                size = "-"
            items.append(
                f'<li>[文件] <a href="{html.escape(href)}">{html.escape(entry)}</a>'
                f'<span class="meta">{size}</span></li>'
            )

    body = f"""
<h2>目录浏览 /{html.escape(subpath)}</h2>
<ul>
{''.join(items)}
</ul>
"""
    return render_page(f"目录: /{subpath}", body)


def render_upload_page(url_base: str = "/", upload_action: str = "/api/upload") -> str:
    safe_base = html.escape(url_base.rstrip("/") or "/")
    body = f"""
<h2>文件上传</h2>
<form action="{html.escape(upload_action)}" method="post" enctype="multipart/form-data">
  <input type="file" name="file" required>
  <button type="submit">上传</button>
</form>
<p><a href="{safe_base}/">返回目录浏览</a></p>
"""
    return render_page("文件上传", body)
