"""统一日志初始化。

- 默认在程序根目录写 app.log
- 启动时若 app.log 已存在，先重命名为 app-[日期时间].log，再新建 app.log
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime

DEFAULT_LOG_NAME = "app.log"


def _rotate_existing(log_file: str) -> str | None:
    """若日志文件已存在，重命名为 app-[YYYYmmdd-HHMMSS].log 并返回新路径。"""
    if not os.path.exists(log_file):
        return None
    base, ext = os.path.splitext(log_file)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    archived = f"{base}-[{stamp}]{ext}"
    # 极端情况下同一秒内重复启动，追加序号避免覆盖
    seq = 1
    while os.path.exists(archived):
        archived = f"{base}-[{stamp}]({seq}){ext}"
        seq += 1
    os.replace(log_file, archived)
    return archived


def setup_logging(
    level: str = "INFO",
    log_file: str = "",
    base_dir: str = ".",
) -> logging.Logger:
    logger = logging.getLogger("staticfileserver")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    # 默认写到程序根目录 app.log；log_file 显式指定则用之
    target = log_file or os.path.join(base_dir, DEFAULT_LOG_NAME)
    target = os.path.abspath(target)

    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    archived = _rotate_existing(target)
    if archived:
        logger.info("已有日志已归档: %s", os.path.basename(archived))

    file_handler = logging.FileHandler(target, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def get_logger(name: str = "staticfileserver") -> logging.Logger:
    return logging.getLogger(name)
