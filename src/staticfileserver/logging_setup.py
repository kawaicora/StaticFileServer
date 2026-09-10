"""统一日志初始化。"""

from __future__ import annotations

import logging
import os
import sys


def setup_logging(level: str = "INFO", log_file: str = "") -> logging.Logger:
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

    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)) or ".", exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def get_logger(name: str = "staticfileserver") -> logging.Logger:
    return logging.getLogger(name)
