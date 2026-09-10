"""入口脚本：源码运行与 PyInstaller 打包的统一入口。

    python main.py
    python main.py --init-config
"""

import os
import sys


def _bootstrap_src_path() -> None:
    """源码运行时把 src/ 加入 sys.path；打包后模块已内联，无需处理。"""
    if getattr(sys, "frozen", False):
        return
    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(here, "src")
    if os.path.isdir(src) and src not in sys.path:
        sys.path.insert(0, src)


_bootstrap_src_path()

from staticfileserver.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
