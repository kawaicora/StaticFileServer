"""入口脚本：源码运行与 PyInstaller 打包的统一入口。

    python main.py
    python main.py --init-config
"""

import os
import sys


def _bootstrap_import_path() -> None:
    """源码运行时把项目根加入 sys.path，使 app 可作为包导入；打包后已内联。"""
    if getattr(sys, "frozen", False):
        return
    repo_root = os.path.dirname(os.path.abspath(__file__))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


_bootstrap_import_path()

from app.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
