# PyInstaller 运行时钩子：收集 wsgidav 的模板与静态资源
from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("wsgidav")
