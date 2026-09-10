# StaticFileServer

一个多协议的静态文件服务：**HTTP**（浏览 / 上传）、**WebDAV**、**FTP** 共用同一个根目录和同一套认证配置。

## 特性

- HTTP 目录浏览、文件下载、文件上传接口与上传页面
- WebDAV（wsgidav + cheroot），可直接被 Windows 资源管理器 / macOS Finder / RaiDrive 挂载
- FTP（pyftpdlib），支持匿名只读与账号读写
- HTTP / WebDAV / FTP 使用 **同一份账号配置**，权限口径一致
- 可选匿名只读：未认证请求只能读，写操作返回 403 / 401
- 路径穿越防护、上传重名自动加 `_xxx` 后缀
- 单文件即可打包为 exe（PyInstaller）

## 快速开始

```powershell
# 1. 创建虚拟环境
python -m venv .venv

# 2. 安装依赖
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 3. 启动全部服务（首次运行会自动生成 config.json 与 ./root）
.\.venv\Scripts\python.exe main.py
```

启动后：

- HTTP  <http://127.0.0.1/>
- WebDAV <http://127.0.0.1:8081/>
- FTP   <ftp://127.0.0.1:2121/>

> 默认配置里 HTTP 端口是 80，需要管理员权限；请按需在 `config.json` 调整。

## 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--config PATH` | 指定配置文件（默认程序目录下 `config.json`） |
| `--root PATH` | 覆盖服务根目录 |
| `--only http\|webdav\|ftp` | 只启动单个服务 |
| `--no-http` / `--no-webdav` / `--no-ftp` | 关闭对应服务 |
| `--log-level LEVEL` | 覆盖日志级别 |

> 首次启动时若程序目录下没有 `config.json`，会自动按默认模板生成，并创建默认根目录 `./root`，然后直接开始服务，无需额外初始化命令。
| `--version` | 打印版本 |

## 配置说明

配置文件为 JSON，字段含义见 `config.example.json`。

关键项：

- `root`：对外暴露的根目录，支持相对路径（相对配置文件所在目录），默认 `./root`
- `allow_access_base_dir_up_level`：是否允许通过 `../` 跳出根目录（默认 `false`，强烈建议保持关闭）
- `auth.anonymous_readonly`：`true` 时未登录可读、写需认证；`false` 时读写都需认证
  - 注意：WebDAV 开启认证时会先返回 `401` 挑战，客户端（WinSCP / 资源管理器 / 映射驱动器）拿到挑战后会提交账号密码，之后可正常读写。
- `auth.users.<name>.password`：支持明文，或 `sha256:<hex>` 哈希
  - 生成哈希：`python -c "import hashlib;print('sha256:'+hashlib.sha256(b'你的密码').hexdigest())"`
- `auth.users.<name>.permissions`：Linux 风格，`r`（只读）或 `rw`（可读写）
- `access.enabled`：是否启用 IP 访问控制（默认 `false`）
- `access.whitelist` / `access.blacklist`：IP 规则数组，支持以下写法混用：
  - 单个 IP：`192.168.2.3`
  - CIDR 网段：`192.168.2.0/24`
  - 区间：`192.168.2.100-192.168.2.150`，缩写形式 `192.168.2.100-150`
  - 通配符：`192.168.2.*`（等价于 `/24`）
  - 全部：`*`
  - IPv6：`::1`、`2001:db8::/32`
  - **优先级：黑名单优先**；白名单非空时，只有命中白名单的 IP 才放行
  - 规则同时作用于 **HTTP / WebDAV / FTP** 三个协议
- `webdav.mount`：WebDAV 挂载路径前缀，默认 `/`（直接挂在根，客户端直接填 `http://IP:8081/`）
  - 如需挂在子路径，改成如 `/dav`，则客户端地址为 `http://IP:8081/dav/`
  - 挂载路径以外的请求会返回 404
- `log.file`：留空时默认写到程序根目录 `app.log`
  - 启动时若 `app.log` 已存在，会先重命名为 `app-[日期时间].log`，再新建 `app.log`

也可用环境变量覆盖：`SFS_ROOT`、`SFS_HTTP_PORT`、`SFS_WEBDAV_PORT`、`SFS_FTP_PORT`、`SFS_LOG_LEVEL`。

## 打包

```powershell
.\bulid.ps1
# 产物：dist\StaticFileServer.exe
```

打包后把 `config.json` 放在 exe 同目录即可。

## 目录结构

```
main.py                      # 入口（源码运行 / 打包入口）
app/
  __main__.py                # CLI 与多服务编排
  config.py                  # 配置加载、路径安全解析
  auth.py                    # 共用认证逻辑
  access.py                  # 统一准入控制（IP 黑白名单 + 热重载）
  iprules.py                 # IP 规则解析与匹配
  admin.py                   # 管理界面路由与 API
  http_server.py             # HTTP 服务（Flask + Jinja2）
  webdav_server.py           # WebDAV 服务
  ftp_server.py              # FTP 服务
  filters.py                 # Jinja2 过滤器（文件大小格式化等）
  logging_setup.py           # 日志
  templates/                 # Jinja2 模板（Flask 约定）
    base.html                # 基础布局
    directory.html           # 目录浏览
    upload.html              # 上传页
    error.html               # 错误页
    admin.html               # 管理控制台
packaging/hooks/             # PyInstaller 钩子
```

HTML 全部放在 `app/templates/*.html`，使用 Jinja2 继承（`{% extends "base.html" %}`），不在 Python 中内嵌页面。

## 管理界面

访问 `http://<IP>/view/admin`，使用拥有 **写权限（`rw`）** 的账号登录（默认 `admin / admin`）。

包含两块：

- **用户管理**：新增 / 修改 / 删除用户，设置权限（`r` / `rw`），密码可明文或勾选按 `sha256` 存储
- **IP 访问控制**：启用开关、白名单、黑名单（每行一条规则）

保存后**立即生效，无需重启**：

- HTTP / WebDAV 规则即时生效（请求级判定）
- FTP 用户表即时刷新（下次连接即可用新账号）

> 管理页面与 API 路径（`/view/admin`、`/api/admin/*`）**不受 IP 黑白名单限制**，
> 且需管理员账号鉴权——避免把规则配错后把自己锁在门外无法修正。
> 修改配置会写回 `config.json`（保持其余字段不变），下次启动继续生效。

## 安全提示

- 公网部署务必修改默认口令（默认 `admin / admin`）。
- 默认匿名只读，如需完全私有请设置 `auth.anonymous_readonly=false`。
- 保持 `allow_access_base_dir_up_level=false`，避免根目录被跳出。
- 需要限制来源时启用 `access.enabled`，用白名单锁定可信网段；黑名单优先级最高。
- Windows 映射网络驱动器若失败，通常是客户端策略（`BasicAuthLevel=1` 且 `AuthForwardServerList` 为空）
  不允许向纯 HTTP 发送 Basic 凭据，需改注册表并重启 `WebClient` 服务，与本服务端无关。
