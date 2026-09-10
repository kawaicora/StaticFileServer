# StaticFileServer

一个静态文件服务：**HTTP 浏览** 与 **WebDAV** 跑在**同一个端口**、共享同一个根目录、同一套账号与访问规则。

- HTTP（Flask + Jinja2）：目录浏览、文件下载、网页上传、管理界面
- WebDAV（wsgidav）：挂在 `/dav/`，支持 Windows 映射驱动器、WinSCP、macOS Finder 等
- **账号存 SQLite，口令用 scrypt 散列**，不落明文
- 支持 Cloudflare / Nginx / FRP 等代理后的**真实 IP** 识别
- IP 黑白名单（单 IP / CIDR / 区间 / 通配符），对 HTTP 与 WebDAV 统一生效
- 管理界面热重载：改用户 / 改规则**保存即生效**，无需重启

---

## 快速开始

### 源码运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 直接启动：首次自动生成 config.json、./root、users.db
python main.py
```

### 打包

```powershell
.\bulid.ps1
# 产物：dist\StaticFileServer.exe（把 config.json 放同目录即可）
```

首次启动会自动创建：

- `config.json` —— 配置
- `root/` —— 对外暴露的根目录
- `users.db` —— SQLite 用户库（口令散列存储）

> 默认端口 **80**。非管理员权限下 80 端口可能无法绑定，可改 `server.port`。

---

## 访问地址

| 用途 | 地址 |
|---|---|
| 网页浏览 | `http://127.0.0.1/` |
| 网页上传 | `http://127.0.0.1/view/upload` |
| 管理界面 | `http://127.0.0.1/view/admin` |
| WebDAV | `http://127.0.0.1/dav/` |

默认账号 **`admin / admin`**，公网部署前请务必修改。

---

## 命令行

| 参数 | 说明 |
|---|---|
| `--config PATH` | 指定配置文件（默认程序目录下 `config.json`） |
| `--root PATH` | 覆盖服务根目录 |
| `--port N` | 覆盖监听端口 |
| `--no-webdav` | 禁用 WebDAV，仅提供 HTTP 浏览 |
| `--log-level LEVEL` | 覆盖日志级别 |
| `--version` | 打印版本 |

> 首次启动若程序目录下没有 `config.json`，会自动按默认模板生成，并创建 `./root`，
> 然后直接开始服务，无需额外初始化命令。

---

## 配置说明

配置文件为 JSON，完整字段见 `config.example.json`。

### 服务与 WebDAV

- `server.host` / `server.port`：唯一对外端口，HTTP 与 WebDAV 共用
- `webdav.mount`：WebDAV 挂载前缀，默认 `/dav`
  - 浏览器访问 `/`，WebDAV 客户端填 `http://IP/dav/`
  - 改为 `/` 则两者同挂根路径（此时按请求方法/UA 自动分流）
- `root`：对外暴露的根目录，支持相对路径（相对配置文件所在目录），默认 `./root`
- `allow_access_base_dir_up_level`：是否允许 `../` 跳出根目录（默认 `false`，建议保持）

### 数据库（SQLite + SQLAlchemy）

- `database.url`：SQLAlchemy 连接串，默认 `sqlite:///./users.db`
  - 相对路径以**配置文件所在目录**为锚点
  - 也可换成 MySQL：`mysql+pymysql://user:pass@host/db`（需自行安装驱动）
- 用户表由 `db.create_all()` 自动创建，首次为空时写入 `auth.initial_user`
- **口令一律 scrypt 散列**（`scrypt$n$r$p$salt$hash`），数据库中不含明文
  - 旧格式（明文 / `sha256:<hex>`）校验通过后会自动升级为 scrypt

### 认证

- `auth.enabled`：是否启用认证
- `auth.anonymous_readonly`：`true` 时未登录可读、写需认证；`false` 时读写都需认证
  - WebDAV 开启认证时会先返回 `401` 挑战，客户端拿到挑战后提交账号密码，之后可正常读写
- `auth.realm`：Basic 认证 realm
- `auth.initial_user`：**仅用于首次建库**，之后用户都在 SQLite / 管理界面里维护

### IP 访问控制

- `access.enabled`：是否启用
- `access.whitelist` / `access.blacklist`：规则数组，支持混用：

  | 格式 | 示例 |
  |---|---|
  | 单个 IP | `192.168.2.3` |
  | CIDR | `192.168.2.0/24` |
  | 区间 | `192.168.2.100-192.168.2.150`、`192.168.2.100-150` |
  | 通配符 | `192.168.2.*`（等价 `/24`） |
  | 全部 | `*` |
  | IPv6 | `::1`、`2001:db8::/32` |

  - **黑名单优先**；白名单非空时，只有命中白名单的 IP 才放行
  - 对 **HTTP 与 WebDAV 统一生效**
- `access.trust_proxy_headers`：是否信任代理头（默认 `true`）
  - 依次读取 `CF-Connecting-IP` → `True-Client-IP` → `X-Real-IP` → `X-Client-IP` → `X-Forwarded-For` → `Forwarded`
  - 能正确处理 `1.2.3.4:5678`、`[::1]:80`、`client, proxy1` 等写法
  - **直连环境（无代理）可设为 `false`**，避免伪造头绕过限制

### 日志

- `log.level` / `log.file`：留空时写到程序目录 `app.log`
  - 启动时若 `app.log` 已存在，会先重命名为 `app-[日期时间].log`，再新建 `app.log`

也可用环境变量覆盖：`SFS_ROOT`、`SFS_PORT`、`SFS_DATABASE_URL`、`SFS_LOG_LEVEL`。

---

## 管理界面

访问 `http://<IP>/view/admin`，用拥有 **写权限（`rw`）** 的账号登录。

- **用户管理**：新增 / 修改 / 删除用户，设置权限（`r` / `rw`），口令存入 SQLite 时自动 scrypt 散列
- **IP 访问控制**：启用开关、白名单、黑名单、是否信任代理头

保存后**立即生效，无需重启**（用户改动直接落库；IP 规则热重载）。

> 管理页面与 API（`/view/admin`、`/api/admin/*`）**不受 IP 黑白名单限制**，
> 且需管理员账号鉴权——避免规则配错后把自己锁在门外。
> IP 规则会写回 `config.json`；用户**只存 SQLite**，不再写入配置文件。

---

## 代理部署要点

放在 Cloudflare / Nginx / FRP 之后时：

1. 回源端口填 `server.port`（默认 80）
2. 确保代理透传来源 IP 头（Cloudflare 默认带 `CF-Connecting-IP`；Nginx 需 `proxy_set_header X-Real-IP $remote_addr;`）
3. 保持 `access.trust_proxy_headers = true`
4. 若代理只允许特定来源直连，建议同时用防火墙限制，避免绕过代理直接伪造头部

---

## 目录结构

```
main.py                      # 入口（源码运行 / 打包入口）
app/
  __main__.py                # CLI 与启动引导（建库、建目录、起服务）
  config.py                  # 配置加载、路径安全解析
  server.py                  # 单端口统一服务（HTTP + WebDAV 合并）
  models.py                  # SQLAlchemy 模型与用户库操作
  users_db.py                # scrypt 散列与校验
  auth.py                    # 共用认证逻辑
  realip.py                  # 真实 IP 解析（CF / 代理）
  access.py                  # 统一准入控制（IP 黑白名单 + 热重载）
  iprules.py                 # IP 规则解析与匹配
  admin.py                   # 管理界面路由与 API
  http_server.py             # Flask 应用（浏览 / 上传 / 管理）
  webdav_server.py           # WebDAV 服务（wsgidav）
  filters.py                 # Jinja2 过滤器
  logging_setup.py           # 日志与轮转
  templates/                 # Jinja2 模板
    base.html                # 基础布局
    directory.html           # 目录浏览
    upload.html              # 上传页
    error.html               # 错误页
    admin.html               # 管理控制台
packaging/hooks/             # PyInstaller 钩子
```

---

## 安全提示

- 公网部署务必修改默认口令（默认 `admin / admin`）。
- 默认匿名只读，如需完全私有请设置 `auth.anonymous_readonly=false`。
- 保持 `allow_access_base_dir_up_level=false`。
- 需要限制来源时启用 `access.enabled`，用白名单锁定可信网段；黑名单优先级最高。
- 直连（无反向代理）时把 `access.trust_proxy_headers` 设为 `false`，
  否则客户端可伪造 `CF-Connecting-IP` 绕过 IP 限制。
- Windows 映射网络驱动器若失败，通常是客户端策略（`BasicAuthLevel=1` 且
  `AuthForwardServerList` 为空）不允许向纯 HTTP 发送 Basic 凭据，需改注册表并重启
  `WebClient` 服务，与本服务端无关。
  PowerShell（管理员）：
  ```powershell
  # 方案 A：允许向所有 HTTP 地址发送 Basic 凭据
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters' BasicAuthLevel 2
  Restart-Service WebClient
  ```
  映射地址用 `\\IP@PORT\dav\`，不要用 `localhost`。
