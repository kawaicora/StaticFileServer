from flask import Flask, send_from_directory, request, redirect
import os, sys

# ====================== 配置开关 ======================
# True：允许 ../ 向上跳出BASE_DIR，访问BASE_DIR的上级目录
# False：禁止向上跳出BASE_DIR，最多只能访问BASE_DIR内部
ALLOW_ACCESS_BASE_DIR_UP_LEVEL = True
# =====================================================

# 当前文件所在目录
if getattr(sys, 'frozen', False):
    # PyInstaller exe运行
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Python源码运行
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.normpath(BASE_DIR)
print(f"BASE_DIR = {BASE_DIR}")
print(f"ALLOW_ACCESS_BASE_DIR_UP_LEVEL = {ALLOW_ACCESS_BASE_DIR_UP_LEVEL}")

app = Flask(__name__, static_folder=None)
def get_real_ip():
    """
    获取客户端真实IP
    支持:
        Cloudflare CDN
        Cloudflare Tunnel
        FRP
        Nginx Reverse Proxy
        Direct Connection
    """

    # Cloudflare
    ip = request.headers.get("CF-Connecting-IP")
    if ip:
        return ip

    # 标准反向代理
    ip = request.headers.get("X-Forwarded-For")
    if ip:
        return ip.split(",")[0].strip()

    # Nginx
    ip = request.headers.get("X-Real-IP")
    if ip:
        return ip

    # 直连
    return request.remote_addr

@app.before_request
def before_request():
    ip = get_real_ip()

    # r = requests.get(
    #     f"https://ipwho.is/{ip}",
    #     timeout=5
    # )
    msg = f"""
****请求开始****
{request.method} {ip}  {request.path}
****headers****
{request.headers}
****cookies****
{request.cookies}

"""
    app.logger.info(msg)
# 文件上传接口，挂载在根路径 /api/upload
@app.route("/api/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return "未选择文件", 400
    file = request.files['file']
    if file.filename == '':
        return "文件名为空", 400
    if file:
        save_path = os.path.join(BASE_DIR, file.filename)
        file.save(save_path)
        return f"上传成功，文件名：{file.filename}"

# 简单上传页面，访问 /view/upload 可以直接上传文件
@app.route("/view/upload", methods=["GET"])
def upload_page():
    return '''
<!DOCTYPE html>
<html>
<body>
    <h3>文件上传</h3>
    <form action="/api/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">上传</button>
    </form>
</body>
</html>
'''

# 目录浏览路由
@app.route("/", defaults={"subpath": ""})
@app.route("/<path:subpath>")
def list_dir(subpath):
    # 直接拼接 + 系统原生归一化，真实解析 ../
    raw_full = os.path.join(BASE_DIR, subpath)
    full_path = os.path.normpath(raw_full)

    # 核心判断：根据开关决定是否允许访问BASE_DIR上级
    base_norm = os.path.normpath(BASE_DIR)
    if not ALLOW_ACCESS_BASE_DIR_UP_LEVEL:
        # 关闭向上访问：必须在BASE_DIR内部
        if not full_path.startswith(base_norm):
            return "禁止访问：超出BASE_DIR上级目录", 403
    else:
        # 开启向上访问：只拦截绝对路径穿越到别的盘符/根以外（最低底线）
        # 这里放开BASE_DIR上层，但仍然拒绝跨盘符（Windows）
        if os.name == "nt":
            if os.path.splitdrive(full_path)[0] != os.path.splitdrive(base_norm)[0]:
                return "禁止跨盘符访问",403

    # 目录不带末尾斜杠，301自动补 /
    if os.path.isdir(full_path) and not request.path.endswith("/"):
        return redirect(request.path + "/", code=301)

    if os.path.isfile(full_path):
        # send_from_directory 要求第一个参数是目录，第二个是相对这个目录的文件名
        # 当full_path在BASE外面，不能用send_from_directory(BASE_DIR, xxx)
        # 改用send_file
        from flask import send_file
        return send_file(full_path)

    if os.path.isdir(full_path):
        items = []
        # 生成返回上级链接
        stripped = subpath.rstrip("/")
        parent_sub = os.path.dirname(stripped)
        parent_sub = parent_sub.replace(os.sep, "/")
        if parent_sub == "":
            parent_link = "/"
        else:
            parent_link = f"/{parent_sub}/"
        items.append(f'<li><a href="{parent_link}">.. 返回上级</a></li>')

        for entry in sorted(os.listdir(full_path)):
            entry_full = os.path.join(full_path, entry)
            entry_rel = os.path.join(subpath, entry).replace(os.sep, "/")
            if os.path.isdir(entry_full):
                items.append(f'<li>[文件夹] <a href="/{entry_rel}/">{entry}/</a></li>')
            else:
                items.append(f'<li>[文件] <a href="/{entry_rel}">{entry}</a></li>')

        html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>目录: /{subpath}</title>
</head>
<body>
<h2>目录浏览 /{subpath}</h2>
<ul>
{''.join(items)}
</ul>
</body>
</html>
"""
        return html

    return "404 Not Found", 404

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=80,
        debug=True
    )
