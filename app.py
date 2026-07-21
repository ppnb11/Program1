from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
import re
import sqlite3
import uuid
import magic
from PIL import Image
from io import BytesIO

app = Flask(__name__)
# 使用环境变量中的密钥，如果未设置则随机生成
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
# 最大上传文件 16MB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# CSRF 保护
csrf = CSRFProtect(app)

# 限流 key 函数
def login_limit_key():
    if request.method == "GET":
        return None
    return get_remote_address()

# 频率限制
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
)


def init_db():
    """初始化 SQLite 数据库，密码使用哈希存储"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            role TEXT DEFAULT 'user',
            balance INTEGER DEFAULT 0
        )
    """)
    # 使用哈希密码存储初始用户
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, ?, ?)",
              ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000", "admin", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, ?, ?)",
              ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001", "user", 100))
    conn.commit()
    conn.close()


def get_user_info(username):
    """从数据库获取用户信息（不含密码字段）"""
    if not username:
        return None
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT username, email, phone, role, balance FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def validate_username(username):
    """校验用户名：3-20位，只能包含字母、数字、下划线"""
    if len(username) < 3 or len(username) > 20:
        return "用户名长度需在3-20个字符之间"
    if not re.match(r'^[a-zA-Z0-9_一-龥]+$', username):
        return "用户名只能包含字母、数字、中文和下划线"
    return None


def validate_password(password):
    """校验密码强度：至少6位"""
    if len(password) < 6:
        return "密码长度至少6位"
    return None


def validate_email(email):
    """基础邮箱格式校验"""
    if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return "邮箱格式不正确"
    return None


def validate_phone(phone):
    """基础手机号校验（可选）"""
    if phone and not re.match(r'^[0-9+\-\s]{6,20}$', phone):
        return "手机号格式不正确"
    return None


@app.route("/")
def index():
    username = session.get("username")
    user_info = get_user_info(username)
    return render_template("index.html", username=username, user=user_info, search_results=None, keyword="")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", key_func=login_limit_key)
def login():
    error = None
    message = request.args.get("message", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row[0], password):
            session["username"] = username
            session["role"] = row[1]
            user_info = get_user_info(username)
            return render_template("index.html", username=username, user=user_info)
        else:
            error = "用户名或密码错误"
    return render_template("login.html", error=error, message=message)


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    username = session.get("username")
    user_info = get_user_info(username)
    search_results = None
    if keyword and username:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # 使用参数化查询防止SQL注入，且只选取必要字段（不包含password）
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_pattern = f"%{keyword}%"
        c.execute(sql, (like_pattern, like_pattern))
        search_results = [dict(row) for row in c.fetchall()]
        conn.close()
    elif keyword and not username:
        # 未登录不执行查询
        pass
    return render_template("index.html", username=username, user=user_info, search_results=search_results, keyword=keyword)


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute", key_func=login_limit_key)
def register():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 输入校验
        err = validate_username(username)
        if err:
            return render_template("register.html", message=err)
        err = validate_password(password)
        if err:
            return render_template("register.html", message=err)
        err = validate_email(email)
        if err:
            return render_template("register.html", message=err)
        err = validate_phone(phone)
        if err:
            return render_template("register.html", message=err)

        # 使用参数化查询和密码哈希存储
        hashed_pw = generate_password_hash(password)
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, 'user', 0)",
                (username, hashed_pw, email, phone)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login", message="注册成功，请登录"))
        except Exception:
            conn.close()
            return render_template("register.html", message="注册失败，用户名可能已存在")
    return render_template("register.html", message=message)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# 确保上传目录存在
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 文件上传安全配置
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_MIME_TYPES = {
    'image/png': ['png'],
    'image/jpeg': ['jpg', 'jpeg'],
    'image/gif': ['gif'],
    'image/webp': ['webp']
}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB


def allowed_file(filename):
    """检查文件扩展名是否在白名单中"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_content(file_stream, filename):
    """验证文件内容是否合法"""
    # 1. 检查文件大小
    file_stream.seek(0, 2)
    file_size = file_stream.tell()
    file_stream.seek(0)
    
    if file_size > MAX_FILE_SIZE:
        return None, "文件大小超过5MB限制"
    
    if file_size == 0:
        return None, "文件为空"
    
    # 2. 检查MIME类型
    content = file_stream.read()
    file_stream.seek(0)
    
    actual_mime = magic.from_buffer(content, mime=True)
    if actual_mime not in ALLOWED_MIME_TYPES:
        return None, "不支持的文件类型"
    
    # 3. 验证扩展名与MIME类型匹配
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in ALLOWED_MIME_TYPES[actual_mime]:
        return None, "文件扩展名与内容不匹配"
    
    # 4. 重新处理图片（去除恶意代码）
    try:
        img = Image.open(BytesIO(content))
        img.verify()
        
        # 重新保存，去除嵌入的恶意代码
        img = Image.open(BytesIO(content))
        output = BytesIO()
        img.save(output, format=img.format, quality=85)
        output.seek(0)
        
        return output, None
    except Exception as e:
        return None, f"无效的图片文件: {str(e)}"


@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        # 1. 过滤文件名，防止路径遍历
        original_filename = secure_filename(file.filename)
        if not original_filename:
            return render_template("upload.html", error="无效的文件名")

        # 2. 检查扩展名
        if not allowed_file(original_filename):
            return render_template(
                "upload.html", 
                error=f"只允许上传 {', '.join(ALLOWED_EXTENSIONS)} 格式的图片"
            )

        # 3. 验证文件内容
        sanitized_content, error = validate_file_content(file.stream, original_filename)
        if error:
            return render_template("upload.html", error=error)

        # 4. 生成安全的文件名（使用UUID防止覆盖）
        ext = original_filename.rsplit('.', 1)[1].lower()
        safe_filename = f"{uuid.uuid4().hex}.{ext}"
        save_path = os.path.join(UPLOAD_FOLDER, safe_filename)

        # 5. 验证最终路径
        real_path = os.path.realpath(save_path)
        if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
            return render_template("upload.html", error="非法的文件路径")

        # 6. 保存文件
        with open(save_path, 'wb') as f:
            f.write(sanitized_content.read())

        file_url = url_for("static", filename=f"uploads/{safe_filename}")
        return render_template(
            "upload.html", 
            success=True, 
            file_url=file_url, 
            filename=original_filename
        )

    return render_template("upload.html")


@app.route("/report02")
def report02():
    return send_file("day02_security_report.html")


@app.route("/report03")
def report03():
    return send_file("day03_security_report.html")


@app.route("/report04")
def report04():
    return send_file("day04_security_report.html")


if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
