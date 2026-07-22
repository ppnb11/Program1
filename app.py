from flask import Flask, render_template, request, redirect, session, url_for, send_file, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
import re
import sqlite3

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
        c.execute("SELECT password, role, id FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row[0], password):
            session["username"] = username
            session["role"] = row[1]
            session["user_id"] = row[2]
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


@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        # 使用用户上传的原始文件名保存，不做任何类型检查
        filename = file.filename
        save_path = os.path.join(UPLOAD_FOLDER, filename)

        # 同名文件保留，不做特殊处理
        file.save(save_path)

        # 生成文件访问 URL
        file_url = url_for("static", filename=f"uploads/{filename}")
        return render_template("upload.html", success=True, file_url=file_url, filename=filename)

    return render_template("upload.html")


@app.route("/report02")
def report02():
    return send_file("day02_security_report.html")


@app.route("/report03")
def report03():
    return send_file("day03_security_report.html")


@app.route("/profile")
def profile():
    # 身份认证检查
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    user_id = request.args.get("user_id", "")
    if not user_id:
        return render_template("profile.html", error="缺少 user_id 参数", profile_user=None)

    # 权限校验：只允许查看自己的资料
    if str(user_id) != str(session.get("user_id")):
        return render_template("profile.html", error="无权查看该用户资料", profile_user=None)

    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, role, balance FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return render_template("profile.html", error="用户不存在", profile_user=None)

    profile_user = dict(row)
    return render_template("profile.html", profile_user=profile_user, error=None)


@app.route("/recharge", methods=["POST"])
def recharge():
    # 身份认证检查
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    # user_id 从 session 获取，不信任前端参数
    user_id = session.get("user_id")

    amount = request.form.get("amount", "")

    if not user_id or not amount:
        return redirect(url_for("profile", user_id=user_id))

    try:
        amount_int = int(amount)
    except ValueError:
        return redirect(url_for("profile", user_id=user_id))

    # 金额校验：必须为正数
    if amount_int <= 0:
        return render_template("profile.html",
            profile_user={"id": user_id}, error="充值金额必须为正数")

    # 金额上限校验
    if amount_int > 100000:
        return render_template("profile.html",
            profile_user={"id": user_id}, error="单次充值上限为100000")

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()

    # 查询当前余额，确保不会为负
    c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row:
        current_balance = row[0]
        new_balance = current_balance + amount_int
        if new_balance < 0:
            conn.close()
            return render_template("profile.html",
                profile_user={"id": user_id}, error="余额不足")

    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount_int, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for("profile", user_id=user_id))


@app.route("/report05")
def report05():
    return send_file("day05_security_report.html")


if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
