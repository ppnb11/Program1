from flask import Flask, render_template, request, redirect, session, url_for, send_file
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets

app = Flask(__name__)
# 使用环境变量中的密钥，如果未设置则随机生成
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# CSRF 保护
csrf = CSRFProtect(app)

# 用户数据库 - 密码经过哈希存储，不再使用明文
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


def get_user_info(username):
    """获取用户信息（不含密码字段）"""
    if username and username in USERS:
        user = USERS[username].copy()
        user.pop("password", None)
        return user
    return None


@app.route("/")
def index():
    username = session.get("username")
    user_info = get_user_info(username)
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            session["role"] = USERS[username]["role"]
            user_info = get_user_info(username)
            return render_template("index.html", username=username, user=user_info)
        else:
            error = "用户名或密码错误"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/report")
def report():
    return send_file("security_report.html")


if __name__ == "__main__":
    # Debug 模式由环境变量控制，生产环境默认关闭
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
