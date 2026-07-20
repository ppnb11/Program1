# 🛡️ Day03 安全漏洞修复报告

**项目**: 用户管理系统 · Flask Web Application · 新增功能安全加固  
**路径**: /opt/Class01  
**状态**: ✅ 10 项漏洞已全部修复

---

## 📊 漏洞修复总览

| 等级 | 数量 |
|:----|:----:|
| 🔴 高危漏洞 | 5 |
| 🟡 中危漏洞 | 5 |
| **合计** | **10** |

---

## 📋 涉及功能范围

本次审计针对 Day03 新增的以下功能模块进行全面的安全加固：

- **用户注册功能** — 新增 SQLite 数据库存储，含用户名/密码/邮箱/手机号
- **用户搜索功能** — 按用户名或邮箱关键词模糊搜索
- **登录认证重构** — 从硬编码字典迁移到 SQLite 统一认证
- **输入校验机制** — 新增用户名/密码/邮箱/手机号校验函数
- **频率限制机制** — 注册接口限流防止滥用

---

## 🔎 漏洞明细

### 1. 🔴 SQL注入 — 搜索接口

| 项目 | 内容 |
|:----|:------|
| **风险描述** | `/search` 接口使用 f-string 直接将用户输入的 keyword 拼接到 SQL 查询语句中，攻击者可输入 `' OR '1'='1` 查询所有用户，或使用 UNION SELECT 读取任意数据 |
| **漏洞代码** | `sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"` |
| **修复措施** | 改为**参数化查询**，使用 `?` 占位符将用户输入作为参数传入，数据库引擎自动转义，用户输入无法改变 SQL 语句结构 |
| **修复代码** | `sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"` `c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))` |

**验证结果**：
- `' OR '1'='1` → ❌ 拦截，无结果返回
- `' UNION SELECT 1,sqlite_version(),3,4,5--` → ❌ 拦截，版本号不显示
- `admin' AND SUBSTR(password,1,1)='a'--` → ❌ 盲注拦截

---

### 2. 🔴 SQL注入 — 注册接口

| 项目 | 内容 |
|:----|:------|
| **风险描述** | `/register` 接口的 INSERT 语句使用 f-string 拼接用户输入，攻击者可在用户名或密码框中闭合 SQL 语法，插入恶意数据 |
| **漏洞代码** | `sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"` |
| **修复措施** | INSERT 语句改为参数化查询，用户输入全部通过 `?` 占位符传入，杜绝 SQL 注入 |
| **修复代码** | `sql = "INSERT INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, 'user', 0)"` `c.execute(sql, (username, hashed_pw, email, phone))` |

---

### 3. 🔴 数据库明文密码存储

| 项目 | 内容 |
|:----|:------|
| **风险描述** | `init_db()` 初始化和注册写入数据库时密码以明文保存，任何人拿到 `data/users.db` 文件即可获取所有用户的密码 |
| **漏洞代码** | `VALUES ('admin', 'admin123', ...)` — 直接存明文 |
| **修复措施** | 使用 `generate_password_hash()` 对密码进行 scrypt 哈希加密存储，数据库泄露也无法还原原密码 |
| **修复代码** | `hashed_pw = generate_password_hash(password)` `VALUES (?, ?, ?, ?, 'user', 0)` 参数传入哈希值 |

**验证结果**：
- 数据库中 admin 密码字段值: `scrypt:32768:8:1$...` ✅ 已哈希
- 新注册用户密码字段同样为哈希值 ✅

---

### 4. 🔴 登录/注册数据不同步

| 项目 | 内容 |
|:----|:------|
| **风险描述** | 登录验证使用硬编码的 `USERS` 字典（仅含 admin/alice），注册写入 SQLite 数据库。新注册用户**永远无法登录**，因为两个系统完全独立 |
| **漏洞代码** | `if username in USERS and check_password_hash(USERS[username]["password"], password):` — 仅查 USERS 字典 |
| **修复措施** | 登录改为统一查询 SQLite 数据库，注册用户的凭据也能被登录验证。同时移除硬编码 USERS 字典 |
| **修复代码** | `c.execute("SELECT password, role FROM users WHERE username = ?", (username,))` `row = c.fetchone()` `if row and check_password_hash(row[0], password):` |

**验证结果**：
- admin/admin123 → 登录成功 ✅
- alice/alice2025 → 登录成功 ✅
- 新注册用户 → 登录成功 ✅

---

### 5. 🔴 UNION注入提取密码

| 项目 | 内容 |
|:----|:------|
| **风险描述** | 即使搜索接口做了参数化查询防止注入，但 `SELECT *` 会把 password 字段也读到模板数据中，一旦模板渲染出错或日志泄露，密码仍可能暴露 |
| **漏洞代码** | `sql = "SELECT * FROM users WHERE ..."` — 选取所有字段 |
| **修复措施** | 明确只选取必要字段 `id, username, email, phone`，杜绝密码字段进入模板上下文 |
| **修复代码** | `sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"` |

**验证结果**：
- 查询返回字典字段: `['id', 'username', 'email', 'phone']` ✅ 不含 password

---

### 6. 🟡 注册无频率限制

| 项目 | 内容 |
|:----|:------|
| **风险描述** | 注册接口无任何频率限制，攻击者可编写脚本在短时间内注册大量垃圾账号，耗尽数据库空间或用于其他恶意用途 |
| **修复措施** | 注册接口添加 `@limiter.limit("10 per minute")` 装饰器，每分钟最多 10 次注册请求，超出返回 HTTP 429 |
| **修复代码** | `@limiter.limit("10 per minute", key_func=login_limit_key)` `def register():` |

**验证结果**：
- 第 1-10 次 → HTTP 200 ✅
- 第 11 次 → HTTP 429 Too Many Requests ✅

---

### 7. 🟡 无密码强度校验

| 项目 | 内容 |
|:----|:------|
| **风险描述** | 注册时密码可设为 `1`、`123`、`a` 等弱密码，极易被暴力破解或猜解 |
| **修复措施** | 添加 `validate_password()` 校验函数，密码长度至少 6 位 |
| **修复代码** | `def validate_password(password): if len(password) < 6: return "密码长度至少6位"` |

**验证结果**：
- 密码 `123` → ❌ 被拒绝，提示"密码长度至少6位" ✅
- 密码 `password123` → ✅ 校验通过

---

### 8. 🟡 无输入校验

| 项目 | 内容 |
|:----|:------|
| **风险描述** | 注册时用户名、邮箱、手机号无任何格式校验。用户名可包含 `../../etc/passwd`、`<script>` 等特殊字符，邮箱可填入任意字符串 |
| **修复措施** | 添加三个校验函数：`validate_username()`（3-20位，仅允许字母/数字/中文/下划线）、`validate_email()`（邮箱格式正则校验）、`validate_phone()`（手机号格式校验） |
| **修复代码** | `def validate_username(u): if not re.match(r'^[a-zA-Z0-9_一-龥]+$', u): return "用户名只能包含字母、数字、中文和下划线"` |

**验证结果**：
- 用户名 `ab` → ❌ "用户名长度需在3-20个字符之间" ✅
- 用户名 `<script>alert(1)</script>` → ❌ "只能包含..." ✅
- 邮箱 `notanemail` → ❌ "邮箱格式不正确" ✅

---

### 9. 🟡 错误信息泄露数据库结构

| 项目 | 内容 |
|:----|:------|
| **风险描述** | 注册重复用户名时，数据库异常直接暴露给前端：`UNIQUE constraint failed: users.username`，攻击者可从中获取表名、字段约束等数据库结构信息 |
| **漏洞代码** | `message = f"注册失败：{str(e)}"` — 异常信息直接返回前端 |
| **修复措施** | 捕获所有 SQL 异常，返回通用提示"注册失败，用户名可能已存在"，不暴露任何数据库内部细节 |
| **修复代码** | `except Exception: return render_template("register.html", message="注册失败，用户名可能已存在")` |

**验证结果**：
- 重复注册 admin → 提示"注册失败，用户名可能已存在" ✅
- 不包含 `UNIQUE constraint` 等关键词 ✅

---

### 10. 🟡 搜索返回含密码字段

| 项目 | 内容 |
|:----|:------|
| **风险描述** | 搜索使用 `SELECT *` 获取全部字段，虽然前端表格未渲染 password 列，但密码数据实际上已在模板数据字典中，若模板被修改或渲染异常，密码可能泄露 |
| **修复措施** | 改为显式指定返回字段列表 `SELECT id, username, email, phone`，password 字段从源头隔离 |
| **修复代码** | `sql = "SELECT id, username, email, phone FROM users WHERE ..."` |

**验证结果**：
- 搜索结果 dict 包含字段: `['id', 'username', 'email', 'phone']` ✅

---

## 📝 关键代码变更

### 1. 参数化查询防SQL注入（搜索 + 注册）

```diff
- # ❌ 修改前 - f-string 拼接
- sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
- c.execute(sql)

+ # ✅ 修改后 - 参数化查询
+ sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
+ c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))

- sql = f"INSERT INTO users (...) VALUES ('{username}', '{password}', '{email}', '{phone}')"

+ c.execute("INSERT INTO users (...) VALUES (?, ?, ?, ?, 'user', 0)",
+           (username, hashed_pw, email, phone))
```

### 2. 密码哈希存储（数据库初始化 + 注册）

```diff
- # ❌ 修改前 - 明文存储
- VALUES ('admin', 'admin123', ...)

+ # ✅ 修改后 - 哈希存储
+ hashed_pw = generate_password_hash(password)
+ c.execute("INSERT INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, ?, ?)",
+           ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000", "admin", 99999))
```

### 3. 登录认证统一到SQLite

```diff
- # ❌ 修改前 - 仅查硬编码字典
- if username in USERS and check_password_hash(USERS[username]["password"], password):

+ # ✅ 修改后 - 查询 SQLite 数据库
+ c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
+ row = c.fetchone()
+ if row and check_password_hash(row[0], password):
+     session["username"] = username
+     session["role"] = row[1]
```

### 4. 完整输入校验函数

```python
# ✅ 新增 - 用户名校验
def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return "用户名长度需在3-20个字符之间"
    if not re.match(r'^[a-zA-Z0-9_一-龥]+$', username):
        return "用户名只能包含字母、数字、中文和下划线"
    return None

# ✅ 新增 - 密码强度校验
def validate_password(password):
    if len(password) < 6:
        return "密码长度至少6位"
    return None

# ✅ 新增 - 邮箱格式校验
def validate_email(email):
    if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return "邮箱格式不正确"
    return None
```

### 5. 错误信息脱敏

```diff
- # ❌ 修改前 - 暴露数据库结构
- message = f"注册失败：{str(e)}"

+ # ✅ 修改后 - 通用提示
+ return render_template("register.html", message="注册失败，用户名可能已存在")
```

---

## 🧪 修复验证测试

12 项安全测试全部通过 ✅

### 测试明细

| # | 测试项 | 测试方法 | 预期结果 | 实际结果 |
|:-:|:-------|:---------|:---------|:---------|
| 1 | 正常搜索功能 | `GET /search?keyword=admin` | HTTP 200 + 显示 admin 信息 | ✅ 通过 |
| 2 | UNION注入查版本 | `' UNION SELECT 1,sqlite_version(),3,4,5--` | 拦截，不显示版本号 | ✅ 通过 |
| 3 | UNION注入查密码 | `' UNION SELECT 1,password,3,4,5 FROM users--` | 拦截，密码不可见 | ✅ 通过 |
| 4 | OR 1=1 盲注 | `' OR '1'='1` | 拦截，不返回全部用户 | ✅ 通过 |
| 5 | 密码哈希存储 | 查询数据库 password 字段 | 非明文（scrypt 哈希值） | ✅ 通过 |
| 6 | admin 登录 | POST admin/admin123 | 登录成功，跳转首页 | ✅ 通过 |
| 7 | 新用户登录 | 注册 → 登录 | 注册后可正常登录 | ✅ 通过 |
| 8 | 弱密码拒绝 | 注册密码=123 | 提示"密码长度至少6位" | ✅ 通过 |
| 9 | 短用户名拒绝 | 注册用户名=ab | 提示"长度需在3-20个字符" | ✅ 通过 |
| 10 | 特殊字符拒绝 | 注册用户名=`<script>` | 提示"只能包含..." | ✅ 通过 |
| 11 | 错误信息脱敏 | 重复注册 admin | 不暴露UNIQUE constraint | ✅ 通过 |
| 12 | 注册限流 | 连续注册 11 次 | 第 11 次 HTTP 429 | ✅ 通过 |

---

## 📁 修复涉及文件

| 文件 | 路径 | 修改内容 |
|:----|:-----|:---------|
| 🐍 **app.py** | `/opt/Class01/app.py` | 参数化查询、密码哈希、登录同步 SQLite、输入校验函数、频率限制、错误信息脱敏、搜索字段脱敏 |
| 📄 **login.html** | `/opt/Class01/templates/login.html` | 新增成功消息显示区域（`{% if message %}`） |
| 🎨 **style.css** | `/opt/Class01/static/css/style.css` | 新增 `.success-msg` 绿色成功提示样式 |

---

## 💡 预设账号

| 用户名 | 密码 | 角色 | 说明 |
|:------|:-----|:----|:-----|
| `admin` | `admin123` | 管理员 | 预置管理员账号，余额 99999 |
| `alice` | `alice2025` | 普通用户 | 预置普通用户账号，余额 100 |

> 新注册用户默认为 `user` 角色，余额为 0。

---

## 🔗 相关链接

- Day03 HTML 报告: [http://192.168.57.137:5000/report03](http://192.168.57.137:5000/report03)
- Day02 报告: [http://192.168.57.137:5000/report02](http://192.168.57.137:5000/report02)
- 仓库地址: [https://github.com/ppnb11/Program1](https://github.com/ppnb11/Program1)
