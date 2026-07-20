# 🛡️ 安全漏洞修复报告

**项目**: 用户管理系统 · Flask Web Application  
**路径**: /opt/Class01  
**状态**: ✅ 已全部修复

---

## 📊 漏洞修复总览

| 等级 | 数量 |
|:----|:----:|
| 🔴 高危漏洞 | 5 |
| 🟡 中危漏洞 | 5 |
| **合计** | **10** |

共发现 10 项安全漏洞，已全部修复完成。经 12 项测试验证，全部通过 ✓

---

## 🔎 漏洞明细与修复方案

### 🔴 漏洞 1：SQL注入 — 搜索接口

| 项目 | 内容 |
|:----|:------|
| **等级** | 🔴 高危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 搜索接口由 f-string 拼接 SQL 改为**参数化查询**（`?` 占位符），用户输入无法改变 SQL 语句结构。UNION 注入、盲注均被拦截。 |

### 🔴 漏洞 2：SQL注入 — 注册接口

| 项目 | 内容 |
|:----|:------|
| **等级** | 🔴 高危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 注册接口由 f-string 拼接 SQL 改为**参数化查询**，用户输入不再拼入 SQL 语句。 |

### 🔴 漏洞 3：数据库明文密码存储

| 项目 | 内容 |
|:----|:------|
| **等级** | 🔴 高危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 注册和初始化时使用 `generate_password_hash()` 对密码进行哈希存储，数据库泄露也无法还原原密码。 |

### 🔴 漏洞 4：登录/注册数据不同步

| 项目 | 内容 |
|:----|:------|
| **等级** | 🔴 高危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 登录验证从硬编码 `USERS` 字典改为统一查询 `SQLite` 数据库，注册的用户现在可以正常登录。 |

### 🔴 漏洞 5：UNION注入提取密码

| 项目 | 内容 |
|:----|:------|
| **等级** | 🔴 高危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 参数化查询 + 搜索改为仅选取 `id, username, email, phone` 字段，不包含 password 字段。 |

### 🟡 漏洞 6：注册无频率限制

| 项目 | 内容 |
|:----|:------|
| **等级** | 🟡 中危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 注册接口添加 `@limiter.limit("10 per minute")` 频率限制，第 11 次请求返回 HTTP 429。 |

### 🟡 漏洞 7：无密码强度校验

| 项目 | 内容 |
|:----|:------|
| **等级** | 🟡 中危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 添加 `validate_password()` 函数，密码长度至少 6 位。 |

### 🟡 漏洞 8：无输入校验

| 项目 | 内容 |
|:----|:------|
| **等级** | 🟡 中危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 添加用户名长度限制（3-20位）、字符集限制、邮箱格式校验。 |

### 🟡 漏洞 9：错误信息泄露数据库结构

| 项目 | 内容 |
|:----|:------|
| **等级** | 🟡 中危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 捕获 SQL 异常，返回通用错误信息，不暴露数据库细节。 |

### 🟡 漏洞 10：搜索返回含密码字段

| 项目 | 内容 |
|:----|:------|
| **等级** | 🟡 中危 |
| **状态** | ✅ 已修复 |
| **修复措施** | 搜索结果改为只选取 `id, username, email, phone`，密码字段不再进入模板。 |

---

## 📝 关键代码变更

### 参数化查询防SQL注入（app.py /search + /register）

```python
# ❌ 修改前
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"

# ✅ 修改后
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
```

### 密码哈希存储（app.py）

```python
# ✅ 修改后
hashed_pw = generate_password_hash(password)
c.execute("INSERT INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, 'user', 0)",
          (username, hashed_pw, email, phone))
```

### 登录统一查询SQLite（app.py /login）

```python
# ❌ 修改前
if username in USERS and check_password_hash(USERS[username]["password"], password):

# ✅ 修改后
c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
row = c.fetchone()
if row and check_password_hash(row[0], password):
```

### 输入校验 + 频率限制（app.py /register）

```python
@limiter.limit("10 per minute", key_func=login_limit_key)
def register():
    err = validate_username(username)
    err = validate_password(password)
    err = validate_email(email)
```

### 错误信息脱敏（app.py /register）

```python
# ❌ 修改前
message = f"注册失败：{str(e)}"

# ✅ 修改后
return render_template("register.html", message="注册失败，用户名可能已存在")
```

---

## 🧪 修复验证测试

| # | 测试项 | 预期 | 结果 |
|:-:|:------|:----|:----:|
| 1 | 正常搜索功能 | 200 + 正常结果 | ✅ 通过 |
| 2 | 搜索 UNION 注入查版本 | 拦截 | ✅ 通过 |
| 3 | 搜索 UNION 注入查密码 | 拦截 | ✅ 通过 |
| 4 | 搜索 OR 1=1 盲注 | 拦截 | ✅ 通过 |
| 5 | 密码哈希存储 | 非明文 | ✅ 通过 |
| 6 | admin/admin123 登录 | 成功 | ✅ 通过 |
| 7 | 新注册用户登录 | 成功 | ✅ 通过 |
| 8 | 弱密码被拒绝 | 提示错误 | ✅ 通过 |
| 9 | 短用户名被拒绝 | 提示错误 | ✅ 通过 |
| 10 | 特殊字符用户名被拒绝 | 提示错误 | ✅ 通过 |
| 11 | 错误信息不泄露数据库结构 | 通用提示 | ✅ 通过 |
| 12 | 注册频率限制 (第11次) | 429 | ✅ 通过 |

---

## 📁 修复涉及文件

| 文件 | 路径 | 修改内容 |
|:----|:-----|:---------|
| 🐍 app.py | `/opt/Class01/app.py` | 参数化查询、密码哈希、登录同步SQLite、输入校验、频率限制、错误信息脱敏、搜索字段脱敏 |
| 📄 login.html | `/opt/Class01/templates/login.html` | 新增成功消息显示区域 |
| 🎨 style.css | `/opt/Class01/static/css/style.css` | 新增成功提示样式 |

---

## 🚀 启动方式

```bash
cd /opt/Class01 && python3 app.py
```

访问: [http://192.168.57.137:5000](http://192.168.57.137:5000)

> 💡 预设账号: admin / admin123 | alice / alice2025
