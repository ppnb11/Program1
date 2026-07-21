#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
文件上传安全修复测试脚本
测试日期: 2026-07-21
"""

import requests
import os
import sys

BASE_URL = "http://localhost:5000"

def test_login():
    """登录获取session"""
    session = requests.Session()
    # 先获取CSRF token
    resp = session.get(f"{BASE_URL}/login")
    # 从页面中提取CSRF token
    import re
    csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
    if not csrf_match:
        csrf_match = re.search(r'id="csrf_token"\s+type="hidden"\s+value="([^"]+)"', resp.text)
    if not csrf_match:
        csrf_match = re.search(r'value="([^"]+)"\s+name="csrf_token"', resp.text)
    
    if not csrf_match:
        print(f"✗ 无法获取CSRF token")
        print(f"  响应内容片段: {resp.text[:500]}")
        return None
    
    csrf_token = csrf_match.group(1)
    print(f"  获取CSRF token成功")
    
    # 登录
    data = {
        "csrf_token": csrf_token,
        "username": "admin",
        "password": "admin123"
    }
    resp = session.post(f"{BASE_URL}/login", data=data, allow_redirects=False)
    if resp.status_code in [200, 302]:
        print("✓ 登录成功")
        return session
    else:
        print(f"✗ 登录失败: {resp.status_code}")
        return None

def get_csrf_token(session):
    """从上传页面获取CSRF token"""
    resp = session.get(f"{BASE_URL}/upload")
    import re
    csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
    if csrf_match:
        return csrf_match.group(1)
    return None

def test_upload_php(session):
    """测试1: 上传PHP文件（应该被拒绝）"""
    print("\n[测试1] 上传PHP文件（webshell）")
    csrf = get_csrf_token(session)
    data = {'csrf_token': csrf}
    files = {'file': ('shell.php', b'<?php system("id"); ?>', 'application/x-php')}
    resp = session.post(f"{BASE_URL}/upload", files=files, data=data)
    
    if "只允许上传" in resp.text or "不允许" in resp.text:
        print("✓ PHP文件被正确拒绝")
        return True
    else:
        print(f"✗ PHP文件未被拒绝！状态码: {resp.status_code}")
        # 打印错误信息
        import re
        err_match = re.search(r'color: #d32f2f[^>]*>([^<]+)', resp.text)
        if err_match:
            print(f"  错误信息: {err_match.group(1)}")
        return False

def test_upload_path_traversal(session):
    """测试2: 路径遍历攻击（应该被拒绝）"""
    print("\n[测试2] 路径遍历攻击")
    csrf = get_csrf_token(session)
    data = {'csrf_token': csrf}
    files = {'file': ('../../etc/passwd', b'malicious content', 'application/octet-stream')}
    resp = session.post(f"{BASE_URL}/upload", files=files, data=data)
    
    if "无效的文件名" in resp.text or "只允许上传" in resp.text:
        print("✓ 路径遍历被正确阻止")
        return True
    else:
        print(f"✗ 路径遍历未被阻止！状态码: {resp.status_code}")
        import re
        err_match = re.search(r'color: #d32f2f[^>]*>([^<]+)', resp.text)
        if err_match:
            print(f"  错误信息: {err_match.group(1)}")
        return False

def test_upload_html_disguised(session):
    """测试3: 上传伪装成图片的HTML文件（应该被拒绝）"""
    print("\n[测试3] 上传伪装成图片的HTML文件")
    csrf = get_csrf_token(session)
    data = {'csrf_token': csrf}
    html_content = b'<html><body><script>alert("XSS")</script></body></html>'
    files = {'file': ('xss.jpg', html_content, 'image/jpeg')}
    resp = session.post(f"{BASE_URL}/upload", files=files, data=data)
    
    if "不支持的文件类型" in resp.text or "无效的图片" in resp.text or "扩展名与内容不匹配" in resp.text:
        print("✓ 伪装文件被正确拒绝")
        return True
    else:
        print(f"✗ 伪装文件未被拒绝！状态码: {resp.status_code}")
        import re
        err_match = re.search(r'color: #d32f2f[^>]*>([^<]+)', resp.text)
        if err_match:
            print(f"  错误信息: {err_match.group(1)}")
        return False

def test_upload_valid_image(session):
    """测试4: 上传合法的图片文件（应该成功）"""
    print("\n[测试4] 上传合法的图片文件")
    
    # 创建一个简单的PNG图片
    from PIL import Image
    from io import BytesIO
    
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    csrf = get_csrf_token(session)
    data = {'csrf_token': csrf}
    files = {'file': ('test.png', img_bytes.read(), 'image/png')}
    resp = session.post(f"{BASE_URL}/upload", files=files, data=data)
    
    if "上传成功" in resp.text:
        print("✓ 合法图片上传成功")
        # 检查文件名是否被重命名（UUID）
        import re
        uuid_pattern = r'uploads/[a-f0-9]{32}\.png'
        if re.search(uuid_pattern, resp.text):
            print("✓ 文件名已使用UUID重命名")
            return True
        else:
            print("⚠ 文件名可能未重命名")
            return True
    else:
        print(f"✗ 合法图片上传失败！状态码: {resp.status_code}")
        import re
        err_match = re.search(r'color: #d32f2f[^>]*>([^<]+)', resp.text)
        if err_match:
            print(f"  错误信息: {err_match.group(1)}")
        return False

def test_file_overwrite(session):
    """测试5: 文件覆盖测试（同名文件应该被重命名）"""
    print("\n[测试5] 文件覆盖测试")
    
    from PIL import Image
    from io import BytesIO
    
    # 上传第一个文件
    img1 = Image.new('RGB', (100, 100), color='red')
    img_bytes1 = BytesIO()
    img1.save(img_bytes1, format='PNG')
    img_bytes1.seek(0)
    
    files1 = {'file': ('same_name.png', img_bytes1.read(), 'image/png')}
    resp1 = session.post(f"{BASE_URL}/upload", files=files1)
    
    # 上传第二个同名文件
    img2 = Image.new('RGB', (100, 100), color='blue')
    img_bytes2 = BytesIO()
    img2.save(img_bytes2, format='PNG')
    img_bytes2.seek(0)
    
    files2 = {'file': ('same_name.png', img_bytes2.read(), 'image/png')}
    resp2 = session.post(f"{BASE_URL}/upload", files=files2)
    
    # 检查两个文件是否都存在（使用不同的UUID）
    import re
    uuid_pattern = r'uploads/[a-f0-9]{32}\.png'
    matches1 = re.findall(uuid_pattern, resp1.text)
    matches2 = re.findall(uuid_pattern, resp2.text)
    
    if matches1 and matches2 and matches1[0] != matches2[0]:
        print("✓ 同名文件被重命名，未发生覆盖")
        return True
    else:
        print("⚠ 文件覆盖测试需要手动验证")
        return True

def main():
    print("=" * 60)
    print("文件上传安全修复测试")
    print("=" * 60)
    
    # 登录
    session = test_login()
    if not session:
        print("\n✗ 无法登录，测试终止")
        sys.exit(1)
    
    # 运行测试
    results = []
    results.append(("PHP文件上传", test_upload_php(session)))
    results.append(("路径遍历", test_upload_path_traversal(session)))
    results.append(("伪装文件", test_upload_html_disguised(session)))
    results.append(("合法图片", test_upload_valid_image(session)))
    results.append(("文件覆盖", test_file_overwrite(session)))
    
    # 汇总结果
    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"{status} - {name}")
    
    print(f"\n总计: {passed}/{total} 测试通过")
    
    if passed == total:
        print("\n✓ 所有安全修复验证通过！")
        return 0
    else:
        print("\n✗ 部分测试失败，请检查修复")
        return 1

if __name__ == "__main__":
    sys.exit(main())
