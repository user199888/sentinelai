"""
Vulnerable Demo App - 故意包含多个安全漏洞用于演示
"""

import sqlite3
import subprocess
import os

# ===== SQL注入 =====
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # ❌ SQL注入: 字符串拼接
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

# ===== 命令注入 =====
def ping_host(hostname):
    # ❌ 命令注入: shell=True + 字符串拼接
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
    return result.stdout

# ===== 硬编码密钥 =====
API_SECRET_KEY = "sk-6f8g9h0j1k2l3m4n5o6p7q8r9s0t1u2v"  # ❌ 硬编码API密钥
JWT_SECRET = "super-secret-key-12345"  # ❌ 硬编码JWT密钥
DB_PASSWORD = "admin123"  # ❌ 硬编码密码

# ===== 路径遍历 =====
def read_file(filename):
    # ❌ 路径遍历: 未做路径校验
    with open(f"/data/files/{filename}", "r") as f:
        return f.read()

# ===== XSS =====
def render_comment(comment_text):
    # ❌ XSS: 未转义直接输出
    return f"<div class='comment'>{comment_text}</div>"

# ===== 不安全的反序列化 =====
import pickle
def load_config(data):
    # ❌ 不安全的反序列化
    return pickle.loads(data)

# ===== 不安全的CORS =====
from flask import Flask
app = Flask(__name__)

@app.after_request
def add_cors(response):
    # ❌ 不安全的CORS: 允许所有来源
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    return response

# ===== 硬编码Token =====
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"  # ❌ 硬编码Token

# ===== eval 注入 =====
def calculate(expression):
    # ❌ eval注入
    return eval(expression)

# ===== 不安全的临时文件 =====
def save_temp(data):
    # ❌ 不安全的临时文件
    with open("/tmp/user_data.txt", "w") as f:
        f.write(data)

if __name__ == '__main__':
    app.run(debug=True)  # ❌ debug模式
