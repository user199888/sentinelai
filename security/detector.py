"""
SentinelAI - Security Agent
安全检测引擎 - 核心漏洞检测模块

检测类型：
- SQL注入
- 命令注入
- 硬编码密钥/密码/Token
- XSS
- 路径遍历
- Prompt Injection
- 不安全的CORS/配置
- 危险依赖版本
- 不安全的反序列化
- eval/exec 动态执行
- 前端安全（Vue/React/原生JS）
"""

import re
import os
import json
import sys
from pathlib import Path


# ═══════════════════════════════════════════════════════════════
# 检测模式定义
# ═══════════════════════════════════════════════════════════════

class VulnPattern:
    def __init__(self, vuln_type, severity, patterns, description_template, fix_template):
        self.vuln_type = vuln_type
        self.severity = severity
        self.patterns = patterns if isinstance(patterns, list) else [patterns]
        self.description_template = description_template
        self.fix_template = fix_template


# ── SQL 注入 ──────────────────────────────────────────────────

SQL_INJECTION_PATTERNS = [
    # Python SQL拼接
    (r'cursor\.execute\(\s*f["\']', 'Python f-string SQL拼接'),
    (r'cursor\.execute\(\s*["\']\s*.*?\s*\+\s*', 'Python SQL字符串拼接'),
    (r'execute\([\s\S]*?["\'].*?\%.*?["\']', 'Python SQL格式化'),
    (r'\.execute\([\s\S]*?\$\{', 'Python SQL模板拼接'),
    # Node.js SQL拼接 - 直接拼接
    (r'db\.query\(\s*`.*?\$\{', 'Node.js SQL模板拼接'),
    (r'db\.query\(\s*["\'].*?\s*\+\s*', 'Node.js SQL字符串拼接'),
    (r'mysql\.query\(\s*["\'].*?\s*\+', 'MySQL字符串拼接'),
    (r'pg\.query\(\s*["\'].*?\s*\+', 'PostgreSQL字符串拼接'),
    # Node.js SQL拼接 - 变量引用（模板字符串赋值后传入query）
    (r'(?:query|sql)\s*=\s*`.*?\$\{.*?\`[\s\S]{0,100}?\.(query|execute)\(', 'Node.js SQL变量模板拼接'),
    (r'(?:query|sql)\s*=\s*["\'].*?\+\s*\w+[\s\S]{0,100}?\.(query|execute)\(', 'Node.js SQL变量字符串拼接'),
    # Node.js +后端等 任意模板字符串含SQL关键字直接传参
    (r'(?:query|sql)\s*=\s*`.*?SELECT\s+.*?\$\{', 'SQL赋值变量含模板插值'),
    # Java SQL拼接
    (r'Statement\.execute(Query|Update)?\(\s*["\']', 'Java SQL直接拼接'),
    (r'\.createStatement\(\).*?execute', 'Java Statement未用PreparedStatement'),
    # 通用ORM原始SQL拼接
    (r'\.raw\(\s*f["\']', 'ORM原始SQL拼接'),
    (r'\.raw\(\s*["\']\s*.*?\s*\+', 'ORM原始SQL拼接'),
    # 通用SQL拼接模式（兜底）
    (r'SELECT\s+.*?\s+FROM\s+.*?\$\{', 'SQL模板字符串含变量插值'),
    (r'SELECT\s+.*?\s+FROM\s+.*?\+\s*\w+', 'SQL字符串拼接变量'),
]

# ── 命令注入 ─────────────────────────────────────────────────

COMMAND_INJECTION_PATTERNS = [
    # Python
    (r'subprocess\.(call|run|Popen|check_call|check_output)\([\s\S]*?shell\s*=\s*True', 'Python shell=True命令执行'),
    (r'os\.system\(\s*["\'].*?\+', 'os.system命令注入'),
    (r'os\.popen\(\s*["\'].*?\+', 'os.popen命令注入'),
    (r'os\.popen\(\s*f["\']', 'os.popen f-string命令执行'),
    # Node.js - exec 命令注入（模板字符串/拼接）
    (r'exec\(\s*`.*?\$\{', 'Node.js exec模板字符串命令注入'),
    (r'exec\(\s*["\'].*?\s*\+', 'Node.js exec字符串拼接'),
    (r'exec\(\s*["\'].*?\$\{', 'Node.js exec模板注入'),
    (r'execSync\(\s*["\'].*?\$\{', 'Node.js execSync命令注入'),
    (r'execSync\(\s*`.*?\$\{', 'Node.js execSync模板字符串命令注入'),
    (r'spawn\(\s*["\'].*?\+.*?shell:\s*true', 'spawn shell注入'),
    # Node.js - 子进程间接命令注入
    (r'child_process\.exec\(\s*`', 'child_process.exec模板字符串命令注入'),
    (r'child_process\.execSync\(\s*`', 'child_process.execSync模板字符串命令注入'),
    (r'child_process\.exec\(\s*["\'].*?\+', 'child_process.exec字符串拼接'),
    # Java
    (r'Runtime\.getRuntime\(\)\.exec\(\s*["\']', 'Java Runtime.exec命令执行'),
]

# ── 硬编码密钥 ────────────────────────────────────────────────

HARDCODED_SECRET_PATTERNS = [
    # API Keys
    (r'(?i)(api[_-]?key|api[_-]?secret|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']', '硬编码API Key'),
    (r'(?i)(sk[-_])[A-Za-z0-9]{20,}', '可能的OpenAI API Key风格密钥'),
    (r'(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{20,}', 'GitHub Token'),
    (r'(?i)(xox[baprs]-)[A-Za-z0-9\-]{20,}', 'Slack Token'),
    (r'(?i)AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'(?i)(?<![A-Za-z0-9])[A-Za-z0-9+/=]{40}(?![A-Za-z0-9])', '可能的Base64编码密钥'),
    # 私钥
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', '私钥硬编码在代码中'),
    # JWT
    (r'(?i)(jwt[_-]?secret|jwt_key|jwt_secret_key)\s*[=:]\s*["\'][^"\']+["\']', '硬编码JWT Secret'),
    (r'(?i)jwt\.sign\(.*?["\'][A-Za-z0-9_\-]{8,}["\']', 'JWT签名使用硬编码密钥'),
    # Passwords
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\'@]{4,}["\']', '硬编码密码'),
    (r'DB_PASSWORD\s*=\s*["\'][^"\']+["\']', '数据库密码硬编码'),
    (r'(?i)(secret|secret_key|secretkey)\s*[=:]\s*["\'][^"\']+["\']', '硬编码Secret'),
    # 连接字符串
    (r'(?i)(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@', '数据库连接字符串含明文密码'),
]

# ── XSS ──────────────────────────────────────────────────────

XSS_PATTERNS = [
    # Python 后端渲染XSS
    (r'return\s+(f?["\'].*?\{.*?\}.*?["\'])\s*\.\s*format', 'Python字符串格式化可能导致XSS'),
    (r'return\s+f["\'].*?\{.*?\}', 'Python f-string未转义输出'),
    (r'render_template_string\(\s*f["\']', '模板字符串渲染可能导致XSS'),
    # Node.js 后端渲染XSS
    (r'res\.(send|write|end)\(.*?`.*?\$\{', 'Node.js响应含未转义模板字符串'),
    (r'res\.(send|write|end)\(\s*["\'].*?\s*\+.*?req\.', 'Node.js响应拼接用户输入'),
    (r'res\.(send|write|end)\(\s*["\'].*?\s*\+.*?params\.', 'Node.js响应拼接路由参数'),
    # DOM型XSS - innerHTML
    (r'\.innerHTML\s*=\s*\w+\s*\+\s*\w+', 'DOM innerHTML拼接'),
    (r'\.innerHTML\s*=\s*["\'].*?\s*\+\s*', 'innerHTML字符串拼接'),
    (r'\.innerHTML\s*=\s*`.*?\$\{', 'innerHTML模板字符串'),
    (r'\.innerHTML\s*=\s*.*?document', 'innerHTML赋值含DOM对象'),
    # DOM型XSS - document.write
    (r'document\.write\(\s*["\'].*?\s*\+', 'document.write未转义'),
    (r'document\.write\(\s*`.*?\$\{', 'document.write模板字符串'),
    # DOM型XSS - outerHTML, insertAdjacentHTML
    (r'\.outerHTML\s*=\s*["\'].*?\+', 'outerHTML字符串拼接'),
    (r'insertAdjacentHTML\(', 'insertAdjacentHTML可能导致XSS'),
    # jQuery XSS
    (r'\$\(["\'].*?\)\.html\(\s*["\']', 'jQuery html()可能导致XSS'),
    (r'\$\(["\'].*?\)\.append\(\s*["\']', 'jQuery append()可能导致XSS'),
    (r'\$\(["\'].*?\)\.prepend\(\s*["\']', 'jQuery prepend()可能导致XSS'),
    # React 安全风险
    (r'dangerouslySetInnerHTML\s*=\s*\{\{', 'React dangerouslySetInnerHTML可能导致XSS'),
    (r'__html:\s*.*?\{.*?\}', 'React __HTML属性含动态内容'),
    # Vue 安全风险
    (r'v-html\s*=\s*["\'].*?\{', 'Vue v-html可能导致XSS'),
    (r'v-html\s*=\s*["\'].*?\+\s*', 'Vue v-html拼接用户输入'),
    # Angular 安全风险
    (r'\[innerHTML\]\s*=\s*', 'Angular innerHTML绑定可能导致XSS'),
]

# ── 路径遍历 ─────────────────────────────────────────────────

PATH_TRAVERSAL_PATTERNS = [
    (r'open\(\s*(f?["\'].*?\{.*?\}|["\'].*?\s*\+\s*\w+)', '文件操作路径拼接'),
    (r'read_text\(\)\s*.*?[+f]', '文件读取拼接路径'),
    (r'readFile\(\s*[`"\'].*?\$\{', 'Node.js文件读取模板字符串'),
    (r'readFile\(\s*["\'].*?\s*\+\s*req', 'Node.js文件读取拼接用户输入'),
    (r'readFile\(\s*["\'].*?\s*\+\s*params', 'Node.js文件读取拼接参数'),
    (r'readFileSync\(\s*[`"\'].*?\$\{', 'Node.js readFileSync模板字符串'),
    (r'readFileSync\(\s*["\'].*?\s*\+', 'Node.js readFileSync字符串拼接'),
    (r'sendFile\(\s*["\'].*?\s*\+\s*', 'sendFile路径拼接'),
    (r'fs\.(readFile|writeFile|unlink)\(\s*f["\']', 'fs操作路径拼接'),
    (r'Path\.join\(.*?\.\.\s*\)', '路径拼接含目录遍历'),
    (r'path\.join\(.*?\.\.\s*\)', '路径拼接含目录遍历'),
]

# ── Prompt Injection ──────────────────────────────────────────

PROMPT_INJECTION_PATTERNS = [
    (r'(?i)(openai|llm|gpt|claude|chat)\.(complete|chat|generate)\([\s\S]*?user_input|[\s\S]*?message[\s\S]*?\{', 'LLM输入直接拼接可能含Prompt注入'),
    (r'(?i)system_prompt\s*\+\s*user_input', 'System Prompt拼接用户输入'),
    (r'(?i)prompt\s*=\s*f["\'].*?\{.*?system.*?\}', 'Prompt模板含未过滤用户输入'),
    (r'messages\.append\(.*?["\'].*?\{.*?\}.*?["\']', '消息构建含未转义模板'),
    (r'(?i)(completions|chat\.completions)\.create\([\s\S]*?messages[\s\S]*?user_input', 'LLM API消息含直接用户输入'),
]

# ── 不安全的CORS/配置 ────────────────────────────────────────

INSECURE_CONFIG_PATTERNS = [
    # CORS头设置 - HTTP响应头格式
    (r'Access-Control-Allow-Origin\s*:\s*\*', 'CORS允许所有来源'),
    # CORS头设置 - Python Flask/框架 headers['key']=value 格式
    (r"""Access-Control-Allow-Origin['"]\s*\]\s*=\s*['"]\*['"]""", 'CORS配置允许所有来源(header赋值)'),
    # CORS头设置 - 通配模式
    (r"""headers\[['"]Access-Control-Allow-Origin['"]\]\s*=\s*['"]\*['"]""", 'CORS header通配赋值'),
    # Debug模式
    (r'app\.run\(.*?debug\s*=\s*True', 'Flask debug模式开启'),
    (r'app\.run\(.*?debug\s*=\s*true', 'Node.js debug模式'),
    (r'DEBUG\s*=\s*True', 'Python DEBUG模式开启'),
    # ALLOWED_HOSTS
    (r'ALLOWED_HOSTS\s*=\s*\[\s*"\*"\s*\]', 'Django ALLOWED_HOSTS=*'),
    # 缺少HTTPS/CSP
    (r'createServer\(\)', 'HTTP服务器无SSL/TLS配置'),
    (r'app\.listen\s*\(\s*\d+\s*\)', '无TLS的HTTP监听'),
]

# ── 会话/Cookie安全 ──────────────────────────────────────────

INSECURE_COOKIE_PATTERNS = [
    (r'cookie\s*=\s*["\'].*?;', 'Cookie设置缺少安全标记'),
    (r'res\.cookie\(["\'].*?["\'].*?[^s]ecure', 'Cookie缺少Secure标记'),
    (r'res\.cookie\(["\'].*?["\'].*?[^Hh]ttpOnly', 'Cookie缺少httpOnly标记'),
    (r'session\.cookie\.secure\s*=\s*false', 'Session Cookie Secure标记关闭'),
    (r'session\.cookie\.httpOnly\s*=\s*false', 'Session Cookie httpOnly标记关闭'),
    (r'session\.cookie\.sameSite\s*=\s*["\']none["\']', 'Session Cookie sameSite=none可能不安全'),
]

# ── 不安全的反序列化 ─────────────────────────────────────────

INSECURE_DESERIALIZE_PATTERNS = [
    (r'pickle\.loads?\(', '不安全的pickle反序列化'),
    (r'yaml\.load\([^)]*(?!Loader=yaml\.SafeLoader)', '不安全的YAML加载'),
    (r'jsonpickle\.(loads|decode)\(', '不安全的jsonpickle反序列化'),
    (r'marshal\.loads?\(', '不安全的marshal反序列化'),
    (r'eval\(\s*[^)]*\)', 'eval执行（可能导致代码注入）'),
    # Python exec() 内置函数（区别于Node.js child_process.exec）
    (r'(?<!\.)exec\(\s*["\'`]', 'Python exec执行（可能导致代码注入）'),
    # Node.js 的 vm.runInThisContext / vm.runInNewContext
    (r'vm\.runInThisContext\(', 'vm.runInThisContext代码注入'),
    (r'vm\.runInNewContext\(', 'vm.runInNewContext代码注入'),
    (r'Function\(["\'`].*?["\'`]\)', 'Function构造器代码注入'),
]

# ── 前端开放端口/服务配置 ────────────────────────────────────

FRONTEND_CONFIG_PATTERNS = [
    (r'(?i)(content-security-policy|csp)\s*[=:]\s*["\'](default-src\s+\'none\'|script-src\s+\'self\')', '安全的CSP配置'),
    (r'X-Content-Type-Options\s*:\s*nosniff', '安全的X-Content-Type-Options'),
    (r'X-Frame-Options\s*:\s*(DENY|SAMEORIGIN)', '安全的X-Frame-Options'),
]

# ── 危险依赖版本 ──────────────────────────────────────────────

KNOWN_VULNERABLE_PACKAGES = {
    # Python
    'cryptography': {'max': '3.4.8', 'reason': '不安全的密码学实现'},
    'pyyaml': {'max': '5.4.1', 'reason': 'CVE-2020-14343 YAML反序列化'},
    'flask': {'max': '2.2.0', 'reason': '旧版本可能有已知漏洞'},
    'requests': {'max': '2.28.0', 'reason': '旧版本可能有已知漏洞'},
    'django': {'max': '4.0', 'reason': 'Django 4.0以下存在已知漏洞'},
    'numpy': {'max': '1.21.0', 'reason': '旧版本可能有已知漏洞'},
    'werkzeug': {'max': '2.0.0', 'reason': 'Werkzeug旧版本可能有已知漏洞'},
    'pillow': {'max': '9.0.0', 'reason': 'Pillow旧版本可能有已知漏洞'},
    # JavaScript
    'lodash': {'max': '4.17.20', 'reason': 'CVE-2021-23337 原型污染'},
    'express': {'max': '4.16.0', 'reason': '旧版本可能有已知漏洞'},
    'ejs': {'max': '3.1.5', 'reason': 'CVE-2022-29078 模板注入'},
    'jsonwebtoken': {'max': '8.5.0', 'reason': '旧版本可能有已知漏洞'},
    'jquery': {'max': '3.5.0', 'reason': 'jQuery旧版本可能有已知XSS漏洞'},
    'axios': {'max': '0.21.0', 'reason': '旧版本可能有已知漏洞'},
    'socket.io': {'max': '2.4.0', 'reason': '旧版本可能有已知漏洞'},
    'next': {'max': '12.0.0', 'reason': '旧版本可能有已知漏洞'},
    'react': {'max': '16.13.0', 'reason': '旧版本可能有已知漏洞'},
    'vue': {'max': '2.6.0', 'reason': '旧版本可能有已知漏洞'},
}


# ═══════════════════════════════════════════════════════════════
# 检测引擎
# ═══════════════════════════════════════════════════════════════

def is_line_commented(line):
    """检查当前行是否为注释"""
    stripped = line.strip()
    return stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*')


# 跨行模式列表 - 需要跨行匹配的正则
MULTILINE_PATTERNS = [
    # Python f-string赋值后再传参execute
    (r'(?:query|sql)\s*=\s*f["\'].*?\{.*?["\'][\s\S]{0,200}?\.(?:execute|query)\(', 'Python f-string变量SQL拼接'),
]


def scan_multiline(file_path, rel_path, findings):
    """扫描跨行模式（用于变量赋值后传参等场景）"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return
    ext = os.path.splitext(file_path)[1].lower()
    if ext != '.py':
        return
        for m in matches:
            ln = content[:m.start()].count('\n') + 1
            print(f'[DEBUG]     line {ln}: {m.group()[:60]}')
    for pattern, description in MULTILINE_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[:m.start()].count('\n') + 1
            # 避免重复 - 检查是否已被单行匹配捕获
            already_found = any(
                f['line_start'] == line_num and 'SQL' in f['title']
                for f in findings
            )
            if already_found:
                continue
            findings.append({
                'vuln_type': 'sql_injection',
                'severity': 'Critical',
                'file_path': rel_path,
                'line_start': line_num,
                'line_end': line_num,
                'title': 'SQL注入风险',
                'description': f'{description}: f-string含变量插值传给execute',
                'evidence': content[m.start():m.end()][:300],
                'fix_suggestion': '使用参数化查询/ORM代替字符串拼接SQL。例如: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                'fix_patch': ''
            })


def scan_file(file_path):
    """扫描单个文件的安全问题"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return findings

    rel_path = os.path.relpath(file_path)
    ext = os.path.splitext(file_path)[1].lower()
    is_js_file = ext in ('.js', '.jsx', '.ts', '.tsx')
    is_py_file = ext == '.py'
    has_csp_config = False
    has_hsts_config = False
    has_xframe_config = False
    has_xcontent_config = False

    for line_num, line in enumerate(lines, 1):
        # ── SQL注入 ──
        for pattern, description in SQL_INJECTION_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'sql_injection',
                    'severity': 'Critical',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': 'SQL注入风险',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '使用参数化查询/ORM代替字符串拼接SQL。例如: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                    'fix_patch': ''
                })

        # ── 命令注入 ──
        for pattern, description in COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'command_injection',
                    'severity': 'Critical',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': '命令注入风险',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '避免使用shell=True。使用参数列表代替字符串命令。例如: subprocess.run(["ping", "-c", "1", hostname])',
                    'fix_patch': ''
                })

        # ── 硬编码密钥 ──
        for pattern, description in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'hardcoded_secret',
                    'severity': 'High',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': '硬编码密钥/密码',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '将密钥存入环境变量或密钥管理服务(如AWS Secrets Manager/Vault)，通过os.getenv()读取',
                    'fix_patch': ''
                })

        # ── XSS ──
        for pattern, description in XSS_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'xss',
                    'severity': 'High',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': 'XSS跨站脚本风险',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '对用户输入进行HTML转义。Python: 使用html.escape()；JS: 使用DOMPurify或escapeHtml()',
                    'fix_patch': ''
                })

        # ── 路径遍历 ──
        for pattern, description in PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'path_traversal',
                    'severity': 'High',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': '路径遍历风险',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '使用安全的路径解析：限制访问目录，使用os.path.realpath()规范化路径，检查路径是否在允许范围内',
                    'fix_patch': ''
                })

        # ── Prompt Injection ──
        for pattern, description in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'prompt_injection',
                    'severity': 'High',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': 'Prompt注入风险',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '对用户输入进行转义和边界分隔。使用角色隔离(Role Isolation)，限制系统Prompt和用户输入的边界',
                    'fix_patch': ''
                })

        # ── 不安全配置 ──
        for pattern, description in INSECURE_CONFIG_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'unsafe_config',
                    'severity': 'Medium',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': '不安全的配置',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '限制CORS为具体域名；生产环境关闭debug模式；ALLOWED_HOSTS指定具体域名',
                    'fix_patch': ''
                })

        # ── Cookie安全 ──
        for pattern, description in INSECURE_COOKIE_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'insecure_cookie',
                    'severity': 'Medium',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': 'Cookie安全配置问题',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '为Cookie设置Secure、httpOnly和SameSite标记',
                    'fix_patch': ''
                })

        # ── 不安全的反序列化 ──
        for pattern, description in INSECURE_DESERIALIZE_PATTERNS:
            # 跳过语言不匹配的模式
            if is_js_file and pattern.startswith(r'(?<!\.)'):
                continue  # Python exec() 不适用于 JS/TS 文件
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'insecure_deserialize',
                    'severity': 'Critical',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': '不安全的反序列化/代码执行',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '避免使用pickle/eval等不安全反序列化。使用安全的替代方案如JSON+schema验证',
                    'fix_patch': ''
                })

        # ── 前端安全配置检查（标记是否已配置） ──
        if re.search(r'(?i)content-security-policy|Content-Security-Policy', line):
            if not line.strip().startswith('#') and not line.strip().startswith('//'):
                has_csp_config = True
        if re.search(r'(?i)Strict-Transport-Security|HSTS', line):
            if not line.strip().startswith('#') and not line.strip().startswith('//'):
                has_hsts_config = True
        if re.search(r'(?i)X-Frame-Options|x-frame-options', line):
            if not line.strip().startswith('#') and not line.strip().startswith('//'):
                has_xframe_config = True
        if re.search(r'(?i)X-Content-Type-Options|x-content-type-options', line):
            if not line.strip().startswith('#') and not line.strip().startswith('//'):
                has_xcontent_config = True

    # ── 文件级别: 安全配置缺失检测 ──
    # 只对 Web/后端文件做这些检查
    ext = os.path.splitext(file_path)[1].lower()
    if ext in ('.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php'):
        # 检查是否有 HTTP 响应/服务相关代码
        is_web_file = False
        web_indicators = ['flask', 'django', 'express', 'app.get(', 'app.post(', 'app.put(',
                          'app.delete(', '@app.route', 'router.get(', 'def get(',
                          'handleRequest', 'http.createServer', 'listen(']
        for indicator in web_indicators:
            for line in lines:
                if indicator in line.lower():
                    is_web_file = True
                    break
            if is_web_file:
                break

        if is_web_file:
            if not has_csp_config:
                findings.append({
                    'vuln_type': 'missing_security_header',
                    'severity': 'Medium',
                    'file_path': rel_path,
                    'line_start': 1,
                    'line_end': 1,
                    'title': '缺少Content-Security-Policy头',
                    'description': 'Web应用未设置Content-Security-Policy响应头，可能面临XSS和数据注入攻击',
                    'evidence': '未发现CSP配置',
                    'fix_suggestion': '添加Content-Security-Policy响应头，限制资源加载来源',
                    'fix_patch': ''
                })
            if not has_hsts_config:
                findings.append({
                    'vuln_type': 'missing_security_header',
                    'severity': 'Low',
                    'file_path': rel_path,
                    'line_start': 1,
                    'line_end': 1,
                    'title': '缺少Strict-Transport-Security头',
                    'description': 'Web应用未设置HSTS头，可能面临SSL剥离攻击',
                    'evidence': '未发现HSTS配置',
                    'fix_suggestion': '添加Strict-Transport-Security头，强制HTTPS连接',
                    'fix_patch': ''
                })
            if not has_xframe_config:
                findings.append({
                    'vuln_type': 'missing_security_header',
                    'severity': 'Medium',
                    'file_path': rel_path,
                    'line_start': 1,
                    'line_end': 1,
                    'title': '缺少X-Frame-Options头',
                    'description': 'Web应用未设置X-Frame-Options头，可能面临点击劫持攻击',
                    'evidence': '未发现X-Frame-Options配置',
                    'fix_suggestion': '添加X-Frame-Options: DENY或SAMEORIGIN头',
                    'fix_patch': ''
                })

    # 跨行模式扫描（变量赋值传参等）
    scan_multiline(file_path, rel_path, findings)

    return findings


def check_env_file(file_path):
    """扫描.env文件中的密钥泄露"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return findings

    rel_path = os.path.relpath(file_path)

    # .env文件本身就有泄露风险
    findings.append({
        'vuln_type': 'info_leak',
        'severity': 'Medium',
        'file_path': rel_path,
        'line_start': 1,
        'line_end': 1,
        'title': '.env文件存在于项目中',
        'description': '项目包含.env文件，可能泄露敏感配置信息。.env文件不应提交到版本控制',
        'evidence': '.env文件',
        'fix_suggestion': '确保.env在.gitignore中。使用.env.example作为模板提交到仓库',
        'fix_patch': ''
    })

    for line_num, line in enumerate(content.splitlines(), 1):
        # 检查KEY=VALUE模式
        if '=' in line and not line.strip().startswith('#'):
            parts = line.strip().split('=', 1)
            if len(parts) == 2:
                key, value = parts[0].strip(), parts[1].strip().strip("'\"")
                if not value:
                    continue
                # 关键词检测
                sensitive_keys = [
                    'password', 'secret', 'key', 'token', 'credential',
                    'access_key', 'secret_key', 'private_key', 'api_key'
                ]
                if any(k in key.lower() for k in sensitive_keys) and len(value) >= 4:
                    findings.append({
                        'vuln_type': 'info_leak',
                        'severity': 'High',
                        'file_path': rel_path,
                        'line_start': line_num,
                        'line_end': line_num,
                        'title': f'环境变量泄露 - {key}',
                        'description': f'环境变量 {key} 包含敏感值（长度: {len(value)}）',
                        'evidence': f'{key}={value[:4]}***',
                        'fix_suggestion': '确保.env文件不被包含在发布的代码中。使用密钥管理服务管理生产密钥',
                        'fix_patch': ''
                    })
                # 检测URL中的凭证
                elif re.match(r'^\w+://[^:]+:[^@]+@', value):
                    findings.append({
                        'vuln_type': 'info_leak',
                        'severity': 'High',
                        'file_path': rel_path,
                        'line_start': line_num,
                        'line_end': line_num,
                        'title': f'连接字符串泄露 - {key}',
                        'description': f'环境变量 {key} 包含带凭证的连接URL',
                        'evidence': f'{key}={value.split("@")[0].split("://")[0]}://***@***',
                        'fix_suggestion': '使用环境变量拆分连接字符串的用户名和密码部分',
                        'fix_patch': ''
                    })

    return findings


def check_vulnerable_dependencies(dep_file_path):
    """检查依赖文件中的危险版本"""
    findings = []
    rel_path = os.path.relpath(dep_file_path)
    filename = os.path.basename(dep_file_path)

    try:
        with open(dep_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return findings

    if filename == 'requirements.txt':
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                parts = re.split(r'[=<>~!]+', line, maxsplit=1)
                if len(parts) >= 2 and len(parts[1].strip()) > 0:
                    pkg = parts[0].strip().lower()
                    ver = parts[1].strip()
                    if pkg in KNOWN_VULNERABLE_PACKAGES:
                        vuln_info = KNOWN_VULNERABLE_PACKAGES[pkg]
                        findings.append({
                            'vuln_type': 'dangerous_dep',
                            'severity': 'Medium',
                            'file_path': rel_path,
                            'line_start': line,
                            'line_end': line,
                            'title': f'危险依赖: {pkg} {ver}',
                            'description': f'{pkg}@{ver} {vuln_info["reason"]}',
                            'evidence': line,
                            'fix_suggestion': f'升级 {pkg} 到 {vuln_info["max"]} 以上版本',
                            'fix_patch': ''
                        })

    elif filename == 'package.json':
        try:
            data = json.loads(content)
            for dep_type in ('dependencies', 'devDependencies'):
                for pkg, ver in data.get(dep_type, {}).items():
                    pkg_lower = pkg.lower()
                    if pkg_lower in KNOWN_VULNERABLE_PACKAGES:
                        vuln_info = KNOWN_VULNERABLE_PACKAGES[pkg_lower]
                        findings.append({
                            'vuln_type': 'dangerous_dep',
                            'severity': 'Medium',
                            'file_path': rel_path,
                            'line_start': 1,
                            'line_end': 1,
                            'title': f'危险依赖: {pkg} {ver}',
                            'description': f'{pkg}@{ver} {vuln_info["reason"]}',
                            'evidence': f'{pkg}: "{ver}"',
                            'fix_suggestion': f'升级 {pkg} 到 {vuln_info["max"]} 以上版本',
                            'fix_patch': ''
                        })
        except json.JSONDecodeError:
            pass

    elif filename in ('yarn.lock', 'pnpm-lock.yaml', 'package-lock.json'):
        # 这些文件已有详细版本锁定，跳过
        pass

    return findings


def check_config_file(file_path):
    """检查配置文件中的不安全配置"""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return findings

    rel_path = os.path.relpath(file_path)

    for line_num, line in enumerate(lines, 1):
        # 检查配置文件中硬编码的密钥
        for pattern, description in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'vuln_type': 'hardcoded_secret',
                    'severity': 'High',
                    'file_path': rel_path,
                    'line_start': line_num,
                    'line_end': line_num,
                    'title': '配置文件中的硬编码凭据',
                    'description': f'{description}: {line.strip()[:100]}',
                    'evidence': line.strip()[:200],
                    'fix_suggestion': '敏感配置应通过环境变量注入，而非硬编码在配置文件中',
                    'fix_patch': ''
                })
                break  # 避免重复匹配

    return findings


def run_security_scan(project_index):
    """运行完整安全扫描（入口函数）"""
    all_findings = []
    project_path = project_index.get('project_path', '')

    if not project_path or not os.path.exists(project_path):
        print(f"⚠️  项目路径不存在: {project_path}")
        return all_findings

    # 获取项目中需要扫描的文件
    scan_targets = []
    for root, dirs, files in os.walk(project_path):
        # 忽略node_modules, .git等
        dirs[:] = [d for d in dirs if d not in {
            'node_modules', '.git', '__pycache__', '.venv', 'venv',
            'env', 'dist', 'build', '.next', 'target', 'vendor',
            '.terraform', '.serverless', '.svelte-kit', '.angular',
            'coverage', '.nyc_output'
        }]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in {'.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go',
                        '.rb', '.php', '.c', '.cpp', '.h', '.hpp',
                        '.kt', '.swift', '.scala', '.rs', '.vue', '.svelte',
                        '.ejs', '.hbs', '.pug', '.jade', '.erb'}:
                scan_targets.append(os.path.join(root, f))

    scan_targets.sort()  # 确定性顺序

    print(f"📁 扫描路径: {project_path}")
    print(f"📄 待扫描文件数: {len(scan_targets)}")

    # 扫描源码文件
    for file_path in scan_targets:
        findings = scan_file(file_path)
        all_findings.extend(findings)

    # 扫描.env文件
    env_path = os.path.join(project_path, '.env')
    if os.path.exists(env_path):
        all_findings.extend(check_env_file(env_path))

    # 检查配置文件
    for cfg_file in project_index.get('config_files', []):
        cfg_path = os.path.join(project_path, cfg_file)
        if os.path.exists(cfg_path) and cfg_file != '.env':
            all_findings.extend(check_config_file(cfg_path))

    # 检查依赖版本
    for dep in project_index.get('dependencies', []):
        dep_path = os.path.join(project_path, dep['file'])
        if os.path.exists(dep_path):
            all_findings.extend(check_vulnerable_dependencies(dep_path))

    # 去重（相同文件相同行的同类型漏洞只保留一个）
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f['file_path'], f['line_start'], f['vuln_type'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


def format_security_report(findings):
    """格式化安全发现报告"""
    lines = []
    lines.append("=" * 60)
    lines.append("🔒 SentinelAI - Security Agent 安全审计报告")
    lines.append("=" * 60)
    lines.append(f"共发现 {len(findings)} 个安全问题\n")

    if not findings:
        lines.append("✅ 未发现安全风险！")
        return '\n'.join(lines)

    # 统计
    by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Info': []}
    by_vuln_type = {}
    for f in findings:
        by_severity.setdefault(f['severity'], []).append(f)
        vt = f['vuln_type']
        by_vuln_type.setdefault(vt, 0)
        by_vuln_type[vt] += 1

    # 概览
    lines.append("📊 漏洞类型分布:")
    for vt, count in sorted(by_vuln_type.items(), key=lambda x: -x[1]):
        lines.append(f"   • {vt}: {count} 个")
    lines.append("")

    # 按严重程度分组输出
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        items = by_severity.get(severity, [])
        if not items:
            continue
        icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Info': 'ℹ️'}
        lines.append(f"\n{icon.get(severity, '•')} [{severity}] 共 {len(items)} 个")
        lines.append("-" * 60)
        for f in items:
            lines.append(f"  📍 {f['file_path']}:{f['line_start']}")
            lines.append(f"  📌 {f['title']}")
            lines.append(f"  💬 {f['description'][:120]}")
            lines.append(f"  🔧 {f['fix_suggestion'][:120]}")
            lines.append("")

    return '\n'.join(lines)


if __name__ == '__main__':
    index_path = sys.argv[1] if len(sys.argv) > 1 else '../parser/project-index.json'

    if not os.path.exists(index_path):
        print(f"❌ 项目索引文件不存在: {index_path}")
        sys.exit(1)

    with open(index_path, 'r') as f:
        project_index = json.load(f)

    findings = run_security_scan(project_index)
    print(format_security_report(findings))

    # 保存结果
    output_dir = os.path.dirname(__file__)
    output_path = os.path.join(output_dir, 'security-findings.json')
    with open(output_path, 'w') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    print(f"\n📄 安全发现已保存: {output_path}")
