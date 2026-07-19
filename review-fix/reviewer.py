"""
SentinelAI - Review & Fix Agent
安全审查与自动修复引擎

职责：
1. 对Security Agent发现的问题进行严重性复核
2. 评估影响范围（单文件/跨模块/全局）
3. 补充修复建议和可应用的Patch
4. 生成审查报告
"""

import json
import os
import sys


# 漏洞严重性权重（用于风险评分）
SEVERITY_WEIGHTS = {
    'Critical': 25,
    'High': 15,
    'Medium': 8,
    'Low': 3,
    'Info': 1,
}

# 影响范围分类
IMPACT_SCOPE = {
    'sql_injection': '跨模块（数据库访问层）',
    'command_injection': '全局（系统命令执行）',
    'hardcoded_secret': '全局（凭据泄露）',
    'xss': '前端模块',
    'path_traversal': '文件系统模块',
    'prompt_injection': 'LLM模块',
    'unsafe_config': '全局（配置层）',
    'insecure_deserialize': '全局（代码注入）',
    'dangerous_dep': '构建模块',
    'info_leak': '全局',
}


def review_findings(findings, project_index=None):
    """审查安全发现，补充修复方案和Patch"""
    reviewed = []

    for finding in findings:
        entry = dict(finding)

        # 复核严重性
        severity = entry.get('severity', 'Medium')
        vuln_type = entry.get('vuln_type', '')
        title = entry.get('title', '')
        file_path = entry.get('file_path', '')
        description = entry.get('description', '')
        evidence = entry.get('evidence', '')

        # 扩充风险说明
        risk_explanations = {
            'sql_injection': '攻击者可通过注入SQL语句窃取、篡改或删除数据库中的数据，甚至获得服务器控制权。',
            'command_injection': '攻击者可在服务器上执行任意系统命令，导致完全失陷。',
            'hardcoded_secret': '硬编码的密钥可被任何人从代码仓库中提取，导致系统认证被突破。',
            'xss': '攻击者可在用户浏览器中执行任意JavaScript，窃取Cookie、Session或重定向到钓鱼页面。',
            'path_traversal': '攻击者可读取服务器上的任意文件，包括配置文件、源代码等敏感信息。',
            'prompt_injection': '攻击者可劫持LLM的指令，使其输出恶意内容或泄露系统提示。',
            'unsafe_config': '不安全的配置为攻击者提供了可利用的攻击面。',
            'insecure_deserialize': '攻击者可通过构造恶意序列化数据在服务器上执行任意代码。',
            'dangerous_dep': '存在已知CVE漏洞的依赖可能被远程利用。',
            'info_leak': '敏感信息泄露可用于进一步攻击的信息收集。',
        }
        entry['risk_explanation'] = risk_explanations.get(vuln_type, '')

        # 影响范围
        entry['impact_scope'] = IMPACT_SCOPE.get(vuln_type, '局部')

        # 修复优先级
        if severity == 'Critical':
            entry['fix_priority'] = 'P0 - 立即修复'
            entry['fix_urgency'] = '建议立刻停止部署，优先修复此问题'
        elif severity == 'High':
            entry['fix_priority'] = 'P1 - 尽快修复'
            entry['fix_urgency'] = '建议在24小时内修复'
        elif severity == 'Medium':
            entry['fix_priority'] = 'P2 - 计划修复'
            entry['fix_urgency'] = '建议在当前迭代内修复'
        else:
            entry['fix_priority'] = 'P3 - 关注'
            entry['fix_urgency'] = '建议在下个迭代中关注'

        # 自动生成Patch
        patch = generate_patch(evidence, vuln_type, severity)
        if patch:
            entry['fix_patch'] = patch

        # 更具体的修复指导
        entry['fix_guide'] = generate_fix_guide(vuln_type, severity, evidence, file_path)

        reviewed.append(entry)

    return reviewed


def generate_patch(code_snippet, vuln_type, severity):
    """根据漏洞类型生成修复Patch"""
    if not code_snippet:
        return ''

    patches = {
        'sql_injection': _fix_sql_injection,
        'command_injection': _fix_command_injection,
        'hardcoded_secret': _fix_hardcoded_secret,
        'xss': _fix_xss,
        'path_traversal': _fix_path_traversal,
        'insecure_deserialize': _fix_insecure_deserialize,
        'unsafe_config': _fix_unsafe_config,
    }

    fixer = patches.get(vuln_type)
    if fixer:
        return fixer(code_snippet)
    return ''


def _fix_sql_injection(code):
    """生成SQL注入修复Patch"""
    import re
    if 'cursor.execute' in code:
        return '--- 原始代码\n' + code + '\n+++ 修复代码\n# cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
    elif 'db.query' in code or 'mysql.query' in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# db.query('SELECT * FROM users WHERE id = ?', [userId], callback)"
    return ''


def _fix_command_injection(code):
    """生成命令注入修复Patch"""
    if 'subprocess' in code and 'shell=True' in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# result = subprocess.run(['ping', '-c', '1', hostname], capture_output=True)"
    elif 'exec(`' in code or "exec('" in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# const {{ exec }} = require('child_process');\n# exec('ping -c 1 ' + sanitize(hostname), (err, stdout) => {{ ... }})"
    return ''


def _fix_hardcoded_secret(code):
    """生成硬编码密钥修复Patch"""
    import re
    # 提取变量名
    match = re.search(r'(\w+)\s*[=:]\s*["\'][^"\']+["\']', code)
    if match:
        var_name = match.group(1)
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# {var_name} = os.getenv('{var_name.upper()}', 'default-value')"
    return f"--- 原始代码\n{code}\n+++ 修复代码\n# 将密钥移至环境变量: os.getenv('SECRET_KEY')"


def _fix_xss(code):
    """生成XSS修复Patch"""
    if 'return' in code and '{' in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# import html\n# return f\"<div>{{html.escape(user_input)}}</div>\""
    elif 'res.send' in code or 'res.write' in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# 使用模板引擎的转义功能，不要直接拼接HTML\n# res.render('template', {{ name: sanitize(name) }})"
    return ''


def _fix_path_traversal(code):
    """生成路径遍历修复Patch"""
    return f"--- 原始代码\n{code}\n+++ 修复代码\n# 使用安全的路径解析\n# import os\n# safe_path = os.path.realpath(os.path.join(BASE_DIR, filename))\n# if not safe_path.startswith(BASE_DIR): raise ValueError('Invalid path')"


def _fix_insecure_deserialize(code):
    """生成不安全反序列化修复Patch"""
    if 'pickle' in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# 使用JSON替代pickle\n# data = json.loads(data_str)"
    elif 'eval(' in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# 使用ast.literal_eval()替代eval()\n# import ast\n# result = ast.literal_eval(expression)"
    return ''


def _fix_unsafe_config(code):
    """生成不安全配置修复Patch"""
    if 'Access-Control-Allow-Origin' in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# response.headers['Access-Control-Allow-Origin'] = 'https://your-domain.com'  # 指定具体域名"
    elif 'debug=True' in code:
        return f"--- 原始代码\n{code}\n+++ 修复代码\n# app.run(debug=False)  # 生产环境关闭debug"
    return ''


def generate_fix_guide(vuln_type, severity, evidence, file_path):
    """生成详细的修复指导"""
    guides = {
        'sql_injection': {
            'steps': [
                '1. 将所有 SQL 字符串拼接改为参数化查询或 PreparedStatement',
                '2. 使用 ORM（如 SQLAlchemy, Prisma）的内置查询构建器',
                '3. 验证所有用户输入的类型和格式',
                '4. 最小化数据库用户权限',
            ],
            'example': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        },
        'command_injection': {
            'steps': [
                '1. 禁用 shell=True，使用参数列表传递命令',
                '2. 对用户输入进行严格校验（白名单模式）',
                '3. 使用专门的库替代系统命令调用',
                '4. 限制低权限用户运行',
            ],
            'example': 'subprocess.run(["ping", "-c", "1", hostname], capture_output=True)',
        },
        'hardcoded_secret': {
            'steps': [
                '1. 从代码中移除所有明文密钥',
                '2. 使用环境变量（.env 文件，不提交到VCS）',
                '3. 生产环境使用密钥管理服务（AWS Secrets Manager, HashiCorp Vault）',
                '4. 轮换已泄露的密钥',
            ],
            'example': 'SECRET_KEY = os.getenv("SECRET_KEY")',
        },
        'xss': {
            'steps': [
                '1. 对所有输出到HTML的用户输入进行转义',
                '2. 使用模板引擎的内置转义功能',
                '3. 设置 Content-Security-Policy 头部',
                '4. 避免使用 dangerouslySetInnerHTML / innerHTML',
            ],
            'example': 'return html.escape(user_input)',
        },
        'path_traversal': {
            'steps': [
                '1. 使用白名单限制可访问的目录',
                '2. 使用 os.path.realpath() 规范化路径',
                '3. 验证目标路径是否在允许的基准目录内',
                '4. 禁止用户输入直接拼接到文件路径中',
            ],
            'example': 'safe_path = os.path.realpath(os.path.join(BASE_DIR, filename))\nif not safe_path.startswith(BASE_DIR): raise ValueError("Access denied")',
        },
        'prompt_injection': {
            'steps': [
                '1. 将用户输入与系统提示严格隔离',
                '2. 使用角色机制（系统/用户/助手）',
                '3. 对用户输入的特殊标记进行转义',
                '4. 添加输入验证和内容过滤',
            ],
            'example': 'messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_input}]',
        },
        'unsafe_config': {
            'steps': [
                '1. CORS 设置为具体域名而非通配符',
                '2. 生产环境关闭调试模式',
                '3. 限制 ALLOWED_HOSTS 为具体域名',
                '4. 禁用不必要的HTTP方法和头部',
            ],
            'example': 'CORS(origins=["https://your-domain.com"])',
        },
        'insecure_deserialize': {
            'steps': [
                '1. 使用安全的序列化格式（JSON + schema 验证）',
                '2. 避免使用 pickle/eval/exec 处理不可信数据',
                '3. 必须使用时，验证数据来源并设置沙箱',
            ],
            'example': 'import json\ndata = json.loads(data_str)\n# 然后使用schema验证',
        },
        'dangerous_dep': {
            'steps': [
                '1. 升级到不存在已知漏洞的版本',
                '2. 运行 pip audit / npm audit 定期检查',
                '3. 使用 Dependabot 或 Renovate 自动升级依赖',
            ],
            'example': 'pip install --upgrade package_name',
        },
    }

    guide = guides.get(vuln_type, {
        'steps': ['1. 评估具体场景进行针对性修复'],
        'example': '',
    })

    result = f"### 修复步骤\n"
    result += '\n'.join(guide['steps'])
    if guide['example']:
        result += f"\n\n### 参考代码\n```\n{guide['example']}\n```"

    return result


def calculate_risk_score(findings):
    """计算项目风险评分 (0=安全, 100=极危险)"""
    max_score = 100
    total_weight = 0

    for finding in findings:
        severity = finding.get('severity', 'Low')
        weight = SEVERITY_WEIGHTS.get(severity, 1)
        total_weight += weight

    # 计算评分（分数越高越危险）
    score = min(max_score, total_weight)
    return score


def get_risk_level(score):
    """获取风险等级"""
    if score <= 20:
        return 'A (安全)'
    elif score <= 40:
        return 'B (低风险)'
    elif score <= 60:
        return 'C (中风险)'
    elif score <= 80:
        return 'D (高风险)'
    else:
        return 'F (极危险)'


def format_review_report(reviewed_findings, risk_score, project_name=''):
    """格式化审查报告"""
    lines = []
    lines.append("=" * 60)
    lines.append(f"📋 SentinelAI - Review & Fix Agent 审查报告")
    lines.append("=" * 60)
    if project_name:
        lines.append(f"📁 项目: {project_name}")

    # 风险评分
    risk_level = get_risk_level(risk_score)
    lines.append(f"\n📊 风险评分: {risk_score}/100  [{risk_level}]")

    # 统计
    counts = {}
    for f in reviewed_findings:
        sev = f.get('severity', 'Unknown')
        counts[sev] = counts.get(sev, 0) + 1

    lines.append(f"\n📈 漏洞统计:")
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        if sev in counts:
            lines.append(f"  {sev}: {counts[sev]}")

    # 每个发现详细审查
    lines.append(f"\n{'=' * 60}")
    lines.append("📑 安全发现详情与修复方案")
    lines.append(f"{'=' * 60}")

    for i, finding in enumerate(reviewed_findings, 1):
        sev = finding.get('severity', 'Unknown')
        icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Info': 'ℹ️'}
        lines.append(f"\n{'─' * 40}")
        lines.append(f"{icon.get(sev, '•')} #{i} [{sev}] {finding.get('title', '')}")
        lines.append(f"{'─' * 40}")
        lines.append(f"  文件: {finding.get('file_path', '')}:{finding.get('line_start', '')}")
        lines.append(f"  类型: {finding.get('vuln_type', '')}")
        lines.append(f"  优先级: {finding.get('fix_priority', '')}")
        if finding.get('impact_scope'):
            lines.append(f"  影响范围: {finding.get('impact_scope', '')}")

        lines.append(f"\n  📝 描述:")
        lines.append(f"    {finding.get('description', '')[:150]}")

        if finding.get('risk_explanation'):
            lines.append(f"\n  ⚠️ 风险说明:")
            lines.append(f"    {finding.get('risk_explanation', '')[:200]}")

        lines.append(f"\n  🔧 修复建议:")
        suggestion = finding.get('fix_suggestion', '')
        if suggestion:
            lines.append(f"    {suggestion[:200]}")

        if finding.get('fix_patch'):
            lines.append(f"\n  📝 修复Patch:")
            patch_lines = finding['fix_patch'].split('\n')
            for pl in patch_lines:
                lines.append(f"    {pl}")

        if finding.get('fix_guide'):
            lines.append(f"\n  📖 详细修复指导:")
            guide_lines = finding['fix_guide'].split('\n')
            for gl in guide_lines:
                lines.append(f"    {gl}")

        lines.append(f"\n  {icon.get(sev, '•')} {finding.get('fix_urgency', '')}")

    return '\n'.join(lines)


def run_review(findings, project_index=None):
    """运行完整审查（入口函数）"""
    project_name = project_index.get('project_name', '') if project_index else ''

    # 审查并补充
    reviewed = review_findings(findings, project_index)
    risk_score = calculate_risk_score(reviewed)
    report = format_review_report(reviewed, risk_score, project_name)

    result = {
        'findings': reviewed,
        'risk_score': risk_score,
        'risk_level': get_risk_level(risk_score),
        'summary': {
            'total': len(reviewed),
            'critical': sum(1 for f in reviewed if f.get('severity') == 'Critical'),
            'high': sum(1 for f in reviewed if f.get('severity') == 'High'),
            'medium': sum(1 for f in reviewed if f.get('severity') == 'Medium'),
            'low': sum(1 for f in reviewed if f.get('severity') == 'Low'),
        }
    }

    return result, report


if __name__ == '__main__':
    findings_path = sys.argv[1] if len(sys.argv) > 1 else '../security/security-findings.json'
    index_path = sys.argv[2] if len(sys.argv) > 2 else '../parser/project-index.json'

    with open(findings_path, 'r') as f:
        findings = json.load(f)

    project_index = {}
    if os.path.exists(index_path):
        with open(index_path, 'r') as f:
            project_index = json.load(f)

    result, report = run_review(findings, project_index)
    print(report)

    # 保存结果
    output_dir = os.path.dirname(__file__)
    with open(os.path.join(output_dir, 'review-report.json'), 'w') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    with open(os.path.join(output_dir, 'review-report.txt'), 'w') as f:
        f.write(report)
    print(f"\n📄 审查报告已保存: review-report.json / review-report.txt")
