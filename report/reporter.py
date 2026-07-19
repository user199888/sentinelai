"""
SentinelAI - Report Agent
安全审计报告生成引擎

输出格式：
1. Markdown (security-report.md)
2. HTML (security-report.html) - 可扩展
3. JSON (security-report.json)
"""

import json
import os
import sys
from datetime import datetime


def generate_markdown_report(project_index, review_result, findings):
    """生成Markdown格式的安全审计报告"""
    project_name = project_index.get('project_name', '未知项目')
    risk_score = review_result.get('risk_score', 0)
    risk_level = review_result.get('risk_level', '未知')
    summary = review_result.get('summary', {})
    reviewed_findings = review_result.get('findings', [])
    tech_stack = ', '.join(project_index.get('tech_stack', []))
    frameworks = ', '.join(project_index.get('frameworks', []))
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    lines = []
    lines.append(f"# 🔒 SentinelAI 安全审计报告")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## 📋 项目概览")
    lines.append(f"")
    lines.append(f"| 项目 | 值 |")
    lines.append(f"|------|-----|")
    lines.append(f"| 项目名称 | {project_name} |")
    lines.append(f"| 扫描时间 | {scan_time} |")
    lines.append(f"| 文件数量 | {project_index.get('file_count', 0)} |")
    lines.append(f"| 技术栈 | {tech_stack if tech_stack else '未检测'} |")
    if frameworks:
        lines.append(f"| 框架 | {frameworks} |")
    lines.append(f"| 依赖文件 | {project_index.get('dep_count', 0)} |")
    lines.append(f"")
    lines.append(f"## 📊 风险评分")
    lines.append(f"")
    lines.append(f"**风险评分: {risk_score}/100**  |  **风险等级: {risk_level}**")
    lines.append(f"")
    lines.append(f"| 严重程度 | 数量 |")
    lines.append(f"|----------|------|")
    lines.append(f"| 🔴 Critical | {summary.get('critical', 0)} |")
    lines.append(f"| 🟠 High | {summary.get('high', 0)} |")
    lines.append(f"| 🟡 Medium | {summary.get('medium', 0)} |")
    lines.append(f"| 🟢 Low | {summary.get('low', 0)} |")
    lines.append(f"| **总计** | **{summary.get('total', 0)}** |")
    lines.append(f"")
    lines.append(f"## 🔍 安全发现详情")
    lines.append(f"")
    lines.append(f"共发现 **{summary.get('total', 0)}** 个安全问题，按严重程度排序如下：")
    lines.append(f"")

    if not reviewed_findings:
        lines.append(f"✅ **未发现安全风险！**")
        lines.append(f"")
        return '\n'.join(lines)

    for i, finding in enumerate(reviewed_findings, 1):
        sev = finding.get('severity', 'Unknown')
        icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Info': 'ℹ️'}.get(sev, '•')
        lines.append(f"---")
        lines.append(f"")
        lines.append(f"### {icon} #{i} [{sev}] {finding.get('title', '')}")
        lines.append(f"")
        lines.append(f"| 字段 | 值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| **类型** | `{finding.get('vuln_type', '')}` |")
        lines.append(f"| **文件** | `{finding.get('file_path', '')}:{finding.get('line_start', '')}` |")
        lines.append(f"| **优先级** | {finding.get('fix_priority', '')} |")
        lines.append(f"| **影响范围** | {finding.get('impact_scope', '')} |")
        lines.append(f"")
        lines.append(f"**📝 描述**")
        lines.append(f"> {finding.get('description', '')}")
        lines.append(f"")
        if finding.get('risk_explanation'):
            lines.append(f"**⚠️ 风险说明**")
            lines.append(f"> {finding.get('risk_explanation', '')}")
            lines.append(f"")

        if finding.get('evidence'):
            lines.append(f"**🔬 检测依据**")
            lines.append(f"```")
            lines.append(f"{finding.get('evidence', '')}")
            lines.append(f"```")
            lines.append(f"")

        lines.append(f"**🔧 修复建议**")
        lines.append(f"> {finding.get('fix_suggestion', '')}")
        lines.append(f"")

        if finding.get('fix_patch'):
            lines.append(f"**📝 修复Patch**")
            lines.append(f"```diff")
            lines.append(f"{finding.get('fix_patch', '')}")
            lines.append(f"```")
            lines.append(f"")

        if finding.get('fix_guide'):
            lines.append(f"**📖 详细修复指导**")
            lines.append(f"{finding.get('fix_guide', '')}")
            lines.append(f"")

        lines.append(f"**{icon} {finding.get('fix_urgency', '')}**")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## ✅ 修复优先级建议")
    lines.append(f"")
    critical_count = summary.get('critical', 0)
    high_count = summary.get('high', 0)
    medium_count = summary.get('medium', 0)

    if critical_count > 0:
        lines.append(f"### 🔴 立即修复（P0）")
        lines.append(f"存在 **{critical_count}** 个Critical级别漏洞，建议立即停止部署并优先修复。")
        lines.append(f"")

    if high_count > 0:
        lines.append(f"### 🟠 尽快修复（P1）")
        lines.append(f"存在 **{high_count}** 个High级别漏洞，建议在24小时内修复。")
        lines.append(f"")

    if medium_count > 0:
        lines.append(f"### 🟡 计划修复（P2）")
        lines.append(f"存在 **{medium_count}** 个Medium级别漏洞，建议在当前迭代内修复。")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"*本报告由 SentinelAI 安全审计系统自动生成于 {scan_time}*")

    return '\n'.join(lines)


def generate_html_report(project_index, review_result, findings):
    """生成HTML格式的安全审计报告"""
    md_content = generate_markdown_report(project_index, review_result, findings)

    # 简单HTML包装（后续可扩展markdown->html转换）
    lines = ['<!DOCTYPE html>',
        '<html lang="zh-CN">',
        '<head>',
        '<meta charset="UTF-8">',
        '<title>SentinelAI 安全审计报告</title>',
        '</head><body>',
        '<pre style="font-family:monospace;white-space:pre-wrap;word-wrap:break-word">',
        md_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'),
        '</pre></body></html>']
    return '\n'.join(lines)


def generate_json_data(project_index, review_result, findings):
    """生成JSON格式的安全审计数据"""
    return {
        'report_version': '1.0',
        'generated_at': datetime.now().isoformat(),
        'project': {
            'name': project_index.get('project_name', ''),
            'path': project_index.get('project_path', ''),
            'tech_stack': project_index.get('tech_stack', []),
            'frameworks': project_index.get('frameworks', []),
            'file_count': project_index.get('file_count', 0),
        },
        'risk_assessment': {
            'score': review_result.get('risk_score', 0),
            'level': review_result.get('risk_level', ''),
        },
        'summary': review_result.get('summary', {}),
        'findings': findings if isinstance(findings, list) else [],
    }


def run_report(project_index, review_result, findings, output_dir=None):
    """生成完整报告（入口函数）"""
    if output_dir is None:
        output_dir = os.path.dirname(__file__)

    # Markdown报告
    md = generate_markdown_report(project_index, review_result, findings)
    md_path = os.path.join(output_dir, 'security-report.md')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f"✅ Markdown报告: {md_path}")

    # HTML报告
    html = generate_html_report(project_index, review_result, findings)
    html_path = os.path.join(output_dir, 'security-report.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"✅ HTML报告: {html_path}")

    # JSON数据
    json_data = generate_json_data(project_index, review_result, findings)
    json_path = os.path.join(output_dir, 'security-report.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print(f"✅ JSON数据: {json_path}")

    # 飞书通知文案
    summary = review_result.get('summary', {})
    notification = (
        "🔒 *SentinelAI 安全扫描完成*\n\n"
        f"📁 项目: {project_index.get('project_name', '未知')}\n"
        f"📊 风险评分: {review_result.get('risk_score', 0)}/100 ({review_result.get('risk_level', '')})\n\n"
        f"📈 共发现 {summary.get('total', 0)} 个安全问题:\n"
        f"🔴 Critical: {summary.get('critical', 0)}\n"
        f"🟠 High: {summary.get('high', 0)}\n"
        f"🟡 Medium: {summary.get('medium', 0)}\n"
        f"🟢 Low: {summary.get('low', 0)}\n\n"
        f"{'⚠️ 发现高危漏洞，建议立即修复！' if summary.get('critical', 0) > 0 or summary.get('high', 0) > 5 else '✅ 整体安全状况良好。'}"
    )

    print(f"\n📢 飞书通知文案:")
    print(notification)

    return {
        'markdown': md_path,
        'html': html_path,
        'json': json_path,
        'notification': notification,
    }


if __name__ == '__main__':
    review_path = sys.argv[1] if len(sys.argv) > 1 else '../review-fix/review-report.json'
    index_path = sys.argv[2] if len(sys.argv) > 2 else '../parser/project-index.json'
    findings_path = sys.argv[3] if len(sys.argv) > 3 else '../security/security-findings.json'

    with open(review_path, 'r') as f:
        review_result = json.load(f)
    with open(index_path, 'r') as f:
        project_index = json.load(f)
    with open(findings_path, 'r') as f:
        findings = json.load(f)

    run_report(project_index, review_result, findings)
