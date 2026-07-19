"""
单元测试 - Report Agent (report/reporter.py)
"""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from report.reporter import (
    generate_markdown_report, generate_html_report,
    generate_json_data, run_report
)


SAMPLE_PROJECT = {
    'project_name': 'test-project',
    'project_path': '/tmp/test',
    'file_count': 10,
    'dep_count': 2,
    'tech_stack': ['Python', 'JavaScript'],
    'frameworks': ['Flask'],
}

SAMPLE_REVIEW = {
    'risk_score': 65,
    'risk_level': 'D (高风险)',
    'summary': {
        'total': 3,
        'critical': 1,
        'high': 1,
        'medium': 1,
        'low': 0,
    },
    'findings': [
        {
            'vuln_type': 'sql_injection',
            'severity': 'Critical',
            'file_path': 'app.py',
            'line_start': 10,
            'title': 'SQL注入风险',
            'description': '发现SQL拼接',
            'risk_explanation': '攻击者可通过注入SQL语句',
            'evidence': 'cursor.execute(f"...")',
            'fix_suggestion': '使用参数化查询',
            'fix_patch': '--- a\n+++ b\n',
            'fix_guide': '### 修复步骤\n1. 使用参数化查询',
            'fix_priority': 'P0 - 立即修复',
            'fix_urgency': '建议立即修复',
            'impact_scope': '跨模块',
        },
        {
            'vuln_type': 'hardcoded_secret',
            'severity': 'High',
            'file_path': 'config.py',
            'line_start': 5,
            'title': '硬编码密钥',
            'description': '发现硬编码Secret',
            'risk_explanation': '硬编码的密钥可被提取',
            'evidence': 'SECRET_KEY = "xxx"',
            'fix_suggestion': '使用环境变量',
            'fix_patch': '',
            'fix_guide': '### 修复步骤\n1. 移除明文密钥',
            'fix_priority': 'P1 - 尽快修复',
            'fix_urgency': '建议24h内修复',
            'impact_scope': '全局',
        },
        {
            'vuln_type': 'dangerous_dep',
            'severity': 'Medium',
            'file_path': 'requirements.txt',
            'line_start': 1,
            'title': '危险依赖',
            'description': 'cryptography 3.4.0',
            'risk_explanation': '存在已知CVE',
            'evidence': 'cryptography==3.4.0',
            'fix_suggestion': '升级版本',
            'fix_patch': '',
            'fix_guide': '### 修复步骤\n1. 升级依赖',
            'fix_priority': 'P2 - 计划修复',
            'fix_urgency': '建议本迭代内修复',
            'impact_scope': '构建模块',
        },
    ],
}

SAMPLE_FINDINGS = SAMPLE_REVIEW['findings']


class TestMarkdownReport:
    def test_generates_report(self):
        report = generate_markdown_report(SAMPLE_PROJECT, SAMPLE_REVIEW, SAMPLE_FINDINGS)
        assert '# 🔒 SentinelAI 安全审计报告' in report
        assert 'test-project' in report
        assert '65/100' in report
        assert 'SQL注入风险' in report
        assert '硬编码密钥' in report

    def test_contains_summary_table(self):
        report = generate_markdown_report(SAMPLE_PROJECT, SAMPLE_REVIEW, SAMPLE_FINDINGS)
        assert '| 🔴 Critical | 1 |' in report
        assert '| 🟠 High | 1 |' in report
        assert '| 🟡 Medium | 1 |' in report

    def test_contains_fix_suggestions(self):
        report = generate_markdown_report(SAMPLE_PROJECT, SAMPLE_REVIEW, SAMPLE_FINDINGS)
        assert 'P0 - 立即修复' in report
        assert 'P1 - 尽快修复' in report

    def test_no_findings(self):
        """无发现时的报告"""
        empty_review = dict(SAMPLE_REVIEW)
        empty_review['summary'] = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        empty_review['findings'] = []
        report = generate_markdown_report(SAMPLE_PROJECT, empty_review, [])
        assert '未发现安全风险' in report


class TestHTMLReport:
    def test_generates_html(self):
        html = generate_html_report(SAMPLE_PROJECT, SAMPLE_REVIEW, SAMPLE_FINDINGS)
        assert '<html' in html
        assert 'SentinelAI' in html

    def test_contains_data(self):
        html = generate_html_report(SAMPLE_PROJECT, SAMPLE_REVIEW, SAMPLE_FINDINGS)
        assert 'test-project' in html
        assert '65/100' in html


class TestJSONReport:
    def test_contains_structure(self):
        data = generate_json_data(SAMPLE_PROJECT, SAMPLE_REVIEW, SAMPLE_FINDINGS)
        assert data['report_version'] == '1.0'
        assert data['project']['name'] == 'test-project'
        assert data['risk_assessment']['score'] == 65
        assert data['summary']['total'] == 3


class TestRunReport:
    def test_run_report_creates_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_report(SAMPLE_PROJECT, SAMPLE_REVIEW, SAMPLE_FINDINGS, tmpdir)
            assert os.path.exists(result['markdown'])
            assert os.path.exists(result['html'])
            assert os.path.exists(result['json'])
            assert 'notification' in result
            assert 'SentinelAI' in result['notification']
