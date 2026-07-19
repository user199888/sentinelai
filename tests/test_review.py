"""
单元测试 - Review & Fix Agent (review-fix/reviewer.py)
"""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from reviewer import (
    review_findings, calculate_risk_score, get_risk_level,
    generate_patch, generate_fix_guide
)


class TestReview:
    def test_review_adds_fields(self):
        findings = [
            {'vuln_type': 'sql_injection', 'severity': 'Critical',
             'file_path': 'app.py', 'line_start': 1, 'title': 'SQL注入',
             'description': 'desc', 'evidence': 'code'}
        ]
        reviewed = review_findings(findings)
        assert len(reviewed) == 1
        assert 'risk_explanation' in reviewed[0]
        assert 'impact_scope' in reviewed[0]
        assert 'fix_priority' in reviewed[0]
        assert 'fix_urgency' in reviewed[0]
        assert 'fix_guide' in reviewed[0]

    def test_critical_priority(self):
        findings = [{'severity': 'Critical', 'vuln_type': 'sql_injection',
                     'file_path': 'a.py', 'line_start': 1, 'title': 'x',
                     'description': 'd', 'evidence': 'e'}]
        reviewed = review_findings(findings)
        assert 'P0' in reviewed[0]['fix_priority']

    def test_high_priority(self):
        findings = [{'severity': 'High', 'vuln_type': 'hardcoded_secret',
                     'file_path': 'a.py', 'line_start': 1, 'title': 'x',
                     'description': 'd', 'evidence': 'e'}]
        reviewed = review_findings(findings)
        assert 'P1' in reviewed[0]['fix_priority']

    def test_impact_scope(self):
        findings = [{'severity': 'Critical', 'vuln_type': 'sql_injection',
                     'file_path': 'a.py', 'line_start': 1, 'title': 'x',
                     'description': 'd', 'evidence': 'e'}]
        reviewed = review_findings(findings)
        assert '跨模块' in reviewed[0]['impact_scope']


class TestRiskScore:
    def test_no_findings(self):
        score = calculate_risk_score([])
        assert score == 0

    def test_one_critical(self):
        findings = [{'severity': 'Critical'}]
        score = calculate_risk_score(findings)
        assert score == 25

    def test_mixed(self):
        findings = [
            {'severity': 'Critical'},
            {'severity': 'High'},
            {'severity': 'Medium'},
        ]
        score = calculate_risk_score(findings)
        assert score == 48  # 25 + 15 + 8

    def test_max_cap(self):
        """验证评分上限为100"""
        findings = [{'severity': 'Critical'} for _ in range(10)]
        score = calculate_risk_score(findings)
        assert score <= 100

    def test_risk_level(self):
        assert 'A' in get_risk_level(10)
        assert 'F' in get_risk_level(95)


class TestFixGuide:
    def test_sql_injection_guide(self):
        guide = generate_fix_guide('sql_injection', 'Critical', 'cursor.execute(f"...")', 'a.py')
        assert '参数化查询' in guide
        assert 'PreparedStatement' in guide

    def test_hardcoded_secret_guide(self):
        guide = generate_fix_guide('hardcoded_secret', 'High', 'PASSWORD = "123"', 'a.py')
        assert '环境变量' in guide
        assert '密钥管理服务' in guide

    def test_xss_guide(self):
        guide = generate_fix_guide('xss', 'High', 'res.send(`<h1>${x}</h1>`)', 'a.py')
        assert '转义' in guide
        assert 'Content-Security-Policy' in guide

    def test_unknown_type(self):
        """未知类型也有兜底"""
        guide = generate_fix_guide('unknown_type', 'Low', 'code', 'a.py')
        assert '修复步骤' in guide


class TestPatch:
    def test_generate_subprocess_patch(self):
        patch = generate_patch(
            'result = subprocess.run(f"ping -c 1 {host}", shell=True)',
            'command_injection', 'Critical'
        )
        assert patch != ''

    def test_generate_secret_patch(self):
        patch = generate_patch(
            'API_KEY = "sk-abcdef123456"',
            'hardcoded_secret', 'High'
        )
        assert patch != ''
        assert 'os.getenv' in patch

    def test_empty_patch_for_unknown(self):
        patch = generate_patch('code', 'unknown_type', 'Low')
        assert patch == ''
