"""
集成测试 - 完整流水线 (pm/orchestrator.py)

测试完整的端到端流水线（Parser → Security → Review → Report）
"""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# 直接从各模块导入测试
from parser.scanner import scan_project
from security.detector import run_security_scan
from reviewer import run_review
from report.reporter import run_report


@pytest.fixture
def vulnerable_project():
    """创建带漏洞的测试项目"""
    tmpdir = tempfile.mkdtemp()
    
    files = {
        'app.py': """
import subprocess
import pickle

def get_user(uid):
    import sqlite3
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # SQL注入 - 同一行
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return cursor.fetchall()

def ping(host):
    # 命令注入
    result = subprocess.run(f"ping -c 1 {host}", shell=True)

def load(data):
    # 不安全的反序列化
    return pickle.loads(data)

API_SECRET = "sk-test-api-key-12345"
""",
        'config.py': 'SECRET_KEY = "hardcoded-key"\nDEBUG = True\n',
        'requirements.txt': 'flask==2.0.0\ncryptography==3.4.0\n',
        '.env': 'DB_PASSWORD=supersecret123\n',
        'README.md': '# Test Project\n',
    }
    
    for name, content in files.items():
        with open(os.path.join(tmpdir, name), 'w') as f:
            f.write(content)
    
    yield tmpdir
    
    import shutil
    shutil.rmtree(tmpdir)


class TestFullPipeline:
    """完整流水线集成测试"""

    def test_full_pipeline_end_to_end(self, vulnerable_project):
        """端到端完整流水线测试"""
        
        # Step 1: Parser
        project_index = scan_project(vulnerable_project)
        assert project_index is not None
        assert project_index['file_count'] == 5
        assert 'Python' in project_index['tech_stack']
        
        # Step 2: Security
        security_findings = run_security_scan(project_index)
        assert len(security_findings) > 0
        
        # 验证关键漏洞被检出
        vuln_types = {f['vuln_type'] for f in security_findings}
        assert 'sql_injection' in vuln_types
        assert 'command_injection' in vuln_types
        assert 'hardcoded_secret' in vuln_types
        
        # 验证严重程度
        severities = {f['severity'] for f in security_findings}
        assert 'Critical' in severities
        assert 'High' in severities
        
        # Step 3: Review & Fix
        review_result, review_report = run_review(security_findings, project_index)
        assert review_result['risk_score'] > 0
        assert review_result['summary']['total'] == len(security_findings)
        assert 'risk_level' in review_result
        
        # 验证Critical评分
        critical_count = sum(1 for f in security_findings if f['severity'] == 'Critical')
        assert review_result['summary']['critical'] == critical_count
        
        # Step 4: Report
        with tempfile.TemporaryDirectory() as report_dir:
            report_result = run_report(project_index, review_result, 
                                      security_findings, report_dir)
            assert os.path.exists(report_result['markdown'])
            assert os.path.exists(report_result['html'])
            assert os.path.exists(report_result['json'])
            assert 'notification' in report_result
            assert 'Critical' in report_result['notification']

    def test_empty_project(self):
        """空项目测试"""
        empty_dir = tempfile.mkdtemp()
        try:
            project_index = scan_project(empty_dir)
            assert project_index['file_count'] == 0
            
            findings = run_security_scan(project_index)
            assert len(findings) == 0
            
            review_result, _ = run_review(findings, project_index)
            assert review_result['risk_score'] == 0
            assert review_result['summary']['total'] == 0
        finally:
            import shutil
            shutil.rmtree(empty_dir)

    def test_safe_project(self):
        """安全项目不应检出漏洞"""
        safe_dir = tempfile.mkdtemp()
        try:
            files = {
                'main.py': """
import sqlite3

def get_user(uid):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cursor.fetchall()

def ping(host):
    import subprocess
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True)
    return result
""",
                'Dockerfile': 'FROM python:3.11\n',
            }
            for name, content in files.items():
                with open(os.path.join(safe_dir, name), 'w') as f:
                    f.write(content)
            
            project_index = scan_project(safe_dir)
            findings = run_security_scan(project_index)
            
            # 安全代码不应检出注入类漏洞
            severe_types = {f['vuln_type'] for f in findings 
                          if f['severity'] in ('Critical', 'High')}
            assert 'sql_injection' not in severe_types
            assert 'command_injection' not in severe_types
        finally:
            import shutil
            shutil.rmtree(safe_dir)
