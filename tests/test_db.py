"""
单元测试 - 数据库模块 (shared/db.py)
"""

import os
import sys
import tempfile
import pytest

# 临时切换DB路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import shared.db as db


@pytest.fixture(autouse=True)
def setup_db():
    """每个测试前使用临时数据库"""
    old_path = db.DB_PATH
    tmp = tempfile.mktemp(suffix='.db')
    db.DB_PATH = tmp
    db.init_db()
    yield
    db.DB_PATH = old_path
    if os.path.exists(tmp):
        os.remove(tmp)


class TestProject:
    def test_create_project(self):
        pid = db.create_project('test-project', '/path/to/proj')
        assert pid > 0

    def test_get_project(self):
        pid = db.create_project('test-project')
        proj = db.get_project(pid)
        assert proj is not None
        assert proj['name'] == 'test-project'
        assert proj['status'] == 'pending'

    def test_update_project(self):
        pid = db.create_project('test')
        db.update_project(pid, status='scanning', file_count=10)
        proj = db.get_project(pid)
        assert proj['status'] == 'scanning'
        assert proj['file_count'] == 10


class TestFindings:
    def test_add_finding(self):
        pid = db.create_project('test')
        fid = db.add_finding(
            project_id=pid,
            vuln_type='sql_injection',
            severity='Critical',
            file_path='app.py',
            line_start=10,
            line_end=12,
            title='SQL注入',
            description='发现SQL拼接',
            evidence='cursor.execute(f"...")',
            fix_suggestion='使用参数化查询'
        )
        assert fid > 0

    def test_get_findings(self):
        pid = db.create_project('test')
        db.add_finding(pid, 'sql_injection', 'Critical', 'app.py', 1, 2, 'SQL', 'desc')
        db.add_finding(pid, 'hardcoded_secret', 'High', 'config.py', 5, 5, 'Secret', 'desc')
        findings = db.get_findings(pid)
        assert len(findings) == 2
        assert findings[0]['severity'] == 'Critical'  # 按严重程度排序

    def test_count_findings(self):
        pid = db.create_project('test')
        db.add_finding(pid, 'sql_injection', 'Critical', 'a.py', 1, 1, 'a', 'b')
        db.add_finding(pid, 'xss', 'High', 'b.py', 2, 2, 'c', 'd')
        db.add_finding(pid, 'xss', 'High', 'c.py', 3, 3, 'e', 'f')
        counts = db.count_findings(pid)
        assert counts['Critical'] == 1
        assert counts['High'] == 2

    def test_update_finding(self):
        pid = db.create_project('test')
        fid = db.add_finding(pid, 'sql_injection', 'Critical', 'a.py', 1, 1, 'SQL', 'desc')
        db.update_finding(fid, status='fixed', fix_patch='-- fixed ++')
        updated = db.get_findings(pid)[0]
        assert updated['status'] == 'fixed'


class TestTaskAndLog:
    def test_create_task(self):
        pid = db.create_project('test')
        tid = db.create_task(pid, 'parser', {'path': '/test'})
        assert tid > 0

    def test_update_task(self):
        pid = db.create_project('test')
        tid = db.create_task(pid, 'security')
        db.update_task(tid, 'done', {'findings': 5})
        # 验证（通过日志确认状态变更）

    def test_add_log(self):
        pid = db.create_project('test')
        db.add_log(pid, 'parser', 'info', '扫描完成')
        db.add_log(pid, 'security', 'warn', '发现高危漏洞')
        logs = db.get_logs(pid)
        assert len(logs) == 2
        levels = [l['level'] for l in logs]
        assert 'info' in levels
        assert 'warn' in levels
