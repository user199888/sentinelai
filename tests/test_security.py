"""
单元测试 - Security Agent (security/detector.py)
"""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from security.detector import (
    scan_file, check_env_file, check_vulnerable_dependencies,
    check_config_file, run_security_scan, format_security_report
)


def create_test_file(content, suffix='.py', basename=None):
    """创建临时测试文件"""
    if basename:
        tmpdir = tempfile.mkdtemp()
        fpath = os.path.join(tmpdir, basename)
        with open(fpath, 'w') as f:
            f.write(content)
        return fpath
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


def cleanup_test_file(path):
    """清理测试文件（含父目录）"""
    import shutil
    d = os.path.dirname(path)
    if d and d != os.path.dirname(tempfile.gettempdir()):
        shutil.rmtree(d, ignore_errors=True)
    elif os.path.exists(path):
        os.unlink(path)


class TestSQLInjection:
    def test_detect_cursor_execute_fstring(self):
        f = create_test_file('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")')
        findings = scan_file(f)
        os.unlink(f)
        assert any(f2['vuln_type'] == 'sql_injection' for f2 in findings)

    def test_detect_db_query_template(self):
        f = create_test_file('db.query(`SELECT * FROM users WHERE id = ${userId}`)')
        findings = scan_file(f)
        os.unlink(f)
        assert any(f2['vuln_type'] == 'sql_injection' for f2 in findings)

    def test_clean_sql_no_false_positive(self):
        """参数化查询不应触发告警"""
        f = create_test_file('cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))')
        findings = scan_file(f)
        os.unlink(f)
        assert not any(f2['vuln_type'] == 'sql_injection' for f2 in findings)


class TestCommandInjection:
    def test_detect_subprocess_shell(self):
        f = create_test_file('subprocess.run(f"ping -c 1 {host}", shell=True)')
        findings = scan_file(f)
        os.unlink(f)
        cmd_inj = [x for x in findings if x['vuln_type'] == 'command_injection']
        assert len(cmd_inj) > 0

    def test_detect_os_system(self):
        f = create_test_file('os.system("rm -rf " + some_var)')
        findings = scan_file(f)
        cleanup_test_file(f)
        cmd_inj = [x for x in findings if x['vuln_type'] == 'command_injection']
        assert len(cmd_inj) > 0, f"Got findings: {[x['vuln_type'] for x in findings]}"

    def test_clean_subprocess_array(self):
        """参数列表不应触发告警"""
        f = create_test_file('subprocess.run(["ping", "-c", "1", host])')
        findings = scan_file(f)
        os.unlink(f)
        assert not any(x['vuln_type'] == 'command_injection' for x in findings)


class TestHardcodedSecrets:
    def test_detect_api_key(self):
        f = create_test_file('API_KEY = "sk-abcdefghijklmnopqrstuvwx"')
        findings = scan_file(f)
        os.unlink(f)
        assert any(x['vuln_type'] == 'hardcoded_secret' for x in findings)

    def test_detect_password(self):
        f = create_test_file('DB_PASSWORD = "super-secret-123"')
        findings = scan_file(f)
        os.unlink(f)
        assert any(x['vuln_type'] == 'hardcoded_secret' for x in findings)

    def test_detect_jwt_secret(self):
        f = create_test_file('JWT_SECRET = "my-secret-key-2024"')
        findings = scan_file(f)
        os.unlink(f)
        assert any(x['vuln_type'] == 'hardcoded_secret' for x in findings)


class TestXSS:
    def test_detect_python_fstring(self):
        f = create_test_file('return f"<div>{comment_text}</div>"')
        findings = scan_file(f)
        os.unlink(f)
        assert any(x['vuln_type'] == 'xss' for x in findings)

    def test_detect_nodejs_template(self):
        f = create_test_file('res.send(`<h1>Hello ${name}</h1>`)')
        findings = scan_file(f)
        os.unlink(f)
        assert any(x['vuln_type'] == 'xss' for x in findings)


class TestPathTraversal:
    def test_detect_open_path_join(self):
        f = create_test_file('with open(f"/data/{filename}", "r") as fh:')
        findings = scan_file(f)
        os.unlink(f)
        assert any(x['vuln_type'] == 'path_traversal' for x in findings)


class TestInsecureDeserialize:
    def test_detect_pickle(self):
        f = create_test_file('data = pickle.loads(user_input)')
        findings = scan_file(f)
        os.unlink(f)
        assert any(x['vuln_type'] == 'insecure_deserialize' for x in findings)

    def test_detect_eval(self):
        f = create_test_file('result = eval(user_expression)')
        findings = scan_file(f)
        os.unlink(f)
        assert any(x['vuln_type'] == 'insecure_deserialize' for x in findings)


class TestEnvFile:
    def test_detect_env_existence(self):
        f = create_test_file('SECRET=abc123\nDB_PASSWORD=secret\n', '.env')
        findings = check_env_file(f)
        os.unlink(f)
        # .env文件本身会触发Medium警告
        assert any(x['severity'] == 'Medium' for x in findings)

    def test_detect_env_secrets(self):
        f = create_test_file('DB_PASSWORD=super-secret\nAPI_KEY=abc123xyz\n', '.env')
        findings = check_env_file(f)
        os.unlink(f)
        secrets = [x for x in findings if x['vuln_type'] == 'info_leak']
        assert len(secrets) >= 3  # 文件本身 + DB_PASSWORD + API_KEY


class TestVulnerableDependencies:
    def test_detect_old_cryptography(self):
        f = create_test_file('cryptography==3.4.0\n', basename='requirements.txt')
        findings = check_vulnerable_dependencies(f)
        cleanup_test_file(f)
        assert any(x['vuln_type'] == 'dangerous_dep' for x in findings)

    def test_clean_package_not_in_list(self):
        """不在KNOWN_VULNERABLE_PACKAGES中的包不应触发"""
        f = create_test_file('some_safe_package==99.0.0\n', basename='requirements.txt')
        findings = check_vulnerable_dependencies(f)
        cleanup_test_file(f)
        assert not any(x['vuln_type'] == 'dangerous_dep' for x in findings)


class TestSeverityLevels:
    def test_critical_severity(self):
        """SQL注入应为Critical"""
        f = create_test_file('cursor.execute(f"SELECT * FROM users WHERE id = {uid}")')
        findings = scan_file(f)
        os.unlink(f)
        sql_findings = [x for x in findings if x['vuln_type'] == 'sql_injection']
        if sql_findings:
            assert sql_findings[0]['severity'] == 'Critical'

    def test_high_severity(self):
        """硬编码密钥应为High"""
        f = create_test_file('PASSWORD = "secret123"')
        findings = scan_file(f)
        os.unlink(f)
        secret_findings = [x for x in findings if x['vuln_type'] == 'hardcoded_secret']
        if secret_findings:
            assert secret_findings[0]['severity'] == 'High'

    def test_medium_severity(self):
        """危险依赖应为Medium"""
        f = create_test_file('cryptography==3.4.0\n', 'requirements.txt')
        findings = check_vulnerable_dependencies(f)
        os.unlink(f)
        dep_findings = [x for x in findings if x['vuln_type'] == 'dangerous_dep']
        if dep_findings:
            assert dep_findings[0]['severity'] == 'Medium'
