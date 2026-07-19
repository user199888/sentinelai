"""
单元测试 - Parser Agent (parser/scanner.py)
"""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from parser.scanner import scan_project, format_project_index, _parse_dependencies


@pytest.fixture
def demo_project():
    """创建临时测试项目"""
    tmpdir = tempfile.mkdtemp()
    
    # 创建需要的文件
    files = {
        'app.py': 'print("hello")\nimport os\n',
        'main.py': 'def main():\n    pass\n',
        'index.js': 'console.log("hello");\n',
        'config.py': 'DEBUG = True\nSECRET_KEY = "test-key"\n',
        'package.json': json.dumps({
            "name": "test-project",
            "dependencies": {"express": "^4.0.0", "lodash": "^4.0.0"}
        }),
        'requirements.txt': 'flask==2.0.0\nrequests>=2.28.0\n',
        '.env': 'SECRET=abc123\nDB_PASSWORD=password\n',
        'Dockerfile': 'FROM python:3.9\n',
    }
    
    for name, content in files.items():
        path = os.path.join(tmpdir, name)
        with open(path, 'w') as f:
            f.write(content)
    
    yield tmpdir
    
    # 清理
    import shutil
    shutil.rmtree(tmpdir)


class TestScanner:
    def test_scan_basic(self, demo_project):
        """基础扫描功能"""
        result = scan_project(demo_project)
        assert 'error' not in result
        assert result['project_name'] == os.path.basename(demo_project)
        assert result['file_count'] == 8

    def test_scan_tech_stack(self, demo_project):
        """技术栈识别"""
        result = scan_project(demo_project)
        assert 'Python' in result['tech_stack']
        assert 'JavaScript' in result['tech_stack']
        assert 'pip' in result['tech_stack']
        assert 'npm' in result['tech_stack']

    def test_scan_dependencies(self, demo_project):
        """依赖文件解析"""
        result = scan_project(demo_project)
        dep_files = [d['file'] for d in result['dependencies']]
        assert 'requirements.txt' in dep_files
        assert 'package.json' in dep_files

    def test_scan_sensitive_files(self, demo_project):
        """敏感文件标记"""
        result = scan_project(demo_project)
        assert '.env' in result['sensitive_files']

    def test_scan_config_files(self, demo_project):
        """配置文件识别"""
        result = scan_project(demo_project)
        assert 'config.py' in result['config_files']
        assert '.env' in result['config_files']

    def test_scan_entry_points(self, demo_project):
        """入口文件识别"""
        result = scan_project(demo_project)
        assert 'main.py' in result['entry_points']

    def test_scan_nonexistent_path(self):
        """不存在的路径"""
        result = scan_project('/nonexistent/path')
        assert 'error' in result

    def test_format_output(self, demo_project):
        """格式化输出"""
        result = scan_project(demo_project)
        output = format_project_index(result)
        assert '📁' in output
        assert result['project_name'] in output

    def test_dep_file_not_project(self):
        """非项目目录的扫描"""
        result = scan_project(tempfile.mkdtemp())
        assert 'error' not in result
        assert result['file_count'] == 0


class TestDependencyParsing:
    def test_parse_requirements(self):
        deps = _parse_dependencies('requirements.txt', 'flask==2.0\ndjango>=4.0\n')
        assert 'flask' in deps
        assert 'django' in deps

    def test_parse_package_json(self):
        content = json.dumps({"dependencies": {"express": "^4.0.0"}})
        deps = _parse_dependencies('package.json', content)
        assert 'express' in deps

    def test_parse_with_comments(self):
        """带注释的requirements"""
        deps = _parse_dependencies('requirements.txt', 
            '# This is a comment\nflask==2.0\n')
        assert 'flask' in deps
