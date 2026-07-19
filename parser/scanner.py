"""
SentinelAI - Parser Agent
项目扫描与索引生成引擎

功能：
1. 遍历项目目录，生成文件结构树
2. 识别关键技术栈和框架
3. 解析依赖文件，生成依赖清单
4. 识别配置文件、入口文件、敏感文件
5. 输出结构化项目索引
"""

import os
import sys
import json
import fnmatch

# Ensure parent directory is in path for shared module imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
import sys
from pathlib import Path

# 需要忽略的目录和文件
IGNORE_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env',
    '.tox', '.eggs', '*.egg-info', '.mypy_cache', '.pytest_cache',
    '.gradle', '.idea', '.vscode', 'dist', 'build', '.next', '.nuxt',
    'target', 'vendor', 'bower_components', '.svn', '.hg',
    'coverage', '.nyc_output', 'logs', 'tmp', '.DS_Store'
}

IGNORE_FILES = {
    '*.pyc', '*.pyo', '*.so', '*.dll', '*.dylib', '*.class',
    '*.min.js', '*.map', '*.swp', '*.swo', '*.bak',
    '.DS_Store', 'Thumbs.db', '*.log', '*.cache'
}

# 依赖文件识别
DEPENDENCY_FILES = {
    'package.json': 'npm',
    'package-lock.json': 'npm',
    'yarn.lock': 'yarn',
    'pnpm-lock.yaml': 'pnpm',
    'requirements.txt': 'pip',
    'Pipfile': 'pipenv',
    'Pipfile.lock': 'pipenv',
    'pyproject.toml': 'poetry',
    'poetry.lock': 'poetry',
    'setup.py': 'setuptools',
    'setup.cfg': 'setuptools',
    'Cargo.toml': 'cargo',
    'Cargo.lock': 'cargo',
    'go.mod': 'go',
    'go.sum': 'go',
    'pom.xml': 'maven',
    'build.gradle': 'gradle',
    'build.gradle.kts': 'gradle',
    'Gemfile': 'bundler',
    'Gemfile.lock': 'bundler',
    'composer.json': 'composer',
    'composer.lock': 'composer',
    'CMakeLists.txt': 'cmake',
    'Makefile': 'make',
    'Dockerfile': 'docker',
    'docker-compose.yml': 'docker-compose',
    'docker-compose.yaml': 'docker-compose',
}

# 配置文件识别
CONFIG_FILES = {
    '.env', '.env.example', '.env.local', '.env.production', '.env.development',
    '.env.test', 'config.py', 'config.js', 'config.json', 'config.yaml', 'config.yml',
    'settings.py', 'settings.json', 'application.yml', 'application.properties',
    'database.yml', 'db.config', 'credentials.yml', 'credentials.json',
    '.gitignore', '.dockerignore', '.npmrc', '.yarnrc', '.eslintrc',
    'tsconfig.json', 'webpack.config.js', 'vite.config.js', 'next.config.js',
    'nginx.conf', 'apache.conf', '.htaccess',
}

# 敏感文件（含密钥/密码风险）
SENSITIVE_FILES = {
    '.env', '.env.local', '.env.production', '.env.development',
    'credentials.json', 'credentials.yml', 'credentials.yaml',
    'service-account.json', 'service-account-key.json',
    'id_rsa', 'id_rsa.pub', 'id_ed25519', 'id_ed25519.pub',
    '*.pem', '*.key', '*.p12', '*.cert', '*.keystore',
    'secrets.yml', 'secrets.yaml', 'secret.json',
    'snowflake.yml', 'snowflake.yaml',  # dbt profiles
    '.npmrc',  # may contain tokens
    '.netrc',
}


def scan_project(project_path):
    """扫描项目并生成完整索引"""
    root = Path(project_path).resolve()
    if not root.exists():
        print("❌ 路径不存在: " + project_path, flush=True)
        return {"error": f"路径不存在: {project_path}"}
    if not root.is_dir():
        print("❌ 不是目录: " + project_path, flush=True)
        return {"error": f"不是目录: {project_path}"}

    print(f"📂 项目: {root.name}", flush=True)

    result = {
        "project_name": root.name,
        "project_path": str(root),
        "tech_stack": [],
        "file_count": 0,
        "dir_count": 0,
        "dependencies": [],
        "frameworks": [],
        "structure": [],
        "config_files": [],
        "sensitive_files": [],
        "entry_points": [],
        "language_stats": {},
    }

    lang_extensions = {
        'Python': ['.py', '.pyx', '.pxd'],
        'JavaScript': ['.js', '.jsx', '.mjs', '.cjs'],
        'TypeScript': ['.ts', '.tsx'],
        'Java': ['.java', '.kt', '.scala'],
        'Go': ['.go'],
        'Rust': ['.rs'],
        'C/C++': ['.c', '.h', '.cpp', '.hpp', '.cc', '.cxx'],
        'Ruby': ['.rb'],
        'PHP': ['.php'],
        'Swift': ['.swift'],
        'Kotlin': ['.kt', '.kts'],
        'Shell': ['.sh', '.bash', '.zsh'],
        'SQL': ['.sql'],
        'YAML': ['.yaml', '.yml'],
        'HTML': ['.html', '.htm'],
        'CSS': ['.css', '.scss', '.sass', '.less'],
        'Docker': ['Dockerfile'],
    }

    file_counter = 0
    for dirpath, dirnames, filenames in os.walk(str(root)):
        # 过滤忽略目录
        rel_dir = os.path.relpath(dirpath, str(root))
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not any(
            fnmatch.fnmatch(d, p) for p in IGNORE_DIRS
        )]

        # 根目录下可能的大目录也要忽略
        if rel_dir == '.':
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        for filename in filenames:
            file_counter += 1
            # 每扫描100个文件输出一次进度
            if file_counter % 100 == 0:
                print(f"📊 已扫描 {file_counter} 个文件...", flush=True)
            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, str(root))

            # 忽略文件
            if any(fnmatch.fnmatch(filename, p) for p in IGNORE_FILES):
                continue

            result['file_count'] += 1

            # 统计语言
            ext = os.path.splitext(filename)[1].lower()
            for lang, exts in lang_extensions.items():
                if ext in exts or filename in exts:
                    result['language_stats'][lang] = result['language_stats'].get(lang, 0) + 1
                    if lang not in result['tech_stack']:
                        result['tech_stack'].append(lang)
                    break

            # 识别技术栈
            if filename in DEPENDENCY_FILES:
                tech = DEPENDENCY_FILES[filename]
                if tech not in result['tech_stack']:
                    result['tech_stack'].append(tech)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    result['dependencies'].append({
                        'file': rel_path,
                        'type': tech,
                        'size': len(content)
                    })
                    # 尝试解析依赖项
                    deps = _parse_dependencies(filename, content)
                    if deps:
                        result['dependencies'][-1]['packages'] = deps
                except Exception:
                    pass

            # 识别配置文件
            if filename in CONFIG_FILES or any(fnmatch.fnmatch(filename, p) for p in CONFIG_FILES if '*' in p):
                result['config_files'].append(rel_path)

            # 识别敏感文件
            if filename in SENSITIVE_FILES or any(fnmatch.fnmatch(filename, p) for p in SENSITIVE_FILES if '*' in p):
                result['sensitive_files'].append(rel_path)

            # 识别入口文件
            if filename in {'main.py', 'app.py', 'index.js', 'index.ts', 'main.js',
                            'main.go', 'main.rs', 'App.jsx', 'App.tsx', 'server.js',
                            'manage.py', 'wsgi.py', 'asgi.py', 'cli.py'}:
                result['entry_points'].append(rel_path)

        # 统计目录数
        if rel_dir != '.':
            result['dir_count'] += 1

        # 记录结构树（只记录深度的关键节点，避免太大）
        if rel_dir == '.':
            result['structure'].append({'path': '.', 'type': 'dir', 'children': []})
            for d in sorted(dirnames):
                result['structure'][0]['children'].append(d)
            result['structure'][0]['files'] = sorted([
                f for f in filenames
                if not any(fnmatch.fnmatch(f, p) for p in IGNORE_FILES)
            ])

    # 推断框架
    result['frameworks'] = _detect_frameworks(result['tech_stack'], result['dependencies'])

    # 清理技术栈，去重
    result['tech_stack'] = list(set(result['tech_stack']))
    result['dep_count'] = len(result['dependencies'])

    print(f"📊 统计: {result['file_count']} 个文件, {result['dir_count']} 个目录", flush=True)
    if result['dependencies']:
        print(f"📦 依赖: {len(result['dependencies'])} 个依赖文件", flush=True)
    if result['config_files']:
        print(f"⚙️  配置文件: {len(result['config_files'])} 个", flush=True)
    if result['sensitive_files']:
        print(f"🔴 敏感文件: {len(result['sensitive_files'])} 个", flush=True)
    print(f"📄 项目扫描完成: {result['file_count']} 个文件", flush=True)

    return result


def _parse_dependencies(filename, content):
    """尝试解析依赖文件中的包名"""
    deps = []
    try:
        if filename == 'package.json':
            data = json.loads(content)
            deps = list(data.get('dependencies', {}).keys()) + list(data.get('devDependencies', {}).keys())
        elif filename == 'requirements.txt':
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    # 去掉版本号
                    pkg = line.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].strip()
                    if pkg:
                        deps.append(pkg)
        elif filename == 'pyproject.toml':
            import re
            match = re.search(r'\[tool\.poetry\.dependencies\](.*?)(?:\[|\Z)', content, re.DOTALL)
            if match:
                for line in match.group(1).splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line and not line.startswith('['):
                        pkg = line.split('=')[0].strip().strip('"').strip("'")
                        if pkg and pkg != 'python':
                            deps.append(pkg)
        elif filename == 'Cargo.toml':
            import re
            match = re.search(r'\[dependencies\](.*?)(?:\[|\Z)', content, re.DOTALL)
            if match:
                for line in match.group(1).splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line and not line.startswith('['):
                        pkg = line.split('=')[0].strip().strip('"').strip("'")
                        if pkg:
                            deps.append(pkg)
    except Exception:
        pass
    return deps


def _detect_frameworks(tech_stack, dependencies):
    """根据技术栈和依赖推断框架"""
    frameworks = []
    known_frameworks = {
        'django': 'Django', 'flask': 'Flask', 'fastapi': 'FastAPI',
        'express': 'Express.js', 'react': 'React', 'vue': 'Vue.js',
        'angular': 'Angular', 'next': 'Next.js', 'nuxt': 'Nuxt.js',
        'spring': 'Spring Boot', 'gin': 'Gin', 'echo': 'Echo',
        'actix': 'Actix-web', 'rocket': 'Rocket', 'axum': 'Axum',
        'rails': 'Ruby on Rails', 'laravel': 'Laravel',
        'tensorflow': 'TensorFlow', 'pytorch': 'PyTorch', 'transformers': 'HuggingFace',
    }

    all_packages = set()
    for dep in dependencies:
        all_packages.update(dep.get('packages', []))

    for pkg in all_packages:
        for key, framework in known_frameworks.items():
            if key in pkg.lower():
                if framework not in frameworks:
                    frameworks.append(framework)

    return frameworks


def format_project_index(result):
    """格式化项目索引为可读文本"""
    if 'error' in result:
        return f"❌ {result['error']}"

    lines = []
    lines.append("=" * 50)
    lines.append(f"📁 项目: {result['project_name']}")
    lines.append(f"📂 路径: {result['project_path']}")
    lines.append("=" * 50)
    lines.append(f"📊 统计: {result['file_count']} 个文件, {result['dir_count']} 个目录")
    lines.append(f"🛠  技术栈: {', '.join(result['tech_stack']) if result['tech_stack'] else '未知'}")
    if result['frameworks']:
        lines.append(f"🏗  框架: {', '.join(result['frameworks'])}")
    lines.append("")

    if result['dependencies']:
        lines.append("📦 依赖文件:")
        for dep in result['dependencies']:
            pkgs = dep.get('packages', [])
            pkg_str = f" ({len(pkgs)} 个包)" if pkgs else ""
            lines.append(f"  - {dep['file']} [{dep['type']}]{pkg_str}")
        lines.append("")

    if result['config_files']:
        lines.append("⚙️  配置文件:")
        for f in result['config_files']:
            lines.append(f"  - {f}")
        lines.append("")

    if result['sensitive_files']:
        lines.append("🔴 敏感文件（需注意）:")
        for f in result['sensitive_files']:
            lines.append(f"  ⚠️  {f}")
        lines.append("")

    if result['entry_points']:
        lines.append("🚪 入口文件:")
        for f in result['entry_points']:
            lines.append(f"  - {f}")
        lines.append("")

    lines.append(f"📈 语言分布: {json.dumps(result['language_stats'], indent=2)}")
    lines.append("")

    lines.append("📂 项目结构:")
    for item in result.get('structure', []):
        if item['type'] == 'dir':
            lines.append(f"  📁 .")
            for child in sorted(item.get('children', [])):
                lines.append(f"    📁 {child}/")
            for f in sorted(item.get('files', [])):
                lines.append(f"    📄 {f}")

    return '\n'.join(lines)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python scanner.py <项目路径或GitHub URL>")
        print("示例: python scanner.py /path/to/project")
        print("     python scanner.py https://github.com/owner/repo")
        sys.exit(1)

    path = sys.argv[1]
    
    # 支持 GitHub URL 自动克隆
    use_github = False
    clone_dir = None
    try:
        from shared.git_support import ensure_project_path, cleanup_clone
        local_path, use_github, clone_dir = ensure_project_path(path)
        if use_github:
            print(f"📥 从 GitHub 克隆后扫描: {path}")
        path = local_path
    except ImportError:
        pass
    except Exception as e:
        print(f"❌ 处理输入失败: {e}")
        sys.exit(1)

    result = scan_project(path)
    print(format_project_index(result))

    # 保存JSON
    workspace = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_path = os.path.join(workspace, 'parser', 'project-index.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n📄 项目索引已保存: {output_path}")
    
    # 记录是否是 GitHub URL
    result['_source_url'] = sys.argv[1] if use_github else ''
    result['_is_github'] = use_github
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    # 注意: 不清理临时目录，后续扫描步骤（detector.py）需要读取克隆的代码
    # 系统会自动清理 /tmp 下的过期文件
