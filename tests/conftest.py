"""
pytest 配置 - 处理目录连字符问题
"""
import sys
import os
import importlib
import importlib.util

# 添加项目根目录和带连字符的子目录到路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
for sub in ['review-fix']:
    sys.path.insert(0, os.path.join(project_root, sub))

# 处理 review-fix 目录的导入（Python不支持带连字符的包名）
def _load_module(name, path):
    """从指定路径加载模块"""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# 预加载所有核心模块
_loader_modules = {}

# 加载 review-fix 下的模块
review_fix_dir = os.path.join(project_root, 'review-fix')
for f in os.listdir(review_fix_dir):
    if f.endswith('.py') and f != '__init__.py':
        mod_name = f[:-3]
        mod_path = os.path.join(review_fix_dir, f)
        mod = _load_module(f'sentinelai_{mod_name}', mod_path)
        _loader_modules[mod_name] = mod
