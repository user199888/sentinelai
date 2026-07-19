"""
SentinelAI - GitHub URL 支持模块
支持从 GitHub URL 自动克隆项目并扫描
"""

import os
import re
import subprocess
import tempfile
import shutil
from urllib.parse import urlparse


def is_github_url(path):
    """判断输入是否为 GitHub URL"""
    if not path:
        return False
    path = path.strip()
    
    # GitHub URL 模式
    patterns = [
        r'^https?://github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?$',
        r'^https?://www\.github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?$',
        r'^git@github\.com:[\w.-]+/[\w.-]+(?:\.git)?$',
        r'^https?://github\.com/[\w.-]+/[\w.-]+/tree/[\w./-]+$',
        r'^https?://github\.com/[\w.-]+/[\w.-]+/archive/[\w.-]+\.(?:zip|tar\.gz)$',
    ]
    
    for pattern in patterns:
        if re.match(pattern, path):
            return True
    return False


def parse_github_url(url):
    """解析 GitHub URL，提取 owner/repo 信息"""
    url = url.strip()
    
    # 处理 git@github.com:owner/repo.git 格式
    ssh_match = re.match(r'git@github\.com:([\w.-]+)/([\w.-]+?)(?:\.git)?$', url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2).replace('.git', '')
    
    # 处理 https://github.com/owner/repo 格式
    parsed = urlparse(url)
    if 'github.com' in parsed.netloc or 'github.com' in parsed.path:
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            owner = path_parts[0]
            repo = path_parts[1].replace('.git', '')
            return owner, repo
    
    return None, None


def clone_repo(url, target_dir=None):
    """克隆 GitHub 仓库到本地"""
    if target_dir is None:
        target_dir = tempfile.mkdtemp(prefix='sentinelai_')
    
    print(f"📥 克隆: {url}", flush=True)
    
    result = subprocess.run(
        ['git', 'clone', '--depth', '1', url, target_dir],
        capture_output=True, text=True, timeout=120
    )
    
    if result.returncode != 0:
        error_msg = result.stderr or result.stdout
        raise RuntimeError(f"克隆失败: {error_msg}")
    
    # 获取仓库信息
    owner, repo = parse_github_url(url)
    print(f"✅ 克隆成功: {owner}/{repo if repo else ''}", flush=True)
    
    return target_dir, owner, repo


def ensure_project_path(path_or_url):
    """
    确保输入是一个本地项目路径。
    - 如果是 GitHub URL，自动克隆并返回本地路径
    - 如果是本地路径，直接返回
    """
    path_or_url = path_or_url.strip()
    
    if is_github_url(path_or_url):
        clone_dir = tempfile.mkdtemp(prefix='sentinelai_')
        try:
            local_path, owner, repo = clone_repo(path_or_url, clone_dir)
            print(f"📁 已克隆到: {local_path}")
            return local_path, True, clone_dir
        except Exception as e:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise e
    else:
        # 本地路径
        if not os.path.exists(path_or_url):
            raise FileNotFoundError(f"路径不存在: {path_or_url}")
        return os.path.abspath(path_or_url), False, None


def cleanup_clone(temp_dir):
    """清理克隆的临时目录"""
    if temp_dir and os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"🧹 已清理临时目录: {temp_dir}")
