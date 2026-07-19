"""
SentinelAI - 安全策略执行器
定义和强制执行各 Agent 的权限级别
"""

import os
import re
import subprocess
import sys

LEVELS = {'L0': 0, 'L1': 1, 'L2': 2, 'L3': 3, 'L4': 4, 'L5': 5}

AGENT_LEVELS = {
    'parser': 'L0', 'security': 'L1',
    'review': 'L2', 'report': 'L3',
    'test': 'L4', 'pm': 'L5',
}

DANGEROUS_PATTERNS = [
    (r'\brm\s+[-][rRfF].*\s+/', '递归删除根目录'),
    (r'\brm\s+[-][rRfF]*\s+/', '递归删除根目录'),
    (r'\bmkfs\b', '格式化文件系统'),
    (r'\bdd\s+if=', '磁盘直接写入'),
    (r'\bchmod\s+[-]?[0-7]{3,4}\s+/', '修改系统权限'),
    (r'chown\s+.*/', '修改系统所有者'),
    (r'>\s*/dev/', '写入设备文件'),
    (r'format\s+[a-z]:', '格式化磁盘'),
    (r'\b(wget|curl)\b.*\|\s*(bash|sh|zsh)\b', '远程下载并通过管道执行'),
    (r'\bcurl\b.*-o\b.*\.(sh|py)\b', '远程下载脚本文件'),
    (r'\bwget\b.*-O\b.*\.(sh|py)\b', '远程下载脚本文件'),
    (r'\bfdisk\b', '磁盘分区'),
    (r'\bmke2fs\b', '创建文件系统'),
    (r'\bswapon\b', '交换分区'),
    (r'\b(halt|reboot|shutdown|poweroff)\b', '关闭或重启系统'),
    (r'init\s+[06]\b', '关闭或重启系统'),
    (r'sudo\s+\w+\s+/etc/', '提权修改系统配置'),
    (r'\b(passwd|useradd|userdel)\b', '账户管理操作'),
    (r':\(\)\s*\{', 'fork炸弹'),
    (r'(nc|netcat)\s+[-]?\w*\s+\d+', '反弹shell'),
    (r'bash\s+-i\s*[><]', '交互式shell'),
    (r'/dev/tcp/', 'TCP反弹shell'),
    (r'python\s+-c\s+[\"\'][\s\S]*socket', 'Python反弹shell'),
]


def check_permission(agent_role, action_type, target_path=None):
    level = AGENT_LEVELS.get(agent_role, 'L0')
    matrix = {
        'read':    {'L0': True, 'L1': True, 'L2': True, 'L3': True, 'L4': True, 'L5': True},
        'write':   {'L0': False, 'L1': False, 'L2': False, 'L3': True, 'L4': False, 'L5': True},
        'execute': {'L0': False, 'L1': True, 'L2': True, 'L3': True, 'L4': True, 'L5': True},
        'modify':  {'L0': False, 'L1': False, 'L2': False, 'L3': False, 'L4': False, 'L5': True},
        'network': {'L0': False, 'L1': False, 'L2': False, 'L3': False, 'L4': False, 'L5': True},
    }
    allowed = matrix.get(action_type, {}).get(level, False)
    if not allowed:
        return False, f"[{level}] {agent_role} 不允许 {action_type}"
    if action_type == 'write' and target_path:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if not os.path.realpath(target_path).startswith(os.path.realpath(base) + '/'):
            return False, f"写入路径超出范围"
    return True, "允许"


def validate_command(agent_role, command):
    allowed, reason = check_permission(agent_role, 'execute')
    if not allowed:
        return allowed, reason
    cmd_str = ' '.join(command) if isinstance(command, list) else command
    for pattern, desc in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd_str, re.IGNORECASE):
            return False, f"禁止: {desc}"
    if AGENT_LEVELS.get(agent_role, 'L0') == 'L0':
        return False, "[L0] Parser 禁止执行命令"
    return True, "通过"


def safe_exec(agent_role, cmd_args, timeout=30):
    allowed, reason = validate_command(agent_role, cmd_args)
    if not allowed:
        print(f"  🔒 拦截: {reason}")
        return None
    try:
        return subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        print(f"  ❌ 执行失败: {e}")
        return None


def print_policy(agent_role=None):
    print(f"\n{'='*50}")
    print("🔒 SentinelAI 安全策略")
    print(f"{'='*50}")
    if agent_role:
        lv = AGENT_LEVELS.get(agent_role, '?')
        acts = ['read','write','execute','modify','network']
        perms = [check_permission(agent_role, a)[0] for a in acts]
        print(f"{agent_role} [{lv}]: {' '.join('✅' if p else '❌' for p in perms)}")
    else:
        print(f"{'Agent':<15}{'级别':<6}{'读':<5}{'写':<5}{'执行':<6}{'修改':<6}{'网络':<5}")
        print("-"*50)
        for role, lv in AGENT_LEVELS.items():
            perms = [check_permission(role, a)[0] for a in ['read','write','execute','modify','network']]
            icons = ' '.join('✅' if p else '❌' for p in perms)
            print(f"{role:<15}{lv:<6}{icons}")
    print(f"\n📋 危险命令规则: {len(DANGEROUS_PATTERNS)} 条")
    for p, d in DANGEROUS_PATTERNS:
        print(f"  🔒 {d}")


if __name__ == '__main__':
    role = sys.argv[1] if len(sys.argv) > 1 else None
    print_policy(role)
