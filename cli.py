#!/usr/bin/env python3
"""
SentinelAI CLI - 命令行安全审计工具

用法:
    sentinelai audit <项目路径或GitHub URL>    运行安全审计
    sentinelai report [--md|--html|--json]     查看报告
    sentinelai version                         显示版本
    sentinelai --help                          显示帮助
"""

import argparse
import json
import os
import sys
import shutil
from datetime import datetime

SENTINELAI_DIR = os.path.dirname(os.path.realpath(__file__))
REPORT_DIR = os.path.join(SENTINELAI_DIR, 'report')


def cmd_audit(args):
    """运行安全审计"""
    project_path = args.project
    
    print("=" * 50)
    print("🔒 SentinelAI 安全审计工具")
    print("=" * 50)
    print(f"📁 项目: {project_path}")
    print(f"⏰ 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # 导入并运行或ches trator
    sys.path.insert(0, SENTINELAI_DIR)
    from pm.orchestrator import run_pipeline
    
    result = run_pipeline(project_path)
    
    if isinstance(result, dict) and result.get('success'):
        print()
        print(f"✅ 审计完成！风险评分: {result['risk_score']}/100")
        return 0
    elif result:
        print()
        print(f"✅ 审计完成！")
        return 0
    else:
        print()
        print("❌ 审计失败")
        return 1


def cmd_report(args):
    """查看报告"""
    fmt = args.format or 'md'
    report_file = os.path.join(REPORT_DIR, f'security-report.{fmt}')
    
    if not os.path.exists(report_file):
        print(f"❌ 报告文件不存在: {report_file}")
        print("请先运行 'sentinelai audit <项目路径>'")
        return 1
    
    if fmt == 'json':
        with open(report_file, 'r') as f:
            data = json.load(f)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        with open(report_file, 'r') as f:
            content = f.read()
        print(content)
    
    return 0


def cmd_report_list(args):
    """列出所有报告"""
    if not os.path.exists(REPORT_DIR):
        print("❌ 报告目录不存在")
        return 1
    
    files = [f for f in os.listdir(REPORT_DIR) if f.startswith('security-report')]
    if not files:
        print("暂无报告文件，请先运行 'sentinelai audit'")
        return 0
    
    print("📄 可用报告:")
    for f in sorted(files):
        fpath = os.path.join(REPORT_DIR, f)
        size = os.path.getsize(fpath)
        mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
        print(f"  📄 {f} ({size} bytes, {mtime.strftime('%m-%d %H:%M')})")
    
    return 0


def cmd_version(args):
    """显示版本"""
    print("SentinelAI v1.0.0")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='🔒 SentinelAI - AI 多智能体安全审计与代码风险分析平台',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  sentinelai audit ./my-project          扫描本地项目
  sentinelai audit https://github.com/   扫描GitHub项目
  sentinelai report                      查看Markdown报告
  sentinelai report --html               查看HTML报告
  sentinelai report --json               查看JSON数据
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # audit 命令
    audit_parser = subparsers.add_parser('audit', help='运行安全审计')
    audit_parser.add_argument('project', help='项目路径或GitHub URL')
    
    # report 命令
    report_parser = subparsers.add_parser('report', help='查看审计报告')
    report_parser.add_argument('--format', '-f', choices=['md', 'html', 'json'],
                              default='md', help='报告格式（默认: md）')
    
    # list 命令
    list_parser = subparsers.add_parser('list', help='列出所有报告')
    
    # version 命令
    version_parser = subparsers.add_parser('version', help='显示版本信息')
    
    args = parser.parse_args()
    
    if args.command == 'audit':
        return cmd_audit(args)
    elif args.command == 'report':
        return cmd_report(args)
    elif args.command == 'list':
        return cmd_report_list(args)
    elif args.command == 'version':
        return cmd_version(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
