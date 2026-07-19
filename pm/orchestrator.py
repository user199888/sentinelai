"""
SentinelAI - PM Orchestrator
流水线编排脚本 - PM Agent 使用

完整执行流程：
1. Parser Agent → 扫描项目结构
2. Security Agent → 漏洞检测
3. Review & Fix Agent → 审查+修复
4. Report Agent → 生成报告
5. Notify → 发送飞书通知

PM Agent 通过 sessions_spawn 调用各步骤。
"""

import json
import os
import sys
import subprocess
from datetime import datetime

# 项目根目录
SENTINELAI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def log(msg, level='info'):
    """输出带时间戳的日志"""
    ts = datetime.now().strftime('%H:%M:%S')
    icon = {'info': 'ℹ️', 'warn': '⚠️', 'error': '❌', 'done': '✅'}.get(level, '•')
    print(f"[{ts}] {icon} {msg}")


def run_step(name, script, args, step_log_file=None, progress_callback=None, step_idx=1, total_steps=5):
    """运行一个步骤并记录日志（支持实时进度回调）"""
    log(f"开始: {name}", 'info')

    cmd = [sys.executable, script] + args
    log(f"执行: {' '.join(cmd)}")

    try:
        # 强制子进程非缓冲输出，确保进度标记实时到达
        _env = os.environ.copy()
        _env['PYTHONUNBUFFERED'] = '1'
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=_env
        )

        stdout_lines = []
        stderr_lines = []
        import time

        # 实时读取输出，同时检测子进程状态
        start_time = time.time()
        timeout = 300  # 5分钟超时

        while True:
            # 检查超时
            if time.time() - start_time > timeout:
                proc.kill()
                log(f"超时: {name} ({timeout}s)", 'error')
                if step_log_file:
                    with open(step_log_file, 'w') as f:
                        f.write(f"TIMEOUT after {timeout}s\n")
                        f.write(''.join(stdout_lines[-200:]))
                return False, f"Timeout ({timeout}s)"

            ret = proc.poll()

            # 读取可用输出
            try:
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    stdout_lines.append(line)
                    if progress_callback:
                        _parse_progress_line(line, progress_callback, step_idx, total_steps)
            except (ValueError, OSError):
                pass

            try:
                while True:
                    err = proc.stderr.readline()
                    if not err:
                        break
                    stderr_lines.append(err)
            except (ValueError, OSError):
                pass

            if ret is not None:
                try:
                    for line in proc.stdout.readlines():
                        stdout_lines.append(line)
                        if progress_callback:
                            _parse_progress_line(line, progress_callback, step_idx, total_steps)
                except (ValueError, OSError):
                    pass
                try:
                    for line in proc.stderr.readlines():
                        stderr_lines.append(line)
                except (ValueError, OSError):
                    pass
                break

            time.sleep(0.1)

        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)

        if proc.returncode == 0:
            log(f"完成: {name}", 'done')
            if step_log_file:
                with open(step_log_file, 'w') as f:
                    f.write(stdout)
            return True, stdout
        else:
            log(f"失败: {name}", 'error')
            err_msg = stderr[:500] if stderr else stdout[-500:]
            log(f"错误: {err_msg}", 'error')
            if step_log_file:
                with open(step_log_file, 'w') as f:
                    f.write(f"ERROR (code {proc.returncode}):\n{stderr}\n--- stdout ---\n{stdout}")
            return False, stderr

    except Exception as e:
        log(f"异常: {name} - {str(e)}", 'error')
        return False, str(e)


def _parse_progress_line(line, callback, step_idx, total_steps):
    """解析子进程输出中的进度标记"""
    line = line.strip()
    if not callback:
        return
    # 扫描器/检测器输出的进度标记
    progress_markers = {
        '📥 克隆': 5,
        '📂 项目': 8,
        '📊 统计': 15,
        '📦 依赖': 18,
        '⚙️  配置': 19,
        '📄 项目': 20,
    }
    for marker, pct in progress_markers.items():
        if marker in line:
            step_range = 100 // total_steps
            base = (step_idx - 1) * step_range
            sub_pct = int(base + pct / 100 * step_range)
            sub_pct = min(max(sub_pct, base + 1), base + step_range - 1)
            callback('subprogress', step_idx, total_steps, None, progress_override=sub_pct)
            return


def run_pipeline(project_path, output_dir=None, progress_callback=None):
    """运行完整的安全审计流水线
    
    progress_callback(step_name, step_index, total_steps, success) 可选进度回调
    """
    if output_dir is None:
        output_dir = SENTINELAI_DIR

    log("=" * 50)
    log("🚀 SentinelAI 安全审计流水线启动")
    log(f"📁 项目: {project_path}")
    log("=" * 50)

    STEPS = [
        (1, 'parser', 'Parser Agent', os.path.join(SENTINELAI_DIR, 'parser', 'scanner.py'), [project_path], 'step1-parser.log'),
        (2, 'security', 'Security Agent', os.path.join(SENTINELAI_DIR, 'security', 'detector.py'), None, 'step2-security.log'),
        (3, 'review', 'Review Agent', os.path.join(SENTINELAI_DIR, 'review-fix', 'reviewer.py'), None, 'step3-review.log'),
        (4, 'report', 'Report Agent', os.path.join(SENTINELAI_DIR, 'report', 'reporter.py'), None, 'step4-report.log'),
    ]
    TOTAL_STEPS = 5

    # Step 1: Parser
    log(f"📂 Step 1/{TOTAL_STEPS}: Parser Agent - 扫描项目结构", 'info')
    if progress_callback:
        progress_callback('parser', 1, TOTAL_STEPS, None)
    success1, output1 = run_step(
        "项目扫描",
        STEPS[0][3],
        STEPS[0][4],
        os.path.join(output_dir, 'pm', 'step1-parser.log'),
        progress_callback=progress_callback,
        step_idx=1,
        total_steps=TOTAL_STEPS
    )
    if not success1:
        log("流水线终止: Parser 失败", 'error')
        if progress_callback:
            progress_callback('parser', 1, TOTAL_STEPS, False)
        return False
    if progress_callback:
        progress_callback('parser', 1, TOTAL_STEPS, True)

    # Step 2: Security
    index_path = os.path.join(SENTINELAI_DIR, 'parser', 'project-index.json')
    log(f"🔒 Step 2/{TOTAL_STEPS}: Security Agent - 漏洞检测", 'info')
    if progress_callback:
        progress_callback('security', 2, TOTAL_STEPS, None)
    success2, output2 = run_step(
        "安全检测",
        STEPS[1][3],
        [index_path],
        os.path.join(output_dir, 'pm', 'step2-security.log'),
        progress_callback=progress_callback,
        step_idx=2,
        total_steps=TOTAL_STEPS
    )
    if not success2:
        log("流水线终止: Security 失败", 'error')
        if progress_callback:
            progress_callback('security', 2, TOTAL_STEPS, False)
        return False
    if progress_callback:
        progress_callback('security', 2, TOTAL_STEPS, True)

    # Step 3: Review & Fix
    findings_path = os.path.join(SENTINELAI_DIR, 'security', 'security-findings.json')
    log(f"🛠  Step 3/{TOTAL_STEPS}: Review & Fix Agent - 审查与修复", 'info')
    if progress_callback:
        progress_callback('review', 3, TOTAL_STEPS, None)
    success3, output3 = run_step(
        "审查修复",
        STEPS[2][3],
        [findings_path, index_path],
        os.path.join(output_dir, 'pm', 'step3-review.log'),
        progress_callback=progress_callback,
        step_idx=3,
        total_steps=TOTAL_STEPS
    )
    if not success3:
        log("流水线终止: Review 失败", 'error')
        if progress_callback:
            progress_callback('review', 3, TOTAL_STEPS, False)
        return False
    if progress_callback:
        progress_callback('review', 3, TOTAL_STEPS, True)

    # Step 4: Report
    review_path = os.path.join(SENTINELAI_DIR, 'review-fix', 'review-report.json')
    log(f"📋 Step 4/{TOTAL_STEPS}: Report Agent - 生成报告", 'info')
    if progress_callback:
        progress_callback('report', 4, TOTAL_STEPS, None)
    success4, output4 = run_step(
        "报告生成",
        STEPS[3][3],
        [review_path, index_path, findings_path],
        os.path.join(output_dir, 'pm', 'step4-report.log'),
        progress_callback=progress_callback,
        step_idx=4,
        total_steps=TOTAL_STEPS
    )
    if not success4:
        log("流水线终止: Report 失败", 'error')
        if progress_callback:
            progress_callback('report', 4, TOTAL_STEPS, False)
        return False
    if progress_callback:
        progress_callback('report', 4, TOTAL_STEPS, True)

    # Step 5: 汇总结果
    log(f"📊 Step 5/5: 汇总审计结果", 'info')
    if progress_callback:
        progress_callback('summary', 5, TOTAL_STEPS, None)
    report_path = os.path.join(SENTINELAI_DIR, 'report', 'security-report.json')
    try:
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        summary = report_data.get('summary', {})
        risk_score = report_data.get('risk_assessment', {}).get('score', 0)
        risk_level = report_data.get('risk_assessment', {}).get('level', '')
    except Exception:
        summary = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        risk_score = 0
        risk_level = '未知'

    if progress_callback:
        progress_callback('summary', 5, TOTAL_STEPS, True)

    log("=" * 50, 'done')
    log(f"🎉 安全审计流水线执行完成！", 'done')
    log("=" * 50, 'done')
    log(f"📊 风险评分: {risk_score}/100 ({risk_level})")
    log(f"📈 共发现 {summary.get('total', 0)} 个安全问题:")
    log(f"   🔴 Critical: {summary.get('critical', 0)}")
    log(f"   🟠 High: {summary.get('high', 0)}")
    log(f"   🟡 Medium: {summary.get('medium', 0)}")
    log(f"   🟢 Low: {summary.get('low', 0)}")
    log("=" * 50, 'done')
    log(f"📄 报告文件:")
    log(f"   📝 report/security-report.md")
    log(f"   🌐 report/security-report.html")
    log(f"   📊 report/security-report.json")

    # 飞书通知（可选：仅当配置了 Webhook 时发送）
    try:
        from shared.feishu_notifier import send_text
        _proj_name = report_data.get('project_name') or os.path.basename(project_path.rstrip('/\\'))
        notif_text = (
            f"🛡 SentinelAI 安全审计完成\n\n"
            f"📁 项目: {_proj_name}\n"
            f"📊 风险评分: {risk_score}/100 ({risk_level})\n\n"
            f"📈 共发现 {summary.get('total', 0)} 个安全问题:\n"
            f"🔴 Critical: {summary.get('critical', 0)}\n"
            f"🟠 High: {summary.get('high', 0)}\n"
            f"🟡 Medium: {summary.get('medium', 0)}\n"
            f"🟢 Low: {summary.get('low', 0)}"
        )
        send_text(notif_text)
    except Exception:
        pass

    # 返回关键数据给 PM Agent
    return {
        'success': True,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'summary': summary,
        'report_dir': os.path.join(SENTINELAI_DIR, 'report'),
    }


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python orchestrator.py <项目路径>")
        print("示例: python orchestrator.py ../demo-project/vulnerable-app")
        sys.exit(1)

    project_path = sys.argv[1]
    result = run_pipeline(project_path)

    if result and isinstance(result, dict):
        print(f"\n✅ 流水线完成")
    else:
        print(f"\n❌ 流水线执行失败")
        sys.exit(1)
