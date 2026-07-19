#!/usr/bin/env python3
"""SentinelAI Web Server - 优化版"""

import os
import sys
import json
import threading
import uuid
import time
import shutil
import re
from datetime import datetime, timedelta

from flask import Flask, request, jsonify

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, 'review-fix'))

from pm.orchestrator import run_pipeline
from shared.git_support import is_github_url
import shared.db as db

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# ── Task Manager ────────────────────────────────────────────
TASKS = {}           # task_id → task_info
TTL = timedelta(minutes=30)

def _task_cleaner():
    """后台线程：定期清理过期任务，释放内存并清理临时文件"""
    while True:
        time.sleep(120)
        now = datetime.now()
        expired = [tid for tid, t in list(TASKS.items())
                   if t.get('finished_at') and (now - t['finished_at']) > TTL]
        for tid in expired:
            info = TASKS.pop(tid, None)
            if info:
                _cleanup_task_files(info)

def _cleanup_task_files(info):
    """清理任务关联的临时文件"""
    tmp_dir = info.get('tmp_dir', info.get('clone_dir'))
    if tmp_dir and os.path.exists(tmp_dir):
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

# 启动清理线程
_cleaner_thread = threading.Thread(target=_task_cleaner, daemon=True)
_cleaner_thread.start()

# ── Helpers ─────────────────────────────────────────────────
def _validate_path(path):
    """校验输入路径，返回 (合法路径, 错误信息)"""
    path = path.strip()
    if not path:
        return None, '请输入项目路径'
    if path.startswith('http'):
        if is_github_url(path):
            return path, None  # 交给 scanner 克隆
        else:
            return None, '暂不支持非 GitHub 的 HTTP 地址，请使用 GitHub 仓库 URL 或本地路径'
    else:
        ap = os.path.abspath(path)
        if not os.path.exists(ap):
            return None, f'路径不存在: {ap}'
        if not os.path.isdir(ap):
            return None, f'不是目录: {ap}'
        return ap, None

def _safe_extract_zip(zip_path, extract_dir):
    """安全解压 ZIP，防止 Zip Slip 路径穿越"""
    import zipfile
    with zipfile.ZipFile(zip_path, 'r') as z:
        for entry in z.infolist():
            # 跳过目录
            if entry.filename.endswith('/'):
                continue
            # 防止路径穿越
            dest = os.path.normpath(os.path.join(extract_dir, entry.filename))
            if not dest.startswith(os.path.normpath(extract_dir)):
                raise Exception(f'Zip Slip 攻击检测: {entry.filename}')
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with z.open(entry) as src, open(dest, 'wb') as dst:
                shutil.copyfileobj(src, dst)

# ── Routes ──────────────────────────────────────────────────
@app.route('/')
def index():
    from flask import render_template
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json or {}
    path, err = _validate_path(data.get('project', ''))
    if err:
        return jsonify({'error': err}), 400

    tid = uuid.uuid4().hex[:8]
    TASKS[tid] = {
        'status': 'queued',
        'progress': 0,
        'result': None,
        'started_at': datetime.now(),
        'finished_at': None,
        'tmp_dir': None,
    }

    t = threading.Thread(target=_scan_worker, args=(tid, path), daemon=True)
    t.start()
    return jsonify({'task_id': tid, 'message': '扫描已启动'})

@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': '请选择文件'}), 400
    if not f.filename.endswith('.zip'):
        return jsonify({'error': '仅支持 ZIP 文件'}), 400

    tid = uuid.uuid4().hex[:8]
    extract_dir = os.path.join(app.config['UPLOAD_FOLDER'], tid)
    os.makedirs(extract_dir, exist_ok=True)

    zpath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
    try:
        f.save(zpath)
        _safe_extract_zip(zpath, extract_dir)
    except Exception as e:
        # 清理
        shutil.rmtree(extract_dir, ignore_errors=True)
        if os.path.exists(zpath):
            os.remove(zpath)
        return jsonify({'error': f'解压失败: {e}'}), 400
    finally:
        if os.path.exists(zpath):
            os.remove(zpath)

    TASKS[tid] = {
        'status': 'queued',
        'progress': 0,
        'result': None,
        'started_at': datetime.now(),
        'finished_at': None,
        'tmp_dir': extract_dir,
    }

    t = threading.Thread(target=_scan_worker, args=(tid, extract_dir), daemon=True)
    t.start()
    return jsonify({'task_id': tid, 'message': '文件已上传'})

@app.route('/api/status/<tid>')
def get_status(tid):
    t = TASKS.get(tid)
    if not t:
        return jsonify({'error': '任务不存在'}), 404
    return jsonify({
        'status': t['status'],
        'progress': t['progress'],
        'error': t.get('error'),
    })

@app.route('/api/report/<tid>')
def get_report(tid):
    """获取指定任务的审计报告"""
    t = TASKS.get(tid)
    if not t:
        return jsonify({'error': '任务不存在'}), 404
    if t['status'] != 'done':
        return jsonify({'error': '报告未就绪，当前状态: ' + t['status']}), 400

    report_path = t.get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': '报告文件缺失'}), 404
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({'error': f'读取报告失败: {e}'}), 500

@app.route('/api/findings', methods=['GET'])
def list_findings():
    """获取所有安全发现（用于批量审批）"""
    # 获取最新的已完成任务的发现
    done_tasks = [(tid, t) for tid, t in TASKS.items() if t['status'] == 'done']
    if not done_tasks:
        return jsonify({'findings': []})
    # 按完成时间取最新的
    latest = max(done_tasks, key=lambda x: x[1].get('finished_at') or datetime.min)[1]
    report_path = latest.get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'findings': []})
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify({'findings': data.get('findings', [])})
    except Exception:
        return jsonify({'findings': []})

@app.route('/api/findings/batch', methods=['PUT'])
def batch_update():
    """批量更新发现状态（审批功能）"""
    data = request.json or {}
    ids = data.get('ids', [])
    status = data.get('status', '')
    if not ids or not status:
        return jsonify({'error': '参数不完整'}), 400
    valid = ['approved', 'rejected', 'fixed', 'false_positive', 'acknowledged']
    if status not in valid:
        return jsonify({'error': f'无效状态，可选: {valid}'}), 400
    import shared.db as db
    count = 0
    for fid in ids:
        try:
            db.update_finding(int(fid), status=status)
            count += 1
        except Exception:
            pass
    return jsonify({'message': f'已更新 {count} 条记录', 'status': status})

# ── History ──────────────────────────────────────────────────
HISTORY_FILE = os.path.join(BASE, 'config', 'scan_history.json')
_hist_lock = threading.Lock()

def _save_scan_history(task_id, info):
    """将扫描记录持久化到 JSON 文件（重启不丢失）"""
    if info['status'] != 'done':
        return
    try:
        with _hist_lock:
            history = []
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    try:
                        history = json.load(f)
                    except:
                        history = []
            
            result = info.get('result') or {}
            project_name = info.get('project_name', '未知项目')
            entry = {
                'task_id': task_id,
                'project_name': project_name,
                'project_path': info.get('project_path', ''),
                'risk_score': result.get('risk_score', 0),
                'risk_level': result.get('risk_level', ''),
                'summary': result.get('summary', {}),
                'finished_at': info['finished_at'].isoformat() if info.get('finished_at') else '',
                'report_path': info.get('report_path', ''),
            }
            # 去重：相同 task_id 则替换
            history = [h for h in history if h.get('task_id') != task_id]
            history.insert(0, entry)
            # 最多保留 50 条
            history = history[:50]
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


@app.route('/api/history')
def list_history():
    """获取扫描历史列表"""
    if not os.path.exists(HISTORY_FILE):
        return jsonify({'history': []})
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            history = json.load(f)
        return jsonify({'history': history})
    except Exception:
        return jsonify({'history': []})


@app.route('/api/history/<task_id>')
def get_history(task_id):
    """获取指定历史记录的完整报告"""
    if not os.path.exists(HISTORY_FILE):
        return jsonify({'error': '无历史记录'}), 404
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            history = json.load(f)
        for entry in history:
            if entry['task_id'] == task_id:
                report_path = entry.get('report_path', '')
                if report_path and os.path.exists(report_path):
                    with open(report_path, 'r', encoding='utf-8') as rf:
                        return jsonify(json.load(rf))
                else:
                    return jsonify({'error': '报告文件已丢失'}), 404
        return jsonify({'error': '未找到该记录'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Scan Worker ─────────────────────────────────────────────
def _scan_worker(task_id, project_path):
    """后台扫描工作线程"""
    info = TASKS[task_id]
    info['status'] = 'running'
    info['progress'] = 2

    def on_progress(step_name, step_idx, total_steps, success, progress_override=None):
        """流水线进度回调"""
        if progress_override is not None:
            info['progress'] = progress_override
            return
        if success is None:
            # 步骤开始
            pct = int((step_idx - 1) / total_steps * 100)
        elif success is True:
            pct = int(step_idx / total_steps * 100)
        else:
            info.update({'status': 'failed', 'progress': 0,
                         'error': f'步骤 {step_name} 执行失败'})
            return
        info['progress'] = max(pct, 2)

    info['progress'] = 5
    info['project_path'] = project_path
    # 提取项目名
    if project_path.startswith('http'):
        project_name = project_path.rstrip('/').split('/')[-1].replace('.git', '')
    else:
        project_name = os.path.basename(project_path.rstrip('/\\'))
    info['project_name'] = project_name

    try:
        result = run_pipeline(project_path, progress_callback=on_progress)

        if isinstance(result, dict) and result.get('success'):
            info['result'] = result
            info['status'] = 'done'
            info['progress'] = 100
            # 记录报告路径
            report_dir = result.get('report_dir', os.path.join(BASE, 'report'))
            info['report_path'] = os.path.join(report_dir, 'security-report.json')
            _save_scan_history(task_id, info)
        else:
            info.update({'status': 'failed', 'progress': 0,
                         'error': '流水线执行失败，请检查日志',
                         'result': None})
    except Exception as e:
        info.update({'status': 'failed', 'progress': 0, 'error': str(e)})
    finally:
        info['finished_at'] = datetime.now()

if __name__ == '__main__':
    print("=" * 40)
    print("  SentinelAI Web Console")
    print("  http://localhost:5000")
    print("=" * 40)
    app.run(host='127.0.0.1', port=5000, debug=False)
