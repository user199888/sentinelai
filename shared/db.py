"""
SentinelAI - Database Manager
SQLite 数据库管理模块，各 Agent 通过此模块读写数据库
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'sentinelai.db')


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """初始化数据库表结构"""
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    conn = get_db()
    with open(schema_path, 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


# ─── Projects ────────────────────────────────────────────────

def create_project(name, source='', tech_stack=None):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO projects (name, source, tech_stack) VALUES (?, ?, ?)",
        (name, source, json.dumps(tech_stack or []))
    )
    conn.commit()
    project_id = cur.lastrowid
    conn.close()
    return project_id


def update_project(project_id, **kwargs):
    fields = []
    values = []
    for k, v in kwargs.items():
        fields.append(f"{k} = ?")
        values.append(json.dumps(v) if isinstance(v, (dict, list)) else v)
    values.append(project_id)
    conn = get_db()
    conn.execute(
        f"UPDATE projects SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        values
    )
    conn.commit()
    conn.close()


def get_project(project_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ─── Tasks ──────────────────────────────────────────────────

def create_task(project_id, agent_role, input_data=None):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO tasks (project_id, agent_role, input) VALUES (?, ?, ?)",
        (project_id, agent_role, json.dumps(input_data or {}))
    )
    conn.commit()
    task_id = cur.lastrowid
    conn.close()
    return task_id


def update_task(task_id, status, output_data=None):
    conn = get_db()
    fields = ["status = ?"]
    values = [status]
    if status == 'running':
        fields.append("started_at = CURRENT_TIMESTAMP")
    elif status in ('done', 'failed'):
        fields.append("finished_at = CURRENT_TIMESTAMP")
    if output_data is not None:
        fields.append("output = ?")
        values.append(json.dumps(output_data))
    values.append(task_id)
    conn.execute(
        f"UPDATE tasks SET {', '.join(fields)} WHERE id = ?",
        values
    )
    conn.commit()
    conn.close()


# ─── Findings ────────────────────────────────────────────────

def add_finding(project_id, vuln_type, severity, file_path, line_start, line_end,
                title, description, evidence='', fix_suggestion='', fix_patch=''):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO findings 
           (project_id, vuln_type, severity, file_path, line_start, line_end,
            title, description, evidence, fix_suggestion, fix_patch)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (project_id, vuln_type, severity, file_path, line_start, line_end,
         title, description, evidence, fix_suggestion, fix_patch)
    )
    conn.commit()
    fid = cur.lastrowid
    conn.close()
    return fid


def get_findings(project_id, severity=None, status=None):
    conn = get_db()
    query = "SELECT * FROM findings WHERE project_id = ?"
    params = [project_id]
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_finding(finding_id, **kwargs):
    fields = []
    values = []
    for k, v in kwargs.items():
        fields.append(f"{k} = ?")
        values.append(v)
    values.append(finding_id)
    conn = get_db()
    conn.execute(f"UPDATE findings SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()
    conn.close()


def count_findings(project_id):
    conn = get_db()
    rows = conn.execute(
        """SELECT severity, COUNT(*) as cnt FROM findings 
           WHERE project_id = ? GROUP BY severity""",
        (project_id,)
    ).fetchall()
    conn.close()
    result = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for r in rows:
        result[r['severity']] = r['cnt']
    return result


# ─── Reports ────────────────────────────────────────────────

def save_report(project_id, fmt, file_path, risk_score, summary):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO reports (project_id, format, file_path, risk_score, summary) VALUES (?, ?, ?, ?, ?)",
        (project_id, fmt, file_path, risk_score, summary)
    )
    conn.commit()
    rid = cur.lastrowid
    conn.close()
    return rid


# ─── Logs ──────────────────────────────────────────────────

def add_log(project_id, agent_role, level, message):
    conn = get_db()
    conn.execute(
        "INSERT INTO logs (project_id, agent_role, level, message) VALUES (?, ?, ?, ?)",
        (project_id, agent_role, level, message)
    )
    conn.commit()
    conn.close()


def get_logs(project_id, limit=50):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM logs WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
        (project_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
