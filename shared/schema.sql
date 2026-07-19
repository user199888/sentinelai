-- SentinelAI Database Schema
-- SQLite 数据库

-- 项目表
CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    source      TEXT,             -- GitHub URL / zip path / directory
    tech_stack  TEXT,             -- JSON: ["Python", "JavaScript", ...]
    file_count  INTEGER DEFAULT 0,
    dep_count   INTEGER DEFAULT 0,
    status      TEXT DEFAULT 'pending',  -- pending | parsing | scanning | reviewing | reporting | done | failed
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 任务表（每个Agent的执行记录）
CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL,
    agent_role  TEXT NOT NULL,     -- parser | security | review_fix | report | test
    status      TEXT DEFAULT 'pending',  -- pending | running | done | failed
    input       TEXT,              -- 任务输入（JSON）
    output      TEXT,              -- 任务产出（JSON / file path）
    started_at  DATETIME,
    finished_at DATETIME,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

-- 安全发现表
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL,
    vuln_type       TEXT NOT NULL,     -- sql_injection | command_injection | hardcoded_secret | xss | path_traversal | prompt_injection | unsafe_cors | dangerous_dep | info_leak | other
    severity        TEXT NOT NULL,     -- Critical | High | Medium | Low | Info
    file_path       TEXT,
    line_start      INTEGER,
    line_end        INTEGER,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    evidence        TEXT,              -- 发现依据/代码片段
    fix_suggestion  TEXT,              -- 修复建议
    fix_patch       TEXT,              -- 可应用的Patch
    status          TEXT DEFAULT 'open',  -- open | fixing | fixed | verified | false_positive
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

-- 报告表
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL,
    format      TEXT NOT NULL,         -- markdown | html | json
    file_path   TEXT,
    risk_score  REAL,                  -- 0-100
    summary     TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

-- 审计日志表
CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER,
    agent_role  TEXT,
    level       TEXT DEFAULT 'info',   -- info | warn | error | debug
    message     TEXT NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id);
CREATE INDEX IF NOT EXISTS idx_reports_project ON reports(project_id);
CREATE INDEX IF NOT EXISTS idx_logs_project ON logs(project_id);
