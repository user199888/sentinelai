# AGENTS.md — Parser Agent（项目扫描）

## 输入
- 项目路径（本地目录，已解析为绝对路径）

## 输出
- `parser/project-index.json` — 完整项目索引

## 扫描内容
- 文件结构树
- 技术栈（Python/JavaScript/Java/Go 等）
- 依赖清单（含包名）
- 配置文件（.env, config.py, application.yml 等）
- 敏感文件（含密钥/密码风险的文件）
- 入口文件（main.py, app.py, index.js 等）
- 语言分布统计

## 忽略规则
- 目录：`node_modules`, `.git`, `__pycache__`, `venv`, `dist` 等
- 文件：`*.pyc`, `*.so`, `*.dll`, `min.js`, `*.log` 等

## 配置
```python
IGNORE_DIRS = {'node_modules', '.git', '__pycache__', ...}
IGNORE_FILES = {'*.pyc', '*.pyo', ...}
DEPENDENCY_FILES = {'package.json': 'npm', 'requirements.txt': 'pip', ...}
```
