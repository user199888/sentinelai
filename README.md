# 多智能体安全审计与代码风险分析平台

## 前言

市面上常规代码检测工具功能单一，大多无多智能体协同能力，人工代码安全审查效率低、容易遗漏密钥泄露、注入类漏洞；本项目贴合实训要求，拆分 6 个专业 Agent 分工处理安全审计全流程，兼顾教学演示与企业真实使用场景。借助多 Agent + 大模型自动完成全流程检测，输出标准化修复方案与报告。

## 项目功能说明

本地代码目录 / 压缩包上传解析
多类型安全漏洞自动扫描（SQL 注入、XSS、硬编码密钥、Prompt 注入等）
漏洞五级风险分级（Critical/High/Medium/Low/Info）
Markdown+JSON 双格式审计报告生成
SQLite 数据持久化存储项目、漏洞、日志、报告
全流程运行日志记录追溯
扫描完成消息通知

## 整体架构说明

五层分层架构（表现层 / 业务层 / Agent 协同层 / Skill 工具层 / 数据层）
6 个核心 Agent（coder/parser/pm/report/review/security）
Skill 工具能力

## 代码审计流程说明

### 环境配置

- python：3.10
- pip install -r requirements.txt
- python database/init_db.py

### 使用方法

执行 Web 启动脚本，打开浏览器访问本地地址，页面支持拖拽上传代码包、查看历史扫描记录、在线打开审计报告。

## 完整审计执行流程

### 第一步：环境准备

```bash
# 1. 打开 sentinelai 目录
# 2. 装依赖
pip install -r requirements.txt
```

### 第二步：配置 API Key（可选，但推荐）

```bash
# 复制 LLM 配置模板
cp config/llm.example.json config/llm.json

# 编辑文件，填入你的 API Key（nano / vim / VSCode）
# Provider 可选：openai / deepseek / ollama
```

### 第三步：配置飞书通知（可选）

```bash
cp config/feishu_webhook.example.txt config/feishu_webhook.txt
# 然后编辑 feishu_webhook.txt，填入群机器人的 Webhook URL
```

### 第四步：启动 Web 服务

```bash
python3 web/app.py
```

浏览器打开 → http://localhost:5000

### 第五步：开始审计

在输入框粘贴以下任一（运行时替换为自己的位置）：

```
/home/zyzyt/.openclaw/workspace/sentinelai/demo-project/vulnerable-app
/home/zyzyt/.openclaw/workspace/pm/login-system/app
https://github.com/WebGoat/WebGoat
```

### 第六步：终端直接跑（可选）

```bash
python3 pm/orchestrator.py /home/zyzyt/.openclaw/workspace/pm/login-system/app
```

## 🔄 流水线执行流程

```
用户输入路径
 ↓
[Web] app.py 接收请求 → 创建任务 → 启动后台线程
 ↓
[PM] orchestrator.py 调度流水线
 ├── ① Parser Agent → scanner.py → project-index.json
 ├── ② Security Agent → detector.py → security-findings.json
 ├── ③ Review Agent → reviewer.py → review-report.json（多模型配合，含 LLM 分析）
 ├── ④ Report Agent → reporter.py → security-report.md/html/json
 └── ⑤ 汇总评分 + 飞书通知
 ↓
用户看到报告 + 群机器人推送通知
```

## 常见使用说明补充

- **权限规范**：各Agent权限隔离，解析/评审仅只读，修复模块仅可生成代码，保障系统安全
- **异常容错**：支持代码包损坏、路径错误、扫描中断等异常捕获，自动记录日志，支持重试执行
- **数据迁移**：所有历史任务、漏洞数据、日志均持久化，直接复制项目文件夹即可完整迁移数据
