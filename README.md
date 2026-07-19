# 多智能体安全审计与代码风险分析平台

## 前言

市面上常规代码检测工具功能单一，大多无多智能体协同能力，人工代码安全审查效率低、容易遗漏密钥泄露、注入类漏洞；本项目贴合实训要求，拆分 6 个专业 Agent 分工处理安全审计全流程，兼顾教学演示与企业真实使用场景。借助多 Agent + 大模型自动完成全流程检测，输出标准化修复方案与报告。

## 项目功能说明

- 本地代码目录 / 压缩包上传解析
- 多类型安全漏洞自动扫描（SQL 注入、XSS、硬编码密钥、Prompt 注入等）
- 漏洞五级风险分级（Critical/High/Medium/Low/Info）
- Markdown+JSON 双格式审计报告生成
- SQLite 数据持久化存储项目、漏洞、日志、报告
- 全流程运行日志记录追溯
- 扫描完成飞书消息通知

## 整体架构说明

- 五层分层架构（表现层 / 业务层 / Agent 协同层 / Skill 工具层 / 数据层）
- 6 个核心 Agent（pm/reviewer/coder/writer/tester）
- Skill 工具能力（Project Parser Skill / Security Scan Skill / LLM Analysis Skill / Report Skill / SQLite Skill / File Skill / Git Skill）

## 环境配置

```bash
# Python 3.10+
pip install -r requirements.txt

# 初始化数据库
python database/init_db.py
```

## 使用方法

### Web 启动

```bash
python web/app.py
```

打开浏览器访问 http://localhost:5000，页面支持输入项目路径、上传代码包、查看审计报告。

### 命令行启动

```bash
python pm/orchestrator.py /path/to/target-project
```

## 完整审计执行流程

### 1. 表现层接收用户请求

上传代码包 / 代码目录，请求传递至业务层任务管理模块。

### 2. 业务层分发任务

任务调度模块记录本次扫描任务，下发任务至 Agent 协同层，依次调度 5 个 Agent 流水线执行。

**步骤 1：PM Agent（项目解析）**
读取代码文件，递归遍历目录，解析 package.json、requirements.txt、.env、Dockerfile 等配置，识别编程语言、项目依赖，生成项目索引，项目基础信息存入 SQLite。

**步骤 2：Reviewer Agent（安全评审）**
读取 PM 产出的项目索引，遍历全部源码执行漏洞检测，识别 SQL 注入、XSS、硬编码密钥、Prompt 注入、高危依赖等风险；对漏洞划分 Critical/High/Medium/Low/Info 风险等级，输出分级漏洞清单。

**步骤 3：Coder Agent（修复生成）**
读取漏洞清单与对应源码片段，调用大模型分析漏洞成因，自动生成安全修复代码、补丁与整改建议。

**步骤 4：Writer Agent（报告生成）**
整合项目信息、漏洞统计、风险分级、修复方案，生成 Markdown、JSON 两份审计报告保存至 reports 文件夹；调用飞书 Webhook，向指定群推送扫描完成通知。

**步骤 5：Tester Agent（日志 & 校验）**
全程监听前四个 Agent 运行状态、耗时、报错信息，统一写入 SQLite 日志表与本地日志文件；流程结束自动校验漏洞数量、报告文件是否完整，异常内容单独记录。

### 3. Skill 工具层支撑

所有 Agent 执行过程会按需调用底层 Skill：文件读写、SQLite 数据库操作、LLM 大模型分析、报告渲染、飞书消息推送等通用工具。

### 4. 数据层持久化存储

项目信息、扫描记录、漏洞详情、报告路径、运行日志全部存入 SQLite 文件；上传源码、生成的报告、本地日志以文件形式保存在对应文件夹，重启程序历史数据不会丢失。

## 查看审计结果

### 在线查看（Web 页面）

进入历史任务列表，点击对应扫描记录，可直接在线浏览完整 Markdown 报告，查看漏洞统计、每条漏洞位置与修复代码。

### 文件本地查看

进入项目 reports 目录，找到本次任务对应的 md、json 文件，使用记事本、VS Code 打开查看。

### 飞书消息通知

扫描全部流程结束后，飞书机器人自动推送消息，包含本次扫描总漏洞数量、高危风险数量，附带报告文件保存路径。

## 查看历史数据与运行日志

### 查询历史扫描任务

Web 页面历史记录 / CLI 查询指令：`history list`，可查看所有过往扫描项目、扫描时间、风险总数。

### 查看系统运行日志

- **方式一**：Web 页面日志面板，查看 Tester Agent 归档的结构化日志
- **方式二**：读取 logs 文件夹本地日志文件
- **方式三**：直接操作 SQLite 数据库，查询 log 数据表

## 结束使用

正常关闭终端、Web 页面即可，所有数据自动保存在 `sentinel.db`；如需迁移项目，直接复制整个项目文件夹，SQLite 数据库文件同步迁移，历史记录完整保留。

## 常见使用说明补充

- **支持文件格式**：本地代码文件夹、zip 压缩代码包
- **支持语言**：Python、JavaScript、Java 主流开发语言
- **权限说明**：PM 仅只读文件，Reviewer 只读源码，Coder 允许生成修复代码，Tester 拥有全量日志读写权限
- **异常处理**：若代码包损坏、路径错误、扫描中断，Tester Agent 会记录异常日志，可重新发起扫描指令重试
