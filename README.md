# 🛡 SentinelAI — 自动化安全审计系统

> 自动化的供应链安全审计流水线，支持本地项目扫描和 GitHub 仓库克隆审计。

## 快速开始

### 1. 克隆
```bash
git clone <your-repo-url>
cd sentinelai
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 启动 Web 控制台
```bash
python3 web/app.py
```

浏览器打开 → http://localhost:5000

### 4. 执⾏审计
在 Web 页面输入本地项目路径或 GitHub URL，点击「开始审计」。

## 命令行使用

```bash
# 直接运行完整流水线
python3 pm/orchestrator.py /path/to/target-project

# 单独运行各步骤
python3 parser/scanner.py /path/to/target-project     # 项目扫描
python3 security/detector.py parser/project-index.json # 安全检测
```

## 飞书通知（可选）

在群中添加自定义机器人，将 Webhook URL 写入配置：

```bash
# 方式一：环境变量
export SENTINELAI_FEISHU_WEBHOOK="https://open.feishu.cn/open-apis/bot/v2/hook/your-webhook"

# 方式二：配置文件
echo "https://open.feishu.cn/open-apis/bot/v2/hook/your-webhook" > config/feishu_webhook.txt
```

审计完成后自动推送报告到飞书群。

## 项目结构

```
sentinelai/
├── cli.py              # 命令行入口
├── web/app.py          # Web 控制台
├── pm/                 # 流水线编排
│   └── orchestrator.py # 主调度器
├── parser/             # 项目扫描引擎
├── security/           # 安全检测引擎
├── review-fix/         # 审查与修复
├── report/             # 报告生成
├── shared/             # 共用模块
├── config/             # 配置文件
├── demo-project/       # 测试用 demo
└── tests/              # 单元测试
```
