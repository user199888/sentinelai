# SentinelAI 安全策略配置

## 权限分级体系

| 级别 | 名称 | 权限范围 | 适用Agent |
|------|------|----------|-----------|
| L0 | 只读 | 只能读取项目文件和元数据 | Parser Agent (coder) |
| L1 | 检测 | 读取文件 + 执行安全检测 | Security Agent (code-reviewer) |
| L2 | 审查修复 | 读取 + 分析 + 生成修复代码 | Review & Fix Agent (reviewer) |
| L3 | 报告生成 | 读取 + 写入+ 生成报告文件 | Report Agent (writer) |
| L4 | 测试执行 | 读取 + 执行测试命令 | Testing Agent (tester) |
| L5 | 管理员 | 完全控制 | PM Agent (pm) |

## 安全策略规则

### L0 - Parser Agent
✅ 允许:
- 递归读取项目目录
- 读取文件内容（仅用于索引）
- 读取依赖文件
- 输出项目索引 JSON

❌ 禁止:
- 修改文件
- 执行代码
- 访问项目外文件
- 网络请求

### L1 - Security Agent
✅ 允许:
- 读取 parser 产出的项目索引
- 读取项目源码文件
- 执行正则匹配检测
- 输出安全发现 JSON

❌ 禁止:
- 修改项目文件
- 执行检测到的危险代码
- 泄露检测到的密钥
- 网络请求（除 API 调用）

### L2 - Review & Fix Agent
✅ 允许:
- 读取安全发现 JSON
- 读取项目索引
- 生成修复建议和 Patch
- 输出审查报告

❌ 禁止:
- 自动应用 Patch
- 修改原始项目文件
- 执行未经验证的代码

### L3 - Report Agent
✅ 允许:
- 读取所有 Agent 产出
- 写入报告文件 (report/)
- 生成 Markdown/HTML/JSON

❌ 禁止:
- 修改项目源码
- 执行任意系统命令
- 发送外部网络请求

### L4 - Testing Agent
✅ 允许:
- 读取项目文件
- 执行测试命令
- 输出测试报告

❌ 禁止:
- 修改生产代码
- 执行危险系统命令
- 访问敏感数据

### L5 - PM Agent
✅ 允许:
- 完整调度流水线
- 读取所有产出
- 在飞书群发送通知
- 协调 Agent 间通信

❌ 禁止:
- 直接执行审计任务（应委托给其他 Agent）
- 修改 Agent 配置文件
