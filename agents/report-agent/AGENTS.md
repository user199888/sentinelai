# AGENTS.md — Report Agent（报告生成）

## 输入
- `review-fix/review-report.json`（审查结果）
- `parser/project-index.json`（项目信息）
- `security/security-findings.json`（原始发现）

## 输出
| 格式 | 文件 | 用途 |
|-----|------|------|
| Markdown | `report/security-report.md` | 文档阅读 |
| HTML | `report/security-report.html` | Web 展示 |
| JSON | `report/security-report.json` | 程序处理 |

## 报告内容
1. 项目基本信息（名称、路径、技术栈）
2. 风险评分 + 风险等级
3. 漏洞统计图表（按严重程度分布）
4. 每条漏洞的详情（类型、位置、描述、修复建议）
5. 飞书通知文案
