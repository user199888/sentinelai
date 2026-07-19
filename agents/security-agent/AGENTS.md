# AGENTS.md — Security Agent（安全检测）

## 输入
- `parser/project-index.json`（Parser Agent 输出的项目索引）

## 输出
- `security/security-findings.json` — 结构化漏洞清单

## 检测类型
| 漏洞类型 | 风险等级 | 检测方式 |
|---------|---------|---------|
| SQL注入 | Critical/High | 正则匹配 + 语义分析 |
| 命令注入 | Critical/High | shell=True / exec() 检测 |
| 硬编码密钥 | High | API Key / JWT / 密码正则 |
| XSS | Medium/High | 未转义输出检测 |
| 路径遍历 | Medium | 路径拼接未校验 |
| Prompt注入 | Medium | LLM prompt 拼接检测 |
| 不安全配置 | Medium | CORS / Debug 模式 |
| 危险依赖 | Medium | 已知CVE版本检测 |

## 严重等级标准
- Critical: 直接影响服务器/数据库安全
- High: 可能导致数据泄露 / 权限提升
- Medium: 增加攻击面 / 信息泄露
- Low: 不符合最佳实践
