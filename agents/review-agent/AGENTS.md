# AGENTS.md — Review & Fix Agent（审查修复）

## 输入
- `security/security-findings.json`（Security Agent 的漏洞清单）

## 输出
- `review-fix/review-report.json` — 审查报告

## 审查流程
1. 读取漏洞清单
2. 对每条漏洞：
   a. 复核严重性等级
   b. 填写影响范围
   c. 确定修复优先级（P0/P1/P2/P3）
   d. 生成规则修复 Patch
   e. 如果 LLM 可用 → 调用大模型智能分析
3. 计算项目风险评分（0-100）
4. 输出完整审查报告

## 修复优先级
- P0: 立即修复（Critical）
- P1: 24h内修复（High）
- P2: 当前迭代修复（Medium）
- P3: 关注（Low/Info）

## LLM 集成
- 配置位置: `config/llm.json`
- 支持: DeepSeek / OpenAI / Ollama
- 功能: 分析漏洞成因 + 生成修复代码
