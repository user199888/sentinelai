# AGENTS.md — Coder Agent（LLM 分析）

## 输入
- 漏洞类型、严重等级、文件路径、代码片段

## 输出
- 漏洞分析（成因 + 攻击路径）
- 修复方案（具体代码 + 修改说明）
- 修复后的代码示例

## 配置
```json
{
  "provider": "deepseek",
  "api_key": "",
  "api_base": "https://api.deepseek.com",
  "model": "deepseek-chat"
}
```

## 支持模型
- DeepSeek Chat （推荐）
- DeepSeek V4 Flash
- GPT-4o Mini
- 本地 Ollama（qwen2.5 等）
