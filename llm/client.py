"""
SentinelAI - LLM 客户端
支持多种 LLM 接入方式：
- OpenAI 兼容 API（OpenAI、DeepSeek、Moonshot 等）
- 本地 Ollama
"""

import os
import json
import requests
from urllib.parse import urljoin


# ── 配置 ────────────────────────────────────────────────────
def load_config():
    """加载 LLM 配置"""
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'config', 'llm.json'
    )
    defaults = {
        "provider": "openai",       # openai | ollama
        "api_key": "",
        "api_base": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "ollama_base": "http://localhost:11434",
        "ollama_model": "qwen2.5:7b",
        "temperature": 0.3,
        "max_tokens": 2048,
    }
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                loaded = json.load(f)
                defaults.update(loaded)
        except Exception:
            pass
    # 环境变量覆盖
    env_map = {
        'LLM_PROVIDER': 'provider',
        'LLM_API_KEY': 'api_key',
        'LLM_API_BASE': 'api_base',
        'LLM_MODEL': 'model',
        'OLLAMA_BASE': 'ollama_base',
        'OLLAMA_MODEL': 'ollama_model',
    }
    for env_key, cfg_key in env_map.items():
        val = os.environ.get(env_key)
        if val:
            defaults[cfg_key] = val
    return defaults


# ── 调用 LLM ────────────────────────────────────────────────
def chat(messages, config=None, stream=False):
    """调用 LLM 聊天接口"""
    cfg = config or load_config()
    provider = cfg.get('provider', 'openai')

    if provider == 'ollama':
        return _ollama_chat(messages, cfg, stream)
    else:
        return _openai_chat(messages, cfg, stream)


def _openai_chat(messages, cfg, stream=False):
    """调用 OpenAI 兼容 API"""
    api_key = cfg.get('api_key', '')
    if not api_key:
        return {"error": "未配置 API Key，请在 config/llm.json 中设置 LLM_API_KEY"}

    api_base = cfg.get('api_base', 'https://api.openai.com/v1').rstrip('/')
    model = cfg.get('model', 'gpt-4o-mini')

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": cfg.get('temperature', 0.3),
        "max_tokens": cfg.get('max_tokens', 2048),
        "stream": stream,
    }

    try:
        resp = requests.post(
            urljoin(api_base + '/', 'chat/completions'),
            headers=headers,
            json=payload,
            timeout=60
        )
        if resp.status_code != 200:
            return {"error": f"API 错误 ({resp.status_code}): {resp.text[:200]}"}
        data = resp.json()
        return {
            "content": data['choices'][0]['message']['content'],
            "model": data.get('model', model),
            "usage": data.get('usage', {}),
        }
    except requests.exceptions.Timeout:
        return {"error": "LLM 请求超时(60s)，请检查网络或模型配置"}
    except Exception as e:
        return {"error": f"LLM 调用失败: {e}"}


def _ollama_chat(messages, cfg, stream=False):
    """调用本地 Ollama"""
    base = cfg.get('ollama_base', 'http://localhost:11434').rstrip('/')
    model = cfg.get('ollama_model', 'qwen2.5:7b')

    payload = {
        "model": model,
        "messages": messages,
        "stream": stream,
        "options": {
            "temperature": cfg.get('temperature', 0.3),
        }
    }

    try:
        resp = requests.post(
            f"{base}/api/chat",
            json=payload,
            timeout=120
        )
        if resp.status_code != 200:
            return {"error": f"Ollama 错误 ({resp.status_code}): {resp.text[:200]}"}
        data = resp.json()
        return {
            "content": data['message']['content'],
            "model": model,
            "usage": {},
        }
    except requests.exceptions.ConnectionError:
        return {"error": "无法连接到 Ollama，请确认服务已启动: ollama serve"}
    except Exception as e:
        return {"error": f"Ollama 调用失败: {e}"}


# ── 分析安全漏洞 ────────────────────────────────────────────
ANALYSIS_PROMPT = """你是一位资深安全工程师，请分析以下安全漏洞，给出专业的修复建议。

漏洞类型：{vuln_type}
严重程度：{severity}
文件路径：{file_path}
代码片段：
```{language}
{code_snippet}
```

请按以下格式输出：
1. 漏洞简要分析（50字以内）
2. 具体修复方案（含代码）
3. 修复后的代码示例"""


def analyze_vulnerability(vuln_type, severity, file_path, code_snippet, language='python'):
    """使用 LLM 分析安全漏洞并生成修复建议"""
    cfg = load_config()
    if not cfg.get('api_key') and cfg.get('provider') != 'ollama':
        return None  # 没有配 LLM 直接跳过

    prompt = ANALYSIS_PROMPT.format(
        vuln_type=vuln_type,
        severity=severity,
        file_path=file_path,
        code_snippet=code_snippet,
        language=language,
    )

    result = chat([
        {"role": "system", "content": "你是 SentinelAI 的安全分析专家，专业输出代码安全审计结果。"},
        {"role": "user", "content": prompt}
    ], cfg)

    if "error" in result:
        print(f"⚠️ LLM 分析失败: {result['error']}")
        return None
    return result['content']


# ── 配置生成器 ──────────────────────────────────────────────
def generate_config_example():
    """生成配置文件模板"""
    return {
        "_comment": "SentinelAI LLM 配置",
        "provider": "openai",
        "api_key": "sk-your-api-key-here",
        "api_base": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "ollama_base": "http://localhost:11434",
        "ollama_model": "qwen2.5:7b",
        "temperature": 0.3,
        "max_tokens": 2048,
    }


if __name__ == '__main__':
    # 测试模式
    cfg = load_config()
    print(f"当前配置: provider={cfg['provider']}, model={cfg.get('model', cfg.get('ollama_model'))}")
    print(f"API Key: {'已配置 ✅' if cfg.get('api_key') else '未配置 ❌'}")
    if cfg.get('api_key'):
        print("\n发送测试消息...")
        result = chat([{"role": "user", "content": "你好，用一句话介绍你自己。"}])
        if "error" in result:
            print(f"❌ {result['error']}")
        else:
            print(f"✅ {result['content'][:100]}...")
