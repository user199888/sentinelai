"""
SentinelAI - 飞书通知模块
审计完成后通过群机器人 Webhook 推送报告到飞书群
"""

import os
import json
import requests


def get_webhook_url():
    """获取飞书 Webhook URL（优先环境变量，其次配置文件）"""
    url = os.environ.get('SENTINELAI_FEISHU_WEBHOOK')
    if url:
        return url

    # 尝试从项目配置文件读取
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'config', 'feishu_webhook.txt'
    )
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            url = f.read().strip()
            if url:
                return url

    return None


def send_text(text):
    """发送纯文本消息到飞书群"""
    webhook_url = get_webhook_url()
    if not webhook_url:
        print("⚠️ 未配置飞书 Webhook URL，跳过通知")
        return

    payload = {
        "msg_type": "text",
        "content": {
            "text": text
        }
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        result = resp.json()
        if result.get('code') == 0:
            print("✅ 飞书通知发送成功")
        else:
            print(f"⚠️ 飞书通知发送失败: {result}")
    except Exception as e:
        print(f"⚠️ 飞书通知异常: {e}")


def send_card(report_data):
    """发送飞书消息卡片（结构化报告）"""
    webhook_url = get_webhook_url()
    if not webhook_url:
        print("⚠️ 未配置飞书 Webhook URL，跳过通知")
        return

    summary = report_data.get('summary', {})
    risk = report_data.get('risk_assessment', {})
    score = risk.get('score', 0)
    level = risk.get('level', '未知')

    # 根据风险等级选择颜色
    if score >= 70:
        template = "red"
        title = "🔴 高危 - 建议立即处理"
    elif score >= 40:
        template = "yellow"
        title = "🟡 中危 - 建议安排修复"
    else:
        template = "green"
        title = "🟢 低风险 - 继续保持"

    total = summary.get('total', 0)

    payload = {
        "msg_type": "interactive",
        "card": {
            "config": {"wide_screen_mode": True},
            "header": {
                "title": {"tag": "plain_text", "content": "🛡 SentinelAI 安全审计报告"},
                "template": template
            },
            "elements": [
                {
                    "tag": "div",
                    "fields": [
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"**风险评分**\n{score}/100"}},
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"**风险等级**\n{level}"}},
                    ]
                },
                {"tag": "hr"},
                {
                    "tag": "div",
                    "fields": [
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"🔴 Critical\n**{summary.get('critical', 0)}**"}},
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"🟠 High\n**{summary.get('high', 0)}**"}},
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"🟡 Medium\n**{summary.get('medium', 0)}**"}},
                        {"is_short": True, "text": {"tag": "lark_md", "content": f"🟢 Low\n**{summary.get('low', 0)}**"}},
                    ]
                },
                {"tag": "hr"},
                {
                    "tag": "div",
                    "text": {"tag": "lark_md", "content": f"📈 本次扫描共发现 **{total}** 个安全问题\n\n" + (
                        "⚠️ 存在严重风险漏洞，建议立即修复！" if summary.get('critical', 0) > 0
                        else "⚠️ 存在中高风险漏洞，建议安排修复计划。" if summary.get('high', 0) > 0
                        else "✅ 安全状况良好，继续保持。"
                    )}
                },
            ]
        }
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        result = resp.json()
        if result.get('code') == 0:
            print("✅ 飞书卡片通知发送成功")
        else:
            print(f"⚠️ 飞书卡片通知发送失败: {result}")
    except Exception as e:
        print(f"⚠️ 飞书通知异常: {e}")


def send_scan_summary(project_name, success, risk_score=0, risk_level='', summary=None):
    """发送简版扫描结果（无需完整报告JSON，适合前端直接调用）"""
    if summary is None:
        summary = {}
    text = (
        f"🛡 SentinelAI 安全审计完成\n\n"
        f"📁 项目: {project_name}\n"
        f"{f'📊 风险评分: {risk_score}/100 ({risk_level})' if success else '❌ 审计执行失败'}\n\n"
        f"📈 共发现 {summary.get('total', 0)} 个安全问题:\n"
        f"🔴 Critical: {summary.get('critical', 0)}\n"
        f"🟠 High: {summary.get('high', 0)}\n"
        f"🟡 Medium: {summary.get('medium', 0)}\n"
        f"🟢 Low: {summary.get('low', 0)}"
    )
    send_text(text)
