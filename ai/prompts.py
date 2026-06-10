"""
Prompt 模板管理。

所有与 AI 交互的 Prompt 集中在此管理。
"""

from typing import Any, Dict, List, Optional


def system_prompt() -> Dict[str, str]:
    """
    System Prompt：设定安全分析师角色。

    Returns:
        dict: {"role": "system", "content": str}
    """
    return {
        "role": "system",
        "content": (
            "你是一名网络安全分析师，负责对攻击事件数据进行研判分析。\n\n"
            "你的职责：\n"
            "1. 根据攻击事件的结构化摘要生成自然语言分析报告\n"
            "2. 对攻击 Payload 进行技术解释\n"
            "3. 给出合理的处置建议\n\n"
            "你的约束：\n"
            "- 只基于提供的数据进行分析，不要编造信息\n"
            "- 不要修改或建议修改风险评分\n"
            "- 不要执行任何系统命令\n"
            "- 不要访问除提供数据外的任何外部资源\n"
            "- 输出使用中文\n"
        ),
    }


def summary_prompt(ip_data: Dict[str, Any]) -> Dict[str, str]:
    """
    生成攻击行为摘要的 Prompt。

    Args:
        ip_data: 结构化攻击源数据。

    Returns:
        dict: {"role": "user", "content": str}
    """
    tags_display = ", ".join(ip_data.get("tags", [])) or "无"
    multi = "是" if ip_data.get("is_multi_source") else "否"
    attack_types = ip_data.get("attack_types", {})
    types_display = "\n".join(
        f"  - {t}: {c}次" for t, c in attack_types.items()
    ) or "  无"
    payloads = ip_data.get("sample_payloads", [])
    payload_display = "\n".join(
        f"  - `{p[:120]}`" for p in payloads[:5]
    ) or "  无"

    usernames = ip_data.get("sample_usernames", [])
    users_display = ", ".join(usernames[:5]) or "无"

    content = f"""请对以下攻击源数据生成一份攻击行为摘要（2-3 段自然语言描述）。

## 攻击源基本信息
- IP: {ip_data.get("ip", "未知")}
- 风险评分: {ip_data.get("risk_score", 0)}/100
- 风险等级: {ip_data.get("risk_level", "unknown")}
- 风险标签: {tags_display}
- 是否多源命中: {multi}

## 事件统计
- 总事件数: {ip_data.get("total_events", 0)}
- SafeLine WAF: {ip_data.get("safeline_events", 0)}
- HFish 蜜罐: {ip_data.get("hfish_events", 0)}
- IOC 数量: {ip_data.get("ioc_count", 0)}

## 攻击类型分布
{types_display}

## 时间范围
- 首次出现: {ip_data.get("first_seen", "未知")}
- 最近活跃: {ip_data.get("last_seen", "未知")}

## 样本 Payload（部分）
{payload_display}

## 登录尝试用户名
{users_display}

请分析攻击者的行为模式、攻击意图和潜在威胁。"""
    return {"role": "user", "content": content}


def payload_explain_prompt(payloads: List[str]) -> Dict[str, str]:
    """
    解释攻击 Payload 的 Prompt。

    Args:
        payloads: Payload 字符串列表。

    Returns:
        dict: {"role": "user", "content": str}
    """
    payload_text = "\n".join(f"```\n{p[:300]}\n```" for p in payloads[:5])
    content = f"""请解释以下攻击 Payload 的技术原理、攻击意图和可能造成的危害：

{payload_text}

请逐条分析，每条用 2-3 句话说明。"""
    return {"role": "user", "content": content}


def remediation_prompt(profile: Dict[str, Any]) -> Dict[str, str]:
    """
    根据画像数据生成处置建议的 Prompt。

    Args:
        profile: 攻击源画像数据。

    Returns:
        dict: {"role": "user", "content": str}
    """
    tags = ", ".join(profile.get("tags", []) or []) or "无"
    risk_level = profile.get("risk_level", "low")

    content = f"""请根据以下攻击源画像数据，给出安全处置建议：

- IP: {profile.get("src_ip", "未知")}
- 风险等级: {risk_level}
- 风险标签: {tags}
- 涉及数据源: {"SafeLine WAF + HFish 蜜罐" if profile.get("is_multi_source") else "单数据源"}
- 总事件数: {profile.get("total_count", 0)}
- SafeLine 事件: {profile.get("safeline_count", 0)}
- HFish 事件: {profile.get("hfish_count", 0)}

请给出：
1. 威胁评估（1-2 句）
2. 具体处置建议（分条列出）
3. 后续监控建议（1-2 条）"""
    return {"role": "user", "content": content}
