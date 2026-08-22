"""飞书/钉钉审批 webhook 通知 + 回调

通知: L2 审批触发时推送卡片消息到飞书/钉钉群
回调: 用户在飞书/钉钉点击"批准/拒绝" → 回调 SecSight 端点

配置:
  FEISHU_WEBHOOK_URL: 飞书群机器人 webhook
  DINGTALK_WEBHOOK_URL: 钉钉群机器人 webhook
  FEISHU_APP_ID/APP_SECRET: 飞书应用 (回调签名校验)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx

from app.core.config import settings

import structlog

log = structlog.get_logger()


class NotifyError(Exception):
    pass


# ============ 飞书 ============


class FeishuNotifier:
    """飞书群机器人 + 审批卡片"""

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url or self._get_webhook_url()

    @staticmethod
    def _get_webhook_url() -> str:
        import os

        return os.environ.get("FEISHU_WEBHOOK_URL", "")

    async def send_approval_card(
        self,
        case_id: str,
        action_id: str,
        action_type: str,
        severity: str,
        callback_base: str,
    ) -> dict:
        """推送审批卡片到飞书群

        卡片含"批准"/"拒绝"按钮,点击后回调 SecSight。
        """
        if not self.webhook_url:
            log.info("feishu.no_webhook", case_id=case_id)
            return {"skipped": True, "reason": "FEISHU_WEBHOOK_URL 未配置"}

        card = self._build_card(case_id, action_id, action_type, severity, callback_base)
        payload = {"msg_type": "interactive", "card": card}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.webhook_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
            log.info("feishu.sent", case_id=case_id, action_id=action_id, code=data.get("code"))
            return {"sent": True, "response": data}
        except Exception as e:  # noqa: BLE001
            log.warning("feishu.send_failed", error=str(e))
            return {"sent": False, "error": str(e)}

    def _build_card(
        self, case_id, action_id, action_type, severity, callback_base
    ) -> dict:
        """构造飞书交互卡片"""
        approve_url = f"{callback_base}/api/approvals/callback/feishu"
        return {
            "header": {
                "title": {"tag": "plain_text", "content": f"🔴 SecSight L2 审批 · {severity}"},
                "template": "red" if severity in ("critical", "high") else "orange",
            },
            "elements": [
                {
                    "tag": "div",
                    "text": {"tag": "lark_md", "content": f"**Case:** {case_id[:8]}\n**动作:** {action_type}\n**严重性:** {severity}"},
                },
                {
                    "tag": "action",
                    "actions": [
                        {
                            "tag": "button",
                            "text": {"tag": "plain_text", "content": "✅ 批准"},
                            "type": "primary",
                            "value": {
                                "case_id": case_id,
                                "action_id": action_id,
                                "decision": "approved",
                                "callback_url": approve_url,
                            },
                        },
                        {
                            "tag": "button",
                            "text": {"tag": "plain_text", "content": "❌ 拒绝"},
                            "type": "danger",
                            "value": {
                                "case_id": case_id,
                                "action_id": action_id,
                                "decision": "rejected",
                                "callback_url": approve_url,
                            },
                        },
                    ],
                },
            ],
        }


# ============ 钉钉 ============


class DingtalkNotifier:
    """钉钉群机器人 + ActionCard"""

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url or self._get_webhook_url()

    @staticmethod
    def _get_webhook_url() -> str:
        import os

        return os.environ.get("DINGTALK_WEBHOOK_URL", "")

    async def send_approval_card(
        self,
        case_id: str,
        action_id: str,
        action_type: str,
        severity: str,
        callback_base: str,
    ) -> dict:
        if not self.webhook_url:
            log.info("dingtalk.no_webhook", case_id=case_id)
            return {"skipped": True, "reason": "DINGTALK_WEBHOOK_URL 未配置"}

        approve_url = f"{callback_base}/api/approvals/callback/dingtalk"
        payload = {
            "msgtype": "action_card",
            "action_card": {
                "title": f"SecSight L2 审批 · {severity}",
                "text": f"**Case:** {case_id[:8]}\n**动作:** {action_type}\n**严重性:** {severity}",
                "btns": [
                    {"title": "✅ 批准", "action_url": f"{approve_url}?case_id={case_id}&action_id={action_id}&decision=approved"},
                    {"title": "❌ 拒绝", "action_url": f"{approve_url}?case_id={case_id}&action_id={action_id}&decision=rejected"},
                ],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.webhook_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
            log.info("dingtalk.sent", case_id=case_id, errcode=data.get("errcode"))
            return {"sent": True, "response": data}
        except Exception as e:  # noqa: BLE001
            log.warning("dingtalk.send_failed", error=str(e))
            return {"sent": False, "error": str(e)}


# ============ 统一入口 ============


async def notify_approval(
    case_id: str,
    action_id: str,
    action_type: str,
    severity: str,
    callback_base: str = "http://secsight-backend:8000",
) -> dict:
    """推送审批通知到所有配置的渠道 (飞书 + 钉钉)"""
    results: dict[str, Any] = {}
    feishu = FeishuNotifier()
    if feishu.webhook_url:
        results["feishu"] = await feishu.send_approval_card(
            case_id, action_id, action_type, severity, callback_base
        )
    dingtalk = DingtalkNotifier()
    if dingtalk.webhook_url:
        results["dingtalk"] = await dingtalk.send_approval_card(
            case_id, action_id, action_type, severity, callback_base
        )
    if not results:
        results["skipped"] = "未配置任何通知渠道"
    return results


# ============ 飞书签名校验 (回调) ============


def verify_feishu_signature(
    timestamp: str, body: str, app_secret: str
) -> bool:
    """校验飞书回调签名"""
    string_to_sign = f"{timestamp}\n{body}"
    import base64

    hmac_code = hmac.new(
        app_secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(hmac_code).decode("utf-8")
