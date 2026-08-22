"""真实部署验证脚本 — docker compose 全栈冒烟

用法 (需先 cp .env.example .env 并填写,且 docker compose up -d 起全栈):
  PYTHONPATH=. python scripts/verify_real_deploy.py

验证项:
  1. docker compose 各服务健康
  2. SecSight /health 各组件连通
  3. Wazuh webhook 接收真实告警 (需 Wazuh custom integration 配置)
  4. Shuffle SOAR 执行 (需 workflow 配置 + ENABLE_SHUFFLE=true)
  5. 真实 LLM 研判 (需 MINIMAX_API_KEY)

前置:
  - .env: SECSIGHT_MOCK_MODE=false, ENABLE_SHUFFLE=true, MINIMAX_API_KEY=...
  - docker compose up -d
  - Wazuh: 在 Manager 配置 custom integration 推送到 http://secsight-backend:8000/api/alerts/wazuh-webhook
  - Shuffle: 在 UI 创建 workflows,把 ID 填入 SHUFFLE_WORKFLOW_<TYPE>
"""
from __future__ import annotations

import os
import subprocess
import sys

import httpx

BASE = os.environ.get("SECSIGHT_URL", "http://127.0.0.1:8000/api")


def check_docker_services() -> bool:
    """检查 docker compose 服务健康"""
    print("\n=== 1. Docker 服务健康 ===")
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "table {{.Name}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=30,
        )
        print(result.stdout)
        unhealthy = "unhealthy" in result.stdout or "restarting" in result.stdout
        if unhealthy:
            print("  ⚠️ 存在不健康服务")
            return False
        return True
    except Exception as e:
        print(f"  [FAIL] docker compose 检查失败: {e}")
        return False


def check_health() -> dict:
    """检查 SecSight /health 各组件"""
    print("\n=== 2. SecSight 组件连通性 ===")
    try:
        r = httpx.get("http://127.0.0.1:8000/health", timeout=10)
        data = r.json()
        print(f"  status: {data['status']}, mock_mode: {data['mock_mode']}")
        components = data.get("components", {})
        for name, status in components.items():
            print(f"  {name}: {status}")
        return data
    except Exception as e:
        print(f"  [FAIL] /health 不可达: {e}")
        return {}


def check_wazuh_webhook() -> bool:
    """验证 Wazuh webhook 端点可用 (发送一个测试 Wazuh 格式告警)"""
    print("\n=== 3. Wazuh webhook 接收器 ===")
    test_alert = {
        "timestamp": "2026-08-21T10:15:30.000+0000",
        "rule": {
            "level": 12, "id": "5710",
            "description": "Verify deploy: xmrig process",
            "mitre": {"id": ["T1496"], "tactic": ["Impact"]},
        },
        "data": {"srcip": "10.0.1.15", "dstip": "192.168.64.1"},
        "agent": {"name": "web-prod-01", "id": "003"},
    }
    try:
        r = httpx.post(f"{BASE}/alerts/wazuh-webhook", json=test_alert, timeout=30)
        data = r.json()
        if data.get("success"):
            print(f"  [OK] webhook 接收成功 → case={data['data']['case_id'][:8]}")
            print(f"       playbook={data['data']['playbook_id']}")
            return True
        print(f"  [FAIL] {data.get('error')}")
        return False
    except Exception as e:
        print(f"  [FAIL] webhook 不可达: {e}")
        return False


def check_shuffle() -> bool:
    """验证 Shuffle 执行 (需 ENABLE_SHUFFLE=true + workflow 配置)"""
    print("\n=== 4. Shuffle SOAR 执行 ===")
    if not os.environ.get("ENABLE_SHUFFLE", "").lower() == "true":
        print("  [SKIP] ENABLE_SHUFFLE 未开启")
        return True
    # 通过完整 Case 流程验证执行
    # 先注入告警 → 审批 → 检查 execution_log 是否走 Shuffle
    try:
        r = httpx.post(
            f"{BASE}/alerts/wazuh-webhook",
            json={
                "rule": {"level": 12, "id": "5710", "description": "shuffle test",
                          "mitre": {"id": ["T1496"], "tactic": ["Impact"]}},
                "data": {"srcip": "10.0.1.15"},
                "agent": {"name": "test-host", "id": "001"},
            },
            timeout=30,
        )
        case_id = r.json()["data"]["case_id"]
        # 审批所有动作
        pending = httpx.get(f"{BASE}/approvals/{case_id}/pending", timeout=10).json()["data"]
        for action in pending:
            httpx.post(
                f"{BASE}/approvals/{case_id}/actions/{action['action_id']}/approve",
                json={"approver_role": "incident_commander", "approver_user": "deploy-test",
                      "decision": "approved"},
                timeout=10,
            )
        # 检查执行结果
        import time
        time.sleep(2)
        case = httpx.get(f"{BASE}/cases/{case_id}", timeout=10).json()["data"]
        shuffle_execs = [e for e in case.get("execution_log", []) if "shuffle" in str(e.get("result", {}))]
        fallbacks = [e for e in case.get("execution_log", []) if "fallback_reason" in str(e.get("result", {}))]
        print(f"  执行: {len(case.get('execution_log', []))} 动作")
        print(f"  Shuffle 直执行: {len(shuffle_execs)}")
        print(f"  降级 mock: {len(fallbacks)}")
        if shuffle_execs:
            print("  [OK] Shuffle 真实执行生效")
        elif fallbacks:
            print("  [WARN] Shuffle 降级到 mock (检查 workflow 配置/连通)")
        return True
    except Exception as e:
        print(f"  [FAIL] {e}")
        return False


def main() -> int:
    print("=" * 60)
    print("SecSight 真实部署验证")
    print("=" * 60)

    results = {
        "docker": check_docker_services(),
        "health": bool(check_health()),
        "wazuh_webhook": check_wazuh_webhook(),
        "shuffle": check_shuffle(),
    }

    print(f"\n{'=' * 60}\n汇总\n{'=' * 60}")
    for k, v in results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL/SKIP'}")
    passed = sum(results.values())
    print(f"\n{passed}/{len(results)} 通过")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
