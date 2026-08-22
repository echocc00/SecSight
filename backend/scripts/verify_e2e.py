"""端到端验证脚本 — 横向扩展的 4 个新场景

用法: 先启动服务 (uvicorn app.main:app --port 8001), 再运行:
  PYTHONPATH=. python scripts/verify_e2e.py

验证每个场景: 注入 → 剧本匹配 → 研判 → L2审批 → 执行 → resolved + Evidence Pack
"""
from __future__ import annotations

import sys
import time

import httpx

BASE = "http://127.0.0.1:8001/api"

SCENARIOS = [
    ("suspicious_crontab", "pb_persistence_v1"),
    ("ssh_bruteforce", "pb_bruteforce_v1"),
    ("log_collection_stopped", "pb_log_compliance_v1"),
    ("critical_service_crash", "pb_service_crash_v1"),
]


def run_scenario(client: httpx.Client, alert_type: str, expected_pb: str) -> bool:
    print(f"\n{'='*60}\n场景: {alert_type} (期望剧本 {expected_pb})\n{'='*60}")

    # 1. 注入
    r = client.post(f"{BASE}/alerts/inject", json={"alert_type": alert_type})
    if not r.json().get("success"):
        print("  [FAIL] 注入失败:", r.json().get("error"))
        return False
    data = r.json()["data"]
    case_id = data["case_id"]
    pb_id = data["playbook_id"]
    print(f"  注入 OK → case={case_id[:8]} playbook={pb_id}")
    if pb_id != expected_pb:
        print(f"  [FAIL] 剧本匹配错误: {pb_id} != {expected_pb}")
        return False

    # 2. 查 Case 研判
    time.sleep(0.5)
    r = client.get(f"{BASE}/cases/{case_id}")
    case = r.json()["data"]
    j = case.get("judgment") or {}
    print(f"  状态={case['status']} severity={j.get('severity')} confidence={j.get('confidence')} ttps={j.get('ttps')}")
    print(f"  动作数={len(case.get('proposed_actions',[]))} L2待审批={sum(1 for a in case.get('proposed_actions',[]) if a.get('approval_required'))}")

    # 3. 批准所有 L2 动作 (双签: 每个动作提交所需角色)
    r = client.get(f"{BASE}/approvals/{case_id}/pending")
    pending = r.json()["data"]
    for action in pending:
        roles = action.get("required_roles", ["incident_commander", "approver"])
        for role in roles:
            ar = client.post(
                f"{BASE}/approvals/{case_id}/actions/{action['action_id']}/approve",
                json={
                    "approver_role": role,
                    "approver_user": f"e2e-{role}",
                    "decision": "approved",
                    "comment": "e2e test",
                },
            )
            res = ar.json()["data"]
            if res.get("all_approved"):
                print(f"  全部批准 → resume workflow")

    # 4. 验证最终状态
    time.sleep(1.0)
    r = client.get(f"{BASE}/cases/{case_id}")
    case = r.json()["data"]
    status = case["status"]
    tttr = case.get("tttr_seconds")
    exec_count = len(case.get("execution_log", []))
    success_count = sum(1 for e in case.get("execution_log", []) if e["status"] == "success")
    pack_id = case.get("evidence_pack_id")
    print(f"  最终: status={status} tttr={tttr}s 执行={exec_count} 成功={success_count} evidence={bool(pack_id)}")

    # 5. Evidence Pack
    if pack_id:
        r = client.get(f"{BASE}/evidence/{case_id}")
        ev = r.json()["data"]
        print(f"  Evidence: timeline={len(ev.get('timeline',[]))} mitre={ev.get('mitre_mapping',{}).get('techniques')}")

    ok = status == "resolved" and success_count == exec_count and exec_count > 0
    print(f"  {'[PASS]' if ok else '[FAIL]'}")
    return ok


def main() -> int:
    results = {}
    with httpx.Client(timeout=30) as client:
        # 健康检查
        try:
            h = client.get("http://127.0.0.1:8001/health")
            print("服务状态:", h.json().get("status"))
        except Exception as e:
            print("服务未启动:", e)
            return 1

        for alert_type, expected_pb in SCENARIOS:
            results[alert_type] = run_scenario(client, alert_type, expected_pb)

    print(f"\n{'='*60}\n汇总\n{'='*60}")
    for k, v in results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    passed = sum(results.values())
    print(f"\n{passed}/{len(results)} 场景通过")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
