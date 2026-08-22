"""知识沉淀 API"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.schemas import ApiResponse
from app.knowledge.sediment import sediment_case

router = APIRouter()


@router.post("/{case_id}/sediment", response_model=ApiResponse)
async def sediment(case_id: str) -> ApiResponse:
    """案例沉淀 — L3 案例 → L1 战术优化检测规则

    从 resolved Case 提取知识,生成 Sigma 检测规则建议,注入 L1 战术层。
    应在 Case resolved 后调用,形成"处置→学习→更强调检测"飞轮。
    """
    try:
        result = await sediment_case(case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return ApiResponse(
        success=True,
        data={
            "case_id": case_id,
            "ttps": result["knowledge"]["ttps"],
            "iocs": result["knowledge"]["iocs"],
            "rules_generated": len(result["generated_rules"]),
            "generated_rules": result["generated_rules"],
            "l1_injection": result["l1_injection"],
        },
    )
