"""剧本 API"""
from __future__ import annotations

from fastapi import APIRouter

from app.api.schemas import ApiResponse
from app.playbooks.engine import engine as playbook_engine

router = APIRouter()


@router.get("", response_model=ApiResponse)
async def list_playbooks() -> ApiResponse:
    return ApiResponse(
        success=True,
        data=[
            {
                "id": pb.id,
                "name": pb.name,
                "category": pb.category,
                "priority": pb.priority,
                "phase": pb.phase,
                "autonomy_default": pb.autonomy_level_default,
                "mitre_techniques": pb.mitre_mapping.techniques,
                "action_count": len(pb.containment_actions),
            }
            for pb in playbook_engine.playbooks
        ],
    )


@router.get("/{playbook_id}", response_model=ApiResponse)
async def get_playbook(playbook_id: str) -> ApiResponse:
    pb = playbook_engine.get_by_id(playbook_id)
    if not pb:
        return ApiResponse(success=False, error="Playbook not found")
    return ApiResponse(success=True, data=pb.model_dump(mode="json"))
