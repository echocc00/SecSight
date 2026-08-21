"""合规报告 API"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.api.schemas import ApiResponse
from app.compliance.generator import report_generator

router = APIRouter()


@router.post("/{case_id}/report")
async def generate_report(
    case_id: str,
    format: str = Query("html", pattern="^(html|markdown)$"),
) -> dict:
    """生成等保 2.0 三级事件报告 (HTML/Markdown)"""
    try:
        result = await report_generator.generate(case_id, format=format)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return result


@router.get("/{case_id}/report", response_class=HTMLResponse)
async def get_report_html(case_id: str) -> HTMLResponse:
    """直接获取 HTML 报告 (浏览器可查看)"""
    try:
        result = await report_generator.generate(case_id, format="html")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return HTMLResponse(content=result["content"])


@router.get("/{case_id}/report.md", response_class=PlainTextResponse)
async def get_report_markdown(case_id: str) -> PlainTextResponse:
    """获取 Markdown 报告"""
    try:
        result = await report_generator.generate(case_id, format="markdown")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return PlainTextResponse(content=result["content"])
