"""付费情报 provider 存根测试 — 确认未接入时正确抛错"""
from __future__ import annotations

import pytest

from app.threat_intel.base import (
    QianxinProvider,
    Qihu360Provider,
    ThreatBookProvider,
)


class TestPaidProvidersNotImplemented:
    """付费 provider 仅定义接口,很长一段时间不接入 → 调用即抛 NotImplementedError"""

    @pytest.mark.asyncio
    async def test_threatbook_raises_not_implemented(self):
        p = ThreatBookProvider(api_key="dummy")
        assert p.is_paid is True
        with pytest.raises(NotImplementedError):
            await p.query_ip("1.2.3.4")

    @pytest.mark.asyncio
    async def test_qianxin_raises_not_implemented(self):
        p = QianxinProvider(api_key="dummy")
        with pytest.raises(NotImplementedError):
            await p.query_domain("evil.com")

    @pytest.mark.asyncio
    async def test_qihu360_raises_not_implemented(self):
        p = Qihu360Provider(api_key="dummy")
        with pytest.raises(NotImplementedError):
            await p.query_file_hash("abc")

    @pytest.mark.asyncio
    async def test_all_paid_provider_methods_raise(self):
        p = ThreatBookProvider(api_key="dummy")
        for coro in [
            p.query_domain("x.com"),
            p.query_file_hash("h"),
            p.query_url("http://x"),
        ]:
            with pytest.raises(NotImplementedError):
                await coro
