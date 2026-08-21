"""LLM 网关层

- MockLLMGateway: 预设报告 (mock_mode=True)
- RealLLMProvider: OpenAI 兼容端点直连 (MiniMax/LiteLLM)
- ResilientLLMGateway: 真 LLM 主 + 故障降级 mock
- get_llm(): 工厂,按 mock_mode / llm_provider 切换
"""
from app.llm_gateway.mock import MockLLMGateway, get_llm
from app.llm_gateway.provider import LLMProviderError, RealLLMProvider
from app.llm_gateway.resilient import ResilientLLMGateway

__all__ = [
    "MockLLMGateway",
    "RealLLMProvider",
    "ResilientLLMGateway",
    "LLMProviderError",
    "get_llm",
]
