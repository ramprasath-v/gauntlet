from fastapi import FastAPI

from gauntlet.core.models import ChatRequest, ChatResponse
from victims.clean_customer_support.agent import CleanCustomerSupportAgent
from victims.clean_customer_support.model import CleanCustomerSupportModel


def create_app(model: CleanCustomerSupportModel | None = None) -> FastAPI:
    app = FastAPI(title="CustomerSupport.CleanRepairBenchmark")
    agent = CleanCustomerSupportAgent(model or CleanCustomerSupportModel())

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ready", "model": "deterministic_role_simulator"}

    @app.post("/chat", response_model=ChatResponse)
    async def chat(request: ChatRequest) -> ChatResponse:
        return await agent.chat(request.message)

    return app


app = create_app()
