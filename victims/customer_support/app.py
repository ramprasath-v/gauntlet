from fastapi import FastAPI
from gauntlet.core.models import ChatRequest, ChatResponse
from gauntlet.llm.base import AgentModelClient
from gauntlet.llm.fake import FakeAgentModelClient
from victims.customer_support.agent import CustomerSupportAgent

def create_app(model: AgentModelClient | None = None) -> FastAPI:
    app = FastAPI(title="CustomerSupport.Vulnerable — local simulator")
    agent = CustomerSupportAgent(model if model is not None else FakeAgentModelClient())

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ready", "model": "deterministic_simulator"}

    @app.post("/chat", response_model=ChatResponse)
    async def chat(request: ChatRequest) -> ChatResponse:
        return await agent.chat(request.message)

    return app

app = create_app()
