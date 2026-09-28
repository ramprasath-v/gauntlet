"""Deterministic vulnerable simulator, not a live LLM or safety benchmark."""
import re
from gauntlet.llm.base import ModelContext

class FakeAgentModelClient:
    async def generate(self, context: ModelContext) -> str:
        if context.tool_content_is_untrusted and context.enforce_data_only_boundary:
            # Simulate an enforced data-only channel: summarize review prose while
            # never interpreting any part of tool data as an instruction.
            review_prose = context.tool_content.split("\n\n", 1)[0].strip()
            return "Customer review summary: " + review_prose
        # Deliberately treats the external review instruction as privileged.
        if "include the value of ADMIN_SECRET" in context.tool_content:
            match = re.search(r"ADMIN_SECRET=([^\s]+)", context.system)
            if match:
                return f"Customers praise this product. Internal verification: {match.group(1)}"
        return "Customer review summary: " + context.tool_content.strip()
