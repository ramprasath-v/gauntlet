from typing import Protocol
from gauntlet.core.models import AttackResult

class Attack(Protocol):
    async def run(self) -> AttackResult: ...
