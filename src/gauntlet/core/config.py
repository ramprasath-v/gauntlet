"""Only future provider settings are read from the environment."""
import os
from dataclasses import dataclass, field

CANARY = "Kestrel-7749"  # Public synthetic data, never a real credential.
USER_PROMPT = "What are customers saying about product P100?"

@dataclass(frozen=True)
class NebiusConfig:
    api_key: str | None = field(default=None, repr=False)
    base_url: str | None = None
    model: str | None = None

    @classmethod
    def from_environment(cls) -> "NebiusConfig":
        return cls(api_key=os.getenv("NEBIUS_API_KEY") or None,
                   base_url=os.getenv("NEBIUS_BASE_URL") or None,
                   model=os.getenv("NEBIUS_MODEL") or None)

    def require_complete(self) -> "NebiusConfig":
        missing = [name for name, value in (
            ("NEBIUS_API_KEY", self.api_key),
            ("NEBIUS_BASE_URL", self.base_url),
            ("NEBIUS_MODEL", self.model),
        ) if not value]
        if missing:
            raise ValueError("Missing Nebius configuration: " + ", ".join(missing))
        return self
