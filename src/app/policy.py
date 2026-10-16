from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    ALLOW = "allow"
    OBSERVE = "observe"
    THROTTLE = "throttle"
    BLOCK = "block"


@dataclass(frozen=True)
class Policy:
    observe_at: float = 0.70
    block_at: float = 0.98
    enforcement_enabled: bool = False
    containment_seconds: float = 60.0

    def __post_init__(self) -> None:
        thresholds = (self.observe_at, self.block_at)
        if not 0 <= thresholds[0] <= thresholds[1] <= 1:
            raise ValueError("policy thresholds must be ordered between zero and one")
        if self.containment_seconds < 0:
            raise ValueError("containment duration cannot be negative")


def decide(risk: float, confirmations: int, config: Policy) -> Action:
    if not 0 <= risk <= 1:
        raise ValueError("risk must be between zero and one")
    if risk < config.observe_at:
        return Action.ALLOW
    if risk < config.block_at:
        return Action.OBSERVE
    if not config.enforcement_enabled:
        return Action.OBSERVE
    return Action.BLOCK
