from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass

from .features import (
    Request,
    extract,
    hint,
    route,
    text,
)
from .inference import Predictor
from .policy import Action, Policy
from .store import Store


@dataclass(frozen=True)
class Decision:
    mitigation_id: int
    risk: float
    action: Action
    attack_type: str
    route: str
    new_mitigation: bool
    features: dict[str, int | float]


class Engine:
    def __init__(self, classifier: Predictor, store: Store, policy: Policy) -> None:
        self.classifier = classifier
        self.store = store
        self.policy = policy
        self._contained: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def inspect(self, request: Request, client: str = "unknown") -> Decision:
        started = time.perf_counter()
        feature_map = extract(request).mapping()
        risk = self.classifier.predict(list(feature_map.values()))
        path = route(request.target)
        key = (client, path)
        now = time.monotonic()
        with self._lock:
            until = self._contained.get(key, 0.0)
            contained = self.policy.enforcement_enabled and until > now
            if until and until <= now:
                self._contained.pop(key, None)
        action = Action.ALLOW
        if contained:
            risk = max(risk, self.policy.block_at)
            action = Action.BLOCK
        elif risk >= self.policy.block_at:
            action = Action.BLOCK if self.policy.enforcement_enabled else Action.OBSERVE
        elif risk >= self.policy.observe_at:
            action = Action.OBSERVE
        attack_type = "automated-scan" if contained else hint(request)
        value, _ = text(request, 2048)
        sample = re.sub(r"(?i)(authorization|cookie):[^\n]+", r"\1:[redacted]", value)[:2048]
        signature = ("contained" if contained else
                     re.sub(r"[0-9a-f]{8,}|\d+", ":value", sample.lower()))
        fingerprint = hashlib.sha256(
            f"{request.method.upper()}\0{path}\0{attack_type}\0{signature}".encode()
        ).hexdigest()
        latency = (time.perf_counter() - started) * 1000
        if action is Action.ALLOW:
            self.store.allow(risk, latency)
            return Decision(0, risk, action, attack_type, path, False, feature_map)
        if action is Action.BLOCK and not contained and self.policy.containment_seconds:
            with self._lock:
                self._contained[key] = now + self.policy.containment_seconds
        mitigation_id, created = self.store.record(
            fingerprint=fingerprint, client=client, method=request.method.upper(), route=path,
            attack_type=attack_type, risk=risk, action=action.value, latency_ms=latency,
            sample=sample, features=feature_map,
        )
        return Decision(mitigation_id, risk, action, attack_type, path, created, feature_map)
